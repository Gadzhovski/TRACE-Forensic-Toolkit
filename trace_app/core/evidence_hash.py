"""Hashing evidence: all of it, or an error -- never part of it (no Qt).

An evidence hash is a claim about every byte. A hash of whatever could be
read before a failure is a claim about something else, and recorded as a
baseline it makes the damaged copy the reference everything later is
checked against. So every evidence hash in TRACE goes through here:

* `hash_reader(read, size)` reads exactly `size` bytes through `read`
  (an image's reader); a read that raises or comes back short ends it
  with `HashingError` saying at which byte.
* `hash_file(path)` hashes a file's own bytes and checks the file still
  has the size it had when hashing began.

MD5, SHA-1 and SHA-256 are always computed together: one read, three
digests, so any one recorded later can be checked.
"""

import hashlib
import os
from collections.abc import Callable

ALGORITHMS = ('md5', 'sha1', 'sha256')
BLOCK = 4 * 1024 * 1024


class HashingError(Exception):
    """The evidence could not be read in full; nothing was hashed."""


def new_hashers():
    return {name: hashlib.new(name) for name in ALGORITHMS}


class Hashing:
    """MD5, SHA-1 and SHA-256 of one stream, each on its own thread.

    hashlib releases the interpreter lock while it digests a large buffer,
    so the three run at once: on 1 GiB, 2.57 s one after another, 1.28 s
    here -- the same digests. Data is handed over in batches of about
    `BATCH` bytes (a list of the pieces, never copied: an E01's 32 KB
    chunks one at a time would cost more in queueing than hashing). Pieces
    must not change after `update` -- bytes do not.

        with Hashing() as hashing:
            for data in ...:
                hashing.update(data)
        result = digests(hashing.hashers, size)   # after the with block
    """

    BATCH = 4 * 1024 * 1024

    def __init__(self, hashers=None):
        """`hashers`: hashlib objects to feed (a dict or a list); by
        default new MD5, SHA-1 and SHA-256 ones."""
        import queue
        import threading
        self.hashers = new_hashers() if hashers is None else hashers
        each = list(self.hashers.values() if isinstance(self.hashers, dict)
                    else self.hashers)
        self._pending, self._pending_size = [], 0
        self._failed = []
        self._queues = [queue.Queue(maxsize=4) for _ in each]
        self._threads = [
            threading.Thread(target=self._digest, args=(hasher, waiting),
                             name=f'hash-{hasher.name}', daemon=True)
            for hasher, waiting in zip(each, self._queues)]
        for thread in self._threads:
            thread.start()

    def _digest(self, hasher, waiting):
        while True:
            batch = waiting.get()
            if batch is None:
                return
            try:
                for piece in batch:
                    hasher.update(piece)
            except Exception as exc:        # MemoryError, a bad buffer
                self._failed.append(exc)

    def update(self, data):
        self._pending.append(data)
        self._pending_size += len(data)
        if self._pending_size >= self.BATCH:
            self._hand_over()

    def _hand_over(self):
        if self._pending:
            for waiting in self._queues:
                waiting.put(self._pending)
            self._pending, self._pending_size = [], 0

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        if kind is None:
            self._hand_over()
        for waiting in self._queues:
            waiting.put(None)
        for thread in self._threads:
            thread.join()
        if kind is None and self._failed:
            raise HashingError(f"Hashing failed: {self._failed[0]}")
        return False


def sha256_file(path: str,
                should_stop: Callable[[], bool] | None = None,
                cancelled: type[BaseException] | None = None) -> str:
    """The SHA-256 of a file TRACE wrote or copied (a report, a manifest,
    an export, a program) -- not of evidence, which hash_file covers with
    its checks. `should_stop()` true raises `cancelled()` (HashingError
    when none is named)."""
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
            if should_stop is not None and should_stop():
                if cancelled is None:
                    raise HashingError("Hashing stopped")
                raise cancelled()
    return digest.hexdigest()


def digests(hashers, size):
    """{'md5', 'sha1', 'sha256', 'size'} from finished hashers."""
    out = {name: hasher.hexdigest() for name, hasher in hashers.items()}
    out['size'] = size
    return out


def _report(progress, done, total):
    """Progress callbacks may raise HashingCancelled (a BaseException):
    that must stop the hashing, so it is not caught here."""
    if progress is not None:
        progress(done, total)


def hash_reader(read, size, progress=None, block=BLOCK, what='image'):
    """Hash `size` bytes read as read(offset, length). Raises HashingError
    on a read error or a short read."""
    position = 0
    with Hashing() as hashing:
        while position < size:
            want = min(block, size - position)
            try:
                data = read(position, want)
            except Exception as exc:
                raise HashingError(
                    f"Reading the {what} failed at byte {position:,} of "
                    f"{size:,}: {exc}") from exc
            if not data:
                raise HashingError(
                    f"The {what} ended at byte {position:,}; it should hold "
                    f"{size:,} bytes")
            if len(data) > want:
                data = data[:want]
            hashing.update(bytes(data))
            position += len(data)
            _report(progress, position, size)
    return digests(hashing.hashers, position)


def hash_file(path, progress=None, block=BLOCK):
    """Hash a file's bytes. Raises HashingError if it cannot be read in
    full, or if it changes size while being hashed."""
    try:
        handle = open(path, 'rb')
    except OSError as exc:
        raise HashingError(f"The file could not be opened: {exc}") from exc
    with handle:
        size = os.fstat(handle.fileno()).st_size

        def read(offset, length):
            handle.seek(offset)
            return handle.read(length)

        result = hash_reader(read, size, progress, block, what='file')
        try:
            after = os.fstat(handle.fileno()).st_size
        except OSError as exc:
            raise HashingError(f"The file could not be checked after "
                               f"hashing: {exc}") from exc
        if after != size:
            raise HashingError(f"The file changed size while it was "
                               f"hashed ({size:,} -> {after:,} bytes)")
    return result
