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

ALGORITHMS = ('md5', 'sha1', 'sha256')
BLOCK = 4 * 1024 * 1024


class HashingError(Exception):
    """The evidence could not be read in full; nothing was hashed."""


def new_hashers():
    return {name: hashlib.new(name) for name in ALGORITHMS}


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
    hashers = new_hashers()
    position = 0
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
        for hasher in hashers.values():
            hasher.update(data)
        position += len(data)
        _report(progress, position, size)
    return digests(hashers, position)


def hash_stream(chunks, size, progress=None, what='image'):
    """Hash an iterable of byte strings that should total `size`."""
    hashers = new_hashers()
    position = 0
    for data in chunks:
        for hasher in hashers.values():
            hasher.update(data)
        position += len(data)
        _report(progress, position, size)
    if position != size:
        raise HashingError(f"The {what} gave {position:,} bytes; it "
                           f"should hold {size:,}")
    return digests(hashers, position)


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
