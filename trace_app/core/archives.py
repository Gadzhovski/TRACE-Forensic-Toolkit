"""Reading archives that live inside a disk image, without unpacking them.

An examiner who finds a ZIP in evidence wants to see what is in it. Extracting
it to disk to find out is both slow and a change to the working set that has to
be explained later, so this reads members straight out of the archive's bytes.

Everything here works from a bytes object, because that is what
ImageHandler.get_file_content returns: the archive is never written to disk to
be opened. Nested archives follow the same path -- a member's bytes are just
another archive.

No Qt imports belong here.
"""

import bz2
import gzip
import io
import logging
import lzma
import os
import tarfile
import zipfile

logger = logging.getLogger('TRACE.Archives')

#: How much of a member will be read into memory at once. An archive found in
#: evidence is untrusted input: a few hundred bytes can expand to gigabytes,
#: and a viewer that tries to show all of it takes the application with it.
MAX_MEMBER_BYTES = 64 * 1024 * 1024

#: Compression ratio past which a member is treated as a decompression bomb
#: rather than a file. Legitimate text compresses perhaps 10:1; 1000:1 is a
#: constructed archive.
BOMB_RATIO = 1000

#: How deep nested archives are followed. An archive inside an archive is
#: ordinary; a hundred deep is an attack on the tool.
MAX_NESTING = 8

#: Signatures, longest first so a more specific one wins.
_SIGNATURES = (
    (b'PK\x03\x04', 'zip'),
    (b'PK\x05\x06', 'zip'),          # empty archive
    (b'\x1f\x8b\x08', 'gzip'),
    (b'BZh', 'bzip2'),
    (b'\xfd7zXZ\x00', 'xz'),
    (b'7z\xbc\xaf\x27\x1c', '7z'),
    (b'Rar!\x1a\x07', 'rar'),
    (b'ustar', 'tar'),               # at offset 257, handled separately
)


class ArchiveError(Exception):
    """An archive could not be opened or read."""


class EncryptedArchive(ArchiveError):
    """The archive, or a member of it, needs a password.

    Raised rather than returning empty content: an examiner told "this file is
    empty" would draw the wrong conclusion about the evidence.
    """


def detect_archive(data):
    """What kind of archive `data` is, or None.

    Reads only the header, so it is cheap enough to call on every file in a
    listing.
    """
    if not data or len(data) < 4:
        return None

    for magic, kind in _SIGNATURES:
        if kind == 'tar':
            continue
        if data.startswith(magic):
            return kind

    # TAR keeps its magic 257 bytes in, and has no signature at offset 0.
    if len(data) > 262 and data[257:262] == b'ustar':
        return 'tar'

    return None


def is_archive(data):
    return detect_archive(data) is not None


def list_members(data, kind=None, password=None):
    """Every member of the archive, as a list of dicts.

    Each entry carries `name`, `size`, `compressed_size`, `is_dir`,
    `modified`, `encrypted` and `crc`. Nothing is decompressed here: listing an
    archive reads its directory, which is what makes browsing one cheap.
    """
    kind = kind or detect_archive(data)
    if kind is None:
        raise ArchiveError("Not a recognised archive format.")

    if kind == 'zip':
        return _list_zip(data)
    if kind == 'tar':
        return _list_tar(data)
    if kind in ('gzip', 'bzip2', 'xz'):
        return _list_single_stream(data, kind)
    if kind == '7z':
        return _list_7z(data, password)
    if kind == 'rar':
        raise ArchiveError(
            "RAR archives need the unrar library, which is not bundled.")

    raise ArchiveError(f"Unsupported archive format: {kind}")


def read_member(data, member_name=None, kind=None, password=None,
                limit=MAX_MEMBER_BYTES):
    """The bytes of one member, without unpacking the rest.

    `member_name` may be omitted for gzip, bzip2 and xz, which hold a single
    stream rather than a directory of members.
    """
    kind = kind or detect_archive(data)
    if kind is None:
        raise ArchiveError("Not a recognised archive format.")

    if kind == 'zip':
        return _read_zip_member(data, member_name, password, limit)
    if kind == 'tar':
        return _read_tar_member(data, member_name, limit)
    if kind in ('gzip', 'bzip2', 'xz'):
        return _read_single_stream(data, kind, limit)
    if kind == '7z':
        return _read_7z_member(data, member_name, password, limit)

    raise ArchiveError(f"Unsupported archive format: {kind}")


# --- ZIP ------------------------------------------------------------------

def _list_zip(data):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = []
            for info in archive.infolist():
                members.append({
                    'name': info.filename,
                    'size': info.file_size,
                    'compressed_size': info.compress_size,
                    'is_dir': info.is_dir(),
                    'modified': _zip_time(info),
                    # Bit 0 of the flag word is set on an encrypted member.
                    'encrypted': bool(info.flag_bits & 0x1),
                    'crc': f"{info.CRC:08x}" if info.CRC else '',
                })
            return members
    except zipfile.BadZipFile as exc:
        raise ArchiveError(f"Damaged ZIP archive: {exc}") from exc


def _read_zip_member(data, name, password, limit):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            info = archive.getinfo(name)
            if info.flag_bits & 0x1 and not password:
                raise EncryptedArchive(
                    f"{name} is encrypted and needs a password.")
            _guard_bomb(info.compress_size, info.file_size, name)
            with archive.open(info, pwd=password.encode() if password else None) as handle:
                return handle.read(limit)
    except RuntimeError as exc:
        # zipfile raises RuntimeError for a bad or missing password.
        if 'password' in str(exc).lower():
            raise EncryptedArchive(str(exc)) from exc
        raise ArchiveError(str(exc)) from exc
    except KeyError as exc:
        raise ArchiveError(f"No member named {name}.") from exc
    except zipfile.BadZipFile as exc:
        raise ArchiveError(f"Damaged ZIP archive: {exc}") from exc


def _zip_time(info):
    try:
        year, month, day, hour, minute, second = info.date_time
        return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
    except (TypeError, ValueError):
        return ''


# --- TAR ------------------------------------------------------------------

def _list_tar(data):
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
            members = []
            for info in archive.getmembers():
                members.append({
                    'name': info.name,
                    'size': info.size,
                    'compressed_size': info.size,
                    'is_dir': info.isdir(),
                    'modified': _epoch_to_text(info.mtime),
                    'encrypted': False,     # TAR has no encryption of its own
                    'crc': '',
                })
            return members
    except tarfile.TarError as exc:
        raise ArchiveError(f"Damaged TAR archive: {exc}") from exc


def _read_tar_member(data, name, limit):
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
            handle = archive.extractfile(name)
            if handle is None:
                raise ArchiveError(f"{name} is not a readable member.")
            return handle.read(limit)
    except tarfile.TarError as exc:
        raise ArchiveError(f"Damaged TAR archive: {exc}") from exc


# --- single-stream compressors -------------------------------------------

def _list_single_stream(data, kind):
    """gzip, bzip2 and xz hold one stream, not a directory.

    The inner name is only recorded by gzip, and only sometimes; where it is
    absent the archive's own name minus its suffix is the best guess a listing
    can offer.
    """
    name = _gzip_inner_name(data) if kind == 'gzip' else ''
    return [{
        'name': name or f'(decompressed {kind} stream)',
        'size': _single_stream_size(data, kind),
        'compressed_size': len(data),
        'is_dir': False,
        'modified': '',
        'encrypted': False,
        'crc': '',
    }]


def _read_single_stream(data, kind, limit):
    # GzipFile takes the stream as `fileobj`; BZ2File and LZMAFile take it
    # positionally. Passing the wrong one is a TypeError, not a bad archive.
    try:
        if kind == 'gzip':
            handle = gzip.GzipFile(fileobj=io.BytesIO(data))
        elif kind == 'bzip2':
            handle = bz2.BZ2File(io.BytesIO(data))
        else:
            handle = lzma.LZMAFile(io.BytesIO(data))
        with handle:
            content = handle.read(limit)
    except (OSError, EOFError, lzma.LZMAError) as exc:
        raise ArchiveError(f"Damaged {kind} stream: {exc}") from exc
    _guard_bomb(len(data), len(content), kind)
    return content


def _single_stream_size(data, kind):
    """Uncompressed size, where it can be had without decompressing.

    gzip stores it in the last four bytes, modulo 4 GB. The others do not, so
    they report their compressed size and the listing says as much.
    """
    if kind == 'gzip' and len(data) > 8:
        return int.from_bytes(data[-4:], 'little')
    return len(data)


def _gzip_inner_name(data):
    """The original filename, if the gzip header carries one."""
    if len(data) < 11 or data[:3] != b'\x1f\x8b\x08':
        return ''
    if not data[3] & 0x08:      # FNAME flag
        return ''
    end = data.find(b'\x00', 10)
    if end == -1:
        return ''
    return data[10:end].decode('utf-8', errors='replace')


# --- 7z -------------------------------------------------------------------

def _list_7z(data, password):
    py7zr = _import_7z()
    try:
        with py7zr.SevenZipFile(io.BytesIO(data), password=password) as archive:
            if archive.needs_password() and not password:
                raise EncryptedArchive(
                    "This 7z archive is encrypted and needs a password.")
            return [{
                'name': info.filename,
                'size': info.uncompressed or 0,
                'compressed_size': info.compressed or 0,
                'is_dir': info.is_directory,
                'modified': str(info.creationtime or ''),
                'encrypted': bool(getattr(info, 'crc32', None) is None
                                  and archive.needs_password()),
                'crc': f"{info.crc32:08x}" if getattr(info, 'crc32', None) else '',
            } for info in archive.list()]
    except EncryptedArchive:
        raise
    except Exception as exc:
        raise ArchiveError(f"Could not read 7z archive: {exc}") from exc


def _read_7z_member(data, name, password, limit):
    py7zr = _import_7z()
    try:
        with py7zr.SevenZipFile(io.BytesIO(data), password=password) as archive:
            if archive.needs_password() and not password:
                raise EncryptedArchive(
                    f"{name} is encrypted and needs a password.")
            extracted = archive.read([name])
            if not extracted or name not in extracted:
                raise ArchiveError(f"No member named {name}.")
            return extracted[name].read(limit)
    except (EncryptedArchive, ArchiveError):
        raise
    except Exception as exc:
        raise ArchiveError(f"Could not read {name}: {exc}") from exc


def _import_7z():
    try:
        import py7zr
    except ImportError as exc:
        raise ArchiveError(
            "7z archives need the py7zr package, which is not installed. "
            "Run: pip install py7zr") from exc
    return py7zr


# --- guards ---------------------------------------------------------------

def _guard_bomb(compressed, uncompressed, name):
    """Refuse a member whose expansion ratio marks it as a bomb.

    An archive recovered from evidence is untrusted input. A file that expands
    a thousandfold is not something an examiner needs shown; it is something
    that takes the application down.
    """
    if compressed and uncompressed / max(compressed, 1) > BOMB_RATIO:
        raise ArchiveError(
            f"{name} expands {uncompressed // max(compressed, 1)}x, which is "
            f"far beyond normal compression. It has not been read, to avoid "
            f"exhausting memory.")


def _epoch_to_text(seconds):
    import datetime
    try:
        return datetime.datetime.utcfromtimestamp(seconds).strftime(
            '%Y-%m-%d %H:%M:%S')
    except (OSError, OverflowError, ValueError):
        return ''


def archive_summary(data):
    """A one-line description of an archive, for a listing or a viewer."""
    kind = detect_archive(data)
    if kind is None:
        return ''
    try:
        members = list_members(data, kind)
    except EncryptedArchive:
        return f"{kind.upper()} archive, encrypted"
    except ArchiveError as exc:
        return f"{kind.upper()} archive ({exc})"

    files = [m for m in members if not m['is_dir']]
    locked = sum(1 for m in files if m['encrypted'])
    text = f"{kind.upper()} archive, {len(files)} file(s)"
    if locked:
        text += f", {locked} encrypted"
    return text
