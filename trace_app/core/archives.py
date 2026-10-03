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
    if hasattr(data, 'read'):
        # A file object (a large mailbox read lazily from the image): its
        # header, and back to the start for whoever reads it next.
        try:
            data.seek(0)
            header = data.read(600)
            data.seek(0)
        except (IOError, OSError):
            return None
        data = header
    if not data or len(data) < 4:
        return None

    # An Outlook mailbox: browsed like an archive (core/mailbox.py).
    from trace_app.core.mailbox import is_mailbox
    if is_mailbox(data[:16]):
        return 'pst'

    # A thumbnail cache: a folder of pictures (core/thumbnails.py).
    from trace_app.core import thumbnails
    if thumbnails.is_thumbcache(data[:8]):
        return 'thumbcache'
    if isinstance(data, (bytes, bytearray)) and len(data) >= 1536 and \
            thumbnails.is_thumbs_db(data):
        return 'thumbsdb'

    for magic, kind in _SIGNATURES:
        if kind == 'tar':
            continue
        if data.startswith(magic):
            return kind

    # TAR keeps its magic 257 bytes in, and has no signature at offset 0.
    if len(data) > 262 and data[257:262] == b'ustar':
        return 'tar'

    # A saved message or an mbox: text, recognised by its header block
    # (core/mailfiles.py), and browsed like an archive of its parts.
    from trace_app.core.mailfiles import mail_kind
    return mail_kind(data[:4096])


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
        # .tar.gz and friends are a tar inside a single-stream compressor, and
        # are far more common than a bare compressed file. tarfile reads all
        # three transparently, so try it first and fall back to treating the
        # stream as one file.
        try:
            return _list_tar(data)
        except ArchiveError:
            return _list_single_stream(data, kind)
    if kind == '7z':
        return _list_7z(data, password)
    if kind == 'rar':
        return _list_rar(data)
    if kind == 'pst':
        return _mailbox_call('list_members', data)
    if kind in MAIL_KINDS:
        return _mailfile_call('list_members', data, kind)
    if kind in THUMBNAIL_KINDS:
        return _thumbnail_call('list_members', data, kind)

    raise ArchiveError(f"Unsupported archive format: {kind}")


#: Mail formats that are text: a saved message, and an mbox of them.
MAIL_KINDS = ('eml', 'mbox')
#: What is browsed from the image as it is read, never held whole.
STREAMED_KINDS = ('pst', 'mbox')


#: Thumbnail caches, browsed as the pictures they hold.
THUMBNAIL_KINDS = ('thumbcache', 'thumbsdb')


def _thumbnail_call(name, *args):
    from trace_app.core import thumbnails
    try:
        return getattr(thumbnails, name)(*args)
    except thumbnails.ThumbnailError as exc:
        raise ArchiveError(str(exc)) from exc


def _mailfile_call(name, *args):
    from trace_app.core import mailfiles
    try:
        return getattr(mailfiles, name)(*args)
    except mailfiles.MailFileError as exc:
        raise ArchiveError(str(exc)) from exc


def _mailbox_call(name, *args):
    from trace_app.core import mailbox
    try:
        return getattr(mailbox, name)(*args)
    except mailbox.MailboxError as exc:
        raise ArchiveError(str(exc)) from exc


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
        # See list_members: a compressed tarball is read as a tar.
        if member_name:
            try:
                return _read_tar_member(data, member_name, limit)
            except ArchiveError:
                pass
        return _read_single_stream(data, kind, limit)
    if kind == '7z':
        return _read_7z_member(data, member_name, password, limit)
    if kind == 'rar':
        return _read_rar_member(data, member_name, limit)
    if kind == 'pst':
        return _mailbox_call('read_member', data, member_name, limit)
    if kind in MAIL_KINDS:
        return _mailfile_call('read_member', data, member_name, limit, kind)
    if kind in THUMBNAIL_KINDS:
        return _thumbnail_call('read_member', data, member_name, kind, limit)

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

def _open_7z(data, password):
    """A py7zr archive, or EncryptedArchive if even its names need a password.

    py7zr raises its own PasswordRequired when the header -- the list of
    names -- is encrypted. That is a finding, not a read failure, and is
    reported as one.
    """
    py7zr = _import_7z()
    try:
        return py7zr.SevenZipFile(io.BytesIO(data), password=password)
    except py7zr.exceptions.PasswordRequired as exc:
        raise EncryptedArchive(
            "This 7z archive encrypts its file names; it needs a password "
            "even to list.") from exc


def _list_7z(data, password):
    try:
        with _open_7z(data, password) as archive:
            # Names are readable but contents are not: list the members and
            # say they are encrypted, as a ZIP is -- the names are evidence
            # even when the bytes are locked.
            locked = archive.needs_password() and not password
            return [{
                'name': info.filename,
                'size': info.uncompressed or 0,
                'compressed_size': info.compressed or 0,
                'is_dir': info.is_directory,
                'modified': str(info.creationtime or ''),
                'encrypted': locked and not info.is_directory,
                'crc': f"{info.crc32:08x}" if getattr(info, 'crc32', None) else '',
            } for info in archive.list()]
    except EncryptedArchive:
        raise
    except Exception as exc:
        raise ArchiveError(f"Could not read 7z archive: {exc}") from exc


def _read_7z_member(data, name, password, limit):
    py7zr = _import_7z()
    from py7zr.io import BytesIOFactory
    try:
        with _open_7z(data, password) as archive:
            if archive.needs_password() and not password:
                raise EncryptedArchive(
                    f"{name} is encrypted and needs a password.")
            info = next((i for i in archive.list() if i.filename == name),
                        None)
            if info is None or info.is_directory:
                raise ArchiveError(f"No member named {name}.")
            size = info.uncompressed or 0
            # Checked before extracting, not after: py7zr's in-memory writer
            # silently stops at its limit, so an oversized member would come
            # back truncated and look complete.
            if size > limit:
                raise ArchiveError(
                    f"{name} is {size:,} bytes, more than the "
                    f"{limit:,} TRACE reads from an archive at once.")
            _guard_bomb(info.compressed or 0, size, name)
            factory = BytesIOFactory(size + 1)
            archive.extract(targets=[name], factory=factory)
            product = factory.products.get(name)
            if product is None:
                raise ArchiveError(f"No member named {name}.")
            product.seek(0)
            return product.read()
    except (EncryptedArchive, ArchiveError):
        raise
    except py7zr.exceptions.PasswordRequired as exc:
        raise EncryptedArchive(f"{name} is encrypted and needs a password.")             from exc
    except Exception as exc:
        raise ArchiveError(f"Could not read {name}: {exc}") from exc


# --- RAR ------------------------------------------------------------------
#
# rarfile parses RAR3 and RAR5 headers in pure Python: every member's name,
# size, date and whether it is encrypted, which is what an examiner needs
# from an archive. Members stored without compression are read the same way.
# Decompressing anything else needs the unrar program -- not installable
# without system packages on every platform, and rarfile would hand it a copy
# of the evidence written to a temporary file -- so TRACE never asks for it:
# a compressed member is listed, and reported, not read.

#: RAR's "store" method: the member's bytes are in the archive as they are.
_RAR_STORED = 0x30


def _import_rar():
    try:
        import rarfile
    except ImportError as exc:
        raise ArchiveError("RAR support needs rarfile "
                           "(pip install -r requirements.txt).") from exc
    # An old RAR3 archive can carry a compressed comment, which rarfile
    # decompresses -- through the external tool -- while merely opening the
    # archive. Listing needs no comment, and no evidence is handed to a
    # program outside TRACE.
    parser = getattr(rarfile, 'RAR3Parser', None)
    if parser is not None and not getattr(parser, '_trace_no_comments', False):
        parser._read_comment_v3 = lambda self, inf, pwd=None: None
        parser._trace_no_comments = True
    return rarfile


def _open_rar(data):
    rarfile = _import_rar()
    try:
        archive = rarfile.RarFile(io.BytesIO(data))
    except rarfile.PasswordRequired as exc:
        raise EncryptedArchive(
            "This RAR archive encrypts its file names; it needs a password "
            "even to list.") from exc
    except (rarfile.Error, OSError, ValueError) as exc:
        raise ArchiveError(f"Could not read RAR archive: {exc}") from exc
    if archive.needs_password() and not archive.infolist():
        raise EncryptedArchive(
            "This RAR archive encrypts its file names; it needs a password "
            "even to list.")
    return archive


def _list_rar(data):
    archive = _open_rar(data)
    members = []
    for info in archive.infolist():
        modified = ''
        if info.mtime is not None:
            modified = info.mtime.strftime('%Y-%m-%d %H:%M:%S')
        elif info.date_time:
            modified = '%04d-%02d-%02d %02d:%02d:%02d' % info.date_time
        members.append({
            'name': info.filename,
            'size': info.file_size or 0,
            'compressed_size': info.compress_size or 0,
            'is_dir': info.is_dir(),
            'modified': modified,
            'encrypted': bool(info.needs_password()) and not info.is_dir(),
            'crc': f"{info.CRC:08x}" if info.CRC else '',
            # Readable here only if stored; otherwise listed, not opened.
            'compressed': info.compress_type != _RAR_STORED,
        })
    return members


def _read_rar_member(data, name, limit):
    rarfile = _import_rar()
    archive = _open_rar(data)
    try:
        info = archive.getinfo(name)
    except (KeyError, rarfile.NoRarEntry) as exc:
        raise ArchiveError(f"No member named {name}.") from exc
    if info.is_dir():
        raise ArchiveError(f"{name} is a folder.")
    if info.needs_password():
        raise EncryptedArchive(f"{name} is encrypted and needs a password.")
    if info.compress_type != _RAR_STORED:
        raise ArchiveError(
            f"{name} is compressed with RAR's own method. TRACE lists it -- "
            f"name, size, date and CRC are above -- but reading its contents "
            f"needs the unrar program, which TRACE does not use.")
    if info.file_size > limit:
        raise ArchiveError(f"{name} is {info.file_size:,} bytes, more than the "
                           f"{limit:,} TRACE reads from an archive at once.")
    try:
        return archive.read(info)
    except rarfile.NeedFirstVolume as exc:
        raise ArchiveError(f"{name} begins in an earlier volume of a "
                           f"multi-part archive.") from exc
    except (rarfile.Error, OSError, EOFError) as exc:
        raise ArchiveError(f"Could not read {name}: {exc} -- in a "
                           f"multi-part archive it may continue in the next "
                           f"volume.") from exc


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
        return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime(
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
