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
import io
import logging
import lzma
import tarfile
import zipfile
import zlib

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

    # An RDP bitmap cache: its tiles, as pictures (core/rdpcache.py).
    from trace_app.core import rdpcache
    if rdpcache.is_bin(data[:8]):
        return 'rdpcache'

    for magic, kind in _SIGNATURES:
        if kind == 'tar':
            continue
        if data.startswith(magic):
            return kind

    # TAR keeps its magic 257 bytes in, and has no signature at offset 0.
    if len(data) > 262 and data[257:262] == b'ustar':
        return 'tar'

    # CPIO (initramfs, RPM payloads): its magic, then a consistent header.
    from trace_app.core import cpio
    if isinstance(data, (bytes, bytearray)) and cpio.format_of(data):
        return 'cpio'

    # Headerless compressed streams: LZMA "alone" (.lzma) and raw zlib.
    # Their few header bytes could start anything, so a trial
    # decompression must succeed as well.
    if isinstance(data, (bytes, bytearray)):
        if _is_lzma_alone(data):
            return 'lzma'
        if _is_zlib(data):
            return 'zlib'

    # Defender's quarantined content (Quarantine\ResourceData\..): RC4 of
    # BackupRead's streams, browsed as the file and its streams.
    from trace_app.core.activity.defender import is_resource_data
    if isinstance(data, (bytes, bytearray)) and is_resource_data(data[:20]):
        return 'defender'

    # A saved message or an mbox: text, recognised by its header block
    # (core/mailfiles.py), and browsed like an archive of its parts.
    if isinstance(data, (bytes, bytearray)) and rdpcache.looks_like_bmc(data):
        return 'rdpcache'

    from trace_app.core.mailfiles import mail_kind
    return mail_kind(data[:4096])



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
    if kind in SINGLE_STREAMS:
        # .tar.gz and friends are a tar inside a single-stream compressor, and
        # are far more common than a bare compressed file. tarfile reads
        # gzip, bzip2, xz and LZMA-alone transparently, so try it first and
        # fall back to treating the stream as one file.
        if kind != 'zlib':
            try:
                return _list_tar(data)
            except ArchiveError:
                pass
        return _list_single_stream(data, kind)
    if kind == 'cpio':
        return _list_cpio(data)
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
    if kind == 'rdpcache':
        return _rdp_call('list_members', data)
    if kind == 'defender':
        return [{'name': name, 'size': len(content),
                 'compressed_size': len(content), 'is_dir': False,
                 'modified': None, 'encrypted': False, 'crc': None}
                for name, content in _quarantined(data)]

    raise ArchiveError(f"Unsupported archive format: {kind}")


def _quarantined(data):
    """[(member name, bytes)] of a Defender ResourceData file: the
    quarantined file, its alternate streams (Zone.Identifier says where it
    came from) and its security descriptor."""
    from trace_app.core.activity.defender import resource_streams
    out = []
    for kind, name, content in resource_streams(bytes(data)):
        if kind == 'data':
            label = 'quarantined file'
        elif kind == 'alternate stream':
            label = 'stream ' + (name.strip(':').split(':')[0] or 'unnamed')
        else:
            label = kind
        while label in {n for n, _c in out}:
            label += ' (2)'
        out.append((label, content))
    if not out:
        raise ArchiveError("Not quarantined content Defender can have "
                           "written")
    return out


#: Mail formats that are text: a saved message, and an mbox of them.
MAIL_KINDS = ('eml', 'mbox')
#: What is browsed from the image as it is read, never held whole.
STREAMED_KINDS = ('pst', 'mbox')


#: Thumbnail caches, browsed as the pictures they hold.
THUMBNAIL_KINDS = ('thumbcache', 'thumbsdb')


def _rdp_call(name, *args):
    from trace_app.core import rdpcache
    try:
        return getattr(rdpcache, name)(bytes(args[0]), *args[1:])
    except rdpcache.RdpCacheError as exc:
        raise ArchiveError(str(exc)) from exc


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
                limit=None):
    """The bytes of one member, without unpacking the rest.

    `member_name` may be omitted for gzip, bzip2 and xz, which hold a single
    stream rather than a directory of members. `limit` defaults to
    MAX_MEMBER_BYTES as it is now -- a case's setting (core/settings.py) --
    not as it was when this module loaded.
    """
    if limit is None:
        limit = MAX_MEMBER_BYTES
    kind = kind or detect_archive(data)
    if kind is None:
        raise ArchiveError("Not a recognised archive format.")

    if kind == 'zip':
        return _read_zip_member(data, member_name, password, limit)
    if kind == 'tar':
        return _read_tar_member(data, member_name, limit)
    if kind in SINGLE_STREAMS:
        # See list_members: a compressed tarball is read as a tar.
        if member_name and kind != 'zlib':
            try:
                return _read_tar_member(data, member_name, limit)
            except ArchiveError:
                pass
        return _read_single_stream(data, kind, limit)
    if kind == 'cpio':
        from trace_app.core import cpio
        try:
            return cpio.read(data, member_name, limit)
        except cpio.CpioError as exc:
            raise ArchiveError(str(exc)) from exc
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
    if kind == 'rdpcache':
        return _rdp_call('read_member', data, member_name)
    if kind == 'defender':
        for name, content in _quarantined(data):
            if name == member_name:
                return content[:limit]
        raise ArchiveError(f"No member {member_name!r}")

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

#: Compressors holding one stream rather than a directory of members.
SINGLE_STREAMS = ('gzip', 'bzip2', 'xz', 'lzma', 'zlib')


def _list_single_stream(data, kind):
    """gzip, bzip2, xz, LZMA-alone and zlib hold one stream, not a
    directory.

    The inner name is only recorded by gzip, and only sometimes. The
    stream is decompressed (up to the member limit) for its true size and
    to find damage: a stream cut short -- a log rotated mid-write, a
    carved or partly overwritten file -- is listed with what can be
    recovered, marked 'damaged', rather than refused.
    """
    name = _gzip_inner_name(data) if kind == 'gzip' else ''
    content, problem = _inflate(data, kind, MAX_MEMBER_BYTES)
    return [{
        'name': name or f'(decompressed {kind} stream)',
        'size': len(content),
        'compressed_size': len(data),
        'is_dir': False,
        'modified': '',
        'encrypted': False,
        'crc': '',
        'damaged': problem,
    }]


def _read_single_stream(data, kind, limit):
    """The stream's bytes; of a damaged stream, what decompresses before
    the damage (the listing says what is missing)."""
    content, problem = _inflate(data, kind, limit)
    if problem and not content:
        raise ArchiveError(f"Damaged {kind} stream: {problem}")
    _guard_bomb(len(data), len(content), kind)
    return content


def _inflate(data, kind, limit):
    """(bytes, problem): the stream decompressed up to `limit` bytes --
    every gzip member, every xz/bzip2 stream in turn -- and '' or what is
    wrong with it. Decompression stops at damage, keeping what came
    before: zlib checks each gzip member's CRC-32 and size as it ends."""
    if limit is None:
        limit = MAX_MEMBER_BYTES
    out = bytearray()
    remaining = bytes(data)
    members = 0
    while remaining and len(out) < limit:
        if kind == 'gzip':
            engine = zlib.decompressobj(31)
        elif kind == 'zlib':
            engine = zlib.decompressobj()
        elif kind == 'bzip2':
            engine = bz2.BZ2Decompressor()
        elif kind == 'xz':
            engine = lzma.LZMADecompressor(lzma.FORMAT_XZ)
        else:
            engine = lzma.LZMADecompressor(lzma.FORMAT_ALONE)
        try:
            if kind in ('gzip', 'zlib'):
                piece = engine.decompress(remaining, limit - len(out))
                while engine.unconsumed_tail and len(out) + len(piece) < \
                        limit:
                    piece += engine.decompress(engine.unconsumed_tail,
                                               limit - len(out) - len(piece))
                out += piece
                finished, rest = engine.eof, engine.unused_data
            else:
                out += engine.decompress(remaining, limit - len(out))
                while not engine.eof and not engine.needs_input and \
                        len(out) < limit:
                    out += engine.decompress(b'', limit - len(out))
                finished, rest = engine.eof, engine.unused_data
        except (zlib.error, OSError, EOFError, lzma.LZMAError) as exc:
            return bytes(out), (f"damaged after {len(out):,} bytes "
                                f"({exc}); what came before is shown")
        members += 1
        if len(out) >= limit:
            return bytes(out[:limit]), ''
        if not finished:
            return bytes(out), (f"the stream ends without its end marker "
                                f"(cut short): {len(out):,} bytes "
                                f"recovered")
        remaining = rest
        # Another member follows only for the formats that allow it, and
        # only if it starts like one; padding (zeros) ends the stream.
        if kind in ('zlib', 'lzma') or not remaining.strip(b'\0'):
            break
        if kind == 'gzip' and not remaining.startswith(b'\x1f\x8b'):
            return bytes(out), (f"{len(remaining):,} bytes follow the last "
                                f"gzip member and are not one")
    return bytes(out), ''


def _is_lzma_alone(data):
    """An LZMA-alone header: properties < 225, a sane dictionary size,
    a size field that is unknown or plausible -- and a trial decode."""
    if len(data) < 18 or data[0] >= 225:
        return False
    dictionary = int.from_bytes(data[1:5], 'little')
    size = int.from_bytes(data[5:13], 'little')
    # The encoders write 2**n or 2**n + 2**(n-1); anything else is not
    # an LZMA header, whatever a permissive decoder makes of it.
    if not 4096 <= dictionary <= 1 << 30 or not any(
            dictionary in (1 << n, (1 << n) + (1 << (n - 1)))
            for n in range(12, 31)):
        return False
    if size != (1 << 64) - 1 and size > 1 << 40:
        return False
    try:
        engine = lzma.LZMADecompressor(lzma.FORMAT_ALONE)
        out = engine.decompress(data[:262144], 4096)
        return len(out) >= 4096 or (engine.eof and bool(out) and (
            size == (1 << 64) - 1 or size == len(out)))
    except lzma.LZMAError:
        return False


def _is_zlib(data):
    """A zlib header (deflate, a valid window, check bits, no preset
    dictionary) whose first bytes inflate."""
    if len(data) < 8:
        return False
    cmf, flg = data[0], data[1]
    if cmf & 0x0F != 8 or cmf >> 4 > 7 or (cmf << 8 | flg) % 31 or \
            flg & 0x20:
        return False
    try:
        engine = zlib.decompressobj()
        out = engine.decompress(data[:262144])
    except zlib.error:
        return False
    if len(out) < 8:
        return False
    # A zlib stream followed by more data (not padding) is the first chunk
    # of a container -- a DMG's data fork begins this way -- not a zlib
    # file.
    if engine.eof and engine.unused_data.strip(b'\0'):
        return False
    return True


def _list_cpio(data):
    from trace_app.core import cpio
    try:
        found = cpio.members(data)
    except cpio.CpioError as exc:
        raise ArchiveError(f"Damaged CPIO archive: {exc}") from exc
    return [{'name': m['name'], 'size': m['size'],
             'compressed_size': m['size'], 'is_dir': m['is_dir'],
             'modified': m['modified'], 'encrypted': False, 'crc': '',
             'damaged': m['damaged']} for m in found]


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


