"""F2FS (core/f2fs.py), checked against volumes F2FS's own tools wrote.

tools/testdata/build/make_f2fs.py builds f2fs-tools 1.16.0 (with LZ4 and
LZO, which distributions leave out) and fills volumes from a known tree with
sload.f2fs: plain, LZ4- and LZO-compressed; where Linux can mount F2FS (CI)
the kernel writes one too, with a deleted file. Every file's bytes, every
link's target and the whole listing must equal the tree's answer key. Linux
CI builds the volumes; these tests skip elsewhere. The geometry tests need
no data.
"""

import hashlib
import json
import struct

import pytest

from tests.conftest import image_path
from trace_app.core import f2fs

KEY = 'f2fs-key.json'
SLOAD = ['f2fs-sload.raw', 'f2fs-lz4.raw', 'f2fs-lzo.raw']


def _key():
    with open(image_path(KEY), encoding='utf-8') as source:
        return json.load(source)


# --- the format's own numbers -------------------------------------------------

def test_layout_constants_are_the_kernels():
    assert f2fs.NAT_ENTRIES_PER_BLOCK == 455
    assert f2fs.SIT_ENTRIES_PER_BLOCK == 55
    assert f2fs.DENTRY_BITMAP == 27 and f2fs.DENTRY_RESERVED == 3
    assert f2fs.SUM_JOURNAL_SIZE == 507
    assert f2fs.I_NID == 4052


def test_checksums_and_bit_orders():
    # crc32_le seeded with the magic, no inversion: the kernel's
    # f2fs_crc32 over nothing is the seed itself.
    assert f2fs.crc32(b'') == f2fs.MAGIC
    assert f2fs._test_bit(b'\x80', 0) and not f2fs._test_bit(b'\x80', 7)
    assert f2fs._test_bit_le(b'\x01', 0) and not f2fs._test_bit_le(b'\x01', 7)


def test_a_long_name_spans_its_slots():
    """A dentry block with '.', '..', a 20-byte name over three slots and
    a short one after it."""
    block = bytearray(f2fs.BLOCK)
    entries = f2fs.DENTRY_BITMAP + f2fs.DENTRY_RESERVED
    names = entries + f2fs.DIR_ENTRY_SIZE * f2fs.NR_DENTRY_IN_BLOCK
    rows = [(b'.', 3, 2), (b'..', 3, 2), (b'a-twenty-byte-name.x', 7, 1),
            (b'b', 8, 7)]
    slot = 0
    for name, nid, kind in rows:
        used = max(1, -(-len(name) // f2fs.SLOT_LEN))
        block[slot >> 3] |= 1 << (slot & 7)
        struct.pack_into('<IIHB', block, entries + slot *
                         f2fs.DIR_ENTRY_SIZE, 0, nid, len(name), kind)
        block[names + slot * 8:names + slot * 8 + len(name)] = name
        slot += used
    out = []
    f2fs._dentries(bytes(block), f2fs.NR_DENTRY_IN_BLOCK, 0, entries, names,
                   out)
    assert out[2:] == [(b'a-twenty-byte-name.x', 7, 1), (b'b', 8, 7)]


def test_an_inline_folder_is_read_from_its_inode():
    """sload.f2fs never writes inline dentries (the kernel does: CI's
    image); this inode is laid out by the kernel's macros -- for a plain
    inode with default inline xattrs, NR_INLINE_DENTRY is 182."""
    class Volume:
        feature = 0
    block = bytearray(f2fs.BLOCK)
    struct.pack_into('<HBB', block, 0, 0o040755, 0,
                     f2fs.INLINE_DENTRY | f2fs.INLINE_XATTR)
    struct.pack_into('<Q', block, 16, 3488)
    inode = f2fs.Inode(Volume(), 40, bytes(block))
    area_size = inode.max_inline
    assert area_size == 3488
    count = area_size * 8 // (19 * 8 + 1)
    assert count == 182
    bitmap = (count + 7) // 8
    reserved = area_size - (19 * count + bitmap)
    area = bytearray(area_size)
    entries = bitmap + reserved
    names = entries + 11 * count
    for slot, (name, nid) in enumerate(((b'.', 40), (b'..', 3),
                                        (b'photo.jpg', 41))):
        position = slot if slot < 2 else 5      # gaps are allowed
        area[position >> 3] |= 1 << (position & 7)
        struct.pack_into('<IIHB', area, entries + position * 11, 0, nid,
                         len(name), 1)
        area[names + position * 8:names + position * 8 + len(name)] = name
    start = f2fs.I_ADDR + 4                    # i_addr[0] is reserved
    block[start:start + area_size] = area
    inode = f2fs.Inode(Volume(), 40, bytes(block))
    assert inode.entries() == [(b'photo.jpg', 41, 1)]


def test_an_unread_compression_is_named():
    with pytest.raises(f2fs.F2fsError, match='LZO-RLE'):
        f2fs.decompress(f2fs.COMPRESS_LZORLE, b'', 4096)


def test_not_f2fs_is_none():
    import io
    assert f2fs.open_f2fs(io.BytesIO(bytes(8192))) is None


# --- volumes F2FS's tools wrote ------------------------------------------------

def _walk(fs):
    seen = {}

    def walk(directory, prefix):
        for entry in directory:
            name = entry.info.name.name.decode('utf-8', 'surrogateescape')
            path = f"{prefix}/{name}"
            seen[path] = entry
            if entry.info.meta.type == 2:
                walk(entry.as_directory(), path)
    walk(fs.open_dir(path='/'), '')
    return seen


@pytest.mark.parametrize('name', SLOAD + ['f2fs-kernel.raw'])
def test_every_file_reads_as_written(name):
    from trace_app.core.image_handler import ImageHandler
    key = _key()
    if name not in key['images']:
        pytest.skip(f"{name}: this machine's kernel could not mount F2FS "
                    f"when the volumes were built")
    handler = ImageHandler(image_path(name))
    try:
        assert handler.load_image()
        assert handler.get_fs_type(0) == 'F2FS'
        assert 'F2FS' in handler.detect_filesystems(0)
        fs = handler.get_fs_info(0)
        seen = _walk(fs)
        assert set(seen) == set(key['files'])        # nothing missing, nothing
        for path, want in key['files'].items():       # extra (deleted gone)
            meta = seen[path].info.meta
            if want['type'] == 'dir':
                assert meta.type == 2, path
            elif want['type'] == 'link':
                assert meta.link == want['target'], path
            else:
                data = seen[path].read_random(0, meta.size)
                assert meta.size == want['size'], path
                assert hashlib.sha256(data).hexdigest() == want['sha256'], \
                    path
                # Read in pieces, across block and cluster edges, too.
                if meta.size > 20000:
                    piece = seen[path].read_random(4000, 17000)
                    assert piece == data[4000:21000], path
        compression = key['images'][name]['compression']
        if compression in ('lz4', 'lzo'):
            entry = fs.volume.get_file_entry_by_path('/big/log.txt')
            assert entry.compression == compression.upper()
            inode = entry._inode
            assert inode.address(0) == f2fs.COMPRESS_ADDR
    finally:
        handler.close_resources()


@pytest.mark.parametrize('name', SLOAD)
def test_live_data_is_never_free_space(name):
    """Carving's map: every block of every file is inside the ranges the
    SIT marks valid."""
    fs = f2fs.open_f2fs(open(image_path(name), 'rb'))
    ranges = fs.allocated_ranges()

    def used(address):
        offset = address * f2fs.BLOCK
        return any(begin <= offset < end for begin, end in ranges)
    for path, entry in _walk(fs).items():
        inode = fs.volume.get_file_entry_by_path(path)._inode
        if inode is None or inode.inline & f2fs.INLINE_DATA:
            continue
        assert used(fs.f2fs.node_address(inode.nid)), path
        for index in range(-(-inode.size // f2fs.BLOCK)):
            address = inode.address(index)
            if address not in (f2fs.NULL_ADDR, f2fs.NEW_ADDR,
                               f2fs.COMPRESS_ADDR):
                assert used(address), (path, index)


def test_the_analysis_hashes_f2fs_files(tmp_path):
    from trace_app.core.analysis import analyse_evidence
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    key = _key()
    path = image_path('f2fs-lz4.raw')
    case = Case.create(str(tmp_path / 'case'), 'F2FS')
    handler = ImageHandler(path)
    try:
        assert handler.load_image()
        evidence = case.add_evidence(path)
        analyse_evidence(handler, case, evidence, ['hash'])
        hashed = {row['path']: row['sha256'] for row in case._db.execute(
            "SELECT path, sha256 FROM file_analysis")}
        files = {p: w['sha256'] for p, w in key['files'].items()
                 if w['type'] == 'file' and w['size']}
        # A link's content is its target, as TSK reads one on ext4.
        files.update({p: hashlib.sha256(w['target'].encode()).hexdigest()
                      for p, w in key['files'].items()
                      if w['type'] == 'link'})
        assert hashed == files
    finally:
        handler.close_resources()
        case.close()
