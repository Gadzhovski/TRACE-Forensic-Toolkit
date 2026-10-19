"""QNX IFS boot images (core/qnx_ifs.py) and UCL NRV2B (core/ucl.py)
against QNX's own dumpifs (tools/testdata/build/make_ifs_images.py:
openqnx's real mkifs image, UCL-compressed, and the same image stored
plain, with zlib, with LZO, and without its startup). Every entry's path,
kind, size, SHA-256, link target, permissions, owner, group and mtime as
dumpifs lists and extracts it."""

import hashlib
import io
import json
import os
import random
import shutil
import stat

import pytest
import pytsk3

from tests.conftest import data_path, image_path

IMAGES = ('ifs-ucl.ifs', 'ifs-plain.ifs', 'ifs-zlib.ifs', 'ifs-lzo.ifs',
          'ifs-imagefs.ifs')
COMPRESSION = {'ifs-ucl.ifs': 'UCL', 'ifs-plain.ifs': 'none',
               'ifs-zlib.ifs': 'zlib', 'ifs-lzo.ifs': 'LZO',
               'ifs-imagefs.ifs': 'none'}


def _key():
    with open(image_path('ifs-key.json'), encoding='utf-8') as handle:
        return json.load(handle)['images']


def _walk(fs):
    out = {}

    def walk(directory, path):
        for entry in directory:
            name = entry.info.name.name.decode('utf-8', 'surrogateescape')
            full = f"{path}/{name}"
            meta = entry.info.meta
            record = {'mode': meta.mode & 0o7777, 'uid': meta.uid,
                      'gid': meta.gid, 'mtime': meta.mtime}
            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                out[full] = dict(record, type='dir')
                walk(entry.as_directory(), full)
            elif meta.type == pytsk3.TSK_FS_META_TYPE_LNK:
                out[full] = dict(record, type='link', target=meta.link,
                                 size=len(meta.link))
            else:
                data = entry.read_random(0, meta.size) if meta.size else b''
                out[full] = dict(record, type='file', size=meta.size,
                                 sha256=hashlib.sha256(data).hexdigest())
    walk(fs.open_dir(path='/'), '')
    return out


def _expected(entries):
    out = {}
    for path, entry in entries.items():
        if path == '/':
            continue
        record = {k: v for k, v in entry.items() if k != 'ino'}
        record['mode'] &= 0o7777
        out[path] = record
    return out


@pytest.mark.parametrize('name', IMAGES)
def test_every_entry_reads_as_dumpifs_lists_and_extracts_it(tmp_path, name):
    from trace_app.core.image_handler import ImageHandler
    key = _key()[name]
    target = tmp_path / name
    shutil.copy(image_path(name), target)
    handler = ImageHandler(str(target))
    try:
        assert handler.load_image()
        assert handler.get_fs_type(0) == 'QNX IFS'
        fs = handler.get_fs_info(0)
        assert fs.facts()['Compression'] == COMPRESSION[name]
        assert (fs.facts()['Checksum'] == 'correct') == key['checksum_ok']
        found = _walk(fs)
    finally:
        handler.close_resources()
    expected = _expected(key['entries'])
    # Folders only a path names: dumpifs lists no entry for them.
    made = {p for p in found if p not in expected and
            found[p]['type'] == 'dir'}
    assert {p: found[p] for p in found if p not in made} == expected
    assert all(any(q.startswith(p + '/') for q in expected) for p in made)


def test_ucl_decompresses_as_libucl_does():
    from trace_app.core.qnx_ifs import IfsImage
    key = _key()['ifs-ucl.ifs']
    with open(data_path('samples', 'openqnx-qnx.ifs'), 'rb') as handle:
        image = IfsImage(handle)
    assert image.compression == 'UCL'
    assert hashlib.sha256(image.image).hexdigest() == \
        key['decompressed_sha256']


def test_damaged_ucl_is_refused_not_misread():
    from trace_app.core.ucl import UclError, nrv2b_decompress
    with open(data_path('samples', 'openqnx-qnx.ifs'), 'rb') as handle:
        data = handle.read()
    at = 1016 + int.from_bytes(data[1016 + 32:1016 + 36], 'little')
    length = int.from_bytes(data[at:at + 2], 'big')
    block = data[at + 2:at + 2 + length]
    assert len(nrv2b_decompress(block)) == 65536
    with pytest.raises(UclError):
        nrv2b_decompress(block[:length // 2])          # cut short
    with pytest.raises(UclError):
        nrv2b_decompress(block + b'\0')                 # bytes after its end


def test_an_ifs_file_inside_a_file_system_is_browsed_as_an_archive():
    """openqnx's QNX4 floppy keeps the IFS as /.boot: the Listing opens it
    like an archive, its members the image's files."""
    from trace_app.core import archives
    from trace_app.core.qnx4 import open_qnx4
    with open(data_path('samples', 'openqnx-qnxfs.img'), 'rb') as handle:
        fs = open_qnx4(handle)
        boot = fs.open('/.boot')
        data = boot.read_random(0, boot.info.meta.size)
    with open(data_path('samples', 'openqnx-qnx.ifs'), 'rb') as handle:
        assert data == handle.read()
    assert archives.detect_archive(data) == 'qnx_ifs'
    members = {m['name']: m for m in archives.list_members(data)}
    key = _key()['ifs-ucl.ifs']['entries']
    files = {p.lstrip('/'): e for p, e in key.items() if e['type'] == 'file'}
    assert {n for n, m in members.items() if not m['is_dir'] and
            not m.get('is_link')} == set(files)
    for name, entry in files.items():
        content = archives.read_member(data, name, kind='qnx_ifs')
        assert hashlib.sha256(content).hexdigest() == entry['sha256'], name


def test_random_data_and_other_formats_are_not_taken_for_ifs():
    from trace_app.core.qnx_ifs import looks_like_ifs, open_ifs
    rng = random.Random(7)
    for _ in range(20):
        blob = bytes(rng.getrandbits(8) for _ in range(65536))
        assert open_ifs(io.BytesIO(blob)) is None
    # The signature alone, without a header that holds, is not an IFS.
    fake = bytearray(4096)
    fake[100:104] = b'\xeb\x7e\xff\x00'
    assert not looks_like_ifs(bytes(fake))
    for sample in ('openqnx-qnxfs.img',):
        with open(data_path('samples', sample), 'rb') as handle:
            head = handle.read(1 << 20)
        # The floppy holds the IFS at block 44: found by the evidence
        # chain only after QNX4 (which opens first).
        assert stat.S_ISDIR(int.from_bytes(head[512 + 50:512 + 52],
                                           'little'))
