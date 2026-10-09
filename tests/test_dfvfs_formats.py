"""Formats from dfvfs's test corpus (log2timeline/dfvfs test_data, fetched
and SHA-256 pinned by tools/fetch_artifact_samples.py).

Expected values come from outside TRACE: dfvfs's own test assertions
(sizes, member names), the reference files the corpus carries (ext2.raw is
the disk that the split E01 and split raw hold; the CPIO, LZMA and zlib
files all hold dfvfs's 'syslog'), and passwords.txt, which every one of
its HFS+ volumes stores.
"""

import hashlib
import os
import shutil

import pytest

from tests.conftest import ROOT

SAMPLES = os.path.join(ROOT, 'test_images', 'artifact_samples')
PASSWORDS = (b"place,user,password\nbank,joesmith,superrich\n"
             b"alarm system,-,1234\ntreasure chest,-,1111\n"
             b"uber secret laire,admin,admin\n")
HDS = 'hfsplus.hdd.0.{5fbaabe3-6958-40ff-92a7-860e329aab41}.hds'


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        message = f"{name} is missing -- run tools/fetch_artifact_samples.py"
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(message)
        pytest.skip(message)
    return path


def _md5(path):
    with open(path, 'rb') as handle:
        return hashlib.md5(handle.read()).hexdigest()


def _handler(path):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(path)
    assert handler.loaded, handler.load_error
    return handler


def _file(handler, name):
    from trace_app.core import walk
    for entry in walk.iter_files(handler):
        if entry.path.rsplit('/', 1)[-1] == name:
            return entry.fs.open_meta(inode=entry.inode).read_random(
                0, entry.size)
    return None


# --- segmented images ---------------------------------------------------

def test_a_two_segment_e01_is_the_raw_disk_and_says_when_cut(tmp_path):
    reference = _md5(sample('ext2.raw'))
    sample('ext2.split.E02')
    handler = _handler(sample('ext2.split.E01'))
    try:
        results = handler.calculate_hashes()
    finally:
        handler.close_resources()
    assert results['computed_md5'] == results['stored_md5'] == reference
    assert not results.get('damaged')
    # The second segment missing: incomplete, and no hash.
    shutil.copyfile(sample('ext2.split.E01'), tmp_path / 'ext2.split.E01')
    handler = _handler(str(tmp_path / 'ext2.split.E01'))
    try:
        assert handler.container_note.startswith('Incomplete E01')
        assert 'segment 2 onwards' in handler.container_note
        assert handler.calculate_hashes()['error']
    finally:
        handler.close_resources()


def test_a_split_raw_numbered_from_000_opens_whole():
    from trace_app.core.case import hash_evidence
    from trace_app.core.evidence_probe import probe
    from trace_app.ui.widgets.evidence_intake import is_later_segment
    first = sample('ext2.splitraw.000')
    second = sample('ext2.splitraw.001')
    reference = _md5(sample('ext2.raw'))
    handler = _handler(first)
    try:
        assert handler.get_image_type() == 'raw'
        assert handler.get_size() == 4 * 1024 * 1024
        assert handler.get_fs_type(0) == 'Ext2'
        assert handler.calculate_hashes()['computed_md5'] == reference
    finally:
        handler.close_resources()
    assert hash_evidence({'path': first})['computed_md5'] == reference
    # Picked together, .001 is the second part, not another image.
    assert is_later_segment(second) and not is_later_segment(first)
    assert probe(first)['format'] == 'Split raw image'


# --- volumes --------------------------------------------------------------

def test_unencrypted_core_storage_opens_without_a_password():
    handler = _handler(sample('cs_single_volume.raw'))
    try:
        assert handler.volume_kind(0) == 'corestorage'
        assert handler.encryption(0) is None
        assert handler.get_fs_type(0) == 'HFS'
        assert _file(handler, 'passwords.txt') == PASSWORDS
    finally:
        handler.close_resources()
    # FileVault (Core Storage with encryption) still needs its key.
    handler = _handler(sample('fvdetest.qcow2'))
    try:
        start = next(p[2] for p in handler.get_partitions()
                     if handler.volume_kind(p[2]))
        assert handler.encryption(start) == 'fvde'
        assert handler.get_fs_info(start) is None
    finally:
        handler.close_resources()


def test_a_luks2_header_from_cryptsetup_unlocks_with_its_key_only():
    """dfvfs's luks2.raw: Argon2i keyslot, aes-cbc-plain, and no data
    area (the segment starts where the file ends)."""
    from trace_app.core import containers
    handler = _handler(sample('luks2.raw'))
    try:
        assert handler.volume_kind(0) == 'luks'
        with pytest.raises(containers.ContainerError):
            handler.unlock_volume(0, 'luks', password='wrong')
        assert handler.unlock_volume(0, 'luks', password='luksde-TEST')
        assert handler._volumes[0].get_size() == 0
    finally:
        handler.close_resources()


def test_partition_tables_are_named_by_their_scheme():
    from trace_app.core import partition_names
    handler = _handler(sample('ufs1.raw'))
    try:
        assert [handler.partition_label(p[2], p[1])
                for p in handler.get_partitions()] == [
            'BSD partition @ 0', 'BSD Disklabel', 'BSD partition @ 16']
    finally:
        handler.close_resources()
    handler = _handler(sample('apm.dmg'))
    try:
        labels = [handler.partition_label(p[2], p[1])
                  for p in handler.get_partitions()]
        assert 'Apple Partition Map' in labels and 'Table @ 1' not in labels
        assert handler.get_fs_type(64) == 'HFS'
    finally:
        handler.close_resources()
    assert partition_names.label(b'Partition Table', 2, scheme=16) == \
        'GPT Partition Table'
    assert partition_names.label(b'Partition Table', 1, scheme=4) == \
        'Sun VTOC'


def test_a_parallels_bundle_opens_however_it_is_picked():
    from trace_app.core import logical_sources
    from trace_app.core.evidence_probe import probe
    bundle = os.path.dirname(sample('hfsplus.hdd/DiskDescriptor.xml'))
    sample('hfsplus.hdd/' + HDS)
    digests = set()
    for path in (bundle, os.path.join(bundle, 'DiskDescriptor.xml'),
                 os.path.join(bundle, HDS)):
        handler = _handler(path)
        try:
            assert handler.get_image_type() == 'virtual'
            assert handler.container_note == 'Parallels disk (bundle)'
            assert handler.get_size() == 32 * 1024 * 1024
            assert _file(handler, 'passwords.txt') == PASSWORDS
            digests.add(handler.calculate_hashes()['computed_md5'])
        finally:
            handler.close_resources()
    assert len(digests) == 1
    assert logical_sources.kind_of(bundle) is None      # not a folder
    assert probe(bundle)['format'] == 'Parallels disk (bundle)'


# --- streams and archives -------------------------------------------------

def _syslog():
    with open(sample('dfvfs-syslog'), 'rb') as handle:
        return handle.read()


def test_cpio_in_all_four_formats():
    from trace_app.core import archives
    syslog = _syslog()
    for kind in ('bin', 'odc', 'newc', 'crc'):
        data = open(sample(f'syslog.{kind}.cpio'), 'rb').read()
        assert archives.detect_archive(data) == 'cpio'
        (member,) = archives.list_members(data)
        # dfvfs: one entry, 'syslog', 1,247 bytes.
        assert (member['name'], member['size']) == ('syslog', 1247)
        assert not member['damaged']
        assert archives.read_member(data, 'syslog') == syslog
    # The crc format's checksum catches one flipped bit.
    data = bytearray(open(sample('syslog.crc.cpio'), 'rb').read())
    data[300] ^= 1
    (member,) = archives.list_members(bytes(data))
    assert 'checksum' in member['damaged']


def test_lzma_and_zlib_streams_and_no_false_alarms():
    from trace_app.core import archives
    syslog = _syslog()
    for name, kind in (('syslog.lzma', 'lzma'), ('syslog.zlib', 'zlib')):
        data = open(sample(name), 'rb').read()
        assert archives.detect_archive(data) == kind
        assert archives.read_member(data, None, kind) == syslog
    # A DMG's data fork starts with a zlib chunk: not a zlib file.
    dmg = open(sample('hfsplus_zlib.dmg'), 'rb').read()
    assert archives.detect_archive(dmg) != 'zlib'
    assert archives.detect_archive(os.urandom(4096)) is None


def test_a_gzip_cut_short_gives_what_it_holds_marked_damaged():
    from trace_app.core import archives
    data = open(sample('corrupt1.gz'), 'rb').read()
    (member,) = archives.list_members(data)
    # dfvfs recovers 2,994,187 bytes from this stream (no member footer).
    assert member['size'] == 2994187
    assert 'cut short' in member['damaged']
    assert len(archives.read_member(data, member['name'], 'gzip')) == \
        2994187
    # An intact one is not marked.
    good = open(sample('syslog.gz'), 'rb').read() if os.path.exists(
        os.path.join(SAMPLES, 'syslog.gz')) else None
    if good:
        assert not archives.list_members(good)[0]['damaged']


# --- a file inside a database ---------------------------------------------

def test_text_that_is_not_text_reads_as_its_bytes():
    """blob.db stores a whole SQLite database (mmssms.db) as TEXT in a
    BLOB column; Python's default decoder failed the whole query."""
    from trace_app.core.activity import sqlite_bytes
    data = open(sample('blob.db'), 'rb').read()
    with sqlite_bytes.open_database(data, exact=True) as db:
        rows = dict(db.execute('SELECT name, blobs FROM myblobs'))
    assert isinstance(rows['mmssms.db'], bytes)
    assert len(rows['mmssms.db']) == 110592           # dfvfs's value
    assert rows['mmssms.db'].startswith(b'SQLite format 3\x00')
    assert rows['blob 2 name'] == 'blob 2 data'
    with sqlite_bytes.open_database(data) as db:      # parsers: never fail
        assert len(db.execute('SELECT * FROM myblobs').fetchall()) == 4


def test_a_database_cell_opens_and_exports_as_a_file(qapp, tmp_path):
    from trace_app.core import evidence_export
    from trace_app.ui.dialogs import message
    from trace_app.ui.viewers.database_viewer import DatabaseViewer
    data = open(sample('blob.db'), 'rb').read()
    viewer = DatabaseViewer()
    opened, audit = [], []
    viewer.blob_opener = lambda content, label: opened.append(
        (content, label))
    viewer.display(data, {'name': 'blob.db'})
    assert viewer.grid.item(0, 1).text().startswith(
        '<SQLite database, 110,592 bytes>')
    viewer._open_cell(0, 1)
    ((content, label),) = opened
    assert content[:16] == b'SQLite format 3\x00' and len(content) == 110592
    assert label == 'blob.db > myblobs.blobs, row 1'
    # Export: written, read back, audited with its hash.
    evidence_export.set_recorder(lambda *line: audit.append(line))
    saved = message.information
    message.information = lambda *a, **k: None
    try:
        path = viewer.export_cell(0, 1, str(tmp_path / 'cell.db'))
    finally:
        message.information = saved
        evidence_export.set_recorder(None)
    assert open(path, 'rb').read() == content
    digest = hashlib.sha256(content).hexdigest()
    assert audit[0][0] == 'database cell exported' and digest in audit[0][1]
    viewer.deleteLater()
