"""Live disks (core/live_disk.py): the helper's protocol, the relay that
shares it with jobs, and an image read through it.

The helper runs unelevated here, serving an ordinary file: elevation is the
platform's prompt, which a test cannot answer, and everything after it is
the same code.
"""

import hashlib
import os
import random
import socket

import pytest

from trace_app.core import live_disk

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JPEG_IMAGE = os.path.join(ROOT, 'test_images', '8-jpeg-search.dd')


@pytest.fixture
def disk_file(tmp_path):
    """A 'disk' of 3 MB plus an odd tail, so its size is not sector-whole."""
    data = random.Random(7).randbytes(3 * 1024 * 1024 + 1234)
    path = tmp_path / 'disk.bin'
    path.write_bytes(data)
    return str(path), data


@pytest.fixture
def isolated(monkeypatch):
    """No relays inherited, none left behind."""
    monkeypatch.delenv(live_disk.RELAY_ENVIRONMENT, raising=False)
    yield
    live_disk.close_all()


def test_the_helper_answers_unaligned_reads_exactly(disk_file, isolated):
    path, data = disk_file
    disk = live_disk.LiveDisk(path, elevate=False)
    try:
        assert disk.size == len(data)
        rng = random.Random(1)
        for _ in range(200):
            offset = rng.randrange(0, len(data))
            length = rng.randrange(1, 300_000)
            assert disk.read_buffer_at_offset(length, offset) == \
                data[offset:offset + length]
        # Past the end: nothing, not an error.
        assert disk.read_buffer_at_offset(10, len(data)) == b''
    finally:
        disk.close()


def test_a_helper_that_cannot_open_the_disk_says_why(tmp_path, isolated):
    with pytest.raises(live_disk.LiveDiskError, match='could not be opened'):
        live_disk.LiveDisk(str(tmp_path / 'no-such-disk'), elevate=False)


def test_jobs_read_through_the_relay_and_strangers_are_refused(
        disk_file, isolated, monkeypatch):
    path, data = disk_file
    monkeypatch.setattr(live_disk, 'is_privileged', lambda: True)
    disk = live_disk.open_disk(path)
    assert live_disk.open_disk(path) is disk           # one helper, shared
    port, token = __import__('json').loads(
        os.environ[live_disk.RELAY_ENVIRONMENT])[path]

    client = live_disk.RelayClient(path, port, token)
    try:
        assert client.size == len(data)
        assert client.read_buffer_at_offset(5000, 4093) == data[4093:9093]
    finally:
        client.close()

    with pytest.raises(live_disk.LiveDiskError):
        live_disk.RelayClient(path, port, '00' * 32)
    # Nor does a connection that sends nothing get a header.
    with socket.create_connection(('127.0.0.1', port), timeout=15) as raw:
        raw.sendall(b'x' * 32)
        assert raw.recv(16) == b''


def test_device_paths_are_told_from_files():
    if os.name == 'nt':
        assert live_disk.is_device_path('\\\\.\\PhysicalDrive1')
        assert live_disk.is_device_path('\\\\.\\physicaldrive0')
        assert not live_disk.is_device_path('C:\\images\\disk.dd')
    else:
        assert live_disk.is_device_path('/dev/sdb')
        assert not live_disk.is_device_path('/home/x/disk.dd')
    assert not live_disk.is_device_path('')
    assert not live_disk.is_device_path(None)


def test_listing_disks_does_not_need_administrator():
    disks = live_disk.list_disks()
    assert isinstance(disks, list)
    for disk in disks:
        assert live_disk.is_device_path(disk['path'])
        assert disk['size'] is None or disk['size'] > 0


def test_a_live_reading_is_never_called_verified():
    from trace_app.core.case import STATUS_LIVE, hash_verdict
    status, detail = hash_verdict(
        {'computed_md5': 'a' * 32, 'computed_sha1': 'b' * 40,
         'computed_sha256': 'c' * 64, 'live': True})
    assert status == STATUS_LIVE
    assert 'verify nothing' in detail


@pytest.mark.skipif(not os.path.exists(JPEG_IMAGE),
                    reason='8-jpeg-search.dd not downloaded')
def test_an_image_read_live_is_the_image(isolated, monkeypatch, tmp_path):
    """ImageHandler on a 'device' (the test image) reads its file system
    and hashes it, and the case records it as live, never verified."""
    from trace_app.core.case import STATUS_LIVE, Case
    from trace_app.core.image_handler import ImageHandler

    monkeypatch.setattr(live_disk, 'is_device_path',
                        lambda path: os.path.normcase(str(path)) ==
                        os.path.normcase(JPEG_IMAGE))
    monkeypatch.setattr(live_disk, 'is_privileged', lambda: True)
    handler = ImageHandler(JPEG_IMAGE)
    assert handler.get_image_type() == 'live'
    assert handler.load_image() and handler.loaded
    assert handler.get_fs_type(0) or handler.get_partitions()
    hashes = handler.calculate_hashes()
    with open(JPEG_IMAGE, 'rb') as stream:
        assert hashes['computed_md5'] == hashlib.md5(stream.read()).hexdigest()
    assert hashes['live'] is True
    handler.close_resources()
    # Closing the handler leaves the disk open for the other readers.
    assert live_disk.open_disk(JPEG_IMAGE).read_buffer_at_offset(512, 0)

    case = Case.create(str(tmp_path / 'case'), name='Live')
    evidence_id = case.add_evidence(JPEG_IMAGE)
    row = next(r for r in case.evidence() if r['id'] == evidence_id)
    assert row['size'] is None
    assert any('live disk' in (entry.get('detail') or '')
               for entry in case.activity())
    from trace_app.core.case import check_evidence
    assert check_evidence(row)['status'] == STATUS_LIVE
    case.close()


def test_the_disk_chooser_warns_about_the_system_disk(qapp):
    from trace_app.ui.dialogs.live_disk import LiveDiskDialog
    disks = [{'path': '/dev/sda', 'name': 'sda', 'size': 500 * 2**30,
              'model': 'Internal', 'removable': False, 'system': True,
              'detail': 'SATA'},
             {'path': '/dev/sdb', 'name': 'sdb', 'size': 32 * 2**30,
              'model': 'USB stick', 'removable': True, 'system': False,
              'detail': 'USB'}]
    dialog = LiveDiskDialog(disks=disks)
    assert not dialog.read_button.isEnabled()
    dialog.table.selectRow(0)
    assert 'running system' in dialog.note.text()
    dialog.table.selectRow(1)
    dialog._accept()
    assert dialog.device == '/dev/sdb'


def test_small_reads_are_served_from_the_cache(disk_file, isolated):
    """The Sleuth Kit reads in small pieces: each must not be a round trip
    to the helper."""
    path, data = disk_file
    disk = live_disk.LiveDisk(path, elevate=False)
    try:
        trips = []
        fetch = disk._fetch
        disk._fetch = lambda length, offset: (trips.append(offset),
                                              fetch(length, offset))[1]
        for offset in range(0, 200_000, 512):
            assert disk.read_buffer_at_offset(512, offset) == \
                data[offset:offset + 512]
        assert len(trips) == 1                  # one 256 KB block
        # A read across blocks and the disk's odd-sized end.
        tail = len(data) - 3000
        assert disk.read_buffer_at_offset(10_000, tail) == data[tail:]
        # Hashing-sized reads go straight through.
        assert disk.read_buffer_at_offset(5 * 2**20, 0) == data[:5 * 2**20]
    finally:
        disk.close()


def test_a_reader_that_dies_is_an_error_not_a_hang(disk_file, isolated):
    path, _data = disk_file
    disk = live_disk.LiveDisk(path, elevate=False)
    disk._process.kill()
    disk._process.wait()
    with pytest.raises(live_disk.LiveDiskError):
        disk.read_buffer_at_offset(512, 2 * 2**20)
    # And it stays an error, said the same way.
    with pytest.raises(live_disk.LiveDiskError, match='add the disk again'):
        disk.read_buffer_at_offset(512, 0)
