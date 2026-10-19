"""Big archives browsed from an index (core/archive_index.py): a phone
extraction's 16 GB tar was read whole into memory and listed flat on the
window's thread. Indexed, it is listed a folder at a time and each member
read at its own offset."""

import io
import os
import tarfile
import zipfile

import pytest

from trace_app.core import archive_index, archives


def _tar(path, members):
    with tarfile.open(path, 'w') as tarred:
        for name, data in members:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type = tarfile.DIRTYPE
                tarred.addfile(info)
                continue
            info.size = len(data)
            info.mtime = 1586700000
            tarred.addfile(info, io.BytesIO(data))
    return path


def _open(path, target):
    return archive_index.IndexedArchive(target, lambda: open(path, 'rb'),
                                        os.path.basename(path))


def test_a_tar_is_listed_a_folder_at_a_time_and_read_in_place(tmp_path):
    source = _tar(str(tmp_path / 'fs.tar'), [
        ('./private/var/mobile/Library/SMS/sms.db', b'SQLite format 3\0x'),
        ('private/var/mobile/Library/SMS/old.txt', b'first'),
        ('private/var/mobile/Media/', None),
        ('private/var/mobile/Media/DCIM/IMG_1.JPG', b'\xff\xd8\xff' * 9),
        # Appended later: the last copy is the one tar extracts.
        ('private/var/mobile/Library/SMS/old.txt', b'second'),
        ('top.txt', b'at the top')])
    target = archive_index.index_file(str(tmp_path / 'index'), 'C:/e',
                                      0, 12, os.path.getsize(source))
    assert not archive_index.is_complete(target)
    seen = []
    with open(source, 'rb') as handle:
        count = archive_index.build(
            handle, 'tar', target,
            progress=lambda done, total, text: seen.append(done))
    assert count == 5 and archive_index.is_complete(target)
    indexed = _open(source, target)
    try:
        assert [(m['name'], m['is_dir']) for m in indexed.level('')] == [
            ('private', True), ('top.txt', False)]
        sms = indexed.level('private/var/mobile/Library/SMS')
        assert [m['name'] for m in sms] == [
            'private/var/mobile/Library/SMS/old.txt',
            'private/var/mobile/Library/SMS/sms.db']
        assert sms[0]['size'] == 6
        assert indexed.level('private/var/mobile')[0]['name'] == \
            'private/var/mobile/Library'
        assert indexed.read('private/var/mobile/Library/SMS/old.txt') == \
            b'second'
        assert archives.read_member(
            indexed, 'private/var/mobile/Media/DCIM/IMG_1.JPG') == \
            b'\xff\xd8\xff' * 9
        with pytest.raises(archives.ArchiveError, match='more than'):
            indexed.read('top.txt', limit=3)
        with pytest.raises(archives.ArchiveError, match='folder'):
            indexed.read('private/var')
        assert indexed.level('nowhere') == []
    finally:
        indexed.close()


def test_a_zip_is_indexed_from_its_central_directory(tmp_path):
    source = str(tmp_path / 'backup.zip')
    with zipfile.ZipFile(source, 'w', zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr('udid/Manifest.db', b'SQLite format 3\0' * 50)
        zipped.writestr('udid/00/0011', b'payload')
    target = str(tmp_path / 'zip.sqlite')
    with open(source, 'rb') as handle:
        assert archive_index.build(handle, 'zip', target) == 2
    indexed = _open(source, target)
    try:
        assert [m['name'] for m in indexed.level('udid')] == [
            'udid/00', 'udid/Manifest.db']
        assert indexed.read('udid/00/0011') == b'payload'
    finally:
        indexed.close()


def test_a_cancelled_index_leaves_nothing(tmp_path):
    source = _tar(str(tmp_path / 'many.tar'),
                  [(f"d/{n}.txt", b'x') for n in range(4500)])
    target = str(tmp_path / 'many.sqlite')
    with open(source, 'rb') as handle:
        with pytest.raises(archive_index.IndexCancelled):
            archive_index.build(handle, 'tar', target,
                                should_stop=lambda: True)
    assert not os.path.exists(target)
    assert not os.path.exists(target + '.partial')
    assert not archive_index.is_complete(target)


def test_the_index_is_kept_per_archive_and_its_state():
    first = archive_index.index_file('/i', 'C:/e', 0, 5, 100, 'm')
    assert first == archive_index.index_file('/i', 'C:/e', 0, 5, 100, 'm')
    assert first != archive_index.index_file('/i', 'C:/e', 0, 5, 101, 'm')
    assert first != archive_index.index_file('/i', 'C:/f', 0, 5, 100, 'm')
