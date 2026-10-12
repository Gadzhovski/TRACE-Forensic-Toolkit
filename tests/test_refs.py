"""ReFS 3.x (core/refs.py) on volumes Windows itself wrote.

R. Nordvik's "Resilient Filesystem Forensic Containers" (Mendeley Data,
doi:10.17632/9d7p6mbhpz.1, CC BY 4.0): refs-v3_2.E01 is a 4 GB GPT disk
whose ReFS 3.2 volume (Windows 10 1703) holds the VeraCrypt 1.23
installer -- its SHA-256 is the one VeraCrypt published
(veracrypt-1.23-sha256sum.txt), so a read that is wrong anywhere in 35 MB
fails. refs-v1_2-3.E01 is ReFS 1.2, which TRACE does not read: it must be
named, not shown as an empty or unknown partition.
"""

import hashlib

from tests.conftest import data_path

# "VeraCrypt Setup 1.23.exe" in veracrypt-1.23-sha256sum.txt.
VERACRYPT_123_SHA256 = \
    '277c1bfe069a889eb752d3c630db34310102b2bb2f0c0ff11cf4246e333b3503'

REFS_START = 67584
SID = 'S-1-5-21-1814885685-2275487565-1242746162-1001'

EXPECTED = {
    '/$RECYCLE.BIN': None,
    f'/$RECYCLE.BIN/{SID}': None,
    f'/$RECYCLE.BIN/{SID}/desktop.ini': 129,
    '/System Volume Information': None,
    '/System Volume Information/IndexerVolumeGuid': 76,
    '/System Volume Information/WPSettings.dat': 12,
    '/TestFolder': None,
    '/TestFolder/TestDocumentSmall.txt': 24,
    '/VeraCrypt%20Setup%201.23.exe': 35837752,
}


def _open(name):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(data_path('samples', name))
    assert handler.loaded
    return handler


def _walk(handler, inode=None, path=''):
    for entry in handler.get_directory_contents(REFS_START, inode):
        if entry['name'] in ('.', '..'):
            continue
        here = f"{path}/{entry['name']}"
        yield here, entry
        if entry.get('is_directory'):
            yield from _walk(handler, entry['inode_number'], here)


def test_refs_3_2_reads_every_file_windows_wrote():
    handler = _open('refs-v3_2.E01')
    try:
        assert handler.get_fs_type(REFS_START) == 'ReFS'
        entries = dict(_walk(handler))
        assert {path: (None if e['is_directory'] else e['size'])
                for path, e in entries.items()} == EXPECTED

        def content(path):
            data, _meta = handler.get_file_content(
                entries[path]['inode_number'], REFS_START)
            return data

        installer = content('/VeraCrypt%20Setup%201.23.exe')
        assert hashlib.sha256(installer).hexdigest() == VERACRYPT_123_SHA256
        assert content('/TestFolder/TestDocumentSmall.txt') == \
            b'This is a small document'
        assert b'[.ShellClassInfo]' in content(
            f'/$RECYCLE.BIN/{SID}/desktop.ini').replace(b'\0', b'')
        # Times are FILETIME, UTC, and plausible for when the image was made.
        assert entries['/TestFolder/TestDocumentSmall.txt'][
            'modified'].startswith('2018-10-19')
    finally:
        handler.close_resources()


def test_refs_free_space_map_keeps_files_and_tables():
    handler = _open('refs-v3_2.E01')
    try:
        used, _note = handler.partition_allocation(REFS_START)
        total = sum(end - begin for begin, end in used)
        # The installer alone is 35 MB; the tables add pages besides.
        assert total > 35837752
        assert total < 8318976 * 512
    finally:
        handler.close_resources()


def test_refs_1_2_is_named_not_read():
    handler = _open('refs-v1_2-3.E01')
    try:
        starts = [p[2] for p in handler.get_partitions()
                  if handler.detect_filesystems(p[2])]
        assert starts
        assert any('ReFS' in handler.detect_filesystems(s) for s in starts)
    finally:
        handler.close_resources()


# --- a Dev Drive this machine's Windows made (local only) -------------------
# tools/testdata/build/make_windows_volumes.ps1 (elevated) writes it and a
# key of Windows' own reads: Get-FileHash, Get-ChildItem.

def _windows_built():
    import json
    import os

    import pytest
    from tools.testdata import LOCAL
    folder = os.path.join(LOCAL, 'windows-built')
    key_path = os.path.join(folder, 'windows-volumes-key.json')
    if not os.path.exists(key_path):
        pytest.skip('run tools/testdata/build/make_windows_volumes.ps1')
    with open(key_path, encoding='utf-8') as handle:
        return folder, json.load(handle)


def test_dev_drive_matches_what_windows_read():
    import os
    from trace_app.core.image_handler import ImageHandler
    folder, key = _windows_built()
    expected = key['volumes']['refs-devdrive.vhdx']
    handler = ImageHandler(os.path.join(folder, 'refs-devdrive.vhdx'))
    try:
        start = expected['partition_offset'] // 512
        assert handler.get_fs_type(start) == 'ReFS'

        def walk(inode=None, path=''):
            for entry in handler.get_directory_contents(start, inode):
                if entry['name'] in ('.', '..'):
                    continue
                here = f"{path}/{entry['name']}"
                if entry.get('is_directory'):
                    if entry['name'] not in ('System Volume Information',
                                             '$RECYCLE.BIN'):
                        yield from walk(entry['inode_number'], here)
                else:
                    yield here, entry

        found = dict(walk())
        assert set(found) == set(expected['files'])
        for path, want in expected['files'].items():
            entry = found[path]
            assert entry['size'] == want['size'], path
            data, _meta = handler.get_file_content(entry['inode_number'],
                                                   start)
            assert hashlib.sha256(data).hexdigest() == want['sha256'], path
        for path in expected['deleted']:
            assert path not in found
    finally:
        handler.close_resources()
