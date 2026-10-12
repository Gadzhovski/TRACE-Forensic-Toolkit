"""Deleted files on HFS+ (core/hfs_deleted.py), against NIST's DFR key.

The Sleuth Kit lists no deleted HFS+ files. TRACE reads the catalog's old
records -- from the journal and node free space. NIST's DFR-01 deleted
four files on four HFS+ volumes; its key says two have metadata left (on
the journaled volumes) and two have none anywhere. NIST's files describe
themselves block by block, so what TRACE recovers is checked as the
file's own bytes.
"""

import json
import os
import re

from tests.conftest import ROOT, data_path


def _key(name):
    with open(os.path.join(ROOT, 'tests', 'expected',
                           'nist_dfr_ground_truth.json'),
              encoding='utf-8') as handle:
        key = json.load(handle)
    return key.get('images', key)[name]


def _deleted(image):
    from trace_app.core import deleted
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(data_path('nist', 'dfr', image))
    records = list(deleted.deleted_files(handler))
    return handler, records


def test_journaled_hfs_gives_back_what_nist_says_is_left():
    """DFR-01: Betelgeuse.txt (journaled HFS+) and Beid.txt (journaled,
    case-sensitive HFSX) come back from the journal's old catalog nodes
    -- named, in their folder, recoverable, their own bytes, with NIST's
    times (the newest copy: NIST set the times back after writing). The
    two NIST lists with no metadata are not invented."""
    from tools.score.dfr_score import own_content
    key = _key('osx-01')
    handler, records = _deleted('dfr-01-osx.dd')
    try:
        by_name = {r['name']: r for r in records}
        for name in ('Betelgeuse.txt', 'Beid.txt'):
            record = by_name[name]
            assert record['path'] == f'/{name}'
            assert record['state'] == 'recoverable'
            assert record['source'] == '$journal'
            content, _meta = handler.get_file_content(record['inode'],
                                                      record['volume'])
            assert own_content(content, name, record['size'])
            expected = key['times'][name]['modify']['utc']
            assert record['modified'][:16] == expected[:16]
        for name in key['metadata_missing']:
            assert name not in by_name
    finally:
        handler.close_resources()


def test_every_recovered_hfs_file_is_its_own_bytes():
    """DFR-04 (non-Latin names; NIST's blocks name each file by an ASCII
    stand-in): every deleted file TRACE calls recoverable reads back as
    the file its own first block declares, whole."""
    from tools.score.dfr_score import own_content
    handler, records = _deleted('dfr-04-osx.dd')
    try:
        checked = 0
        for record in records:
            if record['state'] != 'recoverable' or \
                    record['path'].startswith(('/.Spotlight', '/.fseventsd',
                                               '/.Trashes')):
                continue
            content, _meta = handler.get_file_content(record['inode'],
                                                      record['volume'])
            declared = re.match(rb'\nDFR\nFile (.+?) path ', content or b'')
            assert declared, record['path']
            assert own_content(content, declared.group(1).decode(),
                               record['size']), record['path']
            checked += 1
        assert checked >= 14
    finally:
        handler.close_resources()
