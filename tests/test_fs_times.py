"""File-system times on every file system (core/fs_times): the timeline's
file-system source was NTFS's $MFT alone, and an ext, Btrfs, XFS, HFS+,
APFS, FAT or exFAT volume put not one file time in it."""

import os
import sqlite3
import tempfile

import pytest

from tests.conftest import image_path


def _case_with(*names):
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    case = Case.create(os.path.join(tempfile.mkdtemp(), 'case'), 'times')
    loaded = []
    for name in names:
        path = image_path(name)
        loaded.append((ImageHandler(path), case.add_evidence(path)))
    return case, loaded


def _events(case, evidence_id, path=None):
    sql = ("SELECT time_utc, macb, source, deleted, path FROM fs_events "
           "WHERE evidence_id = ?")
    params = [evidence_id]
    if path:
        sql += " AND path = ?"
        params.append(path)
    return [tuple(r) for r in case._db.execute(sql + " ORDER BY time_utc",
                                               params)]


def test_btrfs_times_are_the_ones_its_inodes_record():
    """dissect.btrfs's published times for 'path': accessed 03:04:16,
    modified and changed 03:04:12, no birth time -- one row per distinct
    time, MACB letters merged, as the NTFS module writes them."""
    from trace_app.core import fs_times, timeline
    case, [(handler, evidence_id)] = _case_with(
        'btrfs-subvolume-snapshot.raw')
    try:
        count = fs_times.analyse_evidence(handler, case, evidence_id)
        assert count >= 20               # files, folders, links, subvolumes
        assert _events(case, evidence_id, '/path') == [
            ('2023-06-28 03:04:12', 'M.C.', 'FS', 0, '/path'),
            ('2023-06-28 03:04:16', '.A..', 'FS', 0, '/path')]
        # Every subvolume's entries, by their own paths.
        paths = {r[4] for r in _events(case, evidence_id)}
        assert {'/subvol/new.txt', '/subvol-snapshot/in-snapshot.txt',
                '/link.txt'} <= paths
        # In the timeline, as file-system rows in UTC.
        with sqlite3.connect(os.path.join(case.folder, 'case.db')) as con:
            con.row_factory = sqlite3.Row
            rows = list(timeline.iter_events(con, timeline.default_filters()))
        mine = [r for r in rows if r['source'] == 'fs']
        assert mine and not any(r['local'] for r in mine)
        assert timeline.describe_kind(mine[0]).endswith('(file system)')
    finally:
        case.close()
        handler.close_resources()


def test_exfat_times_are_local_and_deleted_entries_count():
    """FAT and exFAT keep wall-clock time with no zone: shown as local,
    never as UTC. Deleted entries whose metadata is still theirs count."""
    from trace_app.core import fs_times, timeline
    case, [(handler, evidence_id)] = _case_with('dfr-01-xfat.dd')
    try:
        fs_times.analyse_evidence(handler, case, evidence_id)
        events = _events(case, evidence_id)
        assert events and {r[2] for r in events} == {'FS-local'}
        assert any(r[3] for r in events)                 # deleted ones
        with sqlite3.connect(os.path.join(case.folder, 'case.db')) as con:
            con.row_factory = sqlite3.Row
            rows = [r for r in timeline.iter_events(
                con, timeline.default_filters()) if r['source'] == 'fs']
        assert rows and all(r['local'] for r in rows)
    finally:
        case.close()
        handler.close_resources()


def test_ntfs_and_other_file_systems_keep_each_others_rows():
    """Two modules write fs_events: re-running either must not erase the
    other's -- clear_ntfs used to delete every row of the image."""
    from trace_app.core import fs_times, ntfs
    case, loaded = _case_with('ntfs1-gen2.E01', 'btrfs-subvolume-snapshot.raw')
    try:
        for handler, evidence_id in loaded:
            fs_times.analyse_evidence(handler, case, evidence_id)
            ntfs.analyse_evidence(handler, case, evidence_id)
            fs_times.analyse_evidence(handler, case, evidence_id)
        (_h1, ntfs_id), (_h2, btrfs_id) = loaded
        assert {r[2] for r in _events(case, ntfs_id)} == {'SI', 'FN'}
        assert {r[2] for r in _events(case, btrfs_id)} == {'FS'}
        before = len(_events(case, btrfs_id))
        ntfs.analyse_evidence(loaded[1][0], case, btrfs_id)
        assert len(_events(case, btrfs_id)) == before
    finally:
        case.close()
        for handler, _evidence_id in loaded:
            handler.close_resources()


@pytest.mark.parametrize('seconds, nanoseconds, text', [
    (0, 0, None),
    (1687921452, 0, '2023-06-28 03:04:12'),
    (1687921452, 123456789, '2023-06-28 03:04:12.1234567'),
])
def test_time_text(seconds, nanoseconds, text):
    from trace_app.core.fs_times import time_text
    assert time_text(seconds, nanoseconds) == text
