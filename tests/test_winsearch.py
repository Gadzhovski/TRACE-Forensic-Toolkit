"""The Windows Search index, and the thumbnail pictures it names
(trace_app/core/winsearch.py, core/thumbnails.py).

sidr's test indexes, with the values dissect.target's tests expect for
them -- a Windows 10 Windows.edb (ESE) and a Windows 11 Windows.db
(SQLite) -- and a Windows 11 machine whose thumbnail caches and index were
published together (AndrewRathbun/DFIRArtifactMuseum): its thumbcache
pictures are named from its own index.
"""

import datetime
import os

import pytest

from tests.conftest import ROOT
from tools import testdata

SAMPLES = testdata.SAMPLES
UTC = datetime.timezone.utc


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run python -m tools.testdata.fetch --group samples")
    with open(path, 'rb') as handle:
        return handle.read()


def by_path(items, ending):
    return next(i for i in items if i['path'].endswith(ending))


def test_windows_10_ese_index():
    from trace_app.core import winsearch
    items = list(winsearch.items(sample('search-Windows.edb')))
    assert len(items) == 1182          # dissect: 1183 records, one empty
    example = by_path(items, r'\Desktop\StrozFriedberg-Example.txt')
    assert example['path'] == \
        r'C:\Users\testuser\Desktop\StrozFriedberg-Example.txt'
    assert (example['size'], example['type']) == (50, 'text/plain')
    assert example['summary'] == \
        'Example File from Stroz Friedberg.\r\nHappy Testing!'
    assert example['datemodified'] == \
        datetime.datetime(2023, 2, 16, 14, 36, 14, 922361, tzinfo=UTC)
    assert example['datecreated'] == \
        datetime.datetime(2023, 2, 16, 14, 35, 23, 656454, tzinfo=UTC)
    assert example['dateaccessed'] == \
        datetime.datetime(2023, 2, 16, 14, 36, 22, 893101, tzinfo=UTC)
    script = by_path(items, r'\Content-Check\Malicious.js')
    assert (script['size'], script['type']) == (511, 'JavaScript File')
    assert script['summary'].startswith('Line 1\r\nLine 2\r\n')


def test_windows_11_sqlite_index():
    from trace_app.core import winsearch
    items = list(winsearch.items(sample('search-Windows.db')))
    beacon = by_path(items, r'\Public\malware\New-beacon.xml')
    assert (beacon['size'], beacon['type']) == (174, 'text/xml')
    assert beacon['datecreated'] == \
        datetime.datetime(2023, 1, 31, 2, 26, 28, 898306, tzinfo=UTC)
    # Stored as FILETIME 133196067020564451: .0564451 s. dissect's float
    # conversion gives .056444; the exact microsecond is 56445.
    assert beacon['datemodified'] == \
        datetime.datetime(2023, 1, 31, 2, 45, 2, 56445, tzinfo=UTC)
    assert beacon['cache_id'] == 'babe8e8476718f60'
    assert sum(1 for i in items if i['cache_id']) == 734


def test_windows_paths_to_volume_paths():
    from trace_app.core import winsearch
    assert winsearch.volume_path(r'C:\Users\a\x.jpg') == \
        ('c', '/Users/a/x.jpg')
    assert winsearch.volume_path('D:\\') == ('d', '/')
    assert winsearch.volume_path('iehistory://{S-1-5}/x') == (None, None)
    assert winsearch.is_index_path(
        '/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.db')
    assert not winsearch.is_index_path('/Users/a/Windows.edb')


class _Entry:
    """walk.FileEntry's shape over bytes, on one volume at offset 0."""

    def __init__(self, path, data=b'', deleted=False, inode=0,
                 is_dir=False):
        self.is_dir = is_dir
        self.path, self.name = path, path.rsplit('/', 1)[-1]
        self.data, self.size, self.deleted = data, len(data), deleted
        self.offset, self.inode = 0, inode
        self.ref = f'p0:i{inode}:s1'
        self.fs = self

    def open_meta(self, inode):
        return self

    def read_random(self, offset, length):
        return self.data[offset:offset + length]

    def read(self, length=None, start=0):
        return self.data[start:start + (length or len(self.data))]


def fake_walk(files):
    """walk.iter_files over stand-in entries, reporting every name."""
    def iter_files(handler, should_stop=None, offsets=None,
                   every_name=None):
        for entry in files:
            if every_name is not None:
                every_name(entry.offset, entry.path, entry.deleted,
                           entry.ref)
            if not getattr(entry, 'is_dir', False):
                yield entry
    return iter_files


def test_thumbcache_pictures_named_from_the_index(tmp_path, monkeypatch):
    """The Windows 11 machine's thumbcache_48 and _96 against its own
    Windows.edb: three pictures are of folders the index names; one of
    them is left on the disk, the others are made to be gone."""
    from trace_app.core import thumbnails, walk
    from trace_app.core.case import Case
    explorer = '/Users/AndrewRathbun/AppData/Local/Microsoft/Windows/Explorer'
    files = [
        _Entry(f'{explorer}/thumbcache_48.db',
               sample('rathbun-win11-thumbcache_48.db'), inode=1),
        _Entry(f'{explorer}/thumbcache_96.db',
               sample('rathbun-win11-thumbcache_96.db'), inode=2),
        _Entry('/ProgramData/Microsoft/Search/Data/Applications/Windows/'
               'Windows.edb', sample('rathbun-win11-Windows.edb'),
               inode=3),
        _Entry('/Users/AndrewRathbun/Desktop/Targets', inode=4,
               is_dir=True),
        _Entry('/Users/AndrewRathbun/Videos/Captures', deleted=True,
               inode=5, is_dir=True),
    ]
    monkeypatch.setattr(walk, 'iter_files', fake_walk(files))
    case = Case.create(str(tmp_path / 'case'), 'Thumbnails')
    evidence_id = case.add_evidence(os.path.join(SAMPLES,
                                                 'search-Windows.db'))
    try:
        thumbnails.analyse_evidence(None, case, evidence_id)
        rows = case.thumbnails(evidence_id)
        named = {r['detail'].get('indexed path'): r for r in rows
                 if r['detail'].get('indexed path')}
        assert set(named) == {r'C:\Users\AndrewRathbun\Desktop\Targets',
                              r'C:\Users\AndrewRathbun\Desktop\Modules',
                              r'C:\Users\AndrewRathbun\Videos\Captures'}
        targets = named[r'C:\Users\AndrewRathbun\Desktop\Targets']
        assert targets['name'] == 'Targets'
        assert targets['original_state'] == 'present'
        assert targets['original_ref'] == 'p0:i4:s1'
        assert named[r'C:\Users\AndrewRathbun\Videos\Captures'][
            'original_state'] == 'deleted'
        assert named[r'C:\Users\AndrewRathbun\Desktop\Modules'][
            'original_state'] == 'absent'
        assert targets['detail']['indexed modified'] == '2022-02-05 19:04:45'
        assert targets['detail']['indexed size'] is None     # a folder
        unnamed = [r for r in rows if not r['detail'].get('indexed path')]
        assert all(not r['name'] for r in unnamed)     # the cache id stays
        findings = case.findings(evidence_id, 'thumbnails')
        assert {f['kind'] for f in findings} == {'thumbnail-absent',
                                                 'thumbnail-deleted'}
        assert any(r'C:\Users\AndrewRathbun\Desktop\Modules, which is no '
                   'longer on the disk' in f['summary'] for f in findings)
    finally:
        case.close()
