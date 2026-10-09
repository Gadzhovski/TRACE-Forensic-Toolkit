"""Thumbnail caches (trace_app/core/thumbnails.py).

Real caches: fox-it dissect.thumbcache's test data -- thumbcache_*.db from
Windows Vista, 7, 8.1, 10 and 11, whose entry counts and first hash its
own tests record -- and Thumbs.db files Windows XP and Vista left in folders
that were then committed to open-source projects by accident: a catalog of
33 video frames, one of 8 toolbar bitmaps, and a Vista one of 5 PNGs. On a
real XP image (NPS domexusers, local only) the job finds both Thumbs.db.
"""

import io
import os

import pytest

from tests.conftest import ROOT
from tools import testdata

SAMPLES = testdata.SAMPLES


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{name} missing")
        pytest.skip("run python -m tools.testdata.fetch --group samples")
    with open(path, 'rb') as handle:
        return handle.read()


def decodes(data):
    from PIL import Image
    with Image.open(io.BytesIO(data)) as picture:
        picture.load()
        return picture.size


@pytest.mark.parametrize('name, version, cache, entries, pictures', [
    # Entry counts as dissect.thumbcache's tests record them.
    ('vista-thumbcache_32.db', 20, '32', 18, 17),
    ('win7-thumbcache_256.db', 21, '256', 3, 0),
    ('win81-thumbcache_32.db', 31, '32', 49, 48),
    ('win10-thumbcache_32.db', 32, '32', 6, 5),
    ('win11-thumbcache_32.db', 32, '32', 9, 8),
])
def test_thumbcache_entries_and_pictures(name, version, cache, entries,
                                         pictures):
    from trace_app.core import thumbnails
    data = sample(name)
    parsed = thumbnails.parse_thumbcache(data)
    assert (parsed['version'], parsed['cache']) == (version, cache)
    walked, offset = 0, 24
    while True:
        entry = thumbnails._entry(data, offset, version)
        if entry is None:
            break
        walked += 1
        offset += entry['size']
    assert walked == entries
    assert len(parsed['entries']) == pictures
    for entry in parsed['entries']:
        picture = data[entry['data_offset']:
                       entry['data_offset'] + entry['data_size']]
        size = decodes(picture)
        if entry['width']:
            assert size == (entry['width'], entry['height'])


def test_the_windows_7_entry_dissect_names():
    from trace_app.core import thumbnails
    entry = thumbnails._entry(sample('win7-thumbcache_256.db'), 0x18, 21)
    # dissect writes the hash's bytes in file order (e84eb8f951bc2409);
    # TRACE writes the 64-bit value, as Windows spells the cache id in an
    # entry's identifier and in its Search index.
    assert entry['hash'] == bytes.fromhex('e84eb8f951bc2409')[::-1].hex()
    later = thumbnails.parse_thumbcache(sample('win10-thumbcache_32.db'))
    first = later['entries'][0]
    assert first['identifier'] == first['hash'] == '79b0d2fffa22677a'
    assert entry['identifier'].startswith('::{')     # a shell folder


def test_a_damaged_entry_is_stepped_over_by_its_signature():
    from trace_app.core import thumbnails
    data = bytearray(sample('win10-thumbcache_32.db'))
    first = thumbnails.parse_thumbcache(bytes(data))['entries']
    data[first[1]['offset'] + 4:first[1]['offset'] + 8] = b'\xff' * 4
    again = thumbnails.parse_thumbcache(bytes(data))['entries']
    assert [e['hash'] for e in again] == \
        [e['hash'] for e in first if e is not first[1]]


def test_an_xp_thumbs_db_names_each_file():
    from trace_app.core import thumbnails
    entries = thumbnails.parse_thumbs_db(sample('xp-isetcam-Thumbs.db'))
    assert len(entries) == 33
    first = entries[0]
    assert (first['number'], first['name'], first['modified']) == \
        (1, 'frame_28.jpg', '2013-01-29 09:41:38')
    assert (first['width'], first['height']) == (96, 96)
    # Stream names are the number reversed: 10 is "01".
    tenth = next(e for e in entries if e['number'] == 10)
    assert tenth['stream'] == '01'
    for entry in entries:
        width, height = decodes(entry['data'])
        assert max(width, height) <= 96
    names = [e['name'] for e in thumbnails.parse_thumbs_db(
        sample('xp-tabulareditor-Thumbs.db'))]
    assert names == ['minus.bmp', 'check.bmp', 'Folder.bmp',
                     'FolderClosed.bmp', 'Leaf.bmp', 'plus.bmp',
                     names[6], names[7]] and len(names) == 8


def test_a_vista_thumbs_db_has_cache_ids_and_pngs():
    from trace_app.core import thumbnails
    entries = thumbnails.parse_thumbs_db(sample('vista-w3c-Thumbs.db'))
    assert len(entries) == 5
    assert all(e['format'] == 'png' and not e['name'] and
               len(e['cache_id']) == 16 for e in entries)
    for entry in entries:
        decodes(entry['data'])


def test_caches_browse_like_folders_of_pictures():
    from trace_app.core import archives
    data = sample('xp-isetcam-Thumbs.db')
    assert archives.detect_archive(data) == 'thumbsdb'
    members = archives.list_members(data)
    assert members[0]['name'] == 'frame_28.jpg (thumbnail).jpg'
    assert members[0]['modified'] == '2013-01-29 09:41:38'
    assert archives.read_member(data, members[0]['name'])[:3] == \
        b'\xff\xd8\xff'
    cache = sample('win10-thumbcache_32.db')
    assert archives.detect_archive(cache) == 'thumbcache'
    assert archives.detect_archive(cache[:512]) == 'thumbcache'
    names = [m['name'] for m in archives.list_members(cache)]
    assert names[0] == '0001 79b0d2fffa22677a.bmp' and len(names) == 5
    # Another OLE file (a Jump List) is not one.
    jump_list = sample('1b4dd67f29cb1962.automaticDestinations-ms')
    assert jump_list[:4] == bytes.fromhex('d0cf11e0')
    assert archives.detect_archive(jump_list) is None


class _Entry:
    """walk.FileEntry's shape, over bytes."""

    def __init__(self, path, data=b'', deleted=False, inode=0):
        self.path, self.name = path, path.rsplit('/', 1)[-1]
        self.data, self.size, self.deleted = data, len(data), deleted
        self.ref = f'p0:i{inode}:s1'
        self.offset = 0

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


def test_pictures_of_files_that_are_gone_are_findings(tmp_path,
                                                      monkeypatch):
    """The Thumbs.db of a folder in which one pictured file is still
    there, one is there only as a deleted entry, and the rest are gone."""
    from trace_app.core import thumbnails, walk
    from trace_app.core.case import Case
    thumbs = sample('xp-isetcam-Thumbs.db')
    cache = sample('win10-thumbcache_32.db')
    files = [
        _Entry('/Docs/Frames/Thumbs.db', thumbs, inode=10),
        _Entry('/Docs/Frames/frame_28.jpg', b'x', inode=11),
        _Entry('/Docs/Frames/FRAME_14.JPG', b'x', deleted=True, inode=12),
        _Entry('/Docs/Other/frame_1.jpg', b'x', inode=13),  # another folder
        _Entry('/Users/bob/AppData/Local/Microsoft/Windows/Explorer/'
               'thumbcache_32.db', cache, inode=14),
    ]
    monkeypatch.setattr(walk, 'iter_files', fake_walk(files))
    case = Case.create(str(tmp_path / 'case'), 'Thumbnails')
    evidence_id = case.add_evidence(os.path.join(SAMPLES,
                                                 'xp-isetcam-Thumbs.db'))
    try:
        count = thumbnails.analyse_evidence(None, case, evidence_id)
        assert count == 33 + 5
        rows = case.thumbnails(evidence_id)
        state = {r['name']: r['original_state'] for r in rows
                 if r['cache_kind'] == 'thumbs.db'}
        assert state['frame_28.jpg'] == 'present'
        assert state['frame_14.jpg'] == 'deleted'      # case-insensitive
        assert state['frame_1.jpg'] == 'absent'        # elsewhere only
        cached = [r for r in rows if r['cache_kind'] == 'thumbcache']
        assert len(cached) == 5 and {r['user'] for r in cached} == {'bob'}
        # The row says where the picture is; reading it back gives it.
        row = next(r for r in rows if r['name'] == 'frame_1.jpg')
        assert thumbnails.picture_bytes(thumbs, row)[:3] == b'\xff\xd8\xff'
        row = cached[0]
        decodes(thumbnails.picture_bytes(cache, row))
        findings = case.findings(evidence_id, 'thumbnails', limit=1000)
        assert len(findings) == 32
        assert case.thumbnail_counts(evidence_id) == {
            'pictures': 38, 'caches': 2, 'gone': 32}
        gone = case.thumbnails(evidence_id, gone_only=True)
        assert gone[0]['original_state'] == 'absent'
        from trace_app.core import report
        options = report.default_options(case)
        options.update(formats=['html'], sections=[{'key': 'findings',
                                                    'enabled': True}])
        page = open(report.write_report(case, options, {})[0]['path'],
                    encoding='utf-8').read()
        assert 'Thumbnails of files no longer in their folder (32)' in page
        assert 'frame_1.jpg, which is no longer in the folder' in page
        case.clear_analysis(evidence_id)                  # kept
        assert case.findings(evidence_id, 'thumbnails')
    finally:
        case.close()


def test_a_real_xp_image_end_to_end(tmp_path):
    """NPS domexusers (4.4 GB, local only): both Thumbs.db are found."""
    from trace_app.core import thumbnails
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    path = testdata.locate('nps-2009-domexusers.E01') or ''
    if not os.path.exists(path):
        pytest.skip("nps-2009-domexusers.E01 is not in test_images/")
    handler = ImageHandler(path)
    assert handler.load_image()
    case = Case.create(str(tmp_path / 'case'), 'XP')
    evidence_id = case.add_evidence(path)
    try:
        assert thumbnails.analyse_evidence(handler, case, evidence_id) > 0
        caches = {r['cache_path'] for r in case.thumbnails(evidence_id)}
        assert any(p.endswith('Sample Pictures/Thumbs.db') for p in caches)
        assert any('/domex2/' in p for p in caches)
        states = {r['name']: r['original_state']
                  for r in case.thumbnails(evidence_id)}
        # The Sample Pictures folder's own picture is not a missing file.
        assert states['{A42CD7B6-E9B9-4D02-B7A6-288B71AD28BA}'] == 'folder'
        assert states['domexuser2.JPG'] == 'present'
        assert case.findings(evidence_id, 'thumbnails') == []
    finally:
        handler.close_resources()
        case.close()


def test_every_tile_is_the_same_size_and_its_caption_fits(qapp):
    """A tall picture used to be taller than the grid's uniform item
    (sized from the first one shown) and pushed its caption out of view;
    and the second caption line ('file gone') was never drawn."""
    from PySide6.QtGui import QImage
    from trace_app.ui.viewers.thumbnails_panel import (PICTURE,
                                                       ThumbnailsPanel,
                                                       fitted)
    for width, height in ((40, 400), (400, 40), (256, 256), (1, 1)):
        image = QImage(width, height, QImage.Format_RGB32)
        assert fitted(image).size() == PICTURE
    assert fitted(None).size() == PICTURE
    panel = ThumbnailsPanel()
    try:
        grid = panel.view.gridSize()
        line = panel.view.fontMetrics().height()
        hint = panel.view.itemDelegate().sizeHint(
            panel.view.viewOptions() if hasattr(panel.view, 'viewOptions')
            else _option(panel.view), panel.model.index(0))
        assert grid.height() >= PICTURE.height() + 2 * line
        assert hint.height() <= grid.height() and \
            hint.width() <= grid.width()
    finally:
        panel.deleteLater()


def _option(view):
    from PySide6.QtWidgets import QStyleOptionViewItem
    option = QStyleOptionViewItem()
    option.initFrom(view)
    return option
