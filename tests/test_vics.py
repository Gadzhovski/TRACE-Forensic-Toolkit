"""Project VICS JSON export (core/vics.py).

The model is not published; what is, and what this export is held to, is
a VICS 2.0 file Griffeye Analyze DI 22.1.3.0 wrote (samples:
griffeye-vics-TEST.json). Its keys and value types are read from that
file here, not typed in. The evidence is generated: folder evidence and a
FAT16 volume, with pictures and videos named truthfully and not.
"""

import csv
import hashlib
import io
import json
import os
import re

import pytest

from tests.conftest import data_path
from tests.disk_builders import fat16_volume
from trace_app.core.logical import birth_ns


def jpeg(colour='red', make='NIKON CORPORATION', model='NIKON D850'):
    from PIL import Image
    picture = Image.new('RGB', (24, 24), colour)
    exif = picture.getexif()
    exif[0x010F] = make
    exif[0x0110] = model
    exif[0x0131] = 'GIMP 2.10.30'
    out = io.BytesIO()
    picture.save(out, 'JPEG', exif=exif)
    return out.getvalue()


def png():
    from PIL import Image
    out = io.BytesIO()
    Image.new('RGB', (8, 8), 'blue').save(out, 'PNG')
    return out.getvalue()


#: An MP4's first box: libmagic names it video/mp4.
MP4 = (b'\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom' +
       b'\x00\x00\x00\x08free' + b'\x00\x00\x00\x10mdat' + bytes(4000))


@pytest.fixture
def folder_evidence(tmp_path):
    root = tmp_path / 'phone dump'
    (root / 'DCIM' / 'Camera').mkdir(parents=True)
    (root / 'Downloads').mkdir()
    photo = jpeg()
    (root / 'DCIM' / 'Camera' / 'IMG_0001.jpg').write_bytes(photo)
    (root / 'Downloads' / 'copy of photo.jpg').write_bytes(photo)
    (root / 'Downloads' / 'notes.txt').write_bytes(png())     # renamed
    (root / 'DCIM' / 'Camera' / 'VID_0001.mp4').write_bytes(MP4)
    (root / 'fake.jpg').write_bytes(b'not a picture at all\n' * 40)
    (root / 'readme.txt').write_bytes(b'plain text\n' * 20)
    return str(root), photo


def _export(evidence, out, **options):
    from trace_app.core import vics
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(evidence)
    assert handler.load_image()
    try:
        return vics.export([('EXHIBIT 1', handler, options.pop('carved',
                                                                 ()))],
                           str(out), 'CASE 42',
                           {'ContactName': 'A. Examiner'}, version='2.3.0',
                           **options)
    finally:
        handler.close_resources()


def _case(summary):
    with open(summary['json'], encoding='utf-8') as handle:
        document = json.load(handle)
    return document, document['value'][0]


def _all_keys(cases, field):
    keys = set()
    for media in cases['Media']:
        for entry in media.get(field) or ():
            keys |= set(entry)
    return keys


def _types(objects):
    out = {}
    for item in objects:
        for key, value in item.items():
            out.setdefault(key, set()).add(type(value).__name__)
    return out


# --- the shape ----------------------------------------------------------------

def test_the_export_has_the_shape_griffeye_writes(folder_evidence, tmp_path):
    with open(data_path('samples', 'griffeye-vics-TEST.json'),
              encoding='utf-8') as handle:
        reference = json.load(handle)
    summary = _export(folder_evidence[0], tmp_path / 'out')
    document, case = _case(summary)
    ref_case = reference['value'][0]

    assert list(document) == list(reference)
    assert re.sub(r'/2\.0\.xml/\w+/', '/2.0.xml/X/',
                  document['@odata.context']) == \
        re.sub(r'/2\.0\.xml/\w+/', '/2.0.xml/X/',
               reference['@odata.context'])
    assert set(case) == set(ref_case)
    # Every key TRACE writes is one Griffeye writes, with the same type;
    # only what TRACE cannot know (PhotoDNA, a category) is left out.
    ref_media = _types(ref_case['Media'])
    ours = _types(case['Media'])
    assert set(ours) <= set(ref_media)
    assert set(ref_media) - set(ours) == {'PhotoDNA', 'Category'}
    for key, kinds in ours.items():
        assert kinds <= ref_media[key], key
    ref_files = _types(f for m in ref_case['Media'] for f in m['MediaFiles'])
    our_files = _types(f for m in case['Media'] for f in m['MediaFiles'])
    expected = set(ref_files)
    if os.name != 'nt' and birth_ns(os.stat(folder_evidence[0])) is None:
        expected.discard('Created')     # Linux records no creation time
    assert set(our_files) == expected
    for key, kinds in our_files.items():
        assert kinds <= ref_files[key], key
    assert _all_keys(case, 'Exifs') == _all_keys(ref_case, 'Exifs')
    for key in ('ContactName', 'TotalMediaFiles', 'TotalPrecategorized',
                'SourceApplicationName', 'SourceApplicationVersion'):
        assert type(case[key]) is type(ref_case[key])
    assert case['SourceApplicationName'] == 'TRACE'
    assert case['TotalMediaFiles'] == sum(len(m['MediaFiles'])
                                          for m in case['Media'])
    # Never null: a value not known is left out.
    assert 'null' not in open(summary['json'], encoding='utf-8').read()


def test_values_are_written_as_griffeye_writes_them(folder_evidence,
                                                    tmp_path):
    summary = _export(folder_evidence[0], tmp_path / 'out')
    _document, case = _case(summary)
    stamp = re.compile(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,7})?'
                       r'\+00:00$')
    for number, media in enumerate(case['Media']):
        assert media['MediaID'] == number
        assert re.fullmatch(r'[0-9A-F]{32}', media['MD5'])
        assert re.fullmatch(r'[0-9A-F]{40}', media['SHA1'])
        assert media['IsPrecategorized'] is False
        # Files.<case>\AB\CD\<rest of the MD5>.<ext>, as Griffeye lays
        # its copies out.
        md5 = media['MD5']
        assert media['RelativeFilePath'].startswith(
            f"Files.CASE_42\\{md5[:2]}\\{md5[2:4]}\\{md5[4:]}.")
        for entry in media['MediaFiles']:
            assert entry['MD5'] == md5
            assert entry['SourceID'] == 'EXHIBIT 1'
            assert entry['FilePath'].startswith('EXHIBIT 1')
            assert '/' not in entry['FilePath']
            for key in ('Created', 'Written', 'Accessed'):
                if key in entry:
                    assert stamp.match(entry[key]), entry[key]


# --- what is chosen -------------------------------------------------------------

def test_media_are_chosen_by_content_not_name(folder_evidence, tmp_path):
    summary = _export(folder_evidence[0], tmp_path / 'out')
    _document, case = _case(summary)
    names = {entry['FileName']: media['MimeType'] for media in case['Media']
             for entry in media['MediaFiles']}
    assert names == {'IMG_0001.jpg': 'image/jpeg',
                     'copy of photo.jpg': 'image/jpeg',
                     'notes.txt': 'image/png',
                     'VID_0001.mp4': 'video/mp4'}
    renamed = next(m for m in case['Media'] if m['MimeType'] == 'image/png')
    assert renamed['RelativeFilePath'].endswith('.png')


def test_a_picture_found_twice_is_one_media_with_two_places(
        folder_evidence, tmp_path):
    evidence, photo = folder_evidence
    summary = _export(evidence, tmp_path / 'out')
    _document, case = _case(summary)
    md5 = hashlib.md5(photo).hexdigest().upper()
    media = [m for m in case['Media'] if m['MD5'] == md5]
    assert len(media) == 1
    assert sorted(e['FilePath'] for e in media[0]['MediaFiles']) == \
        ['EXHIBIT 1\\DCIM\\Camera', 'EXHIBIT 1\\Downloads']
    assert summary['media'] == 3 and summary['media_files'] == 4
    copies = [name for _d, _s, files in os.walk(tmp_path / 'out' /
                                                'Files.CASE_42')
              for name in files]
    assert len(copies) == 3


def test_every_copy_is_the_bytes_its_hashes_name(folder_evidence, tmp_path):
    summary = _export(folder_evidence[0], tmp_path / 'out')
    _document, case = _case(summary)
    for media in case['Media']:
        # GLEAPP and VICS-Gallery-Maker resolve the path beside the JSON.
        path = os.path.join(os.path.dirname(summary['json']),
                            *media['RelativeFilePath'].split('\\'))
        data = open(path, 'rb').read()
        assert hashlib.md5(data).hexdigest().upper() == media['MD5']
        assert hashlib.sha1(data).hexdigest().upper() == media['SHA1']
        assert len(data) == media['MediaSize']
    with open(summary['manifest'], encoding='utf-8') as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == summary['media_files']
    assert {row['written_copy_check'] for row in rows} == {'matches'}
    assert summary['json_sha256'] == hashlib.sha256(
        open(summary['json'], 'rb').read()).hexdigest()


def test_exif_is_written_under_griffeyes_property_names(folder_evidence,
                                                        tmp_path):
    summary = _export(folder_evidence[0], tmp_path / 'out')
    _document, case = _case(summary)
    photo = next(m for m in case['Media'] if m['MimeType'] == 'image/jpeg')
    exifs = {e['PropertyName']: e['PropertyValue'] for e in photo['Exifs']}
    assert exifs['Camera Make'] == 'NIKON CORPORATION'
    assert exifs['Camera Model'] == 'NIKON D850'
    assert exifs['Software'] == 'GIMP 2.10.30'
    assert all(e['MD5'] == photo['MD5'] for e in photo['Exifs'])
    assert not any('Exifs' in m for m in case['Media']
                   if m['MimeType'].startswith('video/'))


def test_smaller_files_can_be_left_out(folder_evidence, tmp_path):
    summary = _export(folder_evidence[0], tmp_path / 'out', min_size=2000)
    _document, case = _case(summary)
    assert {m['MimeType'] for m in case['Media']} == {'video/mp4'}


# --- FAT: deleted files and local times ----------------------------------------

def _fat_disk(tmp_path):
    photo, other = jpeg(), jpeg('green', 'Canon', 'EOS R5')
    image, _placed, _free = fat16_volume([('IMG1.JPG', photo),
                                          ('GONE.JPG', other),
                                          ('NOTE.TXT', b'text ' * 100)])
    image = bytearray(image)
    at = image.index(b'GONE    JPG')
    image[at] = 0xE5                    # deleted, as FAT marks it
    path = tmp_path / 'card.dd'
    path.write_bytes(bytes(image))
    return str(path), photo, other


def test_deleted_files_are_marked_and_can_be_left_out(tmp_path):
    disk, _photo, other = _fat_disk(tmp_path)
    summary = _export(disk, tmp_path / 'all')
    _document, case = _case(summary)
    deleted = {e['FileName']: e['Deleted'] for m in case['Media']
               for e in m['MediaFiles']}
    assert deleted['IMG1.JPG'] is False
    gone = [name for name, flag in deleted.items() if flag]
    assert len(gone) == 1 and gone[0].endswith('ONE.JPG')
    assert hashlib.md5(other).hexdigest().upper() in \
        {m['MD5'] for m in case['Media']}
    summary = _export(disk, tmp_path / 'live', include_deleted=False)
    _document, case = _case(summary)
    assert [e['FileName'] for m in case['Media']
            for e in m['MediaFiles']] == ['IMG1.JPG']


def test_a_deleted_file_whose_clusters_a_live_file_holds_is_not_exported(
        tmp_path):
    """Its bytes are the live file's now: exported, it would put another
    file's picture under the deleted name (core/deleted.py: overwritten)."""
    import struct
    photo, other = jpeg(), jpeg('green', 'Canon', 'EOS R5')
    image, _placed, _free = fat16_volume([('IMG1.JPG', photo),
                                          ('GONE.JPG', other)])
    image = bytearray(image)
    at = image.index(b'GONE    JPG')
    image[at] = 0xE5
    struct.pack_into('<H', image, at + 26, 2)    # IMG1.JPG's first cluster
    path = tmp_path / 'reused.dd'
    path.write_bytes(bytes(image))
    summary = _export(str(path), tmp_path / 'out')
    _document, case = _case(summary)
    assert [e['FileName'] for m in case['Media']
            for e in m['MediaFiles']] == ['IMG1.JPG']


def test_deleted_ntfs_files_without_a_name_link_are_found(tmp_path):
    """DFTT #7: NTFS names whose MFT link is gone (TSK gives no metadata)
    -- the file walk passes all of them. They come from core/deleted.py,
    read through their MFT entries; a reader that calls every file a
    picture makes the image's .dat files stand in for deleted pictures."""
    from tests.conftest import image_path
    from trace_app.core import vics, walk
    from trace_app.core.image_handler import ImageHandler

    class EverythingIsAPicture:
        @staticmethod
        def from_buffer(_data):
            return 'image/jpeg'
    handler = ImageHandler(image_path('7-ntfs-undel.dd'))
    assert handler.load_image()
    try:
        assert not any(e.deleted for e in walk.iter_files(handler))
        found = {c['source_path']: c for c in vics.find_media(
            handler, 'DFTT 7', reader=EverythingIsAPicture())
            if c['deleted']}
        # DFTT #7's deleted files whose clusters nothing holds now: every
        # one recoverable or resident (core/deleted.py), none reused.
        assert set(found) == {'/frag1.dat', '/frag2.dat', '/sing1.dat',
                              '/mult1.dat', '/dir1/dir2/frag3.dat',
                              '/dir1/mult2.dat', '/res1.dat',
                              '/$OrphanFiles/sing2.dat'}
        fs = handler.get_fs_info(0)
        for candidate in found.values():
            data = candidate['read'](0, candidate['size'])
            assert len(data) == candidate['size']
            inode = int(candidate['ref'].split(':i')[1].split(':')[0])
            assert data == fs.open_meta(inode=inode).read_random(
                0, candidate['size'])
        assert not any(c['deleted'] for c in vics.find_media(
            handler, 'DFTT 7', include_deleted=False,
            reader=EverythingIsAPicture()))
    finally:
        handler.close_resources()


def test_fat_local_times_are_left_out_not_shifted(tmp_path):
    disk, _photo, _other = _fat_disk(tmp_path)
    summary = _export(disk, tmp_path / 'out')
    _document, case = _case(summary)
    for media in case['Media']:
        for entry in media['MediaFiles']:
            assert not {'Created', 'Written', 'Accessed'} & set(entry)
    assert summary['local_times_omitted'] == summary['media_files']
    with open(summary['manifest'], encoding='utf-8') as handle:
        rows = list(csv.DictReader(handle))
    assert all('local' in row['modified'] for row in rows)
    log = open(os.path.join(summary['folder'], 'vics-export.log'),
               encoding='utf-8').read()
    assert 'no zone' in log


# --- carved files ------------------------------------------------------------------

def test_carved_pictures_are_unallocated_with_their_offset(tmp_path):
    photo = jpeg('purple', 'Sony', 'A7')
    image, _placed, free_at = fat16_volume([('NOTE.TXT', b'x' * 600)])
    offset = free_at + 8192
    image = bytearray(image)
    image[offset:offset + len(photo)] = photo
    path = tmp_path / 'free.dd'
    path.write_bytes(bytes(image))
    carved = [{'name': f'{offset:x}.jpg', 'offset': offset,
               'size': len(photo), 'type': 'jpg', 'fragments': None},
              {'name': 'text.jpg', 'offset': 0, 'size': 600, 'type': 'jpg',
               'fragments': None}]
    summary = _export(str(path), tmp_path / 'out', carved=carved)
    _document, case = _case(summary)
    assert len(case['Media']) == 1
    media = case['Media'][0]
    assert media['MD5'] == hashlib.md5(photo).hexdigest().upper()
    entry = media['MediaFiles'][0]
    assert entry['Unallocated'] is True
    assert entry['PhysicalLocation'] == offset
    assert entry['FilePath'] == 'EXHIBIT 1\\[carved]'
    summary = _export(str(path), tmp_path / 'none', carved=carved,
                      include_carved=False)
    assert summary['media'] == 0


# --- cancel and the job ------------------------------------------------------------

def test_a_cancelled_export_writes_no_json(folder_evidence, tmp_path):
    calls = []

    def stop():
        calls.append(1)
        return len(calls) > 3
    summary = _export(folder_evidence[0], tmp_path / 'out', should_stop=stop)
    assert summary['cancelled'] and summary['json'] == ''
    out = tmp_path / 'out'
    assert not list(out.glob('*.json'))
    assert not [name for _d, _s, files in os.walk(out) for name in files
                if name.endswith('.part')]
    assert 'CANCELLED' in (out / 'vics-export.log').read_text('utf-8')


def test_the_job_exports_from_paths(folder_evidence, tmp_path):
    from trace_app.core import background, vics
    out = tmp_path / 'job'
    out.mkdir()
    items = []
    count = background.job_vics(
        {'sources': [('EXHIBIT 1', folder_evidence[0], None, [])],
         'folder': str(out), 'case_number': 'J-1', 'model': 'CUSTOM',
         'version': '2.3.0'},
        lambda *payload: None, items.append, lambda: False)
    assert count == 4 and len(items) == 1
    document = json.load(open(items[0]['json'], encoding='utf-8'))
    assert document['@odata.context'] == vics.CONTEXT.format(model='CUSTOM')
    assert document['value'][0]['CaseNumber'] == 'J-1'


def test_unknown_models_are_refused(tmp_path):
    from trace_app.core import vics
    with pytest.raises(ValueError):
        vics.Package(str(tmp_path), model='UK')


def test_iso_times_keep_100_ns_and_drop_unset():
    from trace_app.core.vics import iso_time
    assert iso_time(1686592497, 965855200) == \
        '2023-06-12T17:54:57.9658552+00:00'
    assert iso_time(1686592497) == '2023-06-12T17:54:57+00:00'
    assert iso_time(0) is None and iso_time(None) is None


def test_export_folders_are_new_each_time(tmp_path):
    from trace_app.core.vics import export_folder
    first = export_folder(str(tmp_path), 'CASE/42')
    os.makedirs(first)
    second = export_folder(str(tmp_path), 'CASE/42')
    assert first != second
    assert os.path.dirname(first) == str(tmp_path)
    assert '/' not in os.path.basename(first)


# --- the dialog ---------------------------------------------------------------------

def test_the_dialog_gives_the_options_the_window_queues(qapp, tmp_path):
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QDialogButtonBox
    from trace_app.ui.dialogs.vics_export import VicsExportDialog
    evidence = [{'key': 1, 'name': 'phone.E01', 'source_id': 'EX-1',
                 'path': 'a'},
                {'key': 2, 'name': 'card.dd', 'source_id': 'EX-2',
                 'path': 'b'}]
    dialog = VicsExportDialog(evidence, {'folder': str(tmp_path),
                                         'case_number': 'OP-7',
                                         'ContactName': 'A. Examiner'})
    ok = dialog.buttons.button(QDialogButtonBox.Ok)
    assert ok.isEnabled()
    dialog.evidence_list.item(1).setCheckState(Qt.Unchecked)
    dialog.model_combo.setCurrentIndex(1)
    dialog.min_size.setValue(10)
    options = dialog.options
    assert [row['key'] for row in options['evidence']] == [1]
    assert options['case_number'] == 'OP-7'
    assert options['contact']['ContactName'] == 'A. Examiner'
    assert options['model'] == 'CUSTOM' and options['min_size'] == 10240
    # Looking inside files is on, carving inside them (slow) off.
    assert options['inside'] is True and options['carve_inside'] is False
    dialog.inside_box.setChecked(False)
    dialog.carve_inside_box.setChecked(True)
    assert dialog.options['inside'] is False
    assert dialog.options['carve_inside'] is True
    dialog.case_number.setText('  ')
    assert not ok.isEnabled()
    dialog.case_number.setText('OP-7')
    assert ok.isEnabled()
    dialog.evidence_list.item(0).setCheckState(Qt.Unchecked)
    assert not ok.isEnabled()
    dialog.deleteLater()


# --- the window ------------------------------------------------------------------

def test_quick_triage_exports_as_a_job(qapp, tmp_path):
    """No case: the export reads the open image itself, in a child
    process, and the Case menu's entry stays usable."""
    from tests.conftest import close_window, pump
    from trace_app.ui.main_window import MainWindow
    disk, photo, _other = _fat_disk(tmp_path)
    window = MainWindow()
    try:
        window._report_dialogs = False
        assert window.case is None
        assert window.vics_export_action.isEnabled()
        assert window.open_evidence_image(disk)
        # The menu entry opens the dialog (it once handed triggered's
        # `checked` to export_vics as its options).
        from PySide6.QtWidgets import QDialog
        from trace_app.ui.dialogs import vics_export
        shown = []
        original = vics_export.VicsExportDialog.exec

        def refuse(dialog):
            shown.append(dialog)
            return QDialog.Rejected
        vics_export.VicsExportDialog.exec = refuse
        try:
            window.vics_export_action.trigger()
        finally:
            vics_export.VicsExportDialog.exec = original
        assert len(shown) == 1
        # No case to take a number from: the image's name, never empty.
        assert shown[0].case_number.text() == 'card'
        evidence = window._vics_evidence()
        assert [row['name'] for row in evidence] == ['card.dd']
        out = tmp_path / 'exports'
        out.mkdir()
        assert window.queue_vics({'evidence': evidence,
                                  'parent_folder': str(out),
                                  'case_number': 'TRIAGE-1',
                                  'contact': {'ContactName': 'On scene'},
                                  'model': 'US', 'include_deleted': True,
                                  'include_carved': True, 'min_size': 0})
        assert pump(qapp, 120, lambda: not window.job_bar.busy)
        summary = window.last_vics_export
        assert summary and not summary['cancelled'], summary
        assert os.path.dirname(summary['folder']) == str(out)
        _document, case = _case(summary)
        assert case['CaseNumber'] == 'TRIAGE-1'
        assert hashlib.md5(photo).hexdigest().upper() in \
            {m['MD5'] for m in case['Media']}
    finally:
        close_window(window)


# --- Project VIC categories (schema 22) ----------------------------------------

def _case_with_disk(tmp_path):
    """A case holding the FAT card, and its live files' refs as the walk
    makes them (the export matches by those)."""
    from trace_app.core import walk
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    disk, photo, other = _fat_disk(tmp_path)
    case = Case.create(str(tmp_path / 'case'), 'Categories', number='OP-9',
                       examiner='A. Examiner')
    evidence_id = case.add_evidence(disk)
    handler = ImageHandler(disk)
    assert handler.load_image()
    refs = {entry.name: entry.ref for entry in walk.iter_files(handler)}
    handler.close_resources()
    return case, evidence_id, disk, refs, photo, other


def _row(evidence_id, refs, name):
    return {'evidence_id': evidence_id, 'artifact_ref': refs[name],
            'name': name, 'path': f'/{name}'}


def test_a_category_is_one_per_file_and_audited(tmp_path):
    from trace_app.core.case import CaseError
    case, evidence_id, _disk, refs, _p, _o = _case_with_disk(tmp_path)
    try:
        row = _row(evidence_id, refs, 'IMG1.JPG')
        assert case.set_vic_category(2, [row]) == 1
        assert case.set_vic_category(2, [row]) == 0       # no change
        assert case.set_vic_category(1, [row]) == 1       # replaces
        assert case.vic_categories_for(evidence_id) == {refs['IMG1.JPG']: 1}
        listed = case.vic_categories()
        assert len(listed) == 1 and listed[0]['examiner'] == 'A. Examiner'
        assert dict(case.evidence_footprint(evidence_id))[
            'Project VIC categories'] == 1
        with pytest.raises(CaseError):
            case.set_vic_category(5, [row])     # Uncategorized is clearing
        assert case.clear_vic_category([row]) == 1
        assert case.vic_categories() == []
        audit = [(e['action'], e['detail']) for e in case.activity()]
        actions = [action for action, _detail in audit]
        assert actions.count('Project VIC category set') == 2
        assert 'Project VIC category cleared' in actions
        changed = [d for a, d in audit if a == 'Project VIC category set']
        assert any('(was 2 Child Exploitive' in d for d in changed)
    finally:
        case.close()


def test_categories_and_comments_reach_the_export(tmp_path):
    from trace_app.core import vics
    from trace_app.core.image_handler import ImageHandler
    case, evidence_id, disk, refs, photo, _other = _case_with_disk(tmp_path)
    try:
        case.set_vic_category(4, [_row(evidence_id, refs, 'IMG1.JPG')])
        bookmark = case.add_bookmark(evidence_id, refs['IMG1.JPG'],
                                     'Series A', 'IMG1.JPG', '/IMG1.JPG')
        case.add_note('Same background as exhibit 3', evidence_id,
                      refs['IMG1.JPG'], 'IMG1.JPG', '/IMG1.JPG')
        case.add_note('Seen on the seized phone too',
                      bookmark_id=bookmark, evidence_id=evidence_id)
        marks = {'categories': case.vic_categories_for(evidence_id),
                 'comments': case.vics_comments(evidence_id)}
    finally:
        case.close()
    handler = ImageHandler(disk)
    assert handler.load_image()
    try:
        summary = vics.export([('EX-1', handler, (), marks)],
                              str(tmp_path / 'out'), 'OP-9')
    finally:
        handler.close_resources()
    _document, exported = _case(summary)
    md5 = hashlib.md5(photo).hexdigest().upper()
    media = next(m for m in exported['Media'] if m['MD5'] == md5)
    assert media['Category'] == 4
    assert media['IsPrecategorized'] is False
    # Griffeye's order: Category between SHA1 and MediaSize.
    keys = list(media)
    assert keys.index('SHA1') < keys.index('Category') < \
        keys.index('MediaSize')
    assert media['Comments'] == ('Bookmark: Series A | Note: Same '
                                 'background as exhibit 3 | Note: Seen on '
                                 'the seized phone too')
    others = [m for m in exported['Media'] if m['MD5'] != md5]
    assert others and not any('Category' in m or 'Comments' in m
                              for m in others)
    assert exported['TotalPrecategorized'] == 0
    assert summary['categorised'] == 1 and summary['conflicts'] == 0
    log = open(os.path.join(summary['folder'], 'vics-export.log'),
               encoding='utf-8').read()
    assert '4 Comparison Images: 1' in log


def test_copies_categorised_differently_get_the_most_serious(
        folder_evidence, tmp_path):
    from trace_app.core import vics, walk
    from trace_app.core.image_handler import ImageHandler
    evidence, photo = folder_evidence
    handler = ImageHandler(evidence)
    assert handler.load_image()
    try:
        refs = {e.name: e.ref for e in walk.iter_files(handler)}
        marks = {'categories': {refs['IMG_0001.jpg']: 0,
                                refs['copy of photo.jpg']: 3}}
        summary = vics.export([('EX-1', handler, (), marks)],
                              str(tmp_path / 'out'), 'OP-9')
    finally:
        handler.close_resources()
    _document, exported = _case(summary)
    md5 = hashlib.md5(photo).hexdigest().upper()
    media = next(m for m in exported['Media'] if m['MD5'] == md5)
    assert media['Category'] == 3           # 3 is more serious than 0
    assert summary['conflicts'] == 1
    log = open(os.path.join(summary['folder'], 'vics-export.log'),
               encoding='utf-8').read()
    assert f"{md5} -> 3 CGI / Animation" in log
    assert '0 Non-Pertinent: ' in log and 'IMG_0001.jpg' in log


def test_severity_never_under_classifies():
    from trace_app.core.vics import most_serious
    assert most_serious([0, 4, 2]) == 2
    assert most_serious([0, 1]) == 1
    assert most_serious([0]) == 0
    assert most_serious([]) is None and most_serious([5, None]) is None


def _menu_texts(menu):
    """Every entry's text (shortcut cut off), sub-menus as (text, [...]),
    with whether it is enabled."""
    out = []
    for action in menu.actions():
        if action.isSeparator() or not action.text():
            continue
        text = action.text().split('\t')[0]
        if action.menu() is not None:
            out.append((text, _menu_texts(action.menu())))
        else:
            out.append((text, action.isEnabled()))
    return out


@pytest.fixture
def marking_window(qapp, tmp_path):
    """A case window over a FAT card holding a photo, a JPEG named .TXT,
    a text file named .JPG, and a photo carved from free space."""
    from tests.conftest import close_window, pump
    from trace_app.core import walk
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    from trace_app.ui.main_window import MainWindow
    photo, hidden, carved = (jpeg(), jpeg('teal', 'Apple', 'iPhone'),
                             jpeg('purple', 'Sony', 'A7'))
    image, _placed, free_at = fat16_volume([
        ('IMG1.JPG', photo), ('PHOTO.TXT', hidden),
        ('FAKE.JPG', b'plain words\n' * 60)])
    image = bytearray(image)
    offset = free_at + 8192
    image[offset:offset + len(carved)] = carved
    disk = tmp_path / 'card.dd'
    disk.write_bytes(bytes(image))
    case = Case.create(str(tmp_path / 'case'), 'Marks', number='OP-3')
    evidence_id = case.add_evidence(str(disk))
    case.add_carved(evidence_id, {'name': f'{offset:x}.jpg',
                                  'offset': offset, 'size': len(carved),
                                  'type': 'jpg', 'status': 'valid'})
    case._db.commit()
    handler = ImageHandler(str(disk))
    assert handler.load_image()
    refs = {e.name: e.ref for e in walk.iter_files(handler)}
    handler.close_resources()
    folder = case.folder
    case.close()
    window = MainWindow(case=Case.open(folder))
    window._report_dialogs = False
    pump(qapp, 60, lambda: window.evidence_files)
    rows = {name: _row(evidence_id, refs, name) for name in refs}
    carve = window.case.carved_files(evidence_id)[0]
    yield window, rows, carve, (photo, hidden, carved), tmp_path
    close_window(window)


def test_only_pictures_and_videos_take_a_category(marking_window):
    """Judged by content: a JPEG named .TXT is offered the categories, a
    text file named .JPG is not; a mixed selection categorises only its
    pictures and says so."""
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QMenu
    window, rows, _carve, _bytes, _tmp = marking_window
    case = window.case

    def offered(*names):
        menu = QMenu()
        texts = dict(_menu_texts(window.add_vic_menu(
            menu, [rows[n] for n in names]).parentWidget()))
        menu.deleteLater()
        return dict(texts['Project VIC Category'])

    assert offered('IMG1.JPG')['1 Child Abuse Material'] is True
    assert offered('PHOTO.TXT')['1 Child Abuse Material'] is True
    fake = offered('FAKE.JPG')
    assert fake['1 Child Abuse Material'] is False
    assert 'Only pictures and videos are categorised' in fake
    mixed = offered('IMG1.JPG', 'FAKE.JPG')
    assert 'Applies to the 1 picture(s) and video(s) of 2' in mixed
    window._tag_rows = lambda view, row=None: [rows['IMG1.JPG'],
                                               rows['FAKE.JPG']]
    assert window._category_key(None, Qt.Key_2)
    evidence_id = rows['IMG1.JPG']['evidence_id']
    assert case.vic_categories_for(evidence_id) == {
        rows['IMG1.JPG']['artifact_ref']: 2}
    assert 'not pictures or videos' in window.statusBar().currentMessage()


def test_removing_a_tag_or_category_is_offered_where_it_is_looked_for(
        marking_window):
    """Right-click on a tagged, categorised file: 'Remove Tag “Relevant”'
    and 'Remove Project VIC Category (1 ...)' on the menu itself; Remove
    Category in the category menu; Delete in Triage ▸ Tags."""
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QMenu
    window, rows, _carve, _bytes, _tmp = marking_window
    case = window.case
    row = rows['IMG1.JPG']
    relevant = case.tags()[0]['id']
    window.tag_rows(relevant, [row])
    window.categorise_rows(1, [row])
    window._tag_rows = lambda view, clicked=None: [row]
    menu = QMenu()
    window._add_mark_menus(menu, row, None)
    texts = _menu_texts(menu)
    assert texts[0] == ('Remove Tag “Relevant”', True)
    assert texts[1] == ('Remove Project VIC Category (1 Child Abuse '
                        'Material)', True)
    category_menu = dict(dict(texts)['Project VIC Category'])
    assert category_menu['Remove Category (Uncategorized)'] is True
    menu.deleteLater()
    next(a for a in menu.actions()
         if a.text().startswith('Remove Tag')).trigger()
    assert case.tagged() == []
    # Delete in Triage ▸ Tags takes off the mark a file is listed under.
    window.tag_rows(relevant, [row])
    tree = window.tags_panel.tree
    tree.clearSelection()
    for index in range(tree.topLevelItemCount()):
        head = tree.topLevelItem(index)
        for child in range(head.childCount()):
            head.child(child).setSelected(True)
    QTest.keyClick(tree, Qt.Key_Delete)
    assert case.tagged() == [] and case.vic_categories() == []
    assert 'Remove' not in ' '.join(
        t for t, _e in _menu_texts(_fresh_menu(window, row)))


def _fresh_menu(window, row):
    from PySide6.QtWidgets import QMenu
    menu = QMenu()
    window._add_mark_menus(menu, row, None)
    return menu


def test_carved_files_are_tagged_categorised_and_exported(marking_window):
    """A carve, by the span ref the case stores it under: tagged and
    categorised from the Carved files table, listed in Triage ▸ Tags, and
    its category written by the VICS export."""
    from tests.conftest import pump
    from PySide6.QtWidgets import QApplication, QMenu
    window, _rows, carve, (_p, _h, carved), tmp_path = marking_window
    case = window.case
    marks = window._tag_rows(None, carve)
    assert [m['artifact_ref'] for m in marks] == [carve['artifact_ref']]
    assert marks[0]['path'] == f"[carved]/{carve['name']}"
    menu = QMenu()
    window._menu_extras(menu, carve, None)
    texts = dict(_menu_texts(menu))
    assert 'Tag' in texts
    assert dict(texts['Project VIC Category'])['3 CGI / Animation'] is True
    menu.deleteLater()
    window.tag_rows(case.tags()[1]['id'], marks)
    window.categorise_rows(3, marks)
    listed = window.tags_panel.status_label.text()
    assert '1 tagged file(s)' in listed and '1 with a Project VIC' in listed
    out = tmp_path / 'exports'
    out.mkdir()
    assert window.queue_vics({
        'evidence': window._vics_evidence(), 'parent_folder': str(out),
        'case_number': 'OP-3', 'contact': {}, 'model': 'US',
        'include_deleted': True, 'include_carved': True, 'min_size': 0})
    app = QApplication.instance()
    assert pump(app, 120, lambda: not window.job_bar.busy)
    _document, exported = _case(window.last_vics_export)
    media = next(m for m in exported['Media'] if m['MD5'] ==
                 hashlib.md5(carved).hexdigest().upper())
    assert media['Category'] == 3
    assert media['MediaFiles'][0]['Unallocated'] is True


def test_a_case_window_categorises_lists_and_exports(qapp, tmp_path):
    """Alt+1 on a file in a case's window: the category is kept, the Tags
    tab and the tree's Tags node count it alike, the menu offers the
    categories, and the window's VICS export writes it."""
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QMenu
    from tests.conftest import close_window, pump
    from trace_app.core.case import Case
    from trace_app.ui.main_window import MainWindow
    case, evidence_id, _disk, refs, photo, _other = _case_with_disk(
        tmp_path)
    folder = case.folder
    case.close()
    window = MainWindow(case=Case.open(folder))
    try:
        window._report_dialogs = False
        pump(qapp, 60, lambda: window.evidence_files)
        rows = [_row(evidence_id, refs, 'IMG1.JPG')]
        window._tag_rows = lambda view, row=None: rows
        assert window._category_key(None, Qt.Key_1)
        assert window.case.vic_categories_for(evidence_id) == {
            refs['IMG1.JPG']: 1}
        assert window.tags_panel.status_label.text().startswith(
            '1 with a Project VIC category')
        root = next(window.tree_viewer.topLevelItem(i) for i in
                    range(window.tree_viewer.topLevelItemCount())
                    if (window.tree_viewer.topLevelItem(i).data(
                        0, Qt.UserRole) or {}).get('is_tags_root'))
        assert root.text(0) == 'Tags (1)'
        assert root.child(0).text(0) == \
            'Project VIC 1 Child Abuse Material (1)'
        menu = QMenu()
        sub = window.add_vic_menu(menu, rows)
        texts = [a.text().split('\t')[0] for a in sub.actions()
                 if a.text()]
        assert texts[0] == '1 Child Abuse Material (current)'
        assert texts[-1] == 'Remove Category (Uncategorized)'
        menu.deleteLater()
        out = tmp_path / 'exports'
        out.mkdir()
        assert window.queue_vics({
            'evidence': window._vics_evidence(), 'parent_folder': str(out),
            'case_number': 'OP-9', 'contact': {}, 'model': 'US',
            'include_deleted': True, 'include_carved': True,
            'min_size': 0})
        assert pump(qapp, 120, lambda: not window.job_bar.busy)
        summary = window.last_vics_export
        assert summary['categorised'] == 1
        _document, exported = _case(summary)
        md5 = hashlib.md5(photo).hexdigest().upper()
        assert next(m for m in exported['Media']
                    if m['MD5'] == md5)['Category'] == 1
        assert window._category_key(None, Qt.Key_5)       # Uncategorized
        assert window.case.vic_categories() == []
    finally:
        close_window(window)


def test_alt_digits_reach_the_category_hook(qapp):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QTableWidget
    from trace_app.ui.widgets import context_menus
    heard = []
    saved = context_menus._category_key_hook
    context_menus.set_category_key_hook(
        lambda view, key: heard.append(key - Qt.Key_0) or True)
    table = QTableWidget(2, 1)
    context_menus.install(qapp)
    try:
        for key in (Qt.Key_0, Qt.Key_4, Qt.Key_5, Qt.Key_7):
            QTest.keyClick(table, key, Qt.AltModifier)
        QTest.keyClick(table, Qt.Key_1)               # a tag key, not ours
    finally:
        context_menus.set_category_key_hook(saved)
        table.deleteLater()
    assert heard == [0, 4, 5]
