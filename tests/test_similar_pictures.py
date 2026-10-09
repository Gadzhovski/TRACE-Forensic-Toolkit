"""Perceptual hashes (core/phash.py) and Triage > Similar pictures.

The pictures are generated from a sample photo -- resized, re-saved,
brightened, cropped, mirrored -- so each claim about what counts as "the
same picture" is checked against the change that should (or should not)
survive it.
"""

import io
import os
import random
import sqlite3

import pytest

from tests.conftest import ROOT, pump

PHOTO = os.path.join(ROOT, 'test_images', 'carve_samples', 'hopper.webp')
OTHER = os.path.join(ROOT, 'test_images', 'carve_samples', 'gallery-1.webp')


@pytest.fixture
def photo():
    if not os.path.exists(PHOTO) or not os.path.exists(OTHER):
        pytest.skip("carve_samples are not in test_images/")
    from PIL import Image
    return Image.open(PHOTO).convert('RGB').resize((640, 640))


def _encode(image, fmt='JPEG', **options):
    buffer = io.BytesIO()
    image.save(buffer, fmt, **options)
    return buffer.getvalue()


def test_copies_hash_alike_and_other_pictures_do_not(photo):
    from PIL import Image, ImageEnhance, ImageOps
    from trace_app.core.phash import DEFAULT_THRESHOLD, distance, phash
    original = phash(_encode(photo, quality=92))
    assert len(original) == 16
    alike = {
        'resized': _encode(photo.resize((200, 200)), quality=90),
        'recompressed': _encode(photo, quality=30),
        'as PNG': _encode(photo, 'PNG'),
        'brightened': _encode(ImageEnhance.Brightness(photo).enhance(1.25)),
        'cropped 5%': _encode(photo.crop((32, 32, 608, 608))),
    }
    for change, data in alike.items():
        assert distance(original, phash(data)) <= DEFAULT_THRESHOLD, change
    assert distance(original, phash(_encode(photo.resize((200, 200))))) <= 2
    # Not the same picture to a perceptual hash: a mirror image, another
    # photo.
    assert distance(original, phash(_encode(ImageOps.mirror(photo)))) > \
        DEFAULT_THRESHOLD
    other = Image.open(OTHER).convert('RGB')
    assert distance(original, phash(_encode(other))) > DEFAULT_THRESHOLD
    # No hash for what is not a picture, or is only an icon.
    assert phash(b'not a picture') is None and phash(b'') is None
    assert phash(_encode(photo.resize((16, 16)))) is None


def test_grouping_finds_every_pair_brute_force_would():
    from trace_app.core.phash import distance, groups
    rng = random.Random(7)
    items = [{'name': str(i), 'phash': f"{rng.getrandbits(64):016x}",
              'size': i} for i in range(300)]
    # Plant near-copies: a few bits flipped.
    for i in range(0, 60, 3):
        bits = int(items[i]['phash'], 16) ^ (1 << rng.randrange(64)) ^ \
            (1 << rng.randrange(64))
        items.append({'name': f"copy of {i}", 'phash': f"{bits:016x}",
                      'size': 1000 + i})
    found = groups(items, 4)
    paired = {frozenset(m['name'] for m in g) for g in found}
    for a in range(len(items)):
        for b in range(a + 1, len(items)):
            if distance(items[a]['phash'], items[b]['phash']) <= 4:
                assert any({items[a]['name'], items[b]['name']} <= g
                           for g in paired)
    # The largest picture leads each group, at distance 0.
    for group in found:
        assert group[0]['distance'] == 0
        assert group[0]['size'] == max(m['size'] for m in group)


def test_analysis_records_hashes_and_groups_copies(photo, tmp_path):
    from PIL import Image, ImageEnhance
    from trace_app.core.analysis import MODULES, analyse_evidence
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.phash import groups, match, phash
    folder = tmp_path / 'photos'
    folder.mkdir()
    photo.save(folder / 'original.jpg', quality=92)
    photo.resize((200, 200)).save(folder / 'small_copy.jpg', quality=40)
    ImageEnhance.Brightness(photo).enhance(1.25).save(folder / 'edited.png')
    Image.open(OTHER).convert('RGB').save(folder / 'other.jpg')
    case = Case.create(str(tmp_path / 'case'), 'Pictures')
    try:
        evidence = case.add_evidence(str(folder))
        handler = ImageHandler(str(folder))
        analyse_evidence(handler, case, evidence, MODULES)
        handler.close_resources()
        rows = {r['name']: r for r in case.picture_hashes(evidence)}
        assert set(rows) == {'original.jpg', 'small_copy.jpg', 'edited.png',
                             'other.jpg'}
        found = groups(list(rows.values()))
        assert [sorted(m['name'] for m in g) for g in found] == \
            [['edited.png', 'original.jpg', 'small_copy.jpg']]
        # The largest picture leads: the likeliest original.
        assert found[0][0]['size'] == max(m['size'] for m in found[0])
        reference = {'name': 'known.jpg',
                     'phash': phash(_encode(photo.resize((320, 320))))}
        [(ref, hits)] = match([reference], list(rows.values()))
        assert ref is reference and {h['name'] for h in hits} == \
            {'original.jpg', 'small_copy.jpg', 'edited.png'}
    finally:
        case.close()


def test_a_v16_case_gains_the_phash_column(tmp_path):
    from trace_app.core.case import SCHEMA_VERSION, Case
    folder = str(tmp_path / 'old')
    Case.create(folder, 'Old').close()
    db = sqlite3.connect(os.path.join(folder, 'case.db'))
    db.execute("ALTER TABLE file_analysis DROP COLUMN phash")
    db.execute("UPDATE case_info SET value = '16' WHERE key = "
               "'schema_version'")
    db.commit()
    db.close()
    case = Case.open(folder)
    try:
        columns = {r[1] for r in case._db.execute(
            "PRAGMA table_info(file_analysis)")}
        assert 'phash' in columns and SCHEMA_VERSION >= 17
        assert case.picture_hashes() == []
    finally:
        case.close()


def test_the_panel_groups_and_compares_with_references(qapp, photo,
                                                       tmp_path):
    from trace_app.core.case import Case
    from trace_app.core.phash import phash
    from trace_app.ui.viewers.similar_pictures_panel import \
        SimilarPicturesPanel
    case = Case.create(str(tmp_path / 'case'), 'Panel')
    evidence = case.add_evidence(str(tmp_path))
    rows = []
    for name, data in (('a.jpg', _encode(photo, quality=90)),
                       ('a_small.jpg', _encode(photo.resize((150, 150)))),
                       ('lone.jpg', _encode(photo.rotate(90)))):
        rows.append((f'p0:i{len(rows) + 1}:s0', name, f'/{name}', 0,
                     {'size': len(data), 'phash': phash(data)}))
    case.add_analysis_batch(evidence, rows)
    case.commit()
    panel = SimilarPicturesPanel()
    shown = []
    panel.file_selected.connect(shown.append)
    try:
        panel.set_case(case)
        assert pump(qapp, 10, lambda: panel.tree.topLevelItemCount() == 1)
        group = panel.tree.topLevelItem(0)
        assert group.childCount() == 2
        assert {group.child(i).text(0) for i in range(2)} == \
            {'a.jpg', 'a_small.jpg'}
        panel.tree.setCurrentItem(group.child(1))
        assert shown and shown[-1]['artifact_ref'].startswith('p0:i')

        references = tmp_path / 'references'
        references.mkdir()
        photo.resize((300, 300)).save(references / 'known.jpg')
        panel.choose_reference(str(references))
        assert pump(qapp, 10, lambda: panel._mode == 'reference' and
                    panel.tree.topLevelItemCount() == 1 and
                    panel.tree.topLevelItem(0).text(0) == 'known.jpg')
        assert panel.tree.topLevelItem(0).childCount() == 2
        assert 'look like 2 evidence picture(s)' in \
            panel.status_label.text()
        panel.show_groups()
        assert pump(qapp, 10, lambda: panel.groups_button.isHidden() and
                    panel.tree.topLevelItemCount() == 1 and
                    panel.tree.topLevelItem(0).childCount() == 2)
    finally:
        panel.shutdown()
        panel.deleteLater()
        case.close()
