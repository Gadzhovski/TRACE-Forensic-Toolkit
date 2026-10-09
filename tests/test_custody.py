"""Hashing, verification, the audit trail and exports, as an examiner
relies on them.

Every scenario is a real one, on real public images: an examiner's copy
altered by one byte, a copy cut short, a file shrinking while it is
hashed (the OS gives a short read), an E01 with a damaged chunk, an
acquisition log beside a dd image, a hand-edited case database. Expected
values come from somewhere other than TRACE -- the hash an image stores,
hashlib over the bytes, pytsk3 read directly, libewf's own reading --
never from the code under test.

The first test replays the review that started this file: alter the
image, see MISMATCH, close the dialog, verify again. It must still say
CHANGED, and the recorded hash must still be the original's.
"""

import csv
import hashlib
import os
import shutil
import sqlite3
import struct

import pytest

from tests.conftest import image_path, pump

E01, RAW, FAT = 'ntfs1-gen2.E01', '8-jpeg-search.dd', '6-fat-undel.dd'


def _digests(path):
    hashers = {n: hashlib.new(n) for n in ('md5', 'sha1', 'sha256')}
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            for hasher in hashers.values():
                hasher.update(block)
    return {n: h.hexdigest() for n, h in hashers.items()}


def _flip(path, offset):
    with open(path, 'r+b') as handle:
        handle.seek(offset)
        value = handle.read(1)
        handle.seek(offset)
        handle.write(bytes([value[0] ^ 0xFF]))


@pytest.fixture
def quiet_dialogs(monkeypatch):
    from trace_app.ui.dialogs import message
    said = []
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name,
                            lambda *a, name=name, **k: said.append((name, a)))
    monkeypatch.setattr(message, 'question', lambda *a, **k: True)
    return said


# --- the review's scenario, through the window -----------------------------

@pytest.mark.images
@pytest.mark.ui
def test_an_altered_image_stays_changed_whatever_the_dialog_does(
        qapp, tmp_path, quiet_dialogs):
    from trace_app.core.case import (STATUS_BASELINE, STATUS_CHANGED,
                                     STATUS_VERIFIED, Case)
    from trace_app.ui.main_window import MainWindow
    copy = tmp_path / 'exhibit.dd'
    shutil.copyfile(image_path(RAW), copy)
    original = _digests(copy)
    case = Case.create(str(tmp_path / 'Case'), 'Custody')
    evidence = case.add_evidence(str(copy))
    window = MainWindow(case=case)

    def row():
        return next(r for r in case.evidence() if r['id'] == evidence)

    def checked(status, count):
        return lambda: not window.job_bar.busy and \
            row()['last_status'] == status and \
            len(case.verifications(evidence)) == count

    try:
        assert pump(qapp, 60, lambda: str(copy) in window.evidence_files)
        # Tools > Verify Image: hashed in full; a dd stores no hash and
        # has no log, so this is the reference -- and says so.
        window.verify_image(str(copy))
        assert pump(qapp, 60, checked(STATUS_BASELINE, 1))
        assert {n: row()[n] for n in original} == original
        dialog = window.verification_dialog
        assert 'Nothing was recorded to compare with' in dialog.text()

        # The image is altered. Verify Again: MISMATCH.
        _flip(copy, 5 * 1024 * 1024)
        dialog.verify_again.emit()
        assert pump(qapp, 60, checked(STATUS_CHANGED, 2))
        dialog = window.verification_dialog
        assert 'DIFFERENT' in dialog.text()
        # Closing the dialog writes nothing.
        before = (len(case.verifications(evidence)), case.activity(1))
        dialog.close()
        pump(qapp, 0.3)
        assert (len(case.verifications(evidence)), case.activity(1)) == \
            before
        assert {n: row()[n] for n in original} == original

        # Verify again: still CHANGED -- the reference never moved.
        window.start_image_verification(str(copy))
        assert pump(qapp, 60, checked(STATUS_CHANGED, 3))
        assert {n: row()[n] for n in original} == original
        assert any(kind == 'warning' and 'does not match' in args[1]
                   for kind, args in quiet_dialogs)
        assert row()['last_status'] != STATUS_VERIFIED
    finally:
        window.cleanup_resources()
        case.close()


# --- hashing reads everything or nothing ------------------------------------

@pytest.mark.images
def test_a_file_shrinking_while_hashed_gives_no_hash(tmp_path):
    """A real short read: the evidence file is cut while it is being
    hashed (a copy still syncing, a failing share). No digest of the part
    read may come back, and the case records UNREADABLE, not a hash."""
    from trace_app.core import evidence_hash
    from trace_app.core.case import STATUS_UNREADABLE, Case, hash_evidence
    copy = tmp_path / 'exhibit.dd'
    shutil.copyfile(image_path(RAW), copy)
    cut = []

    def progress(done, total):
        if not cut:
            cut.append(done)
            os.truncate(copy, total // 2)

    with pytest.raises(evidence_hash.HashingError, match='ended at byte'):
        evidence_hash.hash_file(str(copy), progress, block=1 << 20)
    shutil.copyfile(image_path(RAW), copy)
    cut.clear()
    case = Case.create(str(tmp_path / 'Case'), 'Short read')
    try:
        evidence = case.add_evidence(str(copy))
        row = case.evidence()[0]
        results = hash_evidence(row, progress)
        assert results['computed_md5'] is None if 'computed_md5' in \
            results else True
        outcome = case.apply_verification(evidence, results)
        assert outcome['status'] == STATUS_UNREADABLE
        row = case.evidence()[0]
        assert row['md5'] is row['sha1'] is row['sha256'] is None
        assert row['last_status'] == STATUS_UNREADABLE
        assert not [a for a in case.activity(50)
                    if a['action'] == 'evidence hashes recorded']
    finally:
        case.close()


@pytest.mark.images
def test_a_truncated_e01_copy_is_unreadable_not_hashed(tmp_path):
    from trace_app.core.case import STATUS_UNREADABLE, Case
    copy = tmp_path / 'exhibit.E01'
    shutil.copyfile(image_path(E01), copy)
    with open(copy, 'r+b') as handle:
        handle.truncate(os.path.getsize(copy) - 1024 * 1024)
    case = Case.create(str(tmp_path / 'Case'), 'Cut')
    try:
        case.add_evidence(str(copy))
        (outcome,) = case.verify_evidence()
        assert outcome[1] == STATUS_UNREADABLE, outcome
        assert 'incomplete' in outcome[2]
        assert case.evidence()[0]['md5'] is None
    finally:
        case.close()


@pytest.mark.images
def test_every_hash_of_an_image_is_of_all_its_bytes(tmp_path):
    """MD5, SHA-1 and SHA-256 together, of exactly the image's bytes:
    a raw file by hashlib over the file, an E01 by the MD5 it stores."""
    from trace_app.core.image_handler import ImageHandler
    for name in (RAW, E01):
        handler = ImageHandler(image_path(name))
        try:
            results = handler.calculate_hashes()
        finally:
            handler.close_resources()
        assert not results.get('error')
        if name == RAW:
            assert {n: results[f'computed_{n}'] for n in
                    ('md5', 'sha1', 'sha256')} == _digests(image_path(name))
            assert results['size'] == os.path.getsize(image_path(name))
        else:
            assert results['computed_md5'] == results['stored_md5']
            assert len(results['computed_sha256']) == 64
            assert results['size'] == 516554752 and not results.get(
                'damaged')


# --- E01s: the image's own checksums ----------------------------------------

def _first_sectors_section(path):
    with open(path, 'rb') as handle:
        offset = 13
        while True:
            handle.seek(offset)
            descriptor = handle.read(76)
            kind = descriptor[:16].rstrip(b'\0')
            following, size = struct.unpack_from('<QQ', descriptor, 16)
            if kind == b'sectors':
                return offset, size
            offset = following


@pytest.mark.images
def test_a_damaged_e01_chunk_is_found_and_located(tmp_path):
    """Bytes flipped inside one compressed chunk. libewf reads that chunk
    as zeros and says nothing; TRACE must say which sectors, hash what
    libewf reads (so both tools agree on the damaged image's hash), and
    judge it CHANGED against the MD5 the image stores."""
    import pyewf
    from trace_app.core import ewf_chunks
    from trace_app.core.case import STATUS_CHANGED, verdict
    from trace_app.core.image_handler import ImageHandler
    copy = tmp_path / 'damaged.E01'
    shutil.copyfile(image_path(E01), copy)
    start, size = _first_sectors_section(copy)
    target = start + 76 + size // 2
    with open(copy, 'r+b') as handle:
        handle.seek(target)
        data = handle.read(16)
        handle.seek(target)
        handle.write(bytes(b ^ 0x5A for b in data))

    chunk_map = ewf_chunks.ChunkMap([str(copy)])
    (index,) = [i for i, c in enumerate(chunk_map.chunks)
                if c.offset <= target < c.offset + c.size]
    first = index * chunk_map.chunk_size // 512
    expected = [(first, first + chunk_map.chunk_size // 512 - 1)]

    handler = ImageHandler(str(copy))
    try:
        results = handler.calculate_hashes()
    finally:
        handler.close_resources()
    assert results['damaged'] == expected

    ewf = pyewf.handle()
    ewf.open([os.path.normpath(str(copy))])
    try:
        md5, total, position = hashlib.md5(), ewf.get_media_size(), 0
        while position < total:
            block = ewf.read(min(1 << 22, total - position))
            md5.update(block)
            position += len(block)
    finally:
        ewf.close()
    assert results['computed_md5'] == md5.hexdigest()
    assert results['computed_md5'] != results['stored_md5']

    outcome = verdict(results)
    assert outcome['status'] == STATUS_CHANGED
    assert f"sectors {first:,}-" in outcome['detail']
    assert 'MD5 is' in outcome['detail']


# --- the verdict: every hash must match -------------------------------------

def test_every_recorded_and_stored_hash_must_match():
    from trace_app.core.case import (STATUS_BASELINE, STATUS_CHANGED,
                                     STATUS_UNREADABLE, STATUS_VERIFIED,
                                     verdict)
    run = {'computed_md5': 'a' * 32, 'computed_sha1': 'b' * 40,
           'computed_sha256': 'c' * 64, 'size': 10}
    recorded = {'md5': 'a' * 32, 'sha1': 'b' * 40, 'sha256': 'c' * 64}
    assert verdict(run, recorded)['status'] == STATUS_VERIFIED
    # One of three recorded hashes differing is CHANGED, not verified.
    outcome = verdict(run, dict(recorded, sha256='d' * 64))
    assert outcome['status'] == STATUS_CHANGED
    assert 'SHA256 is ' + 'c' * 64 in outcome['detail']
    # The image's stored MD5 matching does not excuse its SHA-1.
    stored = dict(run, stored_md5='A' * 32, stored_sha1='e' * 40)
    assert verdict(stored)['status'] == STATUS_CHANGED
    assert verdict(run)['status'] == STATUS_BASELINE
    assert verdict({'error': 'disk gone'})['status'] == STATUS_UNREADABLE
    # A failed run is never judged on stale digests.
    assert verdict(dict(run, error='read failed at byte 4'),
                   recorded)['status'] == STATUS_UNREADABLE


# --- acquisition hashes ------------------------------------------------------

FTK_LOG = """Created By AccessData(R) FTK(R) Imager 4.7.1.2

Case Information:
Acquired using: ADI4.7.1.2
Evidence Number: EX-7

[Computed Hashes]
 MD5 checksum:    {md5}
 SHA1 checksum:   {sha1}

Image Information:
 Acquisition started:   Mon Mar 03 10:01:12 2025
 Segment list:
  {name}

Image Verification Results:
 Verification started:  Mon Mar 03 10:05:40 2025
 MD5 checksum:    {md5} : verified
 SHA1 checksum:   {sha1} : verified
"""


@pytest.mark.images
def test_a_dd_image_is_verified_against_its_acquisition_log(tmp_path):
    from trace_app.core.case import (STATUS_CHANGED, STATUS_VERIFIED,
                                     Case)
    copy = tmp_path / 'exhibit.dd'
    shutil.copyfile(image_path(RAW), copy)
    acquired = _digests(copy)
    (tmp_path / 'exhibit.dd.txt').write_text(FTK_LOG.format(
        name='exhibit.dd', **acquired))
    case = Case.create(str(tmp_path / 'Case'), 'Logged')
    try:
        evidence = case.add_evidence(str(copy))
        row = case.evidence()[0]
        assert (row['stored_md5'], row['stored_sha1']) == \
            (acquired['md5'], acquired['sha1'])
        assert row['stored_source'] == 'acquisition log exhibit.dd.txt'
        (outcome,) = case.verify_evidence()
        assert outcome[1] == STATUS_VERIFIED
        assert 'stored with the image' in outcome[2]

        _flip(copy, 1234567)
        (outcome,) = case.verify_evidence()
        assert outcome[1] == STATUS_CHANGED
        # Both references are named: the case's record and the log's.
        assert 'recorded by the case' in outcome[2]
        assert 'stored with the image' in outcome[2]

        # The examiner corrects nothing by typing: a bad value is refused,
        # and a change is audited with old and new.
        with pytest.raises(ValueError):
            case.set_acquisition_hashes(evidence, 'paperwork', md5='xyz')
        case.set_acquisition_hashes(evidence, 'custody form 12',
                                    sha256=acquired['sha256'])
        line = case.activity(1)[0]
        assert line['action'] == 'acquisition hashes set'
        assert acquired['sha256'] in line['detail']
    finally:
        case.close()


def test_a_log_that_disagrees_with_itself_names_no_hash(tmp_path):
    from trace_app.core import acquisition_log
    image = tmp_path / 'x.dd'
    image.write_bytes(b'\0' * 512)
    (tmp_path / 'x.dd.txt').write_text(
        " MD5 checksum:    " + 'a' * 32 + "\n"
        " MD5 checksum:    " + 'b' * 32 + "\n"
        " SHA1 checksum:   " + 'c' * 40 + "\n")
    hashes, log = acquisition_log.logged_hashes(str(image))
    assert hashes == {'sha1': 'c' * 40} and log.endswith('x.dd.txt')
    # dc3dd's form, and Guymager's.
    assert acquisition_log.read_hashes(
        "   " + 'd' * 32 + " (md5)\n") == {'md5': 'd' * 32}
    assert acquisition_log.read_hashes(
        "MD5 hash                   : " + 'e' * 32) == {'md5': 'e' * 32}


# --- the audit trail and history are append-only and chained ----------------

def test_the_audit_trail_shows_any_edit(tmp_path):
    from trace_app.core.case import Case
    folder = str(tmp_path / 'Case')
    case = Case.create(folder, 'Audit')
    try:
        for n in range(5):
            case.record_event('note', f"entry {n}")
        check = case.verify_audit()
        assert check['ok'] and check['entries'] == 6
        last = case.activity(1)[0]
        assert last['tool'].startswith('TRACE ') and '@' in last['account']
        # Through the case's own connection: refused.
        with pytest.raises(sqlite3.DatabaseError, match='append-only'):
            case._db.execute("UPDATE activity SET detail = 'x' WHERE id = 3")
        case._db.rollback()
        with pytest.raises(sqlite3.DatabaseError, match='append-only'):
            case._db.execute("DELETE FROM activity WHERE id = 3")
        case._db.rollback()
    finally:
        case.close()

    # By hand, with the triggers dropped: the chain shows it.
    raw = sqlite3.connect(os.path.join(folder, 'case.db'))
    raw.execute("DROP TRIGGER activity_no_update")
    raw.execute("UPDATE activity SET detail = 'entry 9' WHERE id = 3")
    raw.commit()
    raw.close()
    case = Case.open(folder)
    try:
        check = case.verify_audit()
        assert not check['ok']
        assert any('entry 3' in p and 'altered' in p
                   for p in check['problems'])
        # The trigger is back once the case is opened.
        with pytest.raises(sqlite3.DatabaseError, match='append-only'):
            case._db.execute("UPDATE activity SET detail = '' WHERE id = 2")
        case._db.rollback()
    finally:
        case.close()

    raw = sqlite3.connect(os.path.join(folder, 'case.db'))
    raw.execute("DROP TRIGGER activity_no_delete")
    raw.execute("DELETE FROM activity WHERE id = 5")
    raw.commit()
    raw.close()
    case = Case.open(folder)
    try:
        problems = case.verify_audit()['problems']
        assert any('entries 5 to 5 are missing' in p for p in problems)
        assert any('entry 6' in p and 'does not follow' in p
                   for p in problems)
    finally:
        case.close()


def test_removing_evidence_keeps_its_verification_history(tmp_path):
    from trace_app.core.case import Case
    image = tmp_path / 'small.dd'
    image.write_bytes(os.urandom(64 * 1024))
    case = Case.create(str(tmp_path / 'Case'), 'Removal')
    try:
        evidence = case.add_evidence(str(image))
        case.verify_evidence()
        case.verify_evidence()
        case.remove_evidence(evidence)
        rows = case._db.execute(
            "SELECT evidence_id, evidence_name, status FROM verifications"
        ).fetchall()
        assert [tuple(r) for r in rows] == [(None, 'small.dd', 'baseline'),
                                            (None, 'small.dd', 'verified')]
        assert case.verify_audit()['ok']
    finally:
        case.close()


def test_an_old_case_is_chained_and_says_so(tmp_path):
    """A case written before schema 18: its entries are chained when it
    is opened, the trail says which were chained late, and its history
    no longer cascades away with its evidence."""
    from trace_app.core.case import SCHEMA_VERSION, Case
    folder = str(tmp_path / 'Old')
    case = Case.create(folder, 'Old')
    case.record_event('note', 'before the chain')
    case.close()
    raw = sqlite3.connect(os.path.join(folder, 'case.db'))
    raw.executescript("""
        DROP TRIGGER activity_no_update; DROP TRIGGER activity_no_delete;
        DROP TRIGGER verifications_no_update;
        DROP TRIGGER verifications_no_delete;
        CREATE TABLE activity_old (id INTEGER PRIMARY KEY AUTOINCREMENT,
            utc TEXT NOT NULL, action TEXT NOT NULL, detail TEXT);
        INSERT INTO activity_old SELECT id, utc, action, detail
            FROM activity;
        DROP TABLE activity;
        ALTER TABLE activity_old RENAME TO activity;
        DROP TABLE verifications;
        CREATE TABLE verifications (id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
            utc TEXT NOT NULL, algorithm TEXT, expected TEXT,
            computed TEXT, status TEXT NOT NULL, detail TEXT);
        UPDATE case_info SET value = '17' WHERE key = 'schema_version';
    """)
    raw.commit()
    raw.close()
    case = Case.open(folder)
    try:
        assert int(case._get('schema_version')) == SCHEMA_VERSION
        check = case.verify_audit()
        assert check['ok'], check['problems']
        actions = [a['action'] for a in reversed(case.activity(20))]
        assert 'audit trail chained' in actions
        image = tmp_path / 'x.dd'
        image.write_bytes(b'\1' * 4096)
        evidence = case.add_evidence(str(image))
        case.verify_evidence()
        case.remove_evidence(evidence)
        assert case._db.execute(
            "SELECT COUNT(*) FROM verifications").fetchone()[0] == 1
    finally:
        case.close()


# --- exports ------------------------------------------------------------------

def _tsk_files(path):
    """{path: (inode, bytes)} of every allocated regular file, read with
    pytsk3 directly."""
    import pytsk3
    image = pytsk3.Img_Info(path)
    fs = pytsk3.FS_Info(image)
    found = {}

    def walk(directory, prefix):
        for entry in directory:
            name = entry.info.name.name.decode('utf-8', 'replace')
            meta = entry.info.meta
            # TSK's pseudo-entries (a FAT volume label, $OrphanFiles) are
            # not files on the volume.
            if name in ('.', '..') or meta is None or                     name.endswith('(Volume Label Entry)') or                     name.startswith('$'):
                continue
            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                if not name.startswith('$'):
                    walk(entry.as_directory(), f"{prefix}/{name}")
            elif meta.type == pytsk3.TSK_FS_META_TYPE_REG and \
                    int(meta.flags) & pytsk3.TSK_FS_META_FLAG_ALLOC:
                found[f"{prefix}/{name}"] = (
                    meta.addr, entry.read_random(0, meta.size)
                    if meta.size else b'')
    walk(fs.open_dir('/'), '')
    return found


@pytest.mark.images
def test_an_exported_folder_is_the_evidence_and_its_manifest_says_so(
        tmp_path):
    from trace_app.core.evidence_export import MANIFEST, Exporter
    from trace_app.core.image_handler import ImageHandler
    expected = _tsk_files(image_path(FAT))
    handler = ImageHandler(image_path(FAT))
    try:
        root = handler.get_root_inode(0)
        exporter = Exporter(handler, str(tmp_path / 'out'), FAT)
        exporter.export([{'start_offset': 0, 'inode_number': root,
                          'name': 'root', 'type': 'directory', 'path': ''}])
        manifest, digest = exporter.write_manifest()
        # Again into the same folder: nothing is overwritten.
        again = Exporter(handler, str(tmp_path / 'out'), FAT)
        again.export([{'start_offset': 0, 'inode_number': root,
                       'name': 'root', 'type': 'directory', 'path': ''}])
        second, _ = again.write_manifest()
    finally:
        handler.close_resources()
    assert os.path.basename(manifest) == MANIFEST
    assert os.path.basename(second) == 'export-manifest (2).csv'
    assert hashlib.sha256(open(manifest, 'rb').read()).hexdigest() == digest
    with open(manifest, newline='', encoding='utf-8') as handle:
        rows = {r['source_path']: r for r in csv.DictReader(handle)}
    for path, (_inode, content) in expected.items():
        row = rows[path]
        assert row['sha256'] == hashlib.sha256(content).hexdigest(), path
        assert row['md5'] == hashlib.md5(content).hexdigest(), path
        assert row['written_copy_check'] == 'matches'
        saved = tmp_path / 'out' / row['saved_as']
        assert saved.read_bytes() == content
        assert row['deleted'] == 'no' and not row['problem']
    # Deleted files are exported too, and marked.
    assert any(r['deleted'] == 'yes' for r in rows.values())
    empty = [p for p, (_i, c) in expected.items() if not c]
    for path in empty:
        assert (tmp_path / 'out' / rows[path]['saved_as']).exists()


@pytest.mark.images
def test_a_file_that_cannot_be_read_in_full_is_not_exported(tmp_path):
    """A real short read: the image copy is cut, so the last file's
    clusters are past its end. Nothing named as that file may be left."""
    from trace_app.core.evidence_export import Exporter
    from trace_app.core.image_handler import ImageHandler
    import pytsk3
    copy = tmp_path / 'cut.dd'
    shutil.copyfile(image_path(FAT), copy)
    fs = pytsk3.FS_Info(pytsk3.Img_Info(str(copy)))
    last = None
    for entry in fs.open_dir('/'):
        meta = entry.info.meta
        if meta is None or meta.type != pytsk3.TSK_FS_META_TYPE_REG or \
                not meta.size:
            continue
        for attribute in entry:
            for run in attribute:
                end = (run.addr + run.len) * fs.info.block_size
                if last is None or end > last[1]:
                    last = (entry.info.name.name.decode(), end, meta.addr,
                            run.addr * fs.info.block_size)
    name, _end, inode, begins = last
    del fs
    with open(copy, 'r+b') as handle:
        handle.truncate(begins + 512)
    handler = ImageHandler(str(copy))
    try:
        exporter = Exporter(handler, str(tmp_path / 'out'), 'cut.dd')
        exporter.export([{'start_offset': 0, 'inode_number': inode,
                          'name': name, 'type': 'file', 'path': '/' + name}])
    finally:
        handler.close_resources()
    (row,) = exporter.rows
    assert row['problem'].startswith('not exported') and not row['saved_as']
    assert not os.listdir(tmp_path / 'out')


def test_names_from_evidence_are_made_safe():
    from trace_app.core.evidence_export import safe_component, unique_path
    assert safe_component('..', 'inode-5') == 'inode-5'
    assert safe_component('a:b\\c/d', 'x') == 'a_b_c_d'
    assert safe_component('CON', 'x') == '_CON'
    assert safe_component('', 'inode-7') == 'inode-7'
    assert unique_path(os.path.dirname(__file__), 'conftest.py').endswith(
        'conftest (2).py')


def test_bytes_saved_from_a_viewer_are_checked_and_audited(tmp_path):
    from trace_app.core import evidence_export
    lines = []
    evidence_export.set_recorder(lambda action, detail:
                                 lines.append((action, detail)))
    try:
        data = os.urandom(300000)
        target = str(tmp_path / 'sel.bin')
        digests = evidence_export.save_bytes(target, data,
                                             'byte range exported', 'x.dd')
    finally:
        evidence_export.set_recorder(None)
    assert open(target, 'rb').read() == data
    assert digests['sha256'] == hashlib.sha256(data).hexdigest()
    assert digests['written_copy_check'] == 'matches'
    assert lines[0][0] == 'byte range exported'
    assert digests['sha256'] in lines[0][1]


# --- work product and the report --------------------------------------------

def test_a_note_edited_or_removed_keeps_its_words_in_the_audit(tmp_path):
    from trace_app.core.case import Case
    case = Case.create(str(tmp_path / 'Case'), 'Notes')
    try:
        note = case.add_note('Suspect copied payroll.xlsx at 14:02')
        case.update_note(note, 'Suspect copied payroll.xlsx at 14:20')
        case.remove_note(note)
        lines = {a['action']: a['detail'] for a in case.activity(10)}
        assert 'at 14:02' in lines['note added']
        assert 'at 14:02' in lines['note edited'] and \
            'at 14:20' in lines['note edited']
        assert 'at 14:20' in lines['note removed']
        assert case.verify_audit()['ok']
    finally:
        case.close()


def test_the_report_states_what_verification_found(tmp_path):
    from trace_app.core import report
    from trace_app.core.case import Case
    image = tmp_path / 'exhibit.dd'
    image.write_bytes(os.urandom(256 * 1024))
    case = Case.create(str(tmp_path / 'Case'), 'Report')
    try:
        case.add_evidence(str(image))
        case.verify_evidence()
        _flip(image, 1000)
        case.verify_evidence()
        options = report.default_options(case)
        for section in options['sections']:
            section['enabled'] = section['key'] in ('evidence', 'audit',
                                                    'methods')
        html, _builder, _body = report.build_html(case, options)
        assert 'did not verify' in html and 'CHANGED' in html
        head = case.verify_audit()['head']
        assert 'hash chain was checked' in html and head in html
        assert 'Recorded hashes are never replaced' in html
    finally:
        case.close()


@pytest.mark.images
@pytest.mark.ui
def test_quick_triage_verifies_without_recording(qapp, quiet_dialogs):
    """No case: the same job and verdict -- the E01 against the MD5 it
    stores -- shown, and nothing written anywhere."""
    from trace_app.core.case import STATUS_VERIFIED
    from trace_app.ui.main_window import MainWindow
    window = MainWindow()
    try:
        path = image_path(E01)
        assert window.open_evidence_image(path)
        window.verify_image(path)
        assert pump(qapp, 120, lambda: window.verification_state(path)
                    == STATUS_VERIFIED and not window.job_bar.busy)
        text = window.verification_dialog.text()
        assert 'MD5 | ' in text and '| match' in text
        assert window.case is None
    finally:
        window.cleanup_resources()
