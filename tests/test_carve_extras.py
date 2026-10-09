"""SQLite write-ahead logs carved and paired with their databases, and the
analysis of carved files.

The databases are written here by Python's sqlite3 in WAL mode, so the
-wal files are SQLite's own: messages committed after the last checkpoint
exist only in the WAL. Laid into a raw image with a decoy database of the
same page size and a stale WAL, the carver must take each WAL to exactly
its last valid frame, pair it with the one database it replays onto, and
the activity reader must then show the messages only the WAL held.
"""

import os
import shutil
import sqlite3

import pytest
from tools import testdata

SECTOR = 512


def _wal_database(folder, name, schema, rows):
    """(database bytes, wal bytes) of a WAL-mode database whose `rows`
    were committed after its last checkpoint."""
    path = os.path.join(folder, name)
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA wal_autocheckpoint=0")
    db.executescript(schema)
    db.commit()
    db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    for statement, values in rows:
        db.execute(statement, values)
    db.commit()
    with open(path, 'rb') as handle:
        database = handle.read()
    with open(path + '-wal', 'rb') as handle:
        wal = handle.read()
    db.close()
    return database, wal


IMESSAGE = """
    CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);
    CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, guid TEXT);
    CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT,
        date INTEGER, date_read INTEGER, is_from_me INTEGER,
        service TEXT, handle_id INTEGER, is_read INTEGER, account TEXT);
    INSERT INTO handle VALUES (1, '+447700900123');
    INSERT INTO message VALUES (1, 'checkpointed long ago', 600000000,
        0, 0, 'SMS', 1, 1, NULL);
"""
ONLY_IN_WAL = [
    ("INSERT INTO message VALUES (?,?,?,?,?,?,?,?,?)",
     (2, 'meet at the north gate', 700000000, 0, 1, 'iMessage', 1, 1,
      None)),
    ("INSERT INTO message VALUES (?,?,?,?,?,?,?,?,?)",
     (3, 'bring the second key', 700000100, 0, 0, 'iMessage', 1, 1, None)),
]
DECOY = """
    CREATE TABLE bookmarks (id INTEGER PRIMARY KEY, url TEXT, title TEXT);
    INSERT INTO bookmarks VALUES (1, 'https://example.org/', 'Example');
"""


def _place(image, at, data):
    image[at:at + len(data)] = data
    return at


def make_image(tmp_path):
    """A raw image: [database] [wal] [decoy] [decoy's wal, damaged]."""
    folder = str(tmp_path / 'build')
    os.makedirs(folder)
    database, wal = _wal_database(folder, 'sms.db', IMESSAGE, ONLY_IN_WAL)
    decoy, decoy_wal = _wal_database(folder, 'bookmarks.db', DECOY, [
        ("INSERT INTO bookmarks VALUES (?,?,?)",
         (2, 'https://example.net/', 'Net'))])
    # A torn write: the decoy WAL's second frame is overwritten, so only
    # the header and first frame are proven.
    page = int.from_bytes(decoy_wal[8:12], 'big')
    damaged = bytearray(decoy_wal)
    second = 32 + (24 + page)
    damaged[second + 30:second + 60] = b'\xAA' * 30
    image = bytearray(4 * 1024 * 1024)
    where = {}
    where['database'] = _place(image, 64 * SECTOR, database)
    where['wal'] = _place(image, 1024 * SECTOR, wal)
    where['decoy'] = _place(image, 2048 * SECTOR, decoy)
    where['decoy_wal'] = _place(image, 3072 * SECTOR, bytes(damaged))
    path = str(tmp_path / 'phone.dd')
    with open(path, 'wb') as handle:
        handle.write(image)
    shutil.rmtree(folder)
    return path, where, database, wal, page


@pytest.fixture
def carved(tmp_path):
    from trace_app.core import carving
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    path, where, database, wal, page = make_image(tmp_path)
    case = Case.create(str(tmp_path / 'case'), 'WAL')
    evidence = case.add_evidence(path)
    handler = ImageHandler(path)
    carving.carve_evidence(handler, case, evidence, ['sqlite', 'wal'],
                           unallocated_only=False)
    yield case, evidence, handler, where, database, wal, page
    case.close()


def test_a_wal_is_carved_to_its_last_proven_frame(carved):
    case, evidence, _handler, where, _database, wal, page = carved
    wals = {int(r['offset']): r for r in case.carved_files(evidence, 'wal')}
    assert set(wals) == {where['wal'], where['decoy_wal']}
    whole = wals[where['wal']]
    assert int(whole['size']) == len(wal)
    assert whole['status'] == 'complete'
    # The torn one ends where its checksum chain breaks: header + 1 frame.
    torn = wals[where['decoy_wal']]
    assert int(torn['size']) == 32 + 24 + page
    assert torn['status'] == 'complete'


def test_each_wal_is_paired_with_the_database_it_replays_onto(carved):
    case, evidence, _handler, where, *_rest = carved
    rows = {int(r['offset']): r for r in case.carved_files(evidence)}
    assert rows[where['wal']]['related']['offset'] == where['database']
    assert rows[where['database']]['related']['wal'] == \
        rows[where['wal']]['name']
    assert 'integrity_check' in rows[where['wal']]['related']['basis']
    # The decoy database has the same page size, but the sms WAL rewrites
    # it into something else: it is not taken. Its own torn WAL holds a
    # committed frame and pairs with it.
    assert rows[where['decoy_wal']]['related']['offset'] == where['decoy']
    audit = [a for a in case.activity() if a['action'] ==
             'carving statistics']
    assert 'wal pairs=2' in audit[0]['detail']


def test_messages_only_in_the_wal_are_read(carved):
    from trace_app.core import activity
    case, evidence, handler, *_rest = carved
    activity.run_evidence(handler, case, evidence)
    texts = {r['subject'] for r in case.user_activity(evidence)
             if r['source'].startswith('iMessage')}
    assert {'checkpointed long ago', 'meet at the north gate',
            'bring the second key'} <= texts


def test_without_its_wal_the_database_lacks_them(carved):
    """The point of pairing: the carved database alone does not have the
    messages committed after its last checkpoint."""
    from trace_app.core.activity import chat
    _case, _evidence, _handler, _where, database, _wal, _page = carved
    texts = {r['subject'] for r in chat.read_database(database, None, '',
                                                      'x', 'r')}
    assert 'checkpointed long ago' in texts
    assert 'meet at the north gate' not in texts


def test_an_ambiguous_wal_is_not_paired(tmp_path):
    """Two copies of one database: the WAL replays onto both, so neither
    is chosen."""
    from trace_app.core.carving import pair_wal
    database, wal = _wal_database(str(tmp_path), 'a.db', IMESSAGE,
                                  ONLY_IN_WAL)
    found = pair_wal(wal, [('first', database), ('second', database)])
    assert found['ambiguous'] == ['first', 'second']
    assert pair_wal(wal, [('only', database)])['database'] == 'only'
    assert pair_wal(b'\0' * 64, [('only', database)]) is None


def test_carved_files_are_analysed(tmp_path):
    """Every carve goes through the file analysis: a carved executable is a
    finding, entropy is measured, and re-running the file analysis keeps
    them while a new carve replaces them."""
    from trace_app.core import analysis, carving
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    from tests.conftest import ROOT
    exe = os.path.join(testdata.SAMPLES,
                       'pageant-w32.exe')
    if not os.path.exists(exe):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail("pageant-w32.exe missing")
        pytest.skip("run python -m tools.testdata.fetch --group samples")
    with open(exe, 'rb') as handle:
        program = handle.read()
    image = bytearray(4 * 1024 * 1024)
    image[8 * SECTOR:8 * SECTOR + len(program)] = program
    path = str(tmp_path / 'disk.dd')
    with open(path, 'wb') as handle:
        handle.write(image)
    case = Case.create(str(tmp_path / 'case'), 'Analysed')
    try:
        evidence = case.add_evidence(path)
        handler = ImageHandler(path)
        carving.carve_evidence(handler, case, evidence, ['exe'],
                               unallocated_only=False)
        [carve] = case.carved_files(evidence)
        [row] = case.findings(evidence, 'executables')
        assert row['artifact_ref'] == carve['artifact_ref']
        assert row['path'] == f"[carved]/{carve['name']}"
        assert 'Simon Tatham' in row['summary']
        stored = case._db.execute(
            "SELECT entropy, sha256 FROM file_analysis WHERE "
            "artifact_ref = ?", (carve['artifact_ref'],)).fetchone()
        assert stored[0] is not None and stored[1] == carve['sha256']
        # The file analysis owns only what it walks.
        case.clear_analysis(evidence)
        assert case.findings(evidence, 'executables')
        # A new carve replaces the carve's analysis.
        case.clear_carved(evidence)
        assert not case.findings(evidence, 'executables')
        assert analysis.MODULE_EXECUTABLES in analysis.MODULES
    finally:
        case.close()


# --- names of the written copies ---------------------------------------------------------

def test_names_keep_the_offset_and_say_what_the_file_was():
    from trace_app.core.carving import carved_name, safe_name
    assert carved_name(0x1A2B000, 'pdf', {'name': 'report.pdf'}) == \
        '1a2b000-report.pdf'
    # The file system's name, and the type the bytes are.
    assert carved_name(0x1A2B000, 'jpg', {'name': 'notes.txt'}) == \
        '1a2b000-notes.txt.jpg'
    assert carved_name(0x1A2B000, 'jpg', {'name': 'IMG_4821.JPEG'}) == \
        '1a2b000-IMG_4821.JPEG'
    # A slack carve's origin is the live file it sat behind, not its name.
    assert carved_name(0x10, 'pdf', {'path': '/live.txt',
                                     'basis': 'found in the slack'}) == \
        '10.pdf'
    assert carved_name(0x10, 'pdf') == '10.pdf'
    assert safe_name('CON.txt') == '_CON.txt'
    assert safe_name(r'a/b\c:d*?.doc. ') == 'a_b_c_d_.doc'
    long = safe_name('x' * 200 + '.docx')
    assert len(long) == 80 and long.endswith('.docx')


def test_a_document_is_named_by_its_title_labelled_as_such():
    import pymupdf
    from trace_app.core.carving import carved_name
    document = pymupdf.open()
    document.new_page()
    document.set_metadata({'title': 'Quarterly: Report / Q3?'})
    assert carved_name(0x2000, 'pdf', None, document.tobytes()) == \
        '2000-[title] Quarterly_ Report _ Q3_.pdf'


def test_deleted_entries_name_the_copies(tmp_path):
    """DFTT #8: both deleted JPEGs carved from free space, each written
    under the name its deleted entry still gives -- file7.hmm is the
    image's disguised JPEG, judged under that name."""
    from tests.conftest import image_path
    from trace_app.core import carving
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    path = image_path('8-jpeg-search.dd')
    case = Case.create(str(tmp_path / 'case'), 'Names')
    try:
        evidence = case.add_evidence(path)
        carving.carve_evidence(ImageHandler(path), case, evidence, ['jpg'])
        rows = case.carved_files(evidence)
        assert sorted(r['name'] for r in rows) == [
            '85400-file7.hmm.jpg', 'd5200-file6.jpg']
        assert all(r['path'] == '' for r in rows)    # references only
        judged = dict(case._db.execute(
            "SELECT name, extension FROM file_analysis").fetchall())
        assert judged['85400-file7.hmm.jpg'] == 'hmm'
    finally:
        case.close()


# --- the statistics view -------------------------------------------------------------------

def test_statistics_show_what_the_run_recorded(qapp, carved):
    from trace_app.ui.viewers.carved_panel import CarvedFilesPanel
    from trace_app.ui.viewers.carving_stats import bar, run_rows, type_rows
    case, evidence, *_rest = carved
    [run] = case.carving_runs(evidence)
    summary = dict((k, v) for k, v in run_rows(run, 'phone.dd') if k)
    assert summary['WAL files paired with a database'] == '2'
    assert summary['Kept'] == '4'
    assert summary['Complete'] == '4'
    assert summary['Source'] == 'Whole image'
    types = {kind: (checked, rejected, kept)
             for kind, checked, rejected, kept in type_rows(run)}
    assert types['wal'][2] == 2 and types['sqlite'][2] == 2
    assert types['wal'][0] >= types['wal'][2]
    assert bar(0.5).startswith('█' * 10 + '░' * 10)
    panel = CarvedFilesPanel()
    panel.set_case(case)
    panel.set_view('statistics', remember=False)
    assert panel.stack.currentWidget() is panel.stats_view
    view = panel.stats_view
    assert view.run_combo.count() == 1
    assert view.types.rowCount() == len(types)
    table = view.summary
    shown = {table.item(r, 0).text(): table.item(r, 1).text()
             for r in range(table.rowCount()) if table.item(r, 1)}
    assert shown['WAL files paired with a database'] == '2'


def test_a_flood_of_carves_is_drawn_in_batches(qapp):
    """Each carve used to re-sort the whole table and re-count the status
    line as it arrived: quadratic on the UI thread, minutes of frozen
    window for a few thousand carves (6,000 took 11.8 s; 30,000 now take
    4.5 s). Carves arriving together are drawn together."""
    from tests.conftest import pump
    from trace_app.ui.viewers.carved_panel import CarvedFilesPanel
    panel = CarvedFilesPanel()
    statuses = []
    original = panel._update_status
    panel._update_status = lambda: (statuses.append(1), original())[1]
    for i in range(3000):
        panel.add_record({'name': f'{i:08x}.gz', 'type': 'gz',
                          'status': 'valid', 'size': 1000 + i,
                          'offset': i * 4096, 'sha256': f'{i:064x}',
                          'evidence_key': 'img', 'path': ''})
    assert panel.count == 3000                # counted at once
    assert pump(qapp, 10, lambda: panel.table.rowCount() == 3000)
    assert len(statuses) <= 3                 # one per batch, not per row
    assert '3,000 file(s) recovered' in panel.status_label.text()
