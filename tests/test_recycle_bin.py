"""The Recycle Bin and Deleted Files, linked.

NIST's dfr-01-recycle-ntfs.dd holds a file deleted through the Recycle
Bin and the bin then emptied: its $I record (resident in its MFT entry)
and $R content are both deleted entries. The activity reader used to list
only live $I files, so this deletion was not shown at all. Now:

* Activity has the record: what was deleted, when, by whom, and that the
  bin was emptied;
* its content links to the Deleted Files row of the $R file and its state;
* Deleted Files shows the $R and $I rows under the name they had.
"""

import os

import pytest

from tests.conftest import ROOT

IMAGE = os.path.join(ROOT, 'test_images', 'dfr-01-recycle-ntfs.dd')
SID = 'S-1-5-21-1906619128-910460487-204217675-1003'
BIN = f'/$RECYCLE.BIN/{SID}'


@pytest.fixture(scope='module')
def case(tmp_path_factory):
    if not os.path.exists(IMAGE):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail("dfr-01-recycle-ntfs.dd missing")
        pytest.skip("run tools/fetch_test_images.py")
    from trace_app.core import activity, deleted
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    case = Case.create(str(tmp_path_factory.mktemp('recycle') / 'case'),
                       'Recycle')
    evidence = case.add_evidence(IMAGE)
    handler = ImageHandler(IMAGE)
    activity.run_evidence(handler, case, evidence)
    deleted.analyse_evidence(handler, case, evidence)
    yield case, evidence, handler
    case.close()


def test_an_emptied_bin_still_says_what_was_deleted(case):
    case, evidence, _handler = case
    [row] = case.user_activity(evidence, 'recycle')
    assert row['subject'] == 'F:\\Bunda.txt'
    assert row['time_utc'] == '2012-03-28 19:03:58'
    assert row['user'] == SID
    assert row['source_path'] == f'{BIN}/$I019S2V.txt'
    detail = row['detail']
    assert detail['size'] == 4296
    assert detail['record'] == 'deleted -- the bin was emptied'
    assert detail['content file'] == f'{BIN}/$R019S2V.txt'
    assert detail['content still present'].startswith('deleted from the bin')
    # Linked to the content's Deleted Files row and its state.
    content = row['recycle_content']
    assert content['path'] == f'{BIN}/$R019S2V.txt'
    assert content['state'] == 'recoverable' and content['size'] == 4296
    assert detail['in Deleted Files'] == 'recoverable'


def test_the_content_reads_back_whole(case):
    """The $R file, read as Deleted Files previews it, is the 4,296 bytes
    the $I record says the file had."""
    case, evidence, handler = case
    content = case.user_activity(evidence, 'recycle')[0]['recycle_content']
    from trace_app.core.case import parse_artifact_ref
    ref = parse_artifact_ref(content['artifact_ref'])
    data, _meta = handler.get_file_content(ref['inode'], ref['start_offset'])
    assert len(data) == 4296 and data.strip(b'\0')


def test_deleted_files_name_the_original(qapp, case):
    case, evidence, _handler = case
    origins = case.recycle_origins(evidence)
    volume = case.user_activity(evidence, 'recycle')[0]['source_ref'] \
        .split(':', 1)[0] + ':'
    assert origins[(evidence, volume, f'{BIN}/$R019S2V.txt'.lower())][
        'original'] == 'F:\\Bunda.txt'
    assert origins[(evidence, volume, f'{BIN}/$I019S2V.txt'.lower())][
        'part'] == '$I record'
    from PySide6.QtCore import Qt
    from trace_app.ui.viewers.deleted_panel import DeletedFilesPanel
    panel = DeletedFilesPanel()
    panel.set_case(case)
    names = {panel.table.item(r, 0).text(): panel.table.item(r, 0)
             for r in range(panel.table.rowCount())}
    assert '$R019S2V.txt — was F:\\Bunda.txt' in names
    assert '$I019S2V.txt — was F:\\Bunda.txt' in names
    assert 'emptied' in names['$R019S2V.txt — was F:\\Bunda.txt'].toolTip()
    content = case.user_activity(evidence, 'recycle')[0]['recycle_content']
    # "Show Content in Deleted Files" lands on the row, past a state filter
    # that hides it.
    panel.state_combo.setCurrentIndex(panel.state_combo.findData(
        'overwritten'))
    assert panel.select(evidence, content['artifact_ref'])
    row = panel.table.item(panel.table.currentRow(), 0).data(Qt.UserRole)
    assert row['artifact_ref'] == content['artifact_ref']


def test_a_click_previews_the_content_not_the_record(case):
    """The window previews a Recycle Bin row's deleted content when it is
    known, and the $I record otherwise."""
    from trace_app.ui.main_window import MainWindow
    case, evidence, _handler = case
    row = case.user_activity(evidence, 'recycle')[0]
    shown = []

    class Window:
        preview_artifact = shown.append
        _activity_source = staticmethod(MainWindow._activity_source)

    MainWindow.preview_activity_source(Window(), row)
    assert shown[-1]['artifact_ref'] == row['recycle_content']['artifact_ref']
    assert shown[-1]['artifact_name'] == '$R019S2V.txt'
    row.pop('recycle_content')
    MainWindow.preview_activity_source(Window(), row)
    assert shown[-1]['artifact_ref'] == row['source_ref']
