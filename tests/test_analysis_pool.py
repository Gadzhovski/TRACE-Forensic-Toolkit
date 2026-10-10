"""The analysis on several processes (core/analysis.py `workers`) writes
exactly the rows one process writes, in the same order -- whichever worker
finished first."""

import pytest

from tests.conftest import image_path


def _rows(case, evidence_id):
    """Both tables' rows in the order written, without row ids and the
    times they were written at."""
    out = []
    for table in ('file_analysis', 'file_findings'):
        cursor = case._db.execute(
            f"SELECT * FROM {table} WHERE evidence_id = ? ORDER BY rowid",
            (evidence_id,))
        columns = [d[0] for d in cursor.description]
        out.append([tuple(v for c, v in zip(columns, row)
                          if c != 'id' and not c.endswith('_utc'))
                    for row in cursor])
    return out


def _analyse(tmp_path, name, image, workers):
    from trace_app.core.analysis import MODULES, analyse_evidence
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    folder = str(tmp_path / f"{name}-{workers}")
    case = Case.create(folder, name)
    handler = ImageHandler(image)
    assert handler.load_image()
    try:
        evidence_id = case.add_evidence(image)
        seen = []
        done = analyse_evidence(
            handler, case, evidence_id, MODULES, workers=workers,
            image_path=image, case_folder=folder,
            progress=lambda d, t, p: seen.append((d, t)))
        state = case.analysis_state(evidence_id)
        return done, seen, state, _rows(case, evidence_id)
    finally:
        handler.close_resources()
        case.close()


@pytest.mark.parametrize('name', ['ntfs1-gen2.E01', '8-jpeg-search.dd'])
def test_a_pool_writes_what_one_process_writes(tmp_path, monkeypatch, name):
    from trace_app.core import analysis
    image = image_path(name)
    # Small pieces, and a pool for any number of files: many pieces in
    # flight, finishing out of order.
    monkeypatch.setattr(analysis, 'MIN_POOL_FILES', 0)
    monkeypatch.setattr(analysis, 'CHUNK_FILES', 3)
    one = _analyse(tmp_path, 'one', image, 1)
    many = _analyse(tmp_path, 'many', image, 3)
    assert one[0] == many[0] > 0
    assert one[2]['status'] == many[2]['status'] == 'done'
    assert one[3][0] == many[3][0]            # file_analysis, row for row
    assert one[3][1] == many[3][1]            # file_findings
    # Progress reaches the total and never goes back.
    done = [d for d, _t in many[1]]
    assert done == sorted(done) and done[-1] == many[1][-1][1] == many[0]


def test_a_cancelled_pool_keeps_what_it_wrote(tmp_path, monkeypatch):
    from trace_app.core import analysis
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    image = image_path('ntfs1-gen2.E01')
    monkeypatch.setattr(analysis, 'MIN_POOL_FILES', 0)
    monkeypatch.setattr(analysis, 'CHUNK_FILES', 2)
    folder = str(tmp_path / 'cancel')
    case = Case.create(folder, 'cancel')
    handler = ImageHandler(image)
    assert handler.load_image()
    try:
        evidence_id = case.add_evidence(image)
        seen = []
        done = analysis.analyse_evidence(
            handler, case, evidence_id, analysis.MODULES, workers=2,
            image_path=image, case_folder=folder,
            progress=lambda d, t, p: seen.append(d),
            should_stop=lambda: len(seen) >= 3)
        state = case.analysis_state(evidence_id)
        assert state['status'] == 'cancelled'
        assert done == state['files_done'] == seen[-1]
        written = case._db.execute(
            "SELECT COUNT(*) FROM file_analysis WHERE evidence_id = ?",
            (evidence_id,)).fetchone()[0]
        assert 0 < written <= done
    finally:
        handler.close_resources()
        case.close()


def test_small_runs_and_logical_evidence_stay_in_one_process():
    from trace_app.core import analysis

    class Handler:
        def __init__(self, kind):
            self.kind = kind

        def get_image_type(self):
            return self.kind

    many = analysis.MIN_POOL_FILES * 10
    assert analysis._pool_size(4, many, Handler('raw'), 'x.dd') == 4
    assert analysis._pool_size(4, 10, Handler('raw'), 'x.dd') == 1
    assert analysis._pool_size(1, many, Handler('raw'), 'x.dd') == 1
    assert analysis._pool_size(4, many, Handler('logical'), 'x') == 1
    assert analysis._pool_size(4, many, Handler('raw'), None) == 1
    assert analysis._pool_size(4, many, Handler('raw'),
                               r'\\.\PhysicalDrive0') == 1
