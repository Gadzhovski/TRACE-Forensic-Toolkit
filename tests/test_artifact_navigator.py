"""The Artifacts navigator and the Case Overview, without evidence: the
taxonomy covers every view that lists artifacts, the states follow the
scans' records, and the widgets show what they are given.

The same views on a real two-image case (counts equal the tabs', clicks
open the right panel) are in tests/test_ui.py, beside its window."""

import pytest

from tests.conftest import pump

pytestmark = pytest.mark.ui


def test_every_activity_category_has_an_entry():
    from trace_app.core import artifact_catalogue as catalogue
    from trace_app.core.activity import CATEGORIES
    keys = {e.key for e in catalogue.entries()}
    missing = [c for c, _label in CATEGORIES if f'activity:{c}' not in keys]
    assert not missing


def test_entries_are_unique_and_open_something():
    from trace_app.core import artifact_catalogue as catalogue
    from trace_app.ui import icons
    keys = [e.key for e in catalogue.entries()]
    assert len(keys) == len(set(keys))
    for entry in catalogue.entries():
        kind = entry.opens[0]
        assert kind in ('triage', 'activity', 'panel'), entry.key
        if kind == 'panel':
            assert entry.opens[1] in ('registry', 'listing', 'timeline',
                                      'search', 'notes'), entry.key
        if not entry.icon.startswith('activity:'):
            assert hasattr(icons, entry.icon), entry.key


def test_states_follow_the_scans(tmp_path):
    from trace_app.core import artifact_catalogue as catalogue
    from trace_app.core import export_readiness as readiness
    from trace_app.core.case import Case
    case = Case.create(str(tmp_path / 'case'), 'States')
    try:
        evidence = case.add_evidence(__file__)
        found = catalogue.counts(case)
        states = catalogue.states(case, [evidence], found)
        # Nothing has run: every counted entry with a scan is waiting.
        assert states['photos'] == catalogue.NOT_RUN
        assert states['activity:browser'] == catalogue.NOT_RUN
        # Whole views are always offered; the examiner's own never "not run".
        assert states['listing'] == catalogue.FOUND
        assert states['bookmarks'] == catalogue.NONE_FOUND
        # A module that cannot find anything here: not applicable.
        ruled = {evidence: {readiness.ACTIVITY: 'no system'}}
        states = catalogue.states(case, [evidence], found, None, ruled)
        assert states['activity:browser'] == catalogue.NOT_APPLICABLE
        missing = catalogue.missing_modules(states, [evidence], case, None,
                                            ruled)
        assert readiness.ACTIVITY not in missing.get(evidence, [])
    finally:
        case.close()


def test_the_navigator_shows_counts_and_hides_the_empty(qapp):
    from trace_app.core import artifact_catalogue as catalogue
    from trace_app.ui.widgets.artifact_navigator import ArtifactNavigator
    navigator = ArtifactNavigator()
    navigator.show_empty = False
    found = {e.key: 0 for e in catalogue.entries()}
    found.update(photos=12, deleted=3)
    for key in catalogue.UNCOUNTED:
        found[key] = None
    states = {e.key: catalogue.NONE_FOUND for e in catalogue.entries()}
    states.update(photos=catalogue.FOUND, deleted=catalogue.FOUND,
                  yara=catalogue.NOT_RUN,
                  **{'activity:usb': catalogue.NOT_APPLICABLE})
    navigator.set_data(found, states)
    assert navigator.counts_text('photos') == '12'
    assert navigator._item_for('photos') is not None
    assert navigator._item_for('yara') is not None          # not run: shown
    assert navigator.waiting() == ['yara']
    assert navigator._item_for('activity:usb') is None      # never shown
    assert navigator._item_for('activity:browser') is None  # none found
    navigator.show_empty = True
    navigator._build()
    assert navigator._item_for('activity:browser') is not None
    assert navigator._item_for('activity:usb') is None
    opened = []
    navigator.open_requested.connect(lambda key, eid: opened.append(key))
    navigator._clicked(navigator._item_for('photos'))
    assert opened == ['photos']
    navigator.deleteLater()


def test_the_overview_links_and_lists_what_has_not_run(qapp):
    from PySide6.QtWidgets import QLabel
    from trace_app.core import artifact_catalogue as catalogue
    from trace_app.ui.viewers.case_overview import CaseOverview
    overview = CaseOverview()
    found = {e.key: 0 for e in catalogue.entries()}
    found.update(photos=12, hidden=4)
    states = {e.key: catalogue.NONE_FOUND for e in catalogue.entries()}
    states.update(photos=catalogue.FOUND, hidden=catalogue.FOUND,
                  sigma=catalogue.NOT_RUN)
    overview.show_data({
        'case': {'name': 'Overview', 'number': '7', 'examiner': 'E'},
        'evidence': [{'name': 'disk.E01', 'system': 'Windows 10',
                      'logo': '', 'kind': 'Disk image', 'size': '1 GB',
                      'status': None}],
        'found': found, 'states': states,
        'stopped': [('disk.E01', 24753, 1046946)],
        'span': ('2020-01-01 10:00:00', '2021-02-03 11:00:00')})
    texts = [label.text() for label in overview.findChildren(QLabel)]
    assert any('stopped at 24,753 of 1,046,946 files (2%)' in t
               for t in texts)
    assert any("href='hidden'" in t for t in texts)          # worth a look
    assert any(t == 'Sigma detections' for t in texts)        # not run
    assert any('2020-01-01 → 2021-02-03' in t for t in texts)
    asked = []
    overview.run_missing_requested.connect(lambda: asked.append(1))
    overview.run_button.click()
    pump(qapp, 0.05)
    assert asked == [1]
    overview.deleteLater()


def test_a_closed_case_is_never_counted(qapp, tmp_path, monkeypatch):
    """TRACE closed as carving was cancelled: the recount timer fired and
    a count already reading came back after the case was closed, and both
    raised ('NoneType' object has no attribute 'execute')."""
    import sys
    from tests.conftest import close_window
    from trace_app.core.case import Case
    from trace_app.ui.main_window import MainWindow
    raised = []
    monkeypatch.setattr(sys, 'excepthook',
                        lambda *info: raised.append(info))
    window = MainWindow(case=Case.create(str(tmp_path / 'case'), 'Closing'))
    try:
        pump(qapp, 0.5)
        window._schedule_artifacts()
        generation = getattr(window, '_artifacts_generation', 0)
        window.case.close()
        pump(qapp, 1.0)                     # past the recount's debounce
        window.refresh_artifacts()
        window._artifacts_read(generation, {'found': {}, 'states': {},
                                            'stopped': [], 'span': None})
        assert raised == []
    finally:
        window.case = None                  # closed above, as cleanup would
        close_window(window)
    assert raised == []
