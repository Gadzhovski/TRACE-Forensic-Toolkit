"""The main window's layout: the Listing fill, the dockable panels and
Triage's grouped tabs."""

import pytest

from tests.conftest import close_window, image_path, pump


def _entries(prefix, count):
    return [{'name': f'{prefix}{number:04d}.txt', 'inode_number': number + 100,
             'is_directory': False, 'size': number, 'type': 'file',
             'created': 'N/A', 'accessed': 'N/A', 'modified': 'N/A',
             'changed': 'N/A', 'is_deleted': False}
            for number in range(count)]


@pytest.fixture
def window(qapp, monkeypatch):
    from trace_app.ui.dialogs import message
    from trace_app.ui.main_window import MainWindow
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name, lambda *a, **k: None)
    window = MainWindow()
    yield window
    close_window(window)


def test_a_listing_interrupted_by_another_holds_only_the_second(qapp,
                                                                window):
    """A large folder is listed in batches, yielding to the event loop; a
    click on another folder meanwhile used to leave both folders' rows in
    the table."""
    from PySide6.QtCore import QTimer
    # Rows are drawn for an image (its inode labels): any small one.
    assert window.open_evidence_image(image_path('8-jpeg-search.dd'))
    first, second = _entries('first-', 1000), _entries('second-', 30)
    QTimer.singleShot(0, lambda: window.populate_listing_table(second, 0))
    window.populate_listing_table(first, 0)
    pump(qapp, 0.1)
    names = {window.listing_table.item(r, 0).text()
             for r in range(window.listing_table.rowCount())}
    assert names == {e['name'] for e in second}
    # An uninterrupted fill lists every entry.
    window.populate_listing_table(first, 0)
    assert window.listing_table.rowCount() == len(first)


# -- the result panels are docks ------------------------------------------

def _shown(qapp, window):
    window.resize(1400, 900)
    window.show()
    pump(qapp, 0.3)
    window._apply_default_layout()
    pump(qapp, 0.3)


def _panels(window):
    return [window.listing_widget, window.registry_extractor_widget,
            window.search_panel, window.triage_panel, window.activity_panel,
            window.modules_panel, window.timeline_panel]


def _rect(window, widget):
    """`widget`'s geometry in the window's coordinates (result panels are
    docks of the inner `result_area`)."""
    from PySide6.QtCore import QPoint, QRect
    return QRect(widget.mapTo(window, QPoint(0, 0)), widget.size())


def test_every_result_panel_is_a_dock(window):
    from PySide6.QtWidgets import QDockWidget, QMenu
    docks = window.result_viewer.docks()
    assert [window.result_viewer.panel(d) for d in docks] == _panels(window)
    assert [d.windowTitle() for d in docks] == [
        'Listing', 'Registry', 'Search', 'Triage', 'Activity', 'Modules',
        'Timeline']
    names = {d.objectName() for d in docks}
    assert len(names) == len(docks) and all(names)
    for dock in docks:
        assert dock.parent() is window.result_area
        assert dock.features() & QDockWidget.DockWidgetMovable
        assert dock.features() & QDockWidget.DockWidgetFloatable
        assert dock.features() & QDockWidget.DockWidgetClosable
    # The middle of the window is theirs; the tree and Utils are the
    # window's own docks around it.
    assert window.centralWidget() is window.result_area
    assert window.tree_dock.parent() is window
    assert window.viewer_dock.parent() is window
    # View > Panels reopens any of them.
    panels = next(m for m in window._view_menu.findChildren(QMenu)
                  if m.title() == 'Panels')
    texts = [a.text() for a in panels.actions()]
    for dock in docks:
        assert dock.windowTitle() in texts
    assert 'Tree View' in texts and 'Utils Panel' in texts


def test_bringing_a_panel_forward_raises_its_dock(qapp, window):
    _shown(qapp, window)
    tabs = window.result_viewer
    assert tabs.currentWidget() is window.listing_widget
    changed = []
    tabs.currentChanged.connect(changed.append)
    tabs.setCurrentWidget(window.timeline_panel)
    pump(qapp, 0.2)
    timeline = tabs.dock(window.timeline_panel)
    assert tabs.currentWidget() is window.timeline_panel
    assert tabs.currentIndex() == 6 and changed[-1] == 6
    assert not timeline.visibleRegion().isEmpty()
    # A closed panel is reopened, not left closed.
    timeline.close()
    pump(qapp, 0.1)
    tabs.setCurrentWidget(window.listing_widget)
    tabs.setCurrentWidget(window.timeline_panel)
    pump(qapp, 0.2)
    assert timeline.toggleViewAction().isChecked()
    assert not timeline.visibleRegion().isEmpty()
    # A tab the examiner clicks is current too.
    search = tabs.dock(window.search_panel)
    window.result_area.tabifiedDockWidgetActivated.emit(search)
    assert tabs.currentWidget() is window.search_panel


def test_default_layout_tree_full_height_results_tabbed_utils_below(
        qapp, window):
    _shown(qapp, window)
    window.reset_layout()
    pump(qapp, 0.5)
    area = window.result_area
    docks = window.result_viewer.docks()
    listing = docks[0]
    assert set(area.tabifiedDockWidgets(listing)) == set(docks[1:])
    assert window.result_viewer.currentWidget() is window.listing_widget
    tree, utils = (_rect(window, window.tree_dock),
                   _rect(window, window.viewer_dock))
    results = _rect(window, listing)
    # Tree on the left, from under the toolbar to the status bar: beside
    # both the results and the Utils dock.
    assert tree.right() < results.left()
    assert tree.right() < utils.left()
    assert tree.top() <= results.top()
    assert tree.bottom() >= utils.bottom()
    assert abs(tree.bottom() - window.statusBar().geometry().top()) <= 2
    # Utils under the results.
    assert utils.top() > results.bottom() - 2
    assert window.tree_dock.width() >= window._TREE_MIN


def test_panels_side_by_side_are_saved_and_restored(qapp, window):
    from PySide6.QtCore import Qt
    _shown(qapp, window)
    area, tabs = window.result_area, window.result_viewer
    listing, timeline = (tabs.dock(window.listing_widget),
                         tabs.dock(window.timeline_panel))
    area.addDockWidget(Qt.RightDockWidgetArea, timeline, Qt.Horizontal)
    pump(qapp, 0.5)
    assert timeline not in area.tabifiedDockWidgets(listing)
    assert timeline.geometry().left() > listing.geometry().right()
    window.save_layout()

    window.reset_layout()
    pump(qapp, 0.5)
    assert timeline in area.tabifiedDockWidgets(listing)

    # What a start does: the window's layout, then the panels'.
    window._saved_state = window.saveState(window.LAYOUT_VERSION).data()
    window._apply_startup_layout()
    pump(qapp, 0.5)
    assert timeline not in area.tabifiedDockWidgets(listing)
    assert timeline.geometry().left() > listing.geometry().right()
    assert not timeline.isFloating()


def test_a_layout_saved_by_2_2_keeps_the_tree_and_utils(qapp, window):
    """2.2 saved a central tab widget with the tree and Utils docks
    (version 0): the window's own docks are arranged the same way now, so
    their sizes are kept, and the panels take the default arrangement."""
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QDockWidget, QMainWindow, QTabWidget
    from trace_app.infra.window_state import save_value
    # 2.2 kept no arrangement of the panels (another test may have: two
    # panels side by side need more width, and take it from the tree).
    save_value('Layout', 'panels', '')
    old = QMainWindow()
    old.resize(1400, 900)
    old.setCentralWidget(QTabWidget())
    for name, area in (('treeDock', Qt.LeftDockWidgetArea),
                       ('utilsDock', Qt.BottomDockWidgetArea)):
        dock = QDockWidget(name, old)
        dock.setObjectName(name)
        dock.setWidget(QTabWidget())
        old.addDockWidget(area, dock)
    old.show()
    pump(qapp, 0.2)
    old.resizeDocks([old.findChild(QDockWidget, 'treeDock')], [260],
                    Qt.Horizontal)
    pump(qapp, 0.2)
    tree = old.findChild(QDockWidget, 'treeDock').width()
    window._saved_state = old.saveState().data()
    old.close()
    old.deleteLater()

    _shown(qapp, window)
    window._apply_startup_layout()
    pump(qapp, 0.3)
    assert abs(window.tree_dock.width() - tree) <= 2
    docks = window.result_viewer.docks()
    assert set(window.result_area.tabifiedDockWidgets(docks[0])) == \
        set(docks[1:])
    assert all(d.toggleViewAction().isChecked() for d in docks)


def test_tree_width_and_utils_height_survive_resizing_and_restarts(
        qapp, window):
    """Without a central widget Qt shared every change of the window's
    size among all the docks: maximising widened the tree to half the
    window, and a restored layout came back wide. The panels' inner
    window now takes the change."""
    from PySide6.QtCore import Qt
    from trace_app.ui.main_window import MainWindow
    window.resize(1100, 800)
    window.show()
    pump(qapp, 0.3)
    window._apply_default_layout()
    pump(qapp, 0.3)
    # The examiner drags the separators.
    window.resizeDocks([window.tree_dock], [240], Qt.Horizontal)
    window.resizeDocks([window.viewer_dock], [230], Qt.Vertical)
    pump(qapp, 0.3)
    tree, utils = window.tree_dock.width(), window.viewer_dock.height()
    assert abs(tree - 240) <= 2 and abs(utils - 230) <= 2

    for size in ((1800, 1000), (1300, 850), (1600, 950)):
        window.resize(*size)
        pump(qapp, 0.4)
        assert window.tree_dock.width() == tree, size
        assert window.viewer_dock.height() == utils, size

    for _start in range(3):
        window.save_layout()
        again = MainWindow()
        try:
            again._saved_state = window.saveState(
                window.LAYOUT_VERSION).data()
            again.resize(1300, 850)
            again.show()
            pump(qapp, 0.3)
            again._apply_startup_layout()
            pump(qapp, 0.3)
            again.resize(1700, 950)
            pump(qapp, 0.4)
            assert again.tree_dock.width() == tree
            assert again.viewer_dock.height() == utils
        finally:
            close_window(again)


# -- Triage's grouped tabs ------------------------------------------------

def test_triage_groups_on_top_and_their_pages_under_them(qapp, window):
    from trace_app.ui.viewers.triage_panel import GROUPS
    triage = window.triage_panel
    nav = triage.tabs
    assert nav.headings() == [heading for _key, heading in GROUPS]
    assert nav.count() == len(triage._tab_for)
    # No row scrolls: a group holds a handful of pages, not 25.
    for key, _heading in GROUPS:
        members = [i for i in range(nav.count()) if nav.group_of(i) == key]
        assert 1 <= len(members) <= 6, key

    for name, widget in (('duplicates', triage.duplicate_table),
                         ('sigma', triage.sigma_table),
                         ('carved', window.carved_panel),
                         ('tags', window.tags_panel)):
        triage.show_group(name)
        index = nav.currentIndex()
        assert nav.currentWidget() is widget, name
        group = nav.group_of(index)
        # The lower row lists that group's pages, the current one picked.
        assert nav.pages_shown() == [i for i in range(nav.count())
                                     if nav.group_of(i) == group]
        assert nav.page_bar.tabData(nav.page_bar.currentIndex()) == index
        assert nav.headings()[nav.group_bar.currentIndex()] == \
            dict(GROUPS)[group]
    # Shown as written, not as a keyboard shortcut ("Matches _hits").
    assert nav.group_bar.tabText(1) == "Matches && hits"


def test_triage_tabs_follow_clicks_and_counts(qapp, window):
    from trace_app.ui.viewers.triage_panel import GROUPS
    triage = window.triage_panel
    nav = triage.tabs
    triage.show_group('mismatch')
    changed = []
    nav.currentChanged.connect(changed.append)
    # A click on a group shows its first page, then the one last seen.
    people = [k for k, _ in GROUPS].index('people')
    nav.group_bar.setCurrentIndex(people)
    first = nav.pages_shown()[0]
    assert nav.currentIndex() == first and changed[-1] == first
    nav.page_bar.setCurrentIndex(2)
    picked = nav.pages_shown()[2]
    assert nav.currentIndex() == picked
    nav.group_bar.setCurrentIndex(0)
    assert nav.group_of(nav.currentIndex()) == 'files'
    nav.group_bar.setCurrentIndex(people)
    assert nav.currentIndex() == picked
    # A count reaches the tab on screen.
    index = triage._tab_for['tags']
    nav.setTabText(index, "Tags (7)")
    assert nav.tabText(index) == "Tags (7)"
    tab = nav.pages_shown().index(index)
    assert nav.page_bar.tabText(tab) == "Tags (7)"


def test_activity_categories_are_grouped_like_triage(qapp, window):
    from trace_app.core.activity import CATEGORIES
    from trace_app.ui.viewers.activity_panel import GROUP_OF, GROUPS
    panel = window.activity_panel
    tabs = panel.tabs
    # Every category has a group, and every group a category -- but From
    # modules, which is there only while external modules read something
    # TRACE did not sort (this case has no module run).
    keys = [key for key, _ in GROUPS if key != 'modules']
    assert all(GROUP_OF.get(key) in keys for key, _ in CATEGORIES)
    assert {tabs.group_of(i) for i in range(tabs.count())} == set(keys)
    assert [h.rsplit(' (', 1)[0] for h in tabs.headings()] == \
        [label for key, label in GROUPS if key != 'modules']
    for category in ('downloads', 'usb', 'logons', None):
        panel.show_category(category)
        index = tabs.currentIndex()
        assert panel._keys[index] == category
        assert panel.category == category
        assert tabs.group_of(index) == GROUP_OF[category]
        assert index in tabs.pages_shown()
    # Counts on the categories, totals on the groups.
    panel._summary = {}
    panel.case = None
    panel._update_counts()
    assert tabs.tabText(0) == 'All (0)'
    assert tabs.headings()[keys.index('web')] == 'Web (0)'



def test_the_same_stylesheet_is_not_set_twice(qapp, window, monkeypatch):
    """Setting the sheet the application already has makes Qt repolish every
    widget; after earlier windows that repolish crashed inside Qt (access
    violation in setStyleSheet, tests building windows one after another).
    A theme switch still sets the new sheet."""
    from PySide6.QtWidgets import QApplication
    calls = []
    original = QApplication.setStyleSheet

    def spy(app, sheet):
        calls.append(sheet)
        return original(app, sheet)

    monkeypatch.setattr(QApplication, 'setStyleSheet', spy)
    before = qapp.styleSheet()
    window.apply_stylesheet('light')
    window.apply_stylesheet('light')
    assert len(calls) <= 1
    if calls:
        assert calls[0] != before
    window.apply_stylesheet('dark')
    assert calls and calls[-1] == qapp.styleSheet() != ''
    window.apply_stylesheet('dark')
    assert calls.count(calls[-1]) == 1
    window.apply_stylesheet('light')
