"""The main area's panels -- Listing, Registry, Search, Triage, Activity,
Timeline -- as dock widgets the examiner can arrange.

They were one fixed QTabWidget in the middle of the window: its tabs could
not be reordered, put side by side (the Listing beside the Timeline) or
moved to a second monitor. Each panel is now a QDockWidget, tabified onto
the first by default, so the window opens as it always did; a tab dragged
out is placed wherever Qt's docking allows. They are docks of an inner
window in the middle (`MainWindow.result_area`), whose saveState keeps
their arrangement.

`ResultDocks` stands where the tab widget was (`MainWindow.result_viewer`)
and answers the part of QTabWidget the window and its tests use, so
"bring the Search panel forward" is still `setCurrentWidget(panel)`. Code
that names a panel by its position would break as soon as the examiner
moved one: name the widget instead.

"Current" is the panel raised or focused last: with panels side by side
more than one is on screen, and the one the examiner touched is the one
they are working in.

A panel is named once. In a tab group the tab is its name (with the
panel's icon) and Qt's title strip is hidden -- tab, strip and the panel's
own heading said "Activity" three times. A panel standing alone, split
beside another or floating, has no tab, so it gets the strip back: that
is what is dragged and closed. The panels themselves carry no heading.
"""

from PySide6.QtCore import QEvent, QObject, Qt, QTimer, Signal
from PySide6.QtWidgets import QApplication, QDockWidget, QTabBar, QWidget

from trace_app.ui import icons


class ResultDocks(QObject):
    """The result panels of `window` (a QMainWindow), one dock each."""

    #: The index of the panel that became current.
    currentChanged = Signal(int)

    def __init__(self, window):
        super().__init__(window)
        self._window = window
        self._docks = []
        self._current = None
        self._icons = {}              # dock -> icon name
        self._pending = False
        window.tabifiedDockWidgetActivated.connect(self._dock_raised)
        QApplication.instance().focusChanged.connect(self._focus_changed)
        window.installEventFilter(self)

    def eventFilter(self, watched, event):
        # Qt makes and refills the docks' tab bars itself as panels move:
        # tidy them after every change of the arrangement.
        if event.type() in (QEvent.ChildAdded, QEvent.LayoutRequest):
            self.refresh()
        return False

    def refresh(self):
        """Tidy the tab rows and title strips once the arrangement has
        settled (also after a theme change, for the icons' tint)."""
        if not self._pending:
            self._pending = True
            QTimer.singleShot(0, self._tidy)

    def _tidy(self):
        self._pending = False
        by_title = {dock.windowTitle(): dock for dock in self._docks}
        for bar in self._window.findChildren(
                QTabBar, options=Qt.FindDirectChildrenOnly):
            # Qt turns the base line on: a dark rule from the last tab to
            # the window's edge that no other tab row in TRACE has.
            bar.setDrawBase(False)
            for tab in range(bar.count()):
                dock = by_title.get(bar.tabText(tab))
                if dock in self._icons:
                    bar.setTabIcon(tab, icons.icon(self._icons[dock]))
        for dock in self._docks:
            tabbed = (not dock.isFloating()
                      and bool(self._window.tabifiedDockWidgets(dock)))
            hidden = dock.titleBarWidget() is not None
            if tabbed and not hidden:
                strip = QWidget(dock)
                strip.setObjectName('hiddenDockTitle')
                dock.setTitleBarWidget(strip)
            elif not tabbed and hidden:
                old = dock.titleBarWidget()
                dock.setTitleBarWidget(None)
                old.deleteLater()

    # -- building --------------------------------------------------------

    def addTab(self, widget, label, icon=None):
        """Make `widget` a dock titled `label`, its tab showing `icon` (a
        name from `icons`). The first goes in the main area; the rest are
        tabbed onto it. Returns its index."""
        dock = QDockWidget(label, self._window)
        if icon:
            self._icons[dock] = icon
        dock.topLevelChanged.connect(lambda _floating: self.refresh())
        dock.setObjectName(
            ''.join(part.capitalize() if n else part.lower()
                    for n, part in enumerate(label.split())) + 'Dock')
        dock.setFeatures(QDockWidget.DockWidgetClosable
                         | QDockWidget.DockWidgetMovable
                         | QDockWidget.DockWidgetFloatable)
        # A QWidget subclass paints the theme's background only when asked:
        # without this its margins showed the window's grey as bands.
        widget.setAttribute(Qt.WA_StyledBackground, True)
        dock.setWidget(widget)
        dock.visibilityChanged.connect(
            lambda shown, d=dock: shown and self._make_current(d))
        if not self._docks:
            self._window.addDockWidget(Qt.RightDockWidgetArea, dock)
            self._current = dock
        else:
            self._window.tabifyDockWidget(self._docks[0], dock)
        self._docks.append(dock)
        return len(self._docks) - 1

    def arrange(self):
        """The default arrangement: every panel docked and tabbed onto the
        first (in the order added), the first in front. Used on a first
        run and by Reset Layout."""
        window = self._window
        first = self._docks[0]
        for dock in self._docks:
            dock.setFloating(False)
            dock.show()
        window.addDockWidget(Qt.RightDockWidgetArea, first)
        for dock in self._docks[1:]:
            window.tabifyDockWidget(first, dock)
        self.setCurrentWidget(first.widget())

    # -- QTabWidget's part -----------------------------------------------

    def docks(self):
        return list(self._docks)

    def dock(self, widget):
        """The dock holding `widget`, or None."""
        return next((d for d in self._docks if d.widget() is widget), None)

    def count(self):
        return len(self._docks)

    def widget(self, index):
        if 0 <= index < len(self._docks):
            return self._docks[index].widget()
        return None

    def indexOf(self, widget):
        dock = self.dock(widget)
        return self._docks.index(dock) if dock is not None else -1

    def tabText(self, index):
        if 0 <= index < len(self._docks):
            return self._docks[index].windowTitle()
        return ''

    def currentWidget(self):
        return self._current.widget() if self._current is not None else None

    def currentIndex(self):
        return (self._docks.index(self._current)
                if self._current is not None else -1)

    def setCurrentWidget(self, widget):
        """Bring the panel holding `widget` forward: reopened if it was
        closed, its tab selected if it shares a place with others."""
        dock = self.dock(widget)
        if dock is None:
            return
        if not dock.toggleViewAction().isChecked():
            dock.show()
        dock.raise_()
        self._make_current(dock)

    def setCurrentIndex(self, index):
        widget = self.widget(index)
        if widget is not None:
            self.setCurrentWidget(widget)

    def setEnabled(self, state):
        for dock in self._docks:
            dock.widget().setEnabled(state)

    # -- tracking the current panel --------------------------------------

    def _make_current(self, dock):
        if dock is self._current or dock not in self._docks:
            return
        self._current = dock
        self.currentChanged.emit(self._docks.index(dock))

    def _dock_raised(self, dock):
        self._make_current(dock)

    def _focus_changed(self, _old, new):
        while new is not None:
            if isinstance(new, QDockWidget):
                self._make_current(new)
                return
            new = new.parentWidget()
