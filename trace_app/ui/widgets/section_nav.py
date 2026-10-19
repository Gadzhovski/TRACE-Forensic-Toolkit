"""Many tabs under a few headings: a row of groups over a row of the
group's tabs.

Triage outgrew its tab row -- about 25 sub-tabs in one scrolling strip,
where "Sigma" sat between "Executables" and "Carved files" and nothing said
what belonged with what -- and Activity's fourteen categories ran past the
window's edge too. A sidebar fixed that but took a column from every table.
The tabs stay on top: a row of groups (Files, Matches & hits, ...), and
under it the tabs of the group picked -- a handful, so neither row scrolls.

`GroupedTabs` is the two rows alone (Activity: one table, filtered by the
tab). `SectionNav` adds a stack of pages under them (Triage) and answers
the part of QTabWidget Triage and its tests use -- addTab, setTabText,
tabText, currentWidget, currentIndex, setCurrentIndex, setCurrentWidget,
indexOf, count, widget, currentChanged. In both, a tab's index is the
order it was added, whatever order the rows show.
"""

from PySide6.QtCore import QSize, Signal
from PySide6.QtWidgets import (QHBoxLayout, QStackedWidget, QTabBar,
                               QVBoxLayout, QWidget)

from trace_app.infra.constants import ROW_EDGE_INSET


def _tab_bar(name):
    bar = QTabBar()
    bar.setObjectName(name)
    bar.setDocumentMode(True)
    bar.setExpanding(False)
    # No base line: in document mode Qt rules one along the tab row, a
    # stray line no other tab strip in TRACE has.
    bar.setDrawBase(False)
    return bar


def _shown(text):
    """'&&': a lone '&' marks a shortcut ("Matches _hits")."""
    return text.replace('&', '&&')


class GroupedTabs(QWidget):
    """Two tab rows. `groups` is [(key, heading), ...] in the order shown;
    a tab added with an unknown group (or none) goes under the last."""

    currentChanged = Signal(int)

    def __init__(self, groups, name='nav', parent=None):
        super().__init__(parent)
        self._groups = list(groups)
        self._tabs = []           # [{'group', 'icon', 'text'}], by index
        self._current = -1
        self._filling = False
        self._last = {}           # group -> the tab last shown in it

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self._top = QHBoxLayout()
        self._top.setContentsMargins(0, 0, 0, 0)
        self.group_bar = _tab_bar(f'{name}Groups')
        self.page_bar = _tab_bar(f'{name}Pages')
        # The lower row is slimmer than the groups above it (the themes'
        # QTabBar[row="pages"]), so the two read as heading and contents.
        self.page_bar.setProperty('row', 'pages')
        self.page_bar.setIconSize(QSize(14, 14))
        self._top.addWidget(self.group_bar, 1)
        layout.addLayout(self._top)
        layout.addWidget(self.page_bar)
        self.group_bar.currentChanged.connect(self._group_changed)
        self.page_bar.currentChanged.connect(self._page_changed)

    def set_corner_widget(self, widget, inset=ROW_EDGE_INSET):
        """Put `widget` at the right of the group row (a filter box),
        `inset` short of the edge -- flush with it, it read as cut off."""
        self._top.addWidget(widget)
        self._top.setContentsMargins(0, 0, inset, 0)

    def addTab(self, icon, text, group=None):
        """Add a tab under `group`; returns its index."""
        keys = [key for key, _ in self._groups]
        if group not in keys:
            group = keys[-1]
        index = len(self._tabs)
        self._tabs.append({'group': group, 'icon': icon, 'text': text})
        if group not in self._shown_groups():
            # In the groups' order, whenever its first tab arrives.
            later = [g for g in keys[keys.index(group) + 1:]
                     if g in self._shown_groups()]
            at = (self._shown_groups().index(later[0]) if later
                  else self.group_bar.count())
            self._filling = True
            self.group_bar.insertTab(at, _shown(dict(self._groups)[group]))
            self.group_bar.setTabData(at, group)
            self._filling = False
        if self._current < 0:
            self._show_group(group, index)
        elif group == self._current_group():
            self._show_group(group, self._current)
        return index

    def remove_group(self, group):
        """Take away `group` and its tabs -- the last ones added (a group
        that comes and goes is added after the fixed ones, so no other
        tab's index changes). The current tab moves to the first group."""
        if group not in self._shown_groups():
            return
        while self._tabs and self._tabs[-1]['group'] == group:
            self._tabs.pop()
        if any(tab['group'] == group for tab in self._tabs):
            raise ValueError(f"{group!r} has tabs before others")
        was_current = self._current >= len(self._tabs)
        self._last.pop(group, None)
        self._filling = True
        try:
            self.group_bar.removeTab(self._shown_groups().index(group))
        finally:
            self._filling = False
        if was_current and self._tabs:
            self._current = -1
            self._show_group(self._tabs[0]['group'], 0)

    def count(self):
        return len(self._tabs)

    def tabText(self, index):
        if 0 <= index < len(self._tabs):
            return self._tabs[index]['text']
        return ''

    def setTabText(self, index, text):
        if not 0 <= index < len(self._tabs):
            return
        self._tabs[index]['text'] = text
        for tab in range(self.page_bar.count()):
            if self.page_bar.tabData(tab) == index:
                self.page_bar.setTabText(tab, text)

    def setGroupText(self, group, text):
        """Relabel a group's tab ("Web (1,204)")."""
        groups = self._shown_groups()
        if group in groups:
            self.group_bar.setTabText(groups.index(group), _shown(text))

    def currentIndex(self):
        return self._current

    def setCurrentIndex(self, index):
        if 0 <= index < len(self._tabs):
            self._show_group(self._tabs[index]['group'], index)

    def headings(self):
        """The groups' labels as shown, in order."""
        return [self.group_bar.tabText(tab).replace('&&', '&')
                for tab in range(self.group_bar.count())]

    def group_of(self, index):
        return self._tabs[index]['group']

    def pages_shown(self):
        """The tab indices in the lower row, in order."""
        return [self.page_bar.tabData(tab)
                for tab in range(self.page_bar.count())]

    def _shown_groups(self):
        return [self.group_bar.tabData(tab)
                for tab in range(self.group_bar.count())]

    def _current_group(self):
        return self.group_bar.tabData(self.group_bar.currentIndex())

    def _show_group(self, group, index):
        """Select `group`, list its tabs, and select tab `index` (or the
        group's first when `index` is not one of them)."""
        members = [i for i, tab in enumerate(self._tabs)
                   if tab['group'] == group]
        if index not in members:
            index = members[0]
        self._last[group] = index
        self._filling = True
        try:
            self.group_bar.setCurrentIndex(self._shown_groups().index(group))
            if self.pages_shown() != members:
                while self.page_bar.count():
                    self.page_bar.removeTab(0)
                for member in members:
                    tab = self._tabs[member]
                    at = self.page_bar.addTab(tab['icon'], tab['text'])
                    self.page_bar.setTabData(at, member)
            self.page_bar.setCurrentIndex(members.index(index))
        finally:
            self._filling = False
        if index != self._current:
            self._current = index
            self.currentChanged.emit(index)

    def _group_changed(self, tab):
        if self._filling or tab < 0:
            return
        group = self.group_bar.tabData(tab)
        # The tab last seen in that group, else its first.
        self._show_group(group, self._last.get(group))

    def _page_changed(self, tab):
        if self._filling or tab < 0:
            return
        index = self.page_bar.tabData(tab)
        self._show_group(self._tabs[index]['group'], index)


class SectionNav(QWidget):
    """Grouped tabs over a stack of pages, one page per tab."""

    currentChanged = Signal(int)

    def __init__(self, groups, name='nav', parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.tabs = GroupedTabs(groups, name)
        self.stack = QStackedWidget()
        layout.addWidget(self.tabs)
        layout.addWidget(self.stack, 1)
        self.tabs.currentChanged.connect(self._tab_changed)
        # The rows, for tests and callers that look at them.
        self.group_bar = self.tabs.group_bar
        self.page_bar = self.tabs.page_bar

    def addTab(self, widget, icon, text, group=None):
        """Add a page under `group`; returns its index."""
        index = self.stack.addWidget(widget)
        self.tabs.addTab(icon, text, group)
        return index

    def count(self):
        return self.stack.count()

    def widget(self, index):
        return self.stack.widget(index)

    def indexOf(self, widget):
        return self.stack.indexOf(widget)

    def tabText(self, index):
        return self.tabs.tabText(index)

    def setTabText(self, index, text):
        self.tabs.setTabText(index, text)

    def currentIndex(self):
        return self.stack.currentIndex()

    def currentWidget(self):
        return self.stack.currentWidget()

    def setCurrentIndex(self, index):
        self.tabs.setCurrentIndex(index)

    def setCurrentWidget(self, widget):
        self.setCurrentIndex(self.indexOf(widget))

    def headings(self):
        return self.tabs.headings()

    def group_of(self, index):
        return self.tabs.group_of(index)

    def pages_shown(self):
        return self.tabs.pages_shown()

    def _tab_changed(self, index):
        if index != self.stack.currentIndex():
            self.stack.setCurrentIndex(index)
            self.currentChanged.emit(index)
