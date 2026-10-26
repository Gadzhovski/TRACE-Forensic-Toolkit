"""Case Overview: the page a case opens on -- its evidence, what the case
holds by kind (core/artifact_catalogue), what is worth a look, and which
scans have not run or stopped before the end.

Every number is a link into the view that lists it, and the counts are
the navigator's (one read, `MainWindow.refresh_artifacts`). The line it
exists for most: an analysis that stopped part-way ("stopped at 24,753 of
1,046,946 files") -- a case that looks analysed and is not."""

import html

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QFrame, QGridLayout, QHBoxLayout, QLabel,
                               QPushButton, QScrollArea, QVBoxLayout,
                               QWidget)

from trace_app.core import artifact_catalogue as catalogue
from trace_app.core.case import (STATUS_BASELINE, STATUS_CHANGED,
                                 STATUS_LIVE, STATUS_MISSING,
                                 STATUS_UNREADABLE, STATUS_VERIFIED)
from trace_app.ui import icons
from trace_app.ui.widgets.dialog_page import badge

#: Evidence status -> (badge text, tone).
STATUS_BADGES = {
    STATUS_VERIFIED: ("Verified", 'ok'), STATUS_BASELINE: ("Hashed", 'info'),
    STATUS_LIVE: ("Live disk", 'warn'), STATUS_CHANGED: ("Changed", 'bad'),
    STATUS_MISSING: ("Missing", 'bad'), STATUS_UNREADABLE: ("Unreadable",
                                                           'bad')}
#: Tiles: the catalogue sections shown as "what the case holds".
TILE_SECTIONS = ('communication', 'web', 'media', 'files', 'system', 'flags')
#: Links listed on a tile, at most.
TILE_LINKS = 3
#: Scans not run listed, at most (then "and n more").
WAITING_SHOWN = 9


def _link(key, text):
    return f"<a href='{html.escape(key)}'>{html.escape(text)}</a>"


class _Tile(QFrame):
    """One section's card; a click opens its largest entry."""

    def __init__(self, key, open_requested):
        super().__init__()
        self.setObjectName("overviewTile")
        self.setCursor(Qt.PointingHandCursor)
        self.key, self._open = key, open_requested

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton and self.key:
            self._open.emit(self.key)
        super().mouseReleaseEvent(event)


class CaseOverview(QScrollArea):
    """`open_requested(entry key)`, `run_missing_requested()`."""

    open_requested = Signal(str)
    run_missing_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("caseOverview")
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        self._body = None
        self.show_data(None)

    # --- the page --------------------------------------------------------------

    def show_data(self, data):
        """`data`: {'case': {name, number, examiner}, 'evidence': [{name,
        system, logo, kind, size, status}], 'found', 'states', 'stopped':
        [(name, done, total)], 'span': (first, last) or None} -- or None
        while it is read."""
        body = QWidget()
        body.setObjectName("overviewBody")
        outer = QVBoxLayout(body)
        outer.setContentsMargins(20, 16, 20, 16)
        outer.setSpacing(10)
        if data is None:
            waiting = QLabel("Reading the case…")
            waiting.setObjectName("pageHint")
            outer.addWidget(waiting)
            outer.addStretch(1)
        else:
            self._header(outer, data['case'])
            self._evidence(outer, data['evidence'])
            columns = QHBoxLayout()
            columns.setSpacing(14)
            left = QVBoxLayout()
            self._holds(left, data['found'], data['states'])
            left.addStretch(1)
            right = QVBoxLayout()
            self._worth(right, data['found'])
            self._unfinished(right, data['states'], data['found'],
                             data['stopped'])
            self._span(right, data.get('span'))
            right.addStretch(1)
            columns.addLayout(left, 3)
            columns.addLayout(right, 1)
            outer.addLayout(columns, 1)
        self.setWidget(body)
        self._body = body

    def _header(self, outer, case):
        row = QHBoxLayout()
        title = QLabel(case.get('name') or 'Case')
        title.setObjectName("pageTitle")
        row.addWidget(title)
        row.addStretch(1)
        facts = QLabel(' · '.join(part for part in (
            f"Case number {case['number']}" if case.get('number') else '',
            f"Examiner {case['examiner']}" if case.get('examiner') else '')
            if part))
        facts.setObjectName("pageIntro")
        row.addWidget(facts)
        outer.addLayout(row)

    def _evidence(self, outer, evidence):
        if not evidence:
            note = QLabel("No evidence in the case yet: File ▸ Add "
                          "Evidence.")
            note.setObjectName("pageNote")
            outer.addWidget(note)
            return
        grid = QGridLayout()
        grid.setSpacing(10)
        for index, item in enumerate(evidence):
            frame, layout = _card()
            top = QHBoxLayout()
            if item.get('logo'):
                mark = QLabel()
                mark.setPixmap(icons.os_logo(item['logo']).pixmap(24, 24))
                top.addWidget(mark)
            name = QLabel(item['name'])
            name.setObjectName("pageCardTitle")
            top.addWidget(name, 1)
            text, tone = STATUS_BADGES.get(item.get('status'),
                                           ("Not verified", 'muted'))
            top.addWidget(badge(text, tone))
            layout.addLayout(top)
            facts = QLabel(' · '.join(part for part in (
                item.get('system') or '', item.get('kind') or '',
                item.get('size') or '') if part))
            facts.setObjectName("pageHint")
            layout.addWidget(facts)
            grid.addWidget(frame, index // 3, index % 3)
        outer.addLayout(grid)

    def _section_label(self, layout, text):
        label = QLabel(text)
        label.setObjectName("pageSection")
        layout.addWidget(label)

    def _holds(self, layout, found, states):
        self._section_label(layout, "What the case holds")
        grid = QGridLayout()
        grid.setSpacing(10)
        sections = {key: (title, members)
                    for key, title, members in catalogue.SECTIONS}
        for index, key in enumerate(TILE_SECTIONS):
            title, members = sections[key]
            counted = sorted((e for e in members if found.get(e.key)),
                             key=lambda e: -found[e.key])
            tile = _Tile(counted[0].key if counted else '',
                         self.open_requested)
            box = QVBoxLayout(tile)
            box.setContentsMargins(14, 12, 14, 12)
            box.setSpacing(3)
            head = QHBoxLayout()
            mark = QLabel()
            from trace_app.ui.widgets.artifact_navigator import entry_icon
            mark.setPixmap(entry_icon(counted[0] if counted else members[0])
                           .pixmap(18, 18))
            head.addWidget(mark)
            name = QLabel(title)
            name.setObjectName("pageCardTitle")
            head.addWidget(name, 1)
            box.addLayout(head)
            total = sum(found.get(e.key) or 0 for e in members)
            number = QLabel(f"{total:,}" if total else "Nothing found")
            number.setObjectName("overviewNumber" if total
                                 else "pageHint")
            box.addWidget(number)
            for entry in counted[:TILE_LINKS]:
                line = QLabel(f"{_link(entry.key, entry.label)} "
                              f"{found[entry.key]:,}")
                line.setTextFormat(Qt.RichText)
                line.linkActivated.connect(self.open_requested)
                box.addWidget(line)
            waiting = sum(1 for e in members if not found.get(e.key) and
                          states.get(e.key) in (catalogue.NOT_RUN,
                                                catalogue.STOPPED))
            if waiting:
                note = QLabel(f"{waiting} not run or stopped")
                note.setObjectName("pageHint")
                box.addWidget(note)
            box.addStretch(1)
            grid.addWidget(tile, index // 3, index % 3)
        layout.addLayout(grid)

    def _worth(self, layout, found):
        flagged = [e for e in catalogue.entries()
                   if e.flag and found.get(e.key)]
        self._section_label(layout, "Worth a look")
        frame, box = _card()
        if not flagged:
            note = QLabel("Nothing flagged by the scans that ran.")
            note.setObjectName("pageHint")
            box.addWidget(note)
        for entry in sorted(flagged, key=lambda e: e.flag != 'bad'):
            row = QHBoxLayout()
            row.addWidget(badge(f"{found[entry.key]:,}", entry.flag))
            text = QLabel(_link(entry.key, entry.label))
            text.setTextFormat(Qt.RichText)
            text.linkActivated.connect(self.open_requested)
            row.addWidget(text, 1)
            box.addLayout(row)
        layout.addWidget(frame)

    def _unfinished(self, layout, states, found, stopped):
        waiting = [(e, states[e.key]) for e in catalogue.entries()
                   if not found.get(e.key) and states.get(e.key) in
                   (catalogue.NOT_RUN, catalogue.STOPPED)]
        if not waiting and not stopped:
            return
        self._section_label(layout, "Scans not finished")
        frame, box = _card()
        for name, done, total in stopped:
            line = QLabel(f"File analysis of {html.escape(name)} stopped at "
                          f"{done:,} of {total:,} files "
                          f"({100 * done / total:.0f}%).")
            line.setObjectName("overviewWarning")
            line.setWordWrap(True)
            box.addWidget(line)
        for entry, state in waiting[:WAITING_SHOWN]:
            row = QHBoxLayout()
            row.addWidget(badge("stopped" if state == catalogue.STOPPED
                                else "not run",
                                'warn' if state == catalogue.STOPPED
                                else 'muted'))
            row.addWidget(QLabel(entry.label), 1)
            box.addLayout(row)
        if len(waiting) > WAITING_SHOWN:
            more = QLabel(f"and {len(waiting) - WAITING_SHOWN} more")
            more.setObjectName("pageHint")
            box.addWidget(more)
        if waiting:
            self.run_button = QPushButton("Run Missing Scans…")
            self.run_button.setObjectName("overviewRun")
            self.run_button.clicked.connect(self.run_missing_requested)
            box.addWidget(self.run_button, 0, Qt.AlignLeft)
        layout.addWidget(frame)

    def _span(self, layout, span):
        self._section_label(layout, "Time span")
        frame, box = _card()
        text = QLabel(f"{span[0][:10]} → {span[1][:10]}" if span
                      else "No dated activity yet")
        box.addWidget(text)
        hint = QLabel("Users' activity, UTC — the Timeline has every event")
        hint.setObjectName("pageHint")
        box.addWidget(hint)
        layout.addWidget(frame)


def _card():
    frame = QFrame()
    frame.setObjectName("pageCard")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(14, 12, 14, 12)
    layout.setSpacing(4)
    return frame, layout
