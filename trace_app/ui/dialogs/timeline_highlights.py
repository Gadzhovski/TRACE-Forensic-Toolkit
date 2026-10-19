"""Timeline ▸ Filters ▸ Highlight Rules: which events are tinted, in what
colour.

A rule is a name, a colour and conditions -- which sources, text in the
Type, text (or a regular expression) in what the event says, file
extensions, deleted only. A row takes the colour of the first rule it
matches, so the order matters: Up / Down. Kept with the case
(case setting 'timeline_highlights'); Restore Defaults brings back the
rules a case starts with (core/timeline.DEFAULT_HIGHLIGHTS).
"""

import re

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QColorDialog,
                               QDialog, QDialogButtonBox, QHBoxLayout,
                               QHeaderView, QLabel, QPushButton,
                               QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget)

from trace_app.core import timeline

#: Columns of the rules table.
(ON, NAME, COLOUR, SOURCES, KINDS, TEXT, EXTENSIONS, DELETED) = range(8)
_HEADERS = ("On", "Name", "Colour", "Sources", "Type contains",
            "Text (re: for a regular expression)", "Extensions", "Deleted")


class HighlightRulesDialog(QDialog):
    def __init__(self, rules, parent=None):
        super().__init__(parent)
        self.setObjectName("timelineHighlightsDialog")
        self.setWindowTitle("Highlight Rules")
        self.resize(980, 380)
        layout = QVBoxLayout(self)
        intro = QLabel("Events matching a rule are tinted in its colour in "
                       "the Timeline -- the first rule that matches wins. "
                       "Sources are keys (fs, usn, activity, photo, "
                       "document, carved, sigma, case), comma-separated; "
                       "empty means any.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.table = QTableWidget(0, len(_HEADERS))
        self.table.setHorizontalHeaderLabels(_HEADERS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setSectionResizeMode(TEXT, QHeaderView.Stretch)
        for column, width in ((ON, 36), (NAME, 170), (COLOUR, 70),
                              (SOURCES, 110), (KINDS, 100),
                              (EXTENSIONS, 150), (DELETED, 60)):
            self.table.setColumnWidth(column, width)
        layout.addWidget(self.table, 1)
        buttons = QHBoxLayout()
        for label, slot in (("Add", self._add), ("Remove", self._remove),
                            ("Up", lambda: self._move(-1)),
                            ("Down", lambda: self._move(1)),
                            ("Restore Defaults", self._defaults)):
            button = QPushButton(label)
            button.clicked.connect(slot)
            buttons.addWidget(button)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        self.problem = QLabel()
        self.problem.setObjectName("wizardError")
        layout.addWidget(self.problem)
        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.accepted.connect(self._accept)
        box.rejected.connect(self.reject)
        layout.addWidget(box)
        for rule in rules:
            self._append(rule)

    # --- rows ---------------------------------------------------------------------

    def _append(self, rule, position=None):
        row = self.table.rowCount() if position is None else position
        self.table.insertRow(row)
        holder = QWidget()
        box = QCheckBox()
        box.setChecked(bool(rule.get('enabled', True)))
        inner = QHBoxLayout(holder)
        inner.setContentsMargins(8, 0, 0, 0)
        inner.addWidget(box)
        self.table.setCellWidget(row, ON, holder)
        self.table.setItem(row, NAME, QTableWidgetItem(rule.get('name', '')))
        swatch = QPushButton()
        swatch.setObjectName("highlightSwatch")
        swatch.setProperty('colour', rule.get('colour') or '#E5534B')
        self._paint_swatch(swatch)
        swatch.clicked.connect(lambda _c=False, b=swatch: self._pick(b))
        self.table.setCellWidget(row, COLOUR, swatch)
        self.table.setItem(row, SOURCES, QTableWidgetItem(
            ', '.join(rule.get('sources') or ())))
        self.table.setItem(row, KINDS, QTableWidgetItem(rule.get('kinds')
                                                        or ''))
        text = rule.get('text') or ''
        self.table.setItem(row, TEXT, QTableWidgetItem(
            ('re:' + text) if rule.get('regex') and text else text))
        self.table.setItem(row, EXTENSIONS, QTableWidgetItem(
            ', '.join(rule.get('extensions') or ())))
        deleted = QWidget()
        tick = QCheckBox()
        tick.setChecked(bool(rule.get('deleted')))
        inner = QHBoxLayout(deleted)
        inner.setContentsMargins(16, 0, 0, 0)
        inner.addWidget(tick)
        self.table.setCellWidget(row, DELETED, deleted)

    @staticmethod
    def _paint_swatch(button):
        colour = button.property('colour')
        # The swatch shows the colour itself: an icon, not a style sheet.
        from trace_app.ui import icons
        button.setIcon(icons.dot_icon(colour))
        button.setText(colour)

    def _pick(self, button):
        chosen = QColorDialog.getColor(QColor(button.property('colour')),
                                       self, "Highlight Colour")
        if chosen.isValid():
            button.setProperty('colour', chosen.name())
            self._paint_swatch(button)

    def _add(self):
        self._append({'name': 'New rule', 'colour': '#E3A008',
                      'enabled': True})
        self.table.selectRow(self.table.rowCount() - 1)

    def _remove(self):
        row = self.table.currentRow()
        if row >= 0:
            self.table.removeRow(row)

    def _move(self, step):
        row = self.table.currentRow()
        target = row + step
        if row < 0 or not 0 <= target < self.table.rowCount():
            return
        rules = self.rules()
        rules.insert(target, rules.pop(row))
        self._fill(rules)
        self.table.selectRow(target)

    def _defaults(self):
        self._fill([dict(rule) for rule in timeline.DEFAULT_HIGHLIGHTS])

    def _fill(self, rules):
        self.table.setRowCount(0)
        for rule in rules:
            self._append(rule)

    # --- out ------------------------------------------------------------------------

    def rules(self):
        out = []
        for row in range(self.table.rowCount()):
            def text(column):
                item = self.table.item(row, column)
                return item.text().strip() if item is not None else ''

            def ticked(column):
                holder = self.table.cellWidget(row, column)
                box = holder.findChild(QCheckBox) if holder else None
                return bool(box and box.isChecked())
            rule = {'name': text(NAME) or 'Rule',
                    'colour': self.table.cellWidget(row, COLOUR)
                    .property('colour'),
                    'enabled': ticked(ON)}
            sources = [s.strip() for s in text(SOURCES).split(',')
                       if s.strip()]
            if sources:
                rule['sources'] = sources
            if text(KINDS):
                rule['kinds'] = text(KINDS)
            pattern = text(TEXT)
            if pattern.startswith('re:'):
                rule['text'], rule['regex'] = pattern[3:], True
            elif pattern:
                rule['text'] = pattern
            extensions = [e.strip().lstrip('.').lower() for e in
                          text(EXTENSIONS).split(',') if e.strip()]
            if extensions:
                rule['extensions'] = extensions
            if ticked(DELETED):
                rule['deleted'] = True
            out.append(rule)
        return out

    def _accept(self):
        for rule in self.rules():
            if rule.get('regex'):
                try:
                    re.compile(rule['text'])
                except re.error as exc:
                    self.problem.setText(
                        f"“{rule['name']}”: the regular expression does not "
                        f"read ({exc}).")
                    return
        self.accept()
