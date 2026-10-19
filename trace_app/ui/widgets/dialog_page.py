"""The look Settings set, for TRACE's other windows (Tools ▸ External
Modules, Supported Features, the libraries...): a header with an icon, a
title and a line on what the window is for; a body of section headings,
cards and help text; a footer with a hint beside the buttons.

Styled by object name in both themes ('page*', next to the Settings
rules), never inline. A window builds its body with `section`, `note`,
`hint`, `card` and `badge`, and its buttons with `add_button` /
`button_box`.
"""

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QFrame,
                               QHBoxLayout, QLabel, QScrollArea, QVBoxLayout,
                               QWidget)

from trace_app.ui import icons

#: Badge tones, matched by the themes' QLabel#pageBadge[tone="..."].
TONES = ('ok', 'warn', 'bad', 'info', 'muted')


def badge(text, tone='muted'):
    """A small rounded status word ('Installed', 'Update available')."""
    label = QLabel(text)
    label.setObjectName("pageBadge")
    set_tone(label, tone)
    return label


def set_tone(label, tone):
    label.setProperty('tone', tone if tone in TONES else 'muted')
    label.style().unpolish(label)
    label.style().polish(label)


def hint(text):
    label = QLabel(text)
    label.setObjectName("pageHint")
    label.setWordWrap(True)
    return label


class PageDialog(QDialog):
    """A window in Settings' look. `scroll` False keeps the body unscrolled
    (a window whose body is one table that scrolls itself)."""

    def __init__(self, title, intro, icon=None, parent=None, scroll=True,
                 object_name="pageDialog"):
        super().__init__(parent)
        # The themes find a page by this property; the object name stays
        # the window's own (its other rules and tests use it).
        self.setProperty('page', True)
        self.setObjectName(object_name)
        self.setWindowTitle(title)
        self.setWindowIcon(icons.icon(icons.LOGO))
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        header = QFrame()
        header.setObjectName("pageHeader")
        row = QHBoxLayout(header)
        row.setContentsMargins(24, 18, 24, 14)
        row.setSpacing(14)
        if icon:
            mark = QLabel()
            mark.setObjectName("pageIcon")
            mark.setPixmap(icons.icon(icon).pixmap(QSize(28, 28)))
            mark.setAlignment(Qt.AlignTop)
            row.addWidget(mark, 0, Qt.AlignTop)
        words = QVBoxLayout()
        words.setSpacing(0)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("pageTitle")
        words.addWidget(self.title_label)
        self.intro_label = QLabel(intro)
        self.intro_label.setObjectName("pageIntro")
        self.intro_label.setWordWrap(True)
        self.intro_label.setVisible(bool(intro))
        words.addWidget(self.intro_label)
        row.addLayout(words, 1)
        #: Widgets at the header's right (a summary badge, a filter).
        self.header_tail = QHBoxLayout()
        self.header_tail.setSpacing(8)
        row.addLayout(self.header_tail)
        outer.addWidget(header)

        self.content = QWidget()
        self.content.setObjectName("pageBody")
        self.body = QVBoxLayout(self.content)
        self.body.setContentsMargins(24, 4, 24, 18)
        self.body.setSpacing(0)
        if scroll:
            self.scroll = QScrollArea()
            self.scroll.setObjectName("pageScroll")
            self.scroll.setWidgetResizable(True)
            self.scroll.setFrameShape(QFrame.NoFrame)
            self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            self.scroll.setWidget(self.content)
            outer.addWidget(self.scroll, 1)
        else:
            self.scroll = None
            outer.addWidget(self.content, 1)

        footer = QFrame()
        footer.setObjectName("pageFooter")
        self.footer_row = QHBoxLayout(footer)
        self.footer_row.setContentsMargins(16, 10, 12, 10)
        self.footer_row.setSpacing(8)
        self.footer_hint = QLabel()
        self.footer_hint.setObjectName("pageHint")
        self.footer_hint.setWordWrap(True)
        self.footer_row.addWidget(self.footer_hint, 1)
        outer.addWidget(footer)

    # --- the body ----------------------------------------------------------

    def section(self, text, first=False):
        label = QLabel(text)
        label.setObjectName("pageSectionFirst" if first else "pageSection")
        self.body.addWidget(label)
        return label

    def note(self, text):
        """A boxed line (where things are kept, why something is off)."""
        label = QLabel(text)
        label.setObjectName("pageNote")
        label.setWordWrap(True)
        self.body.addWidget(label)
        return label

    def hint(self, text):
        label = hint(text)
        self.body.addWidget(label)
        return label

    def card(self):
        """A framed card in the body: (frame, its QVBoxLayout)."""
        frame = QFrame()
        frame.setObjectName("pageCard")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)
        self.body.addWidget(frame)
        return frame, layout

    def finish_body(self):
        """Close the body: what follows stays at the top."""
        self.body.addStretch(1)

    def set_intro(self, text):
        self.intro_label.setText(text)
        self.intro_label.setVisible(bool(text))

    def table_body(self):
        """The body laid out for a window whose body is a table and its
        controls (not sections): spaced rows, the table stretching."""
        self.body.setContentsMargins(24, 8, 24, 16)
        self.body.setSpacing(8)
        return self.body

    # --- the footer --------------------------------------------------------

    def set_footer_hint(self, text):
        self.footer_hint.setText(text)

    def footer_status(self, label):
        """`label` (a status line the window updates) in the footer, in
        the hint's place."""
        self.footer_hint.hide()
        label.setWordWrap(True)
        self.footer_row.insertWidget(0, label, 1)
        return label

    def add_button(self, button):
        self.footer_row.addWidget(button)
        return button

    def button_box(self, buttons):
        """A QDialogButtonBox of `buttons` in the footer, wired to
        accept/reject."""
        box = QDialogButtonBox(buttons)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        self.footer_row.addWidget(box)
        return box
