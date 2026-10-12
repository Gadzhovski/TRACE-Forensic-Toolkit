"""Message dialogs that match the rest of the application.

Qt's convenience calls -- QMessageBox.warning, .information, .critical,
.question -- supply the platform's own icon set: a blue circled "i", a blue
question mark, a yellow triangle. Those were the last pieces of stock art left
in the window, and they sat oddly beside the themed line icons everywhere else.

These wrappers take the same arguments and behave the same way, but draw their
glyph from the icon registry: Tabler's filled glyph, in one colour per kind
(blue question and information, amber warning, red error). The thin grey
outline used before looked unfinished at dialog size.
They also centre the buttons: Qt right-aligns them, which looks unbalanced in
a small dialog whose text is short.
"""

from PySide6.QtWidgets import QDialogButtonBox, QMessageBox

from trace_app.infra.constants import DIALOG_ICON_SIZE
from trace_app.ui import icons


#: Each kind's glyph and colour; the same in both themes (the glyph's
#: mark is cut out, so it reads on either background).
KINDS = {
    'question': (icons.DIALOG_QUESTION, '#1E88E5'),
    'information': (icons.DIALOG_INFO, '#1E88E5'),
    'warning': (icons.DIALOG_WARNING, '#E3A008'),
    'critical': (icons.DIALOG_ERROR, '#D93025'),
}


def _build(parent, title, text, kind, buttons, default=None, informative=None):
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setText(text)
    if informative:
        box.setInformativeText(informative)
    name, colour = KINDS[kind]
    box.setIconPixmap(icons.icon(name, tint=colour).pixmap(
        DIALOG_ICON_SIZE, DIALOG_ICON_SIZE))
    box.setStandardButtons(buttons)
    if default is not None:
        box.setDefaultButton(default)
    _centre_buttons(box)
    return box


def _centre_buttons(box):
    """Centre the button row.

    QMessageBox lays its buttons out right-aligned. In a wide dialog with one
    or two short buttons that leaves them stranded in a corner, so the row is
    centred instead.
    """
    bar = box.findChild(QDialogButtonBox)
    if bar is None:
        return
    bar.setCenterButtons(True)


def warning(parent, title, text, informative=None):
    """A problem the user should know about, but which is not fatal."""
    return _build(parent, title, text, 'warning',
                  QMessageBox.StandardButton.Ok,
                  informative=informative).exec()


def information(parent, title, text, informative=None):
    """Confirmation that something completed."""
    return _build(parent, title, text, 'information',
                  QMessageBox.StandardButton.Ok,
                  informative=informative).exec()


def critical(parent, title, text, informative=None):
    """An operation failed."""
    return _build(parent, title, text, 'critical',
                  QMessageBox.StandardButton.Ok,
                  informative=informative).exec()


def question(parent, title, text, informative=None,
             default=QMessageBox.StandardButton.No):
    """Ask for confirmation. Returns True for Yes."""
    box = _build(parent, title, text, 'question',
                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                 default=default, informative=informative)
    return box.exec() == QMessageBox.StandardButton.Yes
