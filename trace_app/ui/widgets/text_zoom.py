"""Larger or smaller text in one list or viewer, at once (no restart).

Ctrl + mouse wheel, or Ctrl+= / Ctrl+- / Ctrl+0, over a table, tree, list
or text view steps its text size. The themes size text (QWidget
{ font-size }), so a font set in code would be overridden: the step is a
dynamic property, `textZoom`, which both themes give a font size per step
(attribute selectors outrank the type rules). Table rows grow with the
text, so nothing is clipped.

A step is remembered per kind of view -- its object name, else its class
-- in config.ini [Zoom], and given back when Qt first polishes a view of
that kind: a Listing made larger stays larger. The hex view keeps its own
font size (View ▾ in its toolbar) and is left alone. The whole interface's
size is another matter: Settings ▸ Display, applied at start
(infra/ui_scale.py).
"""

import logging

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import (QAbstractItemView, QAbstractScrollArea,
                               QApplication, QComboBox, QHeaderView,
                               QPlainTextEdit, QTableView, QTextEdit)

from trace_app.infra import config_store

logger = logging.getLogger('TRACE.TextZoom')

#: What can be zoomed.
_VIEWS = (QAbstractItemView, QPlainTextEdit, QTextEdit)
#: The steps there are; the themes size each (styles/*.qss, 'Text zoom').
LOWEST, HIGHEST = -2, 6
PROPERTY = 'textZoom'
_SECTION = 'Zoom'
#: A table row's height above its text's line height.
_ROW_PADDING = 8

_saved = None
_filter = None


def _remembered():
    global _saved
    if _saved is None:
        _saved = {}
        parser = config_store.load()
        if parser.has_section(_SECTION):
            for key, value in parser.items(_SECTION):
                try:
                    _saved[key] = max(LOWEST, min(HIGHEST, int(value)))
                except ValueError:
                    continue
    return _saved


def _remember(key, step):
    saved = _remembered()
    if step:
        saved[key] = step
    else:
        saved.pop(key, None)

    def change(parser):
        if parser.has_section(_SECTION):
            parser.remove_section(_SECTION)
        if saved:
            parser.add_section(_SECTION)
            for name, value in sorted(saved.items()):
                parser.set(_SECTION, name, str(value))
    config_store.update(change)


def kind_of(view):
    """The key a view's step is kept under: its object name, else its
    class (lower case: configparser folds keys)."""
    return (view.objectName() or type(view).__name__).lower()


def zoomable(widget):
    """The list or text view `widget` is (or is the viewport of), or None
    -- not headers, not the hex view."""
    view = widget
    if not isinstance(view, (QAbstractItemView, QPlainTextEdit, QTextEdit)):
        parent = widget.parent() if widget is not None else None
        view = parent if isinstance(parent, QAbstractScrollArea) else None
    if view is None or isinstance(view, QHeaderView) or \
            not isinstance(view, (QAbstractItemView, QPlainTextEdit,
                                  QTextEdit)):
        return None
    ancestor = view
    while ancestor is not None:
        if ancestor.objectName().startswith('hex'):
            return None                     # its own font size
        if isinstance(ancestor, QComboBox):
            return None                     # a drop-down's own list
        ancestor = ancestor.parent()
    return view


def step_of(view):
    try:
        return int(view.property(PROPERTY) or 0)
    except (TypeError, ValueError):
        return 0


def set_step(view, step, remember=True):
    """Put `view` at text zoom `step` (clamped); returns the step."""
    step = max(LOWEST, min(HIGHEST, int(step)))
    if step_of(view) != step:
        # Step 0 is no property at all: the view's own size again.
        view.setProperty(PROPERTY, str(step) if step else None)
        style = view.style()
        style.unpolish(view)
        style.polish(view)
        view.viewport().update()
        _fit_rows(view)
    if remember:
        _remember(kind_of(view), step)
    return step


def _fit_rows(view):
    """A table's rows as tall as its text needs (never shorter than they
    were made)."""
    if not isinstance(view, QTableView):
        return
    header = view.verticalHeader()
    base = view.property('textZoomBaseRow')
    if base is None:
        base = header.defaultSectionSize()
        view.setProperty('textZoomBaseRow', base)
    needed = view.fontMetrics().height() + _ROW_PADDING
    header.setDefaultSectionSize(max(int(base), needed))


def restore(view):
    """The remembered step for a view of this kind (called as Qt polishes
    it)."""
    if view.property(PROPERTY) is not None or zoomable(view) is not view:
        return
    step = _remembered().get(kind_of(view), 0)
    if step:
        set_step(view, step, remember=False)


# The filter sees every event of the application: anything else leaves at
# once (a set lookup; comparing with QEvent's attributes costs 3x as much).
_WATCHED = frozenset((QEvent.Wheel, QEvent.KeyPress, QEvent.Polish))


class _Zoomer(QObject):
    def eventFilter(self, watched, event):
        kind = event.type()
        if kind not in _WATCHED:
            return False
        if kind == QEvent.Wheel and \
                event.modifiers() & Qt.ControlModifier:
            view = zoomable(watched)
            if view is None:
                return False
            delta = event.angleDelta().y()
            if delta:
                set_step(view, step_of(view) + (1 if delta > 0 else -1))
            return True
        if kind == QEvent.KeyPress and \
                event.modifiers() & Qt.ControlModifier:
            key = event.key()
            if key not in (Qt.Key_Equal, Qt.Key_Plus, Qt.Key_Minus,
                           Qt.Key_0):
                return False
            view = zoomable(watched)
            if view is None:
                return False
            if key == Qt.Key_0:
                set_step(view, 0)
            else:
                set_step(view, step_of(view) + (-1 if key == Qt.Key_Minus
                                                else 1))
            return True
        if kind == QEvent.Polish and isinstance(watched, _VIEWS) and                 not isinstance(watched, QHeaderView):
            # Every widget is polished as it is made -- a drop-down's own
            # list among them, half-built: only a kind with a step kept is
            # looked at any further (walking a half-built drop-down's
            # parents crashed).
            saved = _remembered()
            if saved and kind_of(watched) in saved:
                restore(watched)
        return False


def install(app=None):
    """The zoom keys and wheel for every list and text view, once."""
    global _filter
    app = app or QApplication.instance()
    if _filter is None and app is not None:
        _filter = _Zoomer(app)
        app.installEventFilter(_filter)
