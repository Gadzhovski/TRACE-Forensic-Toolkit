"""Date-and-time fields with a calendar, drawn in TRACE's style.

The themes draw the field's drop-down button and the calendar it opens
(styles/*.qss, 'Date and time fields'). What a stylesheet cannot reach is
set here: Qt colours Saturday and Sunday red through the calendar's own
text formats, shows ISO week numbers down the side and a grid -- none of
which the rest of the application looks like.
"""

from PySide6.QtCore import QDateTime, Qt, QTimeZone
from PySide6.QtGui import QTextCharFormat
from PySide6.QtWidgets import QCalendarWidget, QDateTimeEdit

FORMAT = "yyyy-MM-dd HH:mm:ss"
#: What the field must show in full, at its widest.
SAMPLE = '8888-88-88 88:88:88'
#: The theme's padding (8 px left, 22 right), the drop-down button over the
#: right padding, the frame, and room so the last digit is never clipped.
CHROME = 72


def tidy_calendar(edit):
    """The calendar `edit` opens, without the platform's red weekends, week
    numbers and grid lines (the theme draws the rest)."""
    calendar = edit.calendarWidget()
    if calendar is None:
        return
    calendar.setGridVisible(False)
    calendar.setVerticalHeaderFormat(QCalendarWidget.NoVerticalHeader)
    calendar.setHorizontalHeaderFormat(QCalendarWidget.ShortDayNames)
    # An empty format: the day takes the theme's text colour, like the rest.
    for day in (Qt.Saturday, Qt.Sunday):
        calendar.setWeekdayTextFormat(day, QTextCharFormat())


def utc_edit(object_name=None, text=None):
    """A date-time field in UTC with a calendar, as wide as a whole time."""
    edit = QDateTimeEdit()
    if object_name:
        edit.setObjectName(object_name)
    edit.setDisplayFormat(FORMAT)
    edit.setTimeZone(QTimeZone.utc())
    edit.setCalendarPopup(True)
    edit.setMinimumDateTime(QDateTime.fromString("1601-01-01 00:00:00",
                                                 FORMAT))
    edit.setFixedWidth(edit.fontMetrics().horizontalAdvance(SAMPLE) + CHROME)
    tidy_calendar(edit)
    if text:
        moment = QDateTime.fromString(text[:19], FORMAT)
        moment.setTimeZone(QTimeZone.utc())
        edit.setDateTime(moment)
    return edit
