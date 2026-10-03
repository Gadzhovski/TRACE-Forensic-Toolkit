"""Timestamps as Windows, browsers and Apple store them, into UTC datetimes.

Every converter returns None for a value that is zero, negative or out of
range, rather than inventing 1601-01-01 or 1970-01-01: an empty field is not
evidence that something happened at the epoch.
"""

import datetime

UTC = datetime.timezone.utc

_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=UTC)
_UNIX_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=UTC)
_MAC_EPOCH = datetime.datetime(2001, 1, 1, tzinfo=UTC)

#: Anything outside this is a misread field, not a date.
_EARLIEST = datetime.datetime(1980, 1, 1, tzinfo=UTC)
_LATEST = datetime.datetime(2100, 1, 1, tzinfo=UTC)


def _checked(value):
    return value if _EARLIEST <= value < _LATEST else None


def filetime(value):
    """100-nanosecond intervals since 1601 (Windows FILETIME)."""
    if not value or value < 0:
        return None
    try:
        return _checked(_FILETIME_EPOCH
                        + datetime.timedelta(microseconds=value // 10))
    except OverflowError:
        return None


def webkit(value):
    """Microseconds since 1601 (Chrome, Edge and other Chromium browsers)."""
    if not value or value < 0:
        return None
    try:
        return _checked(_FILETIME_EPOCH + datetime.timedelta(microseconds=value))
    except OverflowError:
        return None


def unix_micro(value):
    """Microseconds since 1970 (Firefox's PRTime)."""
    if not value or value < 0:
        return None
    try:
        return _checked(_UNIX_EPOCH + datetime.timedelta(microseconds=value))
    except OverflowError:
        return None


def unix(value):
    """Seconds since 1970."""
    if not value or value < 0:
        return None
    try:
        return _checked(_UNIX_EPOCH + datetime.timedelta(seconds=value))
    except (OverflowError, ValueError):
        return None


def mac_absolute(value):
    """Seconds since 2001 (Safari, Core Data)."""
    if value is None or value <= 0:
        return None
    try:
        return _checked(_MAC_EPOCH + datetime.timedelta(seconds=value))
    except OverflowError:
        return None


def iso(value):
    """'YYYY-MM-DD HH:MM:SS' -- how TRACE writes a UTC time everywhere."""
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(UTC)
    return value.strftime('%Y-%m-%d %H:%M:%S')
