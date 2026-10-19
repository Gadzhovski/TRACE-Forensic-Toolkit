"""Windows FILETIME (100-nanosecond intervals since 1601-01-01 UTC) as a
datetime, with no judgement of the value.

The readers differ in what they accept: `activity.times.filetime` drops
anything outside 1980-2100 (an empty or misread field is not an event),
NTFS keeps 1601 and all seven decimals (core/ntfs.filetime_text: they are
evidence), the hex inspector asks whether a value is plausible. This is
the conversion they share; the judgement stays with each."""

import datetime

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def filetime_datetime(value: int | None) -> datetime.datetime | None:
    """The UTC datetime of a FILETIME, to the microsecond; None for 0 or
    a value no datetime holds."""
    if not value:
        return None
    try:
        return FILETIME_EPOCH + datetime.timedelta(microseconds=value // 10)
    except (OverflowError, ValueError):
        return None


def filetime_text(value: int | None) -> str | None:
    """'YYYY-MM-DD HH:MM:SS' (UTC) of a FILETIME, None as above."""
    moment = filetime_datetime(value)
    return moment.strftime('%Y-%m-%d %H:%M:%S') if moment else None
