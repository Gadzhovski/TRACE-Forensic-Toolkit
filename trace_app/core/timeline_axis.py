"""Time-axis ticks on calendar boundaries, shared by the Timeline's
histogram and its Lanes view. No widgets."""

#: Tick steps, finest first: (unit, count, label format).
_TICK_STEPS = (
    ('second', 1, '%H:%M:%S'), ('second', 5, '%H:%M:%S'),
    ('second', 15, '%H:%M:%S'), ('second', 30, '%H:%M:%S'),
    ('minute', 1, '%H:%M'), ('minute', 5, '%H:%M'), ('minute', 15, '%H:%M'),
    ('minute', 30, '%H:%M'), ('hour', 1, '%m-%d %H:00'),
    ('hour', 3, '%m-%d %H:00'), ('hour', 6, '%m-%d %H:00'),
    ('hour', 12, '%m-%d %H:00'), ('day', 1, '%Y-%m-%d'),
    ('day', 2, '%Y-%m-%d'), ('day', 7, '%Y-%m-%d'), ('day', 14, '%Y-%m-%d'),
    ('month', 1, '%Y-%m'), ('month', 3, '%Y-%m'), ('month', 6, '%Y-%m'),
    ('year', 1, '%Y'), ('year', 2, '%Y'), ('year', 5, '%Y'),
    ('year', 10, '%Y'), ('year', 20, '%Y'), ('year', 50, '%Y'),
    ('year', 100, '%Y'))
_STEP_SECONDS = {'second': 1, 'minute': 60, 'hour': 3600, 'day': 86400,
                 'month': 30.44 * 86400, 'year': 365.25 * 86400}


def calendar_ticks(start, end, most):
    """[(moment, label)] on calendar boundaries between `start` and `end`
    (datetimes): the finest step giving at most `most` ticks -- whole
    years, quarters, months, days, hours..., not arbitrary fractions."""
    import datetime
    if start is None or end is None or end <= start:
        return []
    span = (end - start).total_seconds()
    for unit, count, fmt in _TICK_STEPS:
        if span / (_STEP_SECONDS[unit] * count) <= most:
            break
    ticks = []
    if unit == 'year':
        year = (start.year // count) * count
        while True:
            try:
                moment = datetime.datetime(year, 1, 1)
            except ValueError:
                break
            if moment > end:
                break
            if moment >= start:
                ticks.append((moment, moment.strftime(fmt)))
            year += count
    elif unit == 'month':
        index = start.year * 12 + start.month - 1
        index -= index % count
        while True:
            year, month = divmod(index, 12)
            try:
                moment = datetime.datetime(year, month + 1, 1)
            except ValueError:
                break
            if moment > end:
                break
            if moment >= start:
                ticks.append((moment, moment.strftime(fmt)))
            index += count
    else:
        step = datetime.timedelta(seconds=_STEP_SECONDS[unit] * count)
        base = datetime.datetime(start.year, start.month, start.day)
        if unit == 'day':
            # Weeks start on Mondays.
            if count == 7 or count == 14:
                base -= datetime.timedelta(days=base.weekday())
        moment = base
        while moment < start:
            moment += step
        while moment <= end and len(ticks) < most * 3:
            ticks.append((moment, moment.strftime(fmt)))
            moment += step
    return ticks
