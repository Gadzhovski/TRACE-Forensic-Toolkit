"""Records shown as something other than a table (no Qt).

The Activity tab lists records; most questions an examiner asks of them
are not answered by a list. *When* was this machine used, *which* sites,
programs, people and devices come up most, and what is known about each.
This module turns the rows the tab already holds into those answers:

* `overview(rows, category)` -- records over time (stacked by what the
  category is about), weekday x hour, and the top values of the fields
  that matter for the category (`BREAKDOWNS`);
* `inventory(rows, category)` -- one item per thing the records are
  about (`ITEM_KEYS`: a device, a network, a program, a person, a site),
  with first and last seen, how often, by whom, the facts every record
  of it agrees on, and its activity across the records' span.

Both take TRACE's own rows and the LEAPPs' alike: the bridge writes a
LEAPP's typed fields under TRACE's own detail keys
(core/modules/record_types.DETAIL_KEYS).

What a LEAPP left in its own database (Activity > Others: telemetry, caches,
samples) is charted from that database by SQL (`artifact_shape`,
`series_query`...): iLEAPP's unified log is 21 million rows, which no
Python loop reads in a window's time.

Times are never converted: buckets are the stored digits (UTC, or a
zoneless local time as the source wrote it -- counted, and said).
"""

import collections
import datetime
import os
import re
from urllib.parse import urlsplit

TABLE, CHARTS, ITEMS = 'table', 'charts', 'items'
VIEW_LABELS = {TABLE: "Table", CHARTS: "Charts", ITEMS: "Items"}

#: Values listed in a breakdown; the rest are one "Other" row.
MOST_VALUES = 12
#: Stacks in the over-time chart; the rest share one.
MOST_STACKS = 6
OTHER = '\x00other'
NONE = '\x00none'
#: Buckets in an item's activity strip.
STRIP_BUCKETS = 24
#: Facts on an item: detail values every record of it agrees on.
MOST_FACTS = 6
#: Detail keys that say nothing about the item itself (positions,
#: process ids, the basis of a time...).
_NOT_FACTS = {'basis', 'record position', 'pid', 'message id', 'event id',
              'flags', 'node id', 'order', 'position', 'extra', 'level',
              'group id', 'user id', 'read user id', 'module', 'row',
              'inode', 'window id', 'text', 'value', 'title', 'url',
              'visits', 'visit count', 'visits to this URL', 'count',
              'duration', 'seconds', 'until', 'recorded', 'time',
              'direction', 'to', 'from', 'chat id', 'chat'}

#: (title, field) per category, the first one stacking the over-time
#: chart. Fields: 'what', 'subject', 'user', 'source', 'reader',
#: 'category', computed ones (`value_of`), or 'd:a|b' -- the first
#: detail key present.
BREAKDOWNS = {
    None: (("Categories", 'category'), ("What", 'what'),
           ("Read by", 'reader')),
    'programs': (("Programs", 'program'), ("What", 'what'),
                 ("Users", 'user')),
    'system': (("What", 'what'), ("Reported by", 'd:sender|service|source'),
               ("Users", 'user')),
    'usage': (("Programs", 'program'), ("What", 'what'),
              ("Users", 'user')),
    'antivirus': (("Threats", 'subject'), ("What", 'what'),
                  ("Source", 'source')),
    'files': (("Folders", 'folder'), ("What", 'what'),
              ("File types", 'extension')),
    'usb': (("Devices", 'device'), ("What", 'what'), ("Users", 'user')),
    'recycle': (("Original folders", 'd:original folder|folder'),
                ("File types", 'extension'), ("Users", 'user')),
    'notes': (("What", 'what'), ("Source", 'source'), ("Users", 'user')),
    'browser': (("Sites", 'domain'), ("What", 'what'),
                ("Browsers", 'd:browser|app|source')),
    'downloads': (("Sites", 'domain'), ("File types", 'extension'),
                  ("Browsers", 'd:browser|source')),
    'searches': (("Search terms", 'search'), ("Engines", 'd:engine|domain'),
                 ("Browsers", 'd:browser|source')),
    'logons': (("Accounts", 'account'), ("What", 'what'),
               ("From", 'd:host|address|source address|terminal')),
    'network': (("Networks", 'd:ssid|SSID|subject'), ("What", 'what'),
                ("Security", 'd:security|authentication')),
    'cloud': (("Services", 'source'), ("What", 'what'), ("Users", 'user')),
    'accounts': (("Services", 'd:service|source'), ("What", 'what'),
                 ("Accounts", 'd:account|subject')),
    'communication': (("Apps", 'app'), ("People", 'party'),
                      ("What", 'what')),
    'locations': (("Sources", 'source'), ("What", 'what'),
                  ("Read by", 'reader')),
    'calendar': (("Calendars", 'd:calendar|source'), ("What", 'what'),
                 ("Read by", 'reader')),
    'records': (("What", 'what'), ("Source", 'source'),
                ("Read by", 'reader')),
}

#: What an item is, per category: the field naming it. None: the
#: category has no items worth a card (Map, Conversations, a list of
#: events with nothing in common).
ITEM_KEYS = {
    'programs': 'program', 'usage': 'program', 'usb': 'device',
    'network': 'd:ssid|SSID|subject', 'accounts': 'd:account|subject',
    'cloud': 'subject', 'logons': 'account', 'communication': 'party',
    'browser': 'domain', 'downloads': 'domain', 'searches': 'search',
    'antivirus': 'subject', 'system': 'd:service|sender|subject',
}
#: How an item's title reads: what the cards say they are.
ITEM_NAMES = {
    'programs': 'program', 'usage': 'program', 'usb': 'device',
    'network': 'network', 'accounts': 'account', 'cloud': 'item',
    'logons': 'account', 'communication': 'person', 'browser': 'site',
    'downloads': 'site', 'searches': 'search', 'antivirus': 'threat',
    'system': 'service',
}


def views_for(category):
    """The views a category's tab offers, the table first."""
    views = [TABLE, CHARTS]
    if category in ITEM_KEYS:
        views.append(ITEMS)
    return views


# --- the values a row is grouped by ------------------------------------------

_WINDOWS_PATH = re.compile(r'^[A-Za-z]:[\\/]|^\\\\')


def _detail(row, key):
    if key in ('subject', 'source', 'user', 'what'):
        return row.get(key)
    return (row.get('detail') or {}).get(key)


def _first(row, keys):
    for key in keys:
        if key == 'domain':
            value = _domain(row)
        else:
            value = _detail(row, key)
        if value not in (None, ''):
            return str(value)
    return ''


def _url_of(row):
    detail = row.get('detail') or {}
    for value in (detail.get('url'), row.get('subject')):
        if isinstance(value, str) and '://' in value:
            return value
    return ''


def _domain(row):
    url = _url_of(row)
    if not url:
        return ''
    try:
        host = urlsplit(url.strip()).hostname or ''
    except ValueError:
        return ''
    host = host.lower()
    return host[4:] if host.startswith('www.') else host


def _base_name(path):
    path = str(path or '').strip().strip('"')
    if not path:
        return ''
    return re.split(r'[\\/]', path.rstrip('\\/'))[-1]


def _program(row):
    detail = row.get('detail') or {}
    subject = str(row.get('subject') or '')
    # A path before a display name: macOS's recent items name 'Mail' with
    # the path '/System/Applications/Mail.app' -- the Dock's 'Mail.app'.
    path = subject if ('/' in subject or '\\' in subject) else None
    for value in (detail.get('app'), detail.get('path'), path,
                  detail.get('name'), subject):
        name = _base_name(value)
        if name:
            # 'CHROME.EXE-1A2B3C4D.pf' -> 'CHROME.EXE'
            name = re.sub(r'-[0-9A-F]{8}\.pf$', '', name, flags=re.I)
            return name
    return ''


def _folder(row):
    detail = row.get('detail') or {}
    path = str(detail.get('path') or row.get('subject') or '')
    if not path or ('/' not in path and '\\' not in path):
        return ''
    separator = '\\' if _WINDOWS_PATH.match(path) else '/'
    head = path.replace('/' if separator == '\\' else '\\',
                        separator).rstrip(separator).rsplit(separator, 1)[0]
    return head or separator


def _extension(row):
    detail = row.get('detail') or {}
    for value in (detail.get('path'), detail.get('name'),
                  detail.get('original name'), row.get('subject')):
        name = _base_name(value)
        if '?' in name:
            name = name.split('?', 1)[0]
        if '.' in name.strip('.'):
            extension = name.rsplit('.', 1)[1].lower()
            if 0 < len(extension) <= 8 and extension.isalnum():
                return '.' + extension
    return ''


def _device(row):
    detail = row.get('detail') or {}
    for key in ('friendly name', 'device', 'product', 'name', 'volume',
                'serial', 'serial number'):
        if detail.get(key):
            return str(detail[key])
    return row.get('subject') or ''


def _account(row):
    detail = row.get('detail') or {}
    return str(detail.get('account') or detail.get('user name')
               or row.get('user') or row.get('subject') or '')


def _search(row):
    detail = row.get('detail') or {}
    term = str(detail.get('term') or detail.get('query')
               or row.get('subject') or '').strip()
    return term.lower()


def _party(row):
    from trace_app.core import conversations
    return conversations.normalise_party(conversations.party_of(row))


def value_of(row, field):
    """The value of `field` (a BREAKDOWNS / ITEM_KEYS field) on a row, ''
    when it has none."""
    if field == 'category':
        return row.get('category') or ''
    if field == 'reader':
        from trace_app.core import conversations
        return conversations.readers_text(row)
    if field == 'app':
        from trace_app.core import conversations
        return conversations.app_of(row)
    if field == 'party':
        return _party(row)
    if field == 'domain':
        return _domain(row)
    if field == 'program':
        return _program(row)
    if field == 'folder':
        return _folder(row)
    if field == 'extension':
        return _extension(row)
    if field == 'device':
        return _device(row)
    if field == 'account':
        return _account(row)
    if field == 'search':
        return _search(row)
    if field.startswith('d:'):
        return _first(row, field[2:].split('|'))
    value = row.get(field)
    return '' if value is None else str(value)


def _fold(value):
    """The key a value is grouped under: case and spacing do not matter."""
    return ' '.join(str(value).split()).lower()


# --- times ----------------------------------------------------------------------

_UNITS = (('hour', 13), ('day', 10), ('month', 7), ('year', 4))
#: Most buckets an over-time chart has; the unit is the finest within it.
MOST_BUCKETS = 120


def _parse(text):
    try:
        return datetime.datetime.strptime(text[:19], '%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError):
        try:
            return datetime.datetime.strptime(text[:10], '%Y-%m-%d')
        except (TypeError, ValueError):
            return None


def _usable(time):
    """A stored time worth charting: 1970 and 1601 are what a zeroed
    field reads as, and they would stretch every axis to them."""
    return bool(time) and len(time) >= 10 and '1980' <= time[:4] <= '2100'


def bucket_unit(first, last, most=MOST_BUCKETS):
    """'hour' | 'day' | 'month' | 'year': the finest whose buckets
    between `first` and `last` (time texts) number at most `most`."""
    start, end = _parse(first), _parse(last)
    if start is None or end is None:
        return 'day'
    span = max((end - start).total_seconds(), 1)
    for unit, seconds in (('hour', 3600), ('day', 86400),
                          ('month', 30.44 * 86400),
                          ('year', 365.25 * 86400)):
        if span / seconds <= most:
            return unit
    return 'year'


def _prefix(unit):
    return dict(_UNITS)[unit]


def bucket_start(prefix, unit):
    """A bucket's prefix ('2024-03') as the datetime it starts at."""
    if unit == 'year':
        return datetime.datetime(int(prefix), 1, 1)
    if unit == 'month':
        return datetime.datetime(int(prefix[:4]), int(prefix[5:7]), 1)
    if unit == 'day':
        return datetime.datetime.strptime(prefix, '%Y-%m-%d')
    return datetime.datetime.strptime(prefix, '%Y-%m-%d %H')


def bucket_end(start, unit):
    if unit == 'year':
        return start.replace(year=start.year + 1)
    if unit == 'month':
        return (start.replace(day=28) + datetime.timedelta(days=4)) \
            .replace(day=1)
    if unit == 'day':
        return start + datetime.timedelta(days=1)
    return start + datetime.timedelta(hours=1)


# --- the overview -----------------------------------------------------------------

def overview(rows, category=None, zone=None):
    """What the Charts view draws for `rows` of `category`:

    {'total', 'timed', 'local' (zoneless times among them), 'untimed',
     'unit', 'first', 'last',
     'buckets': [(prefix, {stack: count})] in time order,
     'stacks': [(stack key, label)] (busiest first, OTHER last),
     'stack_field': the field stacked by,
     'grid': weekday x hour counts (timeline.weekday_hours, in `zone`),
     'hours': {(weekday, hour): {row ids}},
     'breakdowns': [(title, field, [(key, label, count)], others)],
     'ids': {(field, key): [row ids]}, {('bucket', prefix): [...]} }

    Row ids are the rows' 'id'; a chart's click narrows the table to them.
    """
    from trace_app.core.activity import CATEGORIES
    names = dict(CATEGORIES)
    specs = BREAKDOWNS.get(category, BREAKDOWNS[None])
    counters = [collections.Counter() for _spec in specs]
    labels = [{} for _spec in specs]
    ids = collections.defaultdict(list)
    folded = {'': NONE}
    timed = []
    local = untimed = 0
    for row in rows:
        row_id = row.get('id')
        values = []
        for number, (_title, field) in enumerate(specs):
            value = value_of(row, field)
            key = folded.get(value)
            if key is None:
                key = folded[value] = _fold(value)
            counters[number][key] += 1
            if key not in labels[number]:
                labels[number][key] = (names.get(value, value)
                                       if field == 'category' else value) \
                    or "(none)"
            ids[(field, key)].append(row_id)
            values.append(key)
        time = row.get('time_utc') or ''
        if _usable(time):
            timed.append((time, values[0], row_id, bool(row.get('time_local'))))
            if row.get('time_local'):
                local += 1
        else:
            untimed += 1
    breakdowns = []
    for (title, field), counter, names in zip(specs, counters, labels):
        top = counter.most_common(MOST_VALUES)
        others = sum(counter.values()) - sum(n for _k, n in top)
        breakdowns.append((title, field,
                           [(key, names[key], n) for key, n in top], others))
    result = {'total': len(rows), 'timed': len(timed), 'local': local,
              'untimed': untimed, 'unit': 'day', 'first': '', 'last': '',
              'buckets': [], 'stacks': [], 'stack_field': specs[0][1],
              'grid': None, 'hours': {}, 'breakdowns': breakdowns}
    if timed:
        timed.sort()
        first, last = timed[0][0], timed[-1][0]
        unit = bucket_unit(first, last)
        width = _prefix(unit)
        stack_counts = counters[0]
        # Rows naming nothing are a stack of their own, last: "(none)"
        # in the busiest colour read as the busiest value.
        stack_keys = [k for k, _n in stack_counts.most_common(MOST_STACKS + 1)
                      if k != NONE][:MOST_STACKS]
        chosen = set(stack_keys) | {NONE}
        buckets = collections.OrderedDict()
        hours = collections.Counter()
        hour_ids = collections.defaultdict(list)
        for time, stack, row_id, is_local in timed:
            prefix = time[:width]
            stack = stack if stack in chosen else OTHER
            buckets.setdefault(prefix, collections.Counter())[stack] += 1
            ids[('bucket', prefix)].append(row_id)
            hours[(time[:13], is_local)] += 1
            hour_ids[(time[:13], is_local)].append(row_id)
        for extra in (OTHER, NONE):
            if any(extra in counts for counts in buckets.values()):
                stack_keys.append(extra)
        from trace_app.core import timeline
        grid, cells = timeline.weekday_hours(
            [(prefix, int(is_local), number)
             for (prefix, is_local), number in hours.items()], zone)
        cell_ids = {}
        for cell, prefixes in cells.items():
            members = []
            for prefix in prefixes:
                for is_local in (False, True):
                    members += hour_ids.get((prefix, is_local), [])
            cell_ids[cell] = members
        result.update(
            unit=unit, first=first, last=last,
            buckets=[(prefix, dict(counts))
                     for prefix, counts in buckets.items()],
            stacks=[(key, "Other" if key == OTHER else labels[0][key])
                    for key in stack_keys],
            grid=grid, hours=cell_ids)
    result['ids'] = dict(ids)
    return result


# --- items ------------------------------------------------------------------------

def inventory(rows, category):
    """One item per thing `rows` of `category` are about (ITEM_KEYS):

    [{'key', 'title', 'subtitle', 'count', 'first', 'last', 'local',
      'whats': [(what, n)], 'users', 'readers', 'evidence' (ids),
      'facts': [(key, value)], 'strip': [counts over the span],
      'ids': [row ids], 'latest': the newest row}]

    busiest first. The strip spans every item's records alike, so two
    cards' strips compare. Rows naming nothing (no value) are left out
    and counted by `unnamed`."""
    field = ITEM_KEYS.get(category)
    if field is None:
        return []
    names = {}
    if category == 'communication':
        from trace_app.core import conversations
        names = conversations.contact_names(rows)
    groups = collections.OrderedDict()
    for row in rows:
        value = value_of(row, field)
        if not value:
            continue
        groups.setdefault(_fold(value), []).append((value, row))
    times = [r.get('time_utc') for members in groups.values()
             for _v, r in members if _usable(r.get('time_utc') or '')]
    span = (_parse(min(times)), _parse(max(times))) if times else None
    items = []
    for key, members in groups.items():
        items.append(_item(key, members, category, names, span))
    items.sort(key=lambda item: (-item['count'], item['title'].lower()))
    return items


def unnamed(rows, category):
    """Rows of `category` that name no item."""
    field = ITEM_KEYS.get(category)
    return 0 if field is None else sum(
        1 for row in rows if not value_of(row, field))


def _item(key, members, category, names, span):
    from trace_app.core import conversations
    shown = collections.Counter(value for value, _row in members)
    title = shown.most_common(1)[0][0]
    subtitle = ''
    if category == 'communication':
        party = conversations.party_of(members[0][1])
        name = names.get(key)
        title, subtitle = (name, party) if name else (party or title, '')
        apps = collections.Counter(conversations.app_of(row)
                                   for _v, row in members)
        subtitle = ' · '.join(filter(None, (subtitle, ', '.join(
            app for app, _n in apps.most_common(3)))))
    elif category in ('browser', 'downloads'):
        visits = 0
        for _value, row in members:
            detail = row.get('detail') or {}
            for field in ('visits', 'visit count', 'visits to this URL'):
                try:
                    visits += int(detail.get(field) or 0)
                    break
                except (TypeError, ValueError):
                    continue
        pages = len({_url_of(row) for _v, row in members} - {''})
        subtitle = f"{pages:,} page(s)" + (f", {visits:,} visit(s) counted"
                                          if visits else '')
    elif category in ('programs', 'usage'):
        paths = collections.Counter(
            str((row.get('detail') or {}).get('path') or row.get('subject')
                or '') for _v, row in members)
        best = next((path for path, _n in paths.most_common()
                     if path and path != title), '')
        subtitle = best
    rows = [row for _value, row in members]
    timed = sorted(((row.get('time_utc'), row) for row in rows
                    if _usable(row.get('time_utc') or '')),
                   key=lambda pair: pair[0])
    whats = collections.Counter(row.get('what') or '' for row in rows)
    users = sorted({row.get('user') for row in rows if row.get('user')})
    readers = sorted({reader for row in rows
                      for reader in conversations.readers_of(row)},
                     key=lambda r: (r != 'TRACE', r))
    evidence = sorted({row.get('evidence_id') for row in rows
                       if row.get('evidence_id') is not None})
    item = {'key': key, 'title': title or "(unnamed)", 'subtitle': subtitle,
            'count': len(rows),
            'first': timed[0][0] if timed else '',
            'last': timed[-1][0] if timed else '',
            'local': any(row.get('time_local') for _t, row in timed),
            'whats': [(w, n) for w, n in whats.most_common() if w],
            'users': users, 'readers': readers, 'evidence': evidence,
            'facts': _facts(rows), 'strip': _strip(timed, span),
            'ids': [row.get('id') for row in rows],
            'latest': timed[-1][1] if timed else rows[0]}
    if category == 'usage':
        seconds = 0.0
        for row in rows:
            try:
                seconds += float((row.get('detail') or {}).get('seconds')
                                 or 0)
            except (TypeError, ValueError):
                pass
        if seconds:
            item['facts'].insert(0, ('time in use', duration_text(seconds)))
    return item


def _facts(rows):
    """Detail values every row holding the key agrees on, the most widely
    held first -- what the records say about the item itself."""
    values = collections.defaultdict(set)
    held = collections.Counter()
    for row in rows:
        for key, value in (row.get('detail') or {}).items():
            if key in _NOT_FACTS or value in (None, '') or \
                    isinstance(value, (dict, list)):
                continue
            text = str(value)
            if len(text) > 120:
                continue
            values[key].add(text)
            held[key] += 1
    facts = [(key, next(iter(values[key]))) for key, _n in held.most_common()
             if len(values[key]) == 1]
    return facts[:MOST_FACTS]


def _strip(timed, span):
    if not timed or span is None or span[0] is None or span[1] is None:
        return []
    start, end = span
    width = max((end - start).total_seconds(), 1)
    counts = [0] * STRIP_BUCKETS
    for time, _row in timed:
        moment = _parse(time)
        if moment is None:
            continue
        index = int((moment - start).total_seconds() / width * STRIP_BUCKETS)
        counts[min(STRIP_BUCKETS - 1, max(0, index))] += 1
    return counts


def duration_text(seconds):
    """'2 h 05 min', '4 min 10 s', '12 s'."""
    seconds = int(round(seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours:,} h {minutes:02d} min"
    if minutes:
        return f"{minutes} min {secs:02d} s"
    return f"{secs} s"


# --- a LEAPP's own tables -----------------------------------------------------------

#: Column names that hold numbers which are not measurements.
_IDENTIFIER = re.compile(
    r'\b(id|ids|rowid|pid|uid|gid|pk|zpk|key|uuid|guid|buid|hash|index|'
    r'version|build|port|serial|imei|iccid|bundle|code|type|flags?|'
    r'latitude|longitude|lat|lon|lng|row|number|zone|offset|identifier|'
    r'mcc|mnc|lac|cid|ci|tac|bssid|channel)\b', re.I)
#: Number columns that are not measurements: who, what code, which item.
_NOT_MEASURE = re.compile(
    r'\b(address|partner|user|sender|party|recipient|name|file|filename|'
    r'token|phone|zpk|tid|order|position|category|status|state|kind|'
    r'reason|capabilities|tile|edge|event|algorithm|year|from me|read|'
    r'is|has|enabled|deleted|private|hidden|visible|unread|blacklisted|'
    r'opened|generic|person|location|orientation|scale|width|height|'
    r'mask|score|confidence|altitude|minimum|maximum)\b|'
    r'\(as stored\)|\?', re.I)
#: Number columns that are measurements: charted first.
_MEASURE = re.compile(
    r'level|percent|%|bytes|\bsize\b|count|duration|seconds|minutes|'
    r'\btime\b|steps|distance|rate|heart|weight|calories|brightness|'
    r'speed|amount|length|pages|delay|battery|floors|worn|packets|'
    r'\bkb\b|\bmb\b|accuracy|\bms\b|\(s\)|lux|nits|runtime', re.I)
#: Text that is a number ('87', '-3.5', '12 %').
_NUMERIC_TEXT = re.compile(r'^\s*[-+]?\d+(\.\d+)?\s*%?\s*$')
#: Text columns a chart is not split by: paths, free text, people.
_NOT_LABEL = re.compile(r'\b(path|file|files|text|message|body|url|title|'
                        r'address|name|phone|number|email|recipient|sender|'
                        r'subject|data|value|note|description)\b', re.I)
#: Text columns that say what kind of row it is: split by them first.
_GOOD_LABEL = re.compile(r'\b(type|event|kind|state|status|direction|'
                         r'action|category|app|package|process|source|'
                         r'tag|level|reason|mode)\b', re.I)
#: A pair of time columns that bound an interval ('Start' / 'End').
_START = re.compile(r'\b(start|started|starts|begin|began|from)\b', re.I)
_END = re.compile(r'\b(end|ends|ended|stop|stopped|until|finish|finished)\b',
                  re.I)
#: Rows sampled to judge a column.
SAMPLE_ROWS = 400
#: Distinct values a column may have to stack a chart by.
MOST_LABELS = 40
#: Intervals drawn one by one; past it, the chart says so.
MOST_INTERVALS = 20000
#: Buckets a series is averaged into.
SERIES_BUCKETS = 600


def _quoted(name):
    return '"' + str(name).replace('"', '""') + '"'


def _seconds_sql(column):
    """SQL for a LAVA time column as epoch seconds (datetime is epoch
    already; a date 'YYYY-MM-DD' is converted)."""
    name = _quoted(column['name'])
    if column.get('type') == 'date':
        return f"((julianday({name}) - 2440587.5) * 86400.0)"
    return f"(CASE WHEN typeof({name}) IN ('integer', 'real') " \
           f"THEN {name} END)"


def _value_sql(column):
    """SQL for a column's number, NULL where it holds none -- numbers
    stored as numbers or as text ('87', '12.5 %')."""
    name = _quoted(column['name'])
    bare = f"trim(CAST({name} AS TEXT), ' %')"
    return (f"(CASE WHEN typeof({name}) IN ('integer', 'real') THEN {name} "
            f"WHEN typeof({name}) = 'text' AND {bare} <> '' AND "
            f"{bare} NOT GLOB '*[^0-9.+-]*' AND {bare} GLOB '*[0-9]*' "
            f"THEN CAST({bare} AS REAL) END)")


def _words(column):
    """A column's name and label as words: 'ZENDDATE' stays one, but
    'end_time' and 'endTime' read 'end time'."""
    text = f"{column['name']} {column.get('label') or ''}"
    text = re.sub(r'([a-z])([A-Z])', r'\1 \2', text)
    return text.replace('_', ' ')


def artifact_shape(connection, artifact):
    """How a LEAPP artifact can be charted, judged from its column types
    and a sample of its rows:

    {'kind': 'series' | 'intervals' | 'counts' | None,
     'time': column, 'end': column (intervals), 'numbers': [columns],
     'labels': [columns] (text with few values), 'why': text}

    'series' -- a time and a measurement (battery level, steps, heart
    rate, bytes); 'intervals' -- a start and an end (screen on, locked,
    app in use); 'counts' -- a time only (events: how many when)."""
    columns = artifact.get('columns') or []
    times = [c for c in columns if c.get('type') in ('datetime', 'date')]
    if not times:
        return {'kind': None, 'why': "The tool marks no column of this "
                                     "artifact as a time."}
    table = _quoted(artifact['tablename'])
    others = [c for c in columns if c not in times
              and c.get('type') != 'media']
    numbers, labels = [], []
    if others:
        select = ', '.join(f"typeof({_quoted(c['name'])}), "
                           f"{_quoted(c['name'])}" for c in others)
        try:
            sample = connection.execute(
                f"SELECT {select} FROM {table} LIMIT {SAMPLE_ROWS}"
            ).fetchall()
        except Exception:
            sample = []
        for number, column in enumerate(others):
            kinds = [row[number * 2] for row in sample]
            values = [row[number * 2 + 1] for row in sample]
            filled = [v for k, v in zip(kinds, values) if k != 'null'
                      and v != '']
            if not filled:
                continue
            # The LEAPPs write many numbers as text ('87', '12.5').
            numeric = sum(1 for k, v in zip(kinds, values)
                          if k in ('integer', 'real') or
                          (k == 'text' and _NUMERIC_TEXT.match(v)))
            name = _words(column)
            identifier = _IDENTIFIER.search(name)
            distinct_numbers = {str(v).strip() for v in filled}
            if numeric >= 0.9 * len(filled):
                # Not a flag (0/1), an identifier or a stored code -- a
                # quantity, the measurements first.
                measure = _MEASURE.search(name)
                if len(distinct_numbers) > 1 and not identifier and \
                        not distinct_numbers <= {'0', '1', '0.0', '1.0'} \
                        and (measure or not _NOT_MEASURE.search(name)):
                    numbers.append((0 if measure else 1, len(numbers),
                                    column))
            elif numeric < 0.5 * len(filled) and (
                    _GOOD_LABEL.search(name) or
                    not (identifier or _NOT_LABEL.search(name))):
                # 'Event Type' says what a row is; 'Type' as a word of an
                # identifier rule is meant for numbers and codes.
                distinct = len({str(v) for v in filled})
                if 1 < distinct <= MOST_LABELS and \
                        max(len(str(v)) for v in filled) <= 80:
                    # Columns saying what kind of row it is first, then
                    # the fewest values.
                    labels.append((0 if _GOOD_LABEL.search(name) else 1,
                                   distinct, column))
    labels = [column for _g, _n, column in
              sorted(labels, key=lambda d: d[:2])]
    measured = any(rank == 0 for rank, _n, _c in numbers)
    numbers = [column for _r, _n, column in sorted(numbers,
                                                   key=lambda d: d[:2])]
    end = next((c for c in times if _END.search(_words(c))), None)
    start = next((c for c in times if c is not end and
                  _START.search(_words(c))),
                 next((c for c in times if c is not end), None))
    if start is None:
        start, end = end, None
    # A measurement (steps, battery level) is what such rows are for; a
    # span is next; a count of rows is always there.
    kinds = (['series'] if measured else []) + \
        (['intervals'] if end is not None else []) + \
        (['series'] if numbers and not measured else []) + ['counts']
    shape = {'time': start, 'end': end, 'numbers': numbers,
             'labels': labels, 'kinds': kinds}
    if measured:
        shape.update(kind='series',
                     why=f"'{numbers[0]['label']}' over "
                         f"'{start['label']}'")
    elif end is not None:
        shape.update(kind='intervals',
                     why=f"From '{start['label']}' to '{end['label']}'"
                         + (f", by '{labels[0]['label']}'" if labels else ''))
    elif numbers:
        shape.update(kind='series',
                     why=f"'{numbers[0]['label']}' over "
                         f"'{start['label']}'")
    else:
        shape.update(kind='counts',
                     why=f"Rows over '{start['label']}'"
                         + (f", by '{labels[0]['label']}'" if labels else ''))
    return shape


def time_range(connection, artifact, column):
    """(first, last, rows with a time) of a time column, epoch seconds."""
    seconds = _seconds_sql(column)
    table = _quoted(artifact['tablename'])
    first, last, count = connection.execute(
        f"SELECT MIN(s), MAX(s), COUNT(s) FROM (SELECT {seconds} AS s "
        f"FROM {table}) WHERE s BETWEEN 315532800 AND 4102444800"
    ).fetchone()
    return first, last, count or 0


def _bucket_seconds(first, last, buckets):
    span = max((last or 0) - (first or 0), 1)
    for step in (1, 5, 10, 30, 60, 300, 600, 900, 1800, 3600, 3 * 3600,
                 6 * 3600, 12 * 3600, 86400, 7 * 86400, 30 * 86400,
                 91 * 86400, 365 * 86400):
        if span / step <= buckets:
            return step
    return 365 * 86400


def series_query(connection, artifact, time_column, value_column,
                 buckets=SERIES_BUCKETS):
    """A measurement over time, averaged per bucket:
    {'step', 'points': [(bucket start, count, mean, low, high)],
     'rows', 'first', 'last'} -- epoch seconds."""
    first, last, count = time_range(connection, artifact, time_column)
    if not count:
        return {'step': 0, 'points': [], 'rows': 0, 'first': None,
                'last': None}
    step = _bucket_seconds(first, last, buckets)
    seconds = _seconds_sql(time_column)
    value = _value_sql(value_column)
    table = _quoted(artifact['tablename'])
    points = connection.execute(
        f"SELECT CAST(s / {step} AS INTEGER) * {step} AS b, COUNT(v), "
        f"AVG(v), MIN(v), MAX(v) FROM (SELECT {seconds} AS s, "
        f"{value} AS v FROM {table}) WHERE s BETWEEN 315532800 AND 4102444800 "
        f"AND v IS NOT NULL GROUP BY b ORDER BY b").fetchall()
    return {'step': step, 'points': [tuple(p) for p in points],
            'rows': sum(p[1] for p in points), 'first': first,
            'last': last}


def counts_query(connection, artifact, time_column, label_column=None,
                 buckets=200):
    """Rows per bucket, stacked by a label column's busiest values:
    {'step', 'labels': [label], 'buckets': [(start, {label: n})],
     'rows', 'first', 'last'}."""
    first, last, count = time_range(connection, artifact, time_column)
    result = {'step': 0, 'labels': [], 'buckets': [], 'rows': 0,
              'first': first, 'last': last}
    if not count:
        return result
    step = _bucket_seconds(first, last, buckets)
    seconds = _seconds_sql(time_column)
    table = _quoted(artifact['tablename'])
    label = "''"
    labels = []
    if label_column is not None:
        name = _quoted(label_column['name'])
        labels = [str(row[0]) for row in connection.execute(
            f"SELECT {name}, COUNT(*) AS n FROM {table} GROUP BY {name} "
            f"ORDER BY n DESC LIMIT {MOST_STACKS}") if row[0] not in
            (None, '')]
        label = f"CAST({name} AS TEXT)"
    grouped = collections.OrderedDict()
    for bucket, value, number in connection.execute(
            f"SELECT CAST(s / {step} AS INTEGER) * {step} AS b, l, COUNT(*) "
            f"FROM (SELECT {seconds} AS s, {label} AS l FROM {table}) "
            f"WHERE s BETWEEN 315532800 AND 4102444800 GROUP BY b, l "
            f"ORDER BY b"):
        key = (value if value in labels else OTHER) if labels else ''
        counts = grouped.setdefault(bucket, collections.Counter())
        counts[key] += number
    if labels and any(OTHER in c for c in grouped.values()):
        labels.append(OTHER)
    result.update(step=step, labels=labels or [''],
                  buckets=[(b, dict(c)) for b, c in grouped.items()],
                  rows=sum(sum(c.values()) for c in grouped.values()))
    return result


def intervals_query(connection, artifact, start_column, end_column,
                    label_column=None, most=MOST_INTERVALS):
    """[(start, end, label, rowid)] epoch seconds, by start, and how many
    the artifact has: (intervals, total). An end before its start, or
    none, is a moment (end = start)."""
    start = _seconds_sql(start_column)
    end = _seconds_sql(end_column)
    table = _quoted(artifact['tablename'])
    label = f"CAST({_quoted(label_column['name'])} AS TEXT)" \
        if label_column is not None else "''"
    total = connection.execute(
        f"SELECT COUNT(*) FROM (SELECT {start} AS s FROM {table}) "
        f"WHERE s BETWEEN 315532800 AND 4102444800").fetchone()[0]
    rows = connection.execute(
        f"SELECT s, e, l, r FROM (SELECT {start} AS s, {end} AS e, "
        f"{label} AS l, rowid AS r FROM {table}) "
        f"WHERE s BETWEEN 315532800 AND 4102444800 ORDER BY s "
        f"LIMIT {int(most)}").fetchall()
    out = []
    for s, e, l, r in rows:
        if e is None or e < s or e > s + 366 * 86400:
            e = s
        out.append((s, e, '' if l is None else str(l), r))
    return out, total


def epoch_text(seconds):
    """Epoch seconds as TRACE writes UTC times."""
    try:
        return datetime.datetime.fromtimestamp(
            float(seconds), datetime.timezone.utc).strftime(
            '%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError, OverflowError, OSError):
        return ''


def number_text(value):
    """A measurement for a label: whole numbers grouped, others to three
    significant places past the point."""
    if value is None:
        return ''
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    if number == int(number) and abs(number) < 1e15:
        return f"{int(number):,}"
    if abs(number) >= 100:
        return f"{number:,.1f}"
    return f"{number:.3g}"


def chart_file_name(title):
    """A file name for a saved chart picture."""
    name = re.sub(r'[^\w\- .()]+', '_', title).strip(' ._') or 'chart'
    return os.path.basename(name)[:120] + '.png'
