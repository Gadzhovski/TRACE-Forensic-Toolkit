"""The kinds of record a LEAPP artifact can be mapped to (no Qt), and how a
mapped row becomes an activity record shaped like TRACE's own.

A LEAPP map (resources/leapp_maps/<tool>.json, read by core/modules/maps)
names, per artifact, a record type here and which of the tool's columns
hold each typed field. The fields are written into the record's `detail`
under **the same keys TRACE's own readers use** (core/activity: mobile,
chat, the browsers) -- `to` / `from`, `name`, `duration`, `chat`,
`title`, `visits`, `ssid`... -- so a call iLEAPP read and one TRACE read
fill the same Activity columns and are matched by the same fields.

This is Autopsy's approach to the LEAPPs (an XML mapping of TSV columns
to its standard artifact types and attributes), on TRACE's records.
"""

import re

#: type -> (Activity category, the record's `what`, allowed fields).
#: `what` may hold {verb}: made / received / missed (calls) or sent /
#: received (messages); the subject is chosen by `subject_of`.
TYPES = {
    'call': ('communication', 'Call {verb}',
             ('party', 'name', 'direction', 'duration', 'answered', 'app',
              'location')),
    'message': ('communication', 'Message {verb}',
                ('party', 'sender', 'text', 'direction', 'thread',
                 'thread_name', 'attachment', 'app')),
    'email': ('communication', 'Email {verb}',
              ('party', 'sender', 'subject', 'text', 'direction', 'thread',
               'attachment', 'app')),
    'contact': ('communication', 'Contact',
                ('name', 'phone', 'email', 'app')),
    'web_visit': ('browser', 'Visited', ('url', 'title', 'visits',
                                         'browser')),
    'web_search': ('searches', 'Searched', ('query', 'url', 'browser')),
    'download': ('downloads', 'Downloaded', ('url', 'path', 'size',
                                              'browser')),
    'bookmark': ('browser', 'Bookmark', ('url', 'title', 'browser')),
    'cookie': ('browser', 'Cookie', ('host', 'name', 'browser')),
    'account': ('accounts', 'Account', ('account', 'service', 'app')),
    'location': ('locations', 'Location', ('name', 'latitude', 'longitude',
                                           'accuracy')),
    'installed_app': ('programs', 'Installed', ('app', 'version',
                                                 'bundle')),
    'app_usage': ('usage', 'App used', ('app', 'seconds')),
    'wifi_network': ('network', 'Wi-Fi network', ('ssid', 'bssid',
                                                  'security')),
    'bluetooth_device': ('network', 'Bluetooth device', ('name', 'mac')),
    'calendar_event': ('calendar', 'Calendar event', ('title', 'start',
                                                      'end', 'location')),
    'note': ('notes', 'Note', ('title', 'text')),
    'keystrokes': ('notes', 'Typed (keyboard cache)', ('text', 'app')),
    'device_info': ('system', 'Device information', ('key', 'value')),
    # Anything else worth a record: the map names its category and what
    # (a root grant, a hidden vault file, a factory reset, an app opened).
    'event': (None, None, ('text', 'app', 'name', 'path', 'size')),
}
#: The categories an 'event' may name (core/activity CATEGORIES).
EVENT_CATEGORIES = ('programs', 'system', 'usage', 'files', 'cloud',
                    'network', 'accounts', 'notes', 'records')

#: Typed field -> the detail key TRACE's own readers use for it.
DETAIL_KEYS = {
    'name': 'name', 'duration': 'duration', 'app': 'app',
    'location': 'location', 'thread': 'chat id', 'thread_name': 'chat',
    'attachment': 'attachment', 'phone': 'phone', 'email': 'email',
    'title': 'title', 'visits': 'visits', 'browser': 'browser',
    'url': 'url', 'path': 'path', 'size': 'size', 'host': 'host',
    'service': 'service', 'version': 'version', 'bundle': 'bundle',
    'seconds': 'seconds', 'ssid': 'ssid', 'bssid': 'BSSID',
    'security': 'security', 'mac': 'mac address', 'start': 'start',
    'end': 'end', 'accuracy': 'accuracy', 'subject': 'subject line',
    'query': 'query', 'account': 'account', 'text': 'text',
}

# Words only: numbers mean different things per source (Android's call
# type 1 is incoming, a "from me" flag's 1 outgoing) -- a map gives those
# in its own `directions` table.
_OUT = re.compile(r'\b(out|outgoing|sent|send|made|dialed|dialled|'
                  r'originated|from me)\b', re.I)
_IN = re.compile(r'\b(in|incoming|received|receive|answered|inbox)\b',
                 re.I)
_MISSED = re.compile(r'\b(missed|rejected|declined|blocked|unanswered)\b',
                     re.I)


def direction(value, table=None):
    """'out', 'in', 'missed' or '' from a tool's direction value; a map's
    own table (`directions`) first."""
    text = ('' if value is None else str(value)).strip()
    if not text:
        return ''
    if table:
        for key, meaning in table.items():
            if key.lower() == text.lower():
                return meaning
    if _MISSED.search(text):
        return 'missed'
    if _OUT.search(text):
        return 'out'
    if _IN.search(text):
        return 'in'
    return ''


def duration_text(value):
    """'1:05' / '1:02:03' (TRACE's calls) from seconds or '00:01:05',
    else as given."""
    text = str(value).strip()
    try:
        if re.fullmatch(r'\d+(:\d{1,2}){1,2}(\.\d+)?', text):
            seconds = 0
            for part in text.split(':'):
                seconds = seconds * 60 + float(part)
            seconds = int(seconds)
        else:
            seconds = int(float(value))
    except (TypeError, ValueError):
        return text
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}:{minutes:02d}:{seconds:02d}" if hours else \
        f"{minutes}:{seconds:02d}"


def build(kind, fields, directions=None, mapping=None):
    """(category, what, subject, typed detail) of one mapped row:
    `fields` {typed field: text}; `mapping` the map entry (an 'event''s
    category and what). The caller adds time, source and the tool's
    remaining columns."""
    category, what, _allowed = TYPES[kind]
    if kind == 'event':
        category = (mapping or {}).get('category') or 'records'
        what = (mapping or {}).get('what') or 'Record'
    elif (mapping or {}).get('what') and kind not in ('call', 'message',
                                                       'email'):
        # The map's own wording: 'Wi-Fi joined', 'Significant location'.
        what = mapping['what']
    way = direction(fields.get('direction'), directions)
    detail = {}
    for field, value in fields.items():
        if value in (None, '') or field in ('direction', 'party', 'sender',
                                            'key', 'value', 'answered'):
            continue
        key = DETAIL_KEYS.get(field, field)
        detail[key] = duration_text(value) if field == 'duration' else value
    party, sender = fields.get('party'), fields.get('sender')
    subject = ''
    if kind == 'call' and way == 'in' and str(
            fields.get('answered', '')).strip().lower() in ('no', '0',
                                                            'false'):
        way = 'missed'          # iOS: an incoming call nobody answered
    if kind == 'call':
        verb = {'out': 'made', 'in': 'received',
                'missed': 'missed'}.get(way, '')
        what = f"Call {verb}".strip() if verb else 'Call'
        if party:
            detail['to' if way == 'out' else 'from'] = party
        subject = party or fields.get('name') or ''
    elif kind in ('message', 'email'):
        verb = {'out': 'sent', 'in': 'received'}.get(way, '')
        noun = 'Email' if kind == 'email' else 'Message'
        what = f"{noun} {verb}".strip()
        if way == 'out':
            if party:
                detail['to'] = party
        else:
            if sender or party:
                detail['from'] = sender or party
            if party and sender and party != sender:
                detail['to'] = party
        if way:
            detail['direction'] = 'sent' if way == 'out' else 'received'
        first = ('subject', 'text') if kind == 'email' else ('text',
                                                              'subject')
        subject = fields.get(first[0]) or fields.get(first[1]) or (
            f"[{fields['attachment']}]" if fields.get('attachment') else '')
    elif kind == 'device_info':
        key, value = fields.get('key'), fields.get('value')
        subject = f"{key}: {value}" if key else str(value or '')
    else:
        order = {'contact': ('name', 'phone', 'email'),
                 'web_visit': ('url', 'title'), 'web_search': ('query',),
                 'download': ('url', 'path'), 'bookmark': ('url', 'title'),
                 'cookie': ('host', 'name'), 'account': ('account',
                                                         'service'),
                 'location': ('name',), 'installed_app': ('app', 'bundle'),
                 'app_usage': ('app',), 'wifi_network': ('ssid', 'bssid'),
                 'bluetooth_device': ('name', 'mac'),
                 'calendar_event': ('title',), 'note': ('title', 'text'),
                 'keystrokes': ('text',),
                 'event': ('text', 'name', 'path', 'app')}.get(kind, ())
        subject = next((str(fields[f]) for f in order if fields.get(f)), '')
    return category, what, str(subject), detail
