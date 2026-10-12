"""Messages and calls as conversations (no Qt).

The activity module reads every messaging source on its own terms --
Skype, iMessage and SMS, WhatsApp on iOS and Android, call logs -- into
`user_activity` rows of category 'communication', each with its own
detail keys (who, which chat). An examiner reads them as conversations:
everything between this phone and that contact, in order, in one place.

`thread_key(row)` says which conversation a row belongs to:

* a group or named chat by its id ('chat id', else 'chat'), per app;
* otherwise the other party ('to' / 'from' / 'partner' / 'address'),
  normalised: phone numbers compared by their last nine digits (so
  +44 7700 900123 and 07700 900123 are one person), e-mail addresses and
  handles lower-cased;
* iMessage and SMS from the same sms.db are one app, as on the phone.

Calls and file transfers join their contact's thread. Contacts and
accounts are not messages; contacts name the numbers. Nothing is stored:
threads are built from the rows each time.
"""

import re
from collections import OrderedDict

#: Rows that are not part of a conversation.
_SKIPPED_PREFIXES = ('Skype account', 'Contact')
#: Apps whose records live in one store on the device.
_SAME_APP = {'iMessage': 'Messages', 'SMS': 'Messages',
             'iOS messages': 'Messages'}
SEPARATOR = '\x1f'
MATCH_DIGITS = 9


def app_of(row):
    source = row.get('source') or ''
    return _SAME_APP.get(source, source)


def kind_of(row):
    what = (row.get('what') or '').lower()
    if 'call' in what:
        return 'call'
    if what.startswith('file '):
        return 'file'
    return 'message'


def direction_of(row):
    """'out', 'in' or '' (a recovered row that does not say)."""
    what = (row.get('what') or '').lower()
    detail = row.get('detail') or {}
    if detail.get('direction') in ('sent', 'received'):
        return 'out' if detail['direction'] == 'sent' else 'in'
    if re.search(r'\b(sent|made|outbox|queued|draft|failed)\b', what):
        return 'out'
    if re.search(r'\b(received|missed|rejected|blocked)\b', what):
        return 'in'
    if detail.get('to') and not detail.get('from'):
        return 'out'
    if detail.get('from'):
        return 'in'
    return ''


def is_message(row):
    if row.get('category') != 'communication':
        return False
    what = row.get('what') or ''
    return not any(what.startswith(p) for p in _SKIPPED_PREFIXES)


def normalise_party(value):
    """A comparable form of a phone number, address or handle ('' for
    none). A list ('a, b') is kept whole, its members sorted."""
    value = str(value or '').strip()
    if not value:
        return ''
    if ',' in value:
        return ', '.join(sorted(filter(None, (normalise_party(part)
                                              for part in value.split(',')))))
    inner = re.search(r'<([^>]+)>', value)
    if inner:
        value = inner.group(1)
    value = value.strip().lower()
    if value.startswith(('tel:', 'sms:', 'mailto:')):
        value = value.split(':', 1)[1]
    if '@' in value and not value.endswith(('@s.whatsapp.net', '@g.us',
                                            '@c.us')):
        return value
    digits = re.sub(r'\D', '', value.split('@', 1)[0])
    if len(digits) >= 6 and re.fullmatch(r'[+\d\s().\-/]+',
                                         value.split('@', 1)[0]):
        return digits[-MATCH_DIGITS:]
    if value.endswith(('@s.whatsapp.net', '@c.us')) and digits:
        return digits[-MATCH_DIGITS:]
    return value


def party_of(row):
    """The other party as written on the row (before normalising)."""
    detail = row.get('detail') or {}
    for key in ('to', 'from', 'partner', 'address', 'host'):
        if detail.get(key):
            return str(detail[key])
    if kind_of(row) == 'call' and row.get('subject'):
        return row['subject']
    return ''


def thread_key(row):
    """The conversation a row belongs to, as a string."""
    detail = row.get('detail') or {}
    app = app_of(row)
    for key in ('chat id', 'chat'):
        if detail.get(key):
            return SEPARATOR.join((app, 'chat', str(detail[key])))
    party = normalise_party(party_of(row))
    return SEPARATOR.join((app, 'party', party or '(unknown)'))


def contact_names(rows):
    """{normalised number or address: name} from contact records and from
    what calls and messages name."""
    names = {}
    for row in rows:
        detail = row.get('detail') or {}
        if (row.get('what') or '').startswith('Contact'):
            for phone in str(detail.get('phone') or '').split(','):
                if normalise_party(phone):
                    names.setdefault(normalise_party(phone),
                                     row.get('subject') or '')
            for address in str(detail.get('email') or '').split(','):
                if normalise_party(address):
                    names.setdefault(normalise_party(address),
                                     row.get('subject') or '')
        elif detail.get('name'):
            party = normalise_party(party_of(row))
            if party:
                names.setdefault(party, detail['name'])
    return {key: name for key, name in names.items() if name}


def _title(key, rows, names):
    app, kind, value = key.split(SEPARATOR, 2)
    if kind == 'chat':
        detail = rows[0].get('detail') or {}
        chat = str(detail.get('chat') or value)
        if chat.endswith(('@s.whatsapp.net', '@c.us')):
            # A one-to-one WhatsApp chat is named by its JID: show the
            # number, and the contact's name where one is known.
            number = '+' + chat.split('@', 1)[0]
            name = names.get(normalise_party(chat))
            return f"{name} ({number})" if name else number
        return chat
    if value == '(unknown)':
        return 'Unknown contact'
    party = party_of(rows[0])
    name = names.get(value)
    return f"{name} ({party})" if name and name not in party else \
        (name or party or value)


def threads(rows):
    """[{'key', 'app', 'title', 'party', 'messages', 'calls', 'files',
    'recovered', 'first', 'last', 'evidence_ids'}], most recent first."""
    names = contact_names(rows)
    grouped = OrderedDict()
    for row in rows:
        if is_message(row):
            grouped.setdefault(thread_key(row), []).append(row)
    out = []
    for key, members in grouped.items():
        stamps = sorted(r['time_utc'] for r in members if r.get('time_utc'))
        kinds = [kind_of(r) for r in members]
        out.append({
            'key': key, 'app': key.split(SEPARATOR, 1)[0],
            'title': _title(key, members, names),
            'party': key.split(SEPARATOR, 2)[2],
            'messages': kinds.count('message'), 'calls': kinds.count('call'),
            'files': kinds.count('file'),
            'recovered': sum(1 for r in members if '(recovered)' in
                             (r.get('what') or '')),
            'first': stamps[0] if stamps else None,
            'last': stamps[-1] if stamps else None,
            'evidence_ids': sorted({r.get('evidence_id') for r in members
                                    if r.get('evidence_id') is not None})})
    out.sort(key=lambda t: t['last'] or '', reverse=True)
    return out


def messages(rows, key):
    """The rows of one conversation, oldest first, each with 'direction'
    and 'kind' added (rows without a time last, in their stored order)."""
    names = contact_names(rows)
    out = []
    for row in rows:
        if is_message(row) and thread_key(row) == key:
            item = dict(row)
            item['direction'] = direction_of(row)
            item['kind'] = kind_of(row)
            item['recovered'] = '(recovered)' in (row.get('what') or '')
            detail = row.get('detail') or {}
            sender = detail.get('from') if item['direction'] == 'in' else ''
            item['sender'] = names.get(normalise_party(sender), sender) \
                if sender else ''
            out.append(item)
    out.sort(key=lambda r: (r.get('time_utc') is None,
                            r.get('time_utc') or '', r.get('id') or 0))
    return out


# --- export -------------------------------------------------------------------

def export(thread, rows, folder):
    """Write the conversation as '<title>.html' and '.csv' in `folder`.
    Returns [(path, sha256)]."""
    import hashlib
    import io
    from trace_app.core.evidence_export import safe_component, unique_path
    name = safe_component(f"{thread['app']} - {thread['title']}",
                          'conversation')
    out = []
    text = io.StringIO()
    to_csv(thread, rows, text)
    for suffix, data in (('.html', to_html(thread, rows).encode('utf-8')),
                         ('.csv', text.getvalue().encode('utf-8-sig'))):
        path = unique_path(folder, name + suffix)
        with open(path, 'wb') as handle:
            handle.write(data)
        out.append((path, hashlib.sha256(data).hexdigest()))
    return out


def to_csv(thread, rows, handle):
    """Write a conversation as CSV (time, direction, kind, sender, text,
    what, source file)."""
    import csv
    writer = csv.writer(handle)
    writer.writerow(['Time (UTC)', 'Direction', 'Kind', 'Sender', 'Text',
                     'Record', 'Source file'])
    for row in rows:
        writer.writerow([row.get('time_utc') or '', row['direction'],
                         row['kind'], row.get('sender') or '',
                         row.get('subject') or '', row.get('what') or '',
                         row.get('source_path') or ''])


def to_html(thread, rows):
    """A conversation as a standalone, escaped HTML page."""
    from html import escape
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        f"<title>{escape(thread['title'])}</title><style>",
        "body{font-family:sans-serif;max-width:760px;margin:24px auto;}",
        ".m{margin:6px 0;padding:8px 10px;border-radius:10px;"
        "max-width:75%;white-space:pre-wrap;}",
        ".in{background:#eceff1;}.out{background:#d7ecff;margin-left:auto;}",
        ".meta{font-size:11px;color:#555;margin-bottom:2px;}",
        ".call{font-style:italic;background:#fff3cd;}",
        "</style></head><body>",
        f"<h1>{escape(thread['title'])}</h1>",
        f"<p>{escape(thread['app'])} -- {len(rows)} item(s), "
        f"{escape(thread['first'] or '?')} to "
        f"{escape(thread['last'] or '?')} (UTC)</p>"]
    for row in rows:
        css = row['direction'] or 'in'
        if row['kind'] != 'message':
            css += ' call'
        meta = ' · '.join(filter(None, (
            row.get('time_utc') or 'no time', row.get('sender'),
            row.get('what'))))
        parts.append(f"<div class='m {css}'><div class='meta'>"
                     f"{escape(meta)}</div>"
                     f"{escape(row.get('subject') or '')}</div>")
    parts.append("</body></html>")
    return ''.join(parts)
