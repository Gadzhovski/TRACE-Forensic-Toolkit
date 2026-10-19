"""When two tools read the same record (no Qt).

TRACE's own Activity module and a LEAPP can both read one phone's sms.db,
one browser's history: the same message, the same visit, twice. Both
readings are kept as they were made (custody); the views show such a
record once, naming both readers ("Read by: TRACE, iLEAPP"), and list each
reading in its details. `match_key(row)` says which rows are the same
record; `Case.relink_matches` links them (`user_activity.duplicate_of`).

A key is made only from what both tools record the same way:

* every key starts with the category and the time to the second, in UTC;
  a row whose time is local (no zone) or missing gets no key -- guessing a
  zone would invent an agreement;
* communication: the app (iMessage and SMS one, as on the phone), whether
  it is a call, the direction, and for a message a hash of its text
  (stripped; two tools name senders too differently to compare), for a
  call the other party normalised (last nine digits of a number);
* browser, downloads, searches: the URL (scheme and host lower-cased, no
  trailing slash), else the subject;
* locations: latitude and longitude to five decimals (about a metre);
* anything else: the subject, lower-cased.

Records are matched only within one evidence item, never across two (two
images of one phone are two items: merging them would mix devices).
"""

import hashlib
import re

from trace_app.core import conversations

#: What a reader adds after an app's name: '(iOS)', '(Android)', '(carved)',
#: '(iLEAPP)' -- TRACE's WhatsApp rows say 'WhatsApp (iOS)', iLEAPP's
#: 'WhatsApp'; one app either way.
_APP_SUFFIX = re.compile(r'(\s*\([^()]*\))+\s*$')


def _when(row):
    if row.get('local') or row.get('time_local'):
        return None
    moment = row.get('time') or row.get('time_utc')
    if not moment:
        return None
    text = str(moment).replace('T', ' ')
    return text[:19] if len(text) >= 19 and text[:4].isdigit() else None


def _app(row):
    source = _APP_SUFFIX.sub('', row.get('source') or '')
    return conversations.app_of({'source': source}).lower()


def _digest(text):
    text = re.sub(r'\s+', ' ', str(text or '')).strip()
    return hashlib.sha1(text.encode('utf-8', 'replace')).hexdigest()[:16]


def normalise_url(value):
    value = str(value or '').strip()
    match = re.match(r'([a-z][a-z0-9+.-]*://)([^/?#]+)(.*)', value, re.I)
    if match:
        value = match.group(1).lower() + match.group(2).lower() + \
            match.group(3)
    return value.rstrip('/')


def match_key(row):
    """The record a row is, as a string; None when it cannot be matched."""
    category = row.get('category') or ''
    when = _when(row)
    if not category or when is None:
        return None
    detail = row.get('detail') or {}
    if category == 'communication':
        if not conversations.is_message(row):
            return None                 # contacts, accounts: not events
        kind = conversations.kind_of(row)
        direction = conversations.direction_of(row)
        if kind == 'call':
            party = conversations.normalise_party(
                conversations.party_of(row))
            return '|'.join(('call', _app(row), when, direction, party))
        return '|'.join(('message', _app(row), when, direction,
                         _digest(row.get('subject'))))
    if category in ('browser', 'downloads', 'searches'):
        url = detail.get('url') or detail.get('URL') or ''
        what = normalise_url(url) if url else \
            str(row.get('subject') or '').strip().lower()
        return '|'.join((category, when, what))
    if category == 'locations':
        try:
            latitude = float(detail['latitude'])
            longitude = float(detail['longitude'])
        except (KeyError, TypeError, ValueError):
            return None
        return '|'.join((category, when, f"{latitude:.5f}",
                         f"{longitude:.5f}"))
    return '|'.join((category, when,
                     str(row.get('subject') or '').strip().lower()))
