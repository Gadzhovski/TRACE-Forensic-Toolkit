"""Deleted messages and history entries, recovered from the databases the
activity readers already read (core/sqlite_recover.py).

For the tables an examiner reads activity from -- Skype's Messages,
iMessage's message, Android's sms, Chrome's urls, Firefox's moz_places --
a recovered record becomes an activity record of its own, marked as
deleted and saying where in the database it was found. A record whose
values were partly overwritten is shown with what survived.
"""

import logging

from trace_app.core.activity import record, times

logger = logging.getLogger('TRACE.Activity.Recovered')


def _values(row):
    return dict(zip(row['columns'], row['values']))


def _skype(row, base):
    from trace_app.core.activity.chat import _plain
    v = _values(row)
    text = _plain(v.get('body_xml') or '')
    if not text:
        return None
    sender = v.get('from_dispname') or v.get('author') or ''
    return record('communication', base['source'],
                  times.unix(v.get('timestamp')) if isinstance(
                      v.get('timestamp'), int) else None,
                  'Deleted Skype message (recovered)', text,
                  dict(base['detail'], **{'from': sender,
                                          'chat': v.get('chatname')}),
                  **base['where'])


def _imessage(row, base):
    from trace_app.core.activity.chat import _apple_date
    v = _values(row)
    if not v.get('text'):
        return None
    when = v.get('date')
    return record('communication', base['source'],
                  _apple_date(when) if isinstance(when, (int, float))
                  else None,
                  'Deleted iMessage (recovered)', v['text'],
                  dict(base['detail'], **{
                      'direction': {1: 'sent', 0: 'received'}.get(
                          v.get('is_from_me'), ''),
                      'service': v.get('service')}),
                  **base['where'])


def _sms(row, base):
    v = _values(row)
    if not v.get('body'):
        return None
    when = v.get('date')
    return record('communication', base['source'],
                  times.unix_micro(when * 1000) if isinstance(when, int)
                  else None,
                  'Deleted SMS (recovered)', v['body'],
                  dict(base['detail'], address=v.get('address')),
                  **base['where'])


def _chrome(row, base):
    v = _values(row)
    if not v.get('url'):
        return None
    when = v.get('last_visit_time')
    return record('browser', base['source'],
                  times.webkit(when) if isinstance(when, int) else None,
                  'Deleted history entry (recovered)', v['url'],
                  dict(base['detail'], title=v.get('title'),
                       visits=v.get('visit_count')),
                  **base['where'])


def _firefox(row, base):
    v = _values(row)
    if not v.get('url'):
        return None
    when = v.get('last_visit_date')
    return record('browser', base['source'],
                  times.unix_micro(when) if isinstance(when, int) else None,
                  'Deleted history entry (recovered)', v['url'],
                  dict(base['detail'], title=v.get('title'),
                       visits=v.get('visit_count')),
                  **base['where'])


#: table name -> (source label, maker)
_READERS = {'Messages': ('Skype', _skype), 'message': ('iMessage', _imessage),
            'sms': ('Android SMS', _sms), 'urls': ('Chromium', _chrome),
            'moz_places': ('Firefox', _firefox)}


def deleted_records(data, wal, user, path, ref, carved=False):
    """Activity records for the deleted rows still in a database."""
    from trace_app.core import sqlite_recover
    try:
        rows = sqlite_recover.recover(data, wal)
    except Exception as exc:
        logger.debug("No recovery from %s: %s", path, exc)
        return []
    out = []
    for row in rows:
        reader = _READERS.get(row['table'])
        if reader is None:
            continue
        label, maker = reader
        base = {'source': f"{label} (recovered{', carved' if carved else ''})",
                'detail': {'found in': f"{row['source']}, page "
                                       f"{row['page']}",
                           'note': row['note'],
                           'basis': 'deleted from the database; read from '
                                    'where SQLite left it'},
                'where': {'user': user, 'path': path, 'ref': ref}}
        try:
            made = maker(row, base)
        except Exception as exc:
            logger.debug("Recovered %s row unusable: %s", row['table'], exc)
            continue
        if made is not None:
            out.append(made)
    return out
