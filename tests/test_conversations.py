"""Conversations (core/conversations.py, Triage ▸ Conversations): the
messages and calls the activity parsers read, grouped into threads.

Records come from the real parsers (core/activity) over databases written
here in each app's schema, and over pinned real samples (Skype's main.db,
Android's mmssms.db), so a thread is what an examiner would find on the
device: every message in exactly one thread, a contact the same whether
written +44 7700 900123 or 07700 900123, named from the address book."""

import hashlib
import os
import sqlite3

import pytest

from tests.conftest import data_path, pump
from trace_app.core import conversations


def _db(script):
    db = sqlite3.connect(':memory:')
    db.executescript(script)
    return db


def ios_messages():
    """sms.db: iMessage and SMS with one contact, and a group chat."""
    from trace_app.core.activity.chat import imessage
    db = _db("""
        CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);
        CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT,
            date INTEGER, date_read INTEGER, is_from_me INTEGER,
            service TEXT, handle_id INTEGER, is_read INTEGER, account TEXT);
        INSERT INTO handle VALUES (1, '+447700900123'), (2, 'alex@icloud.com');
        INSERT INTO message VALUES
          (1, 'Hi Sam', 700000000000000000, 0, 1, 'iMessage', 1, 1, 'e:me'),
          (2, 'Hello!', 700000060000000000, 0, 0, 'iMessage', 1, 1, 'e:me'),
          (3, 'Running late', 700000120000000000, 0, 0, 'SMS', 1, 1, ''),
          (4, 'Lunch?', 700000180000000000, 0, 0, 'iMessage', 2, 1, 'e:me');
    """)
    return imessage(db, 'mobile', '/private/var/mobile/Library/SMS/sms.db',
                    'p0:i10:s0')


def android_records():
    """Calls (one number written two ways), contacts, WhatsApp."""
    from trace_app.core.activity import mobile
    calls = _db("""
        CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT,
            date INTEGER, duration INTEGER, type INTEGER, name TEXT);
        INSERT INTO calls VALUES (1, '+447700900123', 1663171200000, 95, 1,
            'Sam'), (2, '07700 900123', 1663174800000, 0, 3, NULL),
            (3, '+447700900456', 1663178400000, 60, 2, NULL);
    """)
    contacts = _db("""
        CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY,
            display_name TEXT, last_time_contacted INTEGER, deleted INTEGER);
        CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT);
        CREATE TABLE data (_id INTEGER PRIMARY KEY, raw_contact_id INTEGER,
            mimetype_id INTEGER, data1 TEXT);
        INSERT INTO mimetypes VALUES (1, 'vnd.android.cursor.item/phone_v2');
        INSERT INTO raw_contacts VALUES (1, 'Alex Morgan', 1663178400000, 0);
        INSERT INTO data VALUES (1, 1, 1, '+44 7700 900456');
    """)
    whatsapp = _db("""
        CREATE TABLE jid (_id INTEGER PRIMARY KEY, user TEXT, server TEXT,
            raw_string TEXT);
        CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER,
            subject TEXT);
        CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER,
            from_me INTEGER, key_id TEXT, sender_jid_row_id INTEGER,
            timestamp INTEGER, text_data TEXT);
        INSERT INTO jid VALUES (1, '447700900123', 's.whatsapp.net',
            '447700900123@s.whatsapp.net'),
            (2, '120363000000000000', 'g.us', '120363000000000000@g.us'),
            (3, '447700900456', 's.whatsapp.net',
            '447700900456@s.whatsapp.net');
        INSERT INTO chat VALUES (1, 1, NULL), (2, 2, 'Weekend plans');
        INSERT INTO message VALUES
            (1, 1, 0, 'A1', 0, 1663171300000, 'Are you there?'),
            (2, 1, 1, 'A2', 0, 1663171360000, 'Yes, on my way'),
            (3, 2, 0, 'A3', 3, 1663171420000, 'Who is driving?'),
            (4, 2, 1, 'A4', 0, 1663171480000, 'Me');
    """)
    return (mobile.android_calls(calls, '/data/calllog.db', 'p0:i1:s0')
            + mobile.android_contacts(contacts, '/data/contacts2.db',
                                      'p0:i2:s0')
            + mobile.android_whatsapp(whatsapp, '/data/msgstore.db',
                                      'p0:i3:s0'))


def _as_rows(records, evidence_id=1):
    """Records as the case returns them (what query_user_activity gives)."""
    return [dict(r, id=index, evidence_id=evidence_id, time_utc=r['time'],
                 source_path=r['path'], source_ref=r['ref'])
            for index, r in enumerate(records, start=1)]


# --- grouping --------------------------------------------------------------

def test_numbers_and_addresses_compare_as_people_write_them():
    norm = conversations.normalise_party
    assert norm('+44 7700 900123') == norm('07700 900123') == \
        norm('447700900123@s.whatsapp.net') == norm('tel:+447700900123')
    assert norm('Sam <SAM@Example.com>') == 'sam@example.com'
    assert norm('live:sam.taylor') == 'live:sam.taylor'
    assert norm('b@x.com, a@x.com') == 'a@x.com, b@x.com'
    assert norm('') == ''


def test_ios_messages_make_one_thread_per_contact():
    rows = _as_rows(ios_messages())
    threads = {t['party']: t for t in conversations.threads(rows)}
    sam = threads[conversations.normalise_party('+447700900123')]
    # iMessage and SMS with the same number: one thread, as on the phone.
    assert sam['app'] == 'Messages' and sam['messages'] == 3
    assert threads['alex@icloud.com']['messages'] == 1
    shown = conversations.messages(rows, sam['key'])
    assert [m['subject'] for m in shown] == ['Hi Sam', 'Hello!',
                                             'Running late']
    assert [m['direction'] for m in shown] == ['out', 'in', 'in']


def test_android_calls_join_their_contact_and_contacts_name_them():
    rows = _as_rows(android_records())
    threads = conversations.threads(rows)
    calls = [t for t in threads if t['app'] == 'Android call log']
    by_party = {t['party']: t for t in calls}
    # +447700900123 and 07700 900123 are the same person.
    assert by_party['700900123']['calls'] == 2
    assert 'Sam' in by_party['700900123']['title']
    # Named from the address book, not the call.
    assert 'Alex Morgan' in by_party['700900456']['title']
    whatsapp = {t['title']: t for t in threads
                if t['app'] == 'WhatsApp (Android)'}
    assert whatsapp['Weekend plans']['messages'] == 2
    # A one-to-one chat by its number and the contact's name (from the
    # call log), not its JID.
    assert 'Sam (+447700900123)' in whatsapp
    # Contacts are not a conversation.
    assert not any(t['app'] == 'Android contacts' for t in threads)
    group = conversations.messages(rows, whatsapp['Weekend plans']['key'])
    assert [m['direction'] for m in group] == ['in', 'out']


def test_every_message_of_real_samples_is_in_exactly_one_thread():
    """Skype's main.db and Android's mmssms.db (plaso's test data), read by
    the real parsers."""
    from trace_app.core.activity.chat import read_database
    records = []
    for name in ('skype_main.db', 'mmssms.db'):
        with open(data_path('samples', name), 'rb') as handle:
            records += read_database(handle.read(), None, 'user', name,
                                     'p0:i1:s0')
    rows = _as_rows(records)
    wanted = [r for r in rows if conversations.is_message(r)]
    assert len(wanted) > 10
    threads = conversations.threads(rows)
    placed = []
    for thread in threads:
        placed += [m['id'] for m in conversations.messages(rows,
                                                           thread['key'])]
    assert sorted(placed) == sorted(r['id'] for r in wanted)
    assert sum(t['messages'] + t['calls'] + t['files']
               for t in threads) == len(wanted)


def test_export_writes_escaped_html_and_csv(tmp_path):
    rows = _as_rows(ios_messages())
    rows[0]['subject'] = '<script>alert(1)</script>'
    thread = next(t for t in conversations.threads(rows)
                  if t['messages'] == 3)
    written = conversations.export(thread, conversations.messages(
        rows, thread['key']), str(tmp_path))
    assert [os.path.splitext(p)[1] for p, _d in written] == ['.html', '.csv']
    html = open(written[0][0], encoding='utf-8').read()
    assert '<script>' not in html and '&lt;script&gt;' in html
    for path, digest in written:
        assert hashlib.sha256(open(path, 'rb').read()).hexdigest() == digest
    lines = open(written[1][0], encoding='utf-8-sig').read().splitlines()
    assert lines[0].startswith('Time (UTC),Direction')
    assert len(lines) == 4


# --- in a case and the window ----------------------------------------------------

@pytest.fixture
def case(tmp_path):
    from trace_app.core.case import Case
    case = Case.create(str(tmp_path / 'case'), 'Messages')
    evidence = case.add_evidence(str(tmp_path / 'phone.dd'))
    case.add_user_activity(evidence, ios_messages() + android_records())
    case.commit()
    yield case
    if case.is_open:
        case.close()


def test_the_case_and_report_show_chosen_conversations(case):
    from trace_app.core import report
    threads = case.conversations()
    assert {t['app'] for t in threads} >= {'Messages', 'Android call log',
                                           'WhatsApp (Android)'}
    plans = next(t for t in threads if t['title'] == 'Weekend plans')
    assert len(case.conversation(plans['key'])) == 2
    case.add_report_items('conversation', [{
        'title': 'WhatsApp: Weekend plans',
        'detail': {'key': plans['key']}}])
    options = report.default_options(case)
    options['sections'] = [{'key': 'conversations', 'enabled': True}]
    options['thumbnails'] = False
    html = report.build_html(case, options)[0]
    assert 'Who is driving?' in html and 'Weekend plans (2)' in html


def test_the_panel_lists_threads_and_shows_one(qapp, case, tmp_path,
                                               monkeypatch):
    import time
    from trace_app.ui.dialogs import message
    from trace_app.ui.main_window import MainWindow
    # The case's phone image is not on disk: no modal box about it.
    for name in ('information', 'warning', 'critical'):
        monkeypatch.setattr(message, name, lambda *a, **k: None)
    monkeypatch.setattr(message, 'question', lambda *a, **k: False)
    window = MainWindow(case=case)
    try:
        panel = window.conversations_panel
        panel.refresh()
        deadline = time.monotonic() + 10
        while panel.loading and time.monotonic() < deadline:
            pump(qapp, 0.05)
        assert panel.threads_view.topLevelItemCount() == len(
            case.conversations())
        plans = next(t for t in case.conversations()
                     if t['title'] == 'Weekend plans')
        assert panel.select_thread(plans['key'])
        assert panel.messages_view.count() == 2
        assert 'Weekend plans' in panel.title_label.text()
        # Finding a word keeps only the threads that hold it.
        panel.filter_input.setText('driving')
        assert panel.threads_view.topLevelItemCount() == 1
        panel.filter_input.setText('')
        # Export from the window: written and audited.
        written = window.export_conversation(
            plans, case.conversation(plans['key']), str(tmp_path))
        assert len(written) == 2
        line = next(a for a in case.activity(5)
                    if a['action'] == 'conversation exported')
        assert written[0][1] in line['detail']
        window.add_conversation_to_report(plans)
        assert case.report_items('conversation')
    finally:
        window.cleanup_resources()
