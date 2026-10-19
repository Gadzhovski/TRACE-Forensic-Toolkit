"""Chats a LEAPP read, as conversations (core/modules/chats.py, stored by
core/modules/bridge.py): the artifact's LAVA conversation view names the
columns; its rows join Triage ▸ Conversations beside TRACE's own
messages."""

import json
import os
import sqlite3

import pytest

#: A WhatsApp table as iLEAPP's LAVA writes one, and its conversation view.
VIEW = {'conversationDiscriminatorColumn': 'chat_id',
        'conversationLabelColumn': 'chat_name', 'textColumn': 'message',
        'directionColumn': 'direction', 'directionSentValue': 'Outgoing',
        'timeColumn': 'timestamp', 'senderColumn': 'sender_name',
        'mediaColumn': 'attachment_file'}
COLUMNS = [{'name': 'timestamp', 'label': 'Timestamp', 'type': 'datetime'},
           {'name': 'direction', 'label': 'Direction', 'type': ''},
           {'name': 'sender_name', 'label': 'Sender', 'type': ''},
           {'name': 'chat_name', 'label': 'Chat', 'type': ''},
           {'name': 'message', 'label': 'Message', 'type': ''},
           {'name': 'attachment_file', 'label': 'Attachment',
            'type': 'media'},
           {'name': 'latitude', 'label': 'Latitude', 'type': ''},
           {'name': 'longitude', 'label': 'Longitude', 'type': ''},
           {'name': 'chat_id', 'label': 'Chat id', 'type': ''}]
ROWS = [
    (1586629000, 'Incoming', 'Alice', 'Alice', 'Hi there', '', '', '',
     'alice@s.whatsapp.net'),
    (1586629060, 'Outgoing', 'Local User', 'Alice', 'Hello Alice', '', '',
     '', 'alice@s.whatsapp.net'),
    (1586629120, 'Outgoing', 'Local User', 'Alice', None, 'm1', '', '',
     'alice@s.whatsapp.net'),
    (1586629180, 'Outgoing', 'Local User', 'Alice', None, '',
     '35.660969', '-78.879852', 'alice@s.whatsapp.net'),
    (1586629240, 'Incoming', 'Bob', 'Weekend group', 'See you Saturday',
     '', '', '', 'group-1@g.us'),
]


def _lava_run(case, evidence_id, name):
    """A completed run whose report holds the WhatsApp table."""
    folder = os.path.join(case.folder, 'modules', name)
    report = os.path.join(folder, 'report')
    os.makedirs(os.path.join(report, 'media'))
    with open(os.path.join(report, 'media', 'photo.jpg'), 'wb') as handle:
        handle.write(b'\xff\xd8\xff\xe0 not a real picture')
    database = sqlite3.connect(os.path.join(report, '_lava_artifacts.db'))
    database.execute("CREATE TABLE whatsappmessages (" + ', '.join(
        c['name'] for c in COLUMNS) + ")")
    database.executemany("INSERT INTO whatsappmessages VALUES (" +
                         ','.join('?' * len(COLUMNS)) + ")", ROWS)
    database.execute("CREATE TABLE _lava_media_info (media_ref_id, "
                     "source_path, extraction_path, type, name)")
    database.execute("INSERT INTO _lava_media_info VALUES (?,?,?,?,?)",
                     ('m1', 'private/var/mobile/photo.jpg',
                      'media/photo.jpg', 'image/jpeg', 'photo.jpg'))
    database.commit()
    database.close()
    entry = {'artifact_key': 'whatsAppMessages',
             'name': 'WhatsApp - Messages', 'tablename': 'whatsappmessages',
             'module': 'whatsapp',
             'column_map': {c['name']: c['label'] for c in COLUMNS},
             'object_columns': [{'name': c['name'], 'type': c['type']}
                                for c in COLUMNS if c['type']],
             'record_count': len(ROWS),
             'source_path': 'ChatStorage.sqlite',
             'artifact_icon': 'message-circle',
             'data_views': {'conversation': VIEW}}
    with open(os.path.join(report, '_lava_data.lava'), 'w') as handle:
        json.dump({'lava_schema_version': 2, 'processing_status': 'Complete',
                   'parser_info': {'leapp_name': 'iLEAPP',
                                   'leapp_version': '2026.4.4'},
                   'artifacts': {'WhatsApp': [entry]}, 'modules': []},
                  handle)
    run = case.add_module_run(evidence_id, 'iLEAPP', '2026.4.4', 'x' * 64,
                              {}, folder)
    from trace_app.core.modules import bridge, lava
    case.add_module_artifacts(run, lava.load(report)['artifacts'])
    case.finish_module_run(run, 'complete')
    bridge.bridge_run(case, run)
    return run


@pytest.fixture
def chat_case(tmp_path):
    from trace_app.core.case import Case
    evidence = tmp_path / 'phone'
    evidence.mkdir()
    (evidence / 'note.txt').write_text('x')
    case = Case.create(str(tmp_path / 'case'), 'Chats')
    evidence_id = case.add_evidence(str(evidence))
    _lava_run(case, evidence_id, 'first')
    _lava_run(case, evidence_id, 'second')     # the same phone read again
    yield case
    case.close()


def test_a_leapps_chats_are_conversations(chat_case):
    threads = {t['title']: t for t in chat_case.conversations()}
    assert set(threads) == {'Alice', 'Weekend group'}
    alice = threads['Alice']
    assert (alice['app'], alice['messages']) == ('WhatsApp', 4)  # once each
    rows = chat_case.conversation(alice['key'])
    assert [r['direction'] for r in rows] == ['in', 'out', 'out', 'out']
    assert rows[0]['sender'] == 'Alice'
    assert rows[0]['subject'] == 'Hi there'
    assert rows[0]['time_utc'] == '2020-04-11 18:16:40'
    picture = rows[2]
    assert picture['subject'] == '[photo.jpg]'
    assert os.path.isfile(picture['detail']['attachment_file'])
    assert picture['source_path'] == 'private/var/mobile/photo.jpg'
    place = rows[3]
    assert place['subject'] == '[Location 35.660969, -78.879852]'
    assert (place['detail']['latitude'], place['detail']['longitude']) == \
        (35.660969, -78.879852)
    # Each row is its LAVA row: a click shows the source, a double-click
    # the row in the Modules tab -- of the newer run.
    newest = max(r['id'] for r in chat_case.module_runs())
    assert rows[1]['source_ref'] == f'mod:{newest}:whatsappmessages:2'


def test_the_tools_database_is_only_read(chat_case):
    from trace_app.core.modules import bridge
    report = os.path.join(chat_case.folder, 'modules', 'first', 'report')
    before = {name: os.path.getmtime(os.path.join(report, name))
              for name in os.listdir(report)}
    for run in chat_case.module_runs():
        bridge.bridge_run(chat_case, run['id'], force=True)
    assert {name: os.path.getmtime(os.path.join(report, name))
            for name in os.listdir(report)} == before


def test_app_names_and_looks():
    from trace_app.core.modules.chats import app_name
    assert app_name('Discord - Chats') == 'Discord'
    assert app_name('Kik Messages') == 'Kik'
    assert app_name('Instagram Threads') == 'Instagram'
    assert app_name('Houseparty - Direct Messages') == 'Houseparty'
    from trace_app.ui.viewers.conversations_panel import app_look, initials
    assert app_look('WhatsApp') == ('brand-whatsapp', '#25D366')
    assert app_look('Twitter X')[0] == 'brand-x'
    assert app_look('Something new') == ('message-circle', None)
    assert initials('Josh Hickman') == 'JH'
    assert initials('josh_hickman1') == 'JH'
    assert initials('') == '?'


def test_the_leapps_logos_ship_with_trace(qapp):
    """Shown before a tool is installed (tests run with none installed)."""
    from trace_app.core.modules.spec import TOOLS
    from trace_app.infra.paths import resource_path
    from trace_app.ui import icons
    for tool in TOOLS:
        assert os.path.isfile(resource_path(f'Icons/modules/{tool}.png'))
        logo = icons.module_logo(tool)
        assert not logo.isNull()
        assert logo.cacheKey() != icons.icon(icons.MODULES).cacheKey()


def test_the_conversations_tab_draws_a_leapps_chat(qapp, chat_case):
    from tests.conftest import pump
    from trace_app.ui.viewers.conversations_panel import ConversationsPanel
    panel = ConversationsPanel()
    try:
        panel.set_case(chat_case)
        pump(qapp, 10, lambda: not panel.loading and
             panel.threads_view.topLevelItemCount())
        thread = next(t for t in panel._threads if t['title'] == 'Alice')
        assert panel.select_thread(thread['key'])
        assert panel.messages_view.count() == 4
        assert 'WhatsApp' in panel.title_label.text()
        assert panel.app_label.pixmap() is not None
        delegate = panel.messages_view.itemDelegate()
        first = panel.messages_view.model().index(0, 0)
        assert delegate.row(first)['subject'] == 'Hi there'
    finally:
        panel.deleteLater()


def test_every_bubble_is_readable_in_both_themes(qapp):
    """A bubble's text is chosen by contrast with its own fill (WCAG 4.5:1
    at least) -- the light theme's dark tooltip colour once drew dark text
    on dark call bubbles."""
    from PySide6.QtGui import QColor
    from trace_app.ui.viewers.conversations_panel import (
        APP_LOOKS, _luminance, bubble_fill, readable_on)

    def contrast(a, b):
        high, low = sorted((_luminance(a), _luminance(b)), reverse=True)
        return (high + 0.05) / (low + 0.05)

    fills = [QColor(colour) for _key, _icon, colour in APP_LOOKS]
    for base in ('#ffffff', '#2e2e2e', '#1e1e1e', '#f5f5f5'):
        fills += [bubble_fill(QColor(base), kind)
                  for kind in ('received', 'event')]
    darkened = []
    for colour in fills:
        fill, text, _meta = readable_on(colour)
        assert contrast(fill, text) >= 4.5, colour.name()
        # The fill changes only when neither text colour can be read on
        # it as the app has it (Viber's purple, Threads' grey).
        best = max(contrast(colour, QColor('#111111')),
                   contrast(colour, QColor('#FFFFFF')))
        assert (fill == colour) == (best >= 4.5), colour.name()
        if fill != colour:
            darkened.append(colour.name())
    assert '#7360f2' in darkened and len(darkened) <= 3
    # A bubble stands apart from the view behind it.
    for base in ('#ffffff', '#2e2e2e'):
        for kind in ('received', 'event'):
            assert bubble_fill(QColor(base), kind) != QColor(base)
