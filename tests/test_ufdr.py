"""Cellebrite UFDR reports (core/ufdr.py).

No complete UFDR is published. What is: report.xml fragments Physical
Analyzer wrote -- a decoded WhatsApp chat of eleven messages with its
participants and a voice-note attachment, and a WhatsApp Business account
-- kept by IPED as test data (tools/testdata/samples.py, pinned). They are
wrapped here in a report's outer layout (project, device info, tagged
files, decodedData, as Physical Analyzer and the readers that handle it
lay one out) and zipped with the files the report names.

The expected values are read from the fragments with ElementTree directly
-- who sent each message, by the Party's IsPhoneOwner -- not through
core/ufdr.
"""

import datetime
import hashlib
import xml.etree.ElementTree as ET
import zipfile

import pytest

from tests.conftest import data_path

VOICE = b'OggS' + bytes(range(256)) * 8          # the voice note's bytes
PHOTO = b'\xff\xd8\xff\xe0' + b'JFIF' * 300


def _fragment(name):
    with open(data_path('samples', name), encoding='utf-8') as handle:
        return handle.read()


def _report():
    chat = _fragment('ufed-model-chat.xml')
    account = _fragment('ufed-model-useraccount.xml')
    return f'''<?xml version="1.0" encoding="utf-8"?>
<project id="d3c6" name="Phone report" reportVersion="7.70.0.1"
    xmlns="http://pa.cellebrite.com/report/2.0">
  <sourceExtractions>
    <extractionInfo id="0" name="Logical" type="Logical"/>
    <extractionInfo id="2" name="File System" type="FileSystem"/>
  </sourceExtractions>
  <metadata section="Device Info">
    <item id="1" name="DeviceInfoSelectedManufacturer"><![CDATA[Samsung]]></item>
    <item id="2" name="DeviceInfoSelectedDeviceName"><![CDATA[Galaxy S21]]></item>
    <item id="3" name="IMEI"><![CDATA[351234567890123]]></item>
    <item id="4" name="DeviceInfoOSVersion"><![CDATA[14]]></item>
  </metadata>
  <taggedFiles>
    <file fs="Samsung SM-G991B (File System)" fsid="f1"
        path="/data/media/0/WhatsApp/Media/WhatsApp Voice Notes/PTT-20241103-WA0101.opus"
        size="{len(VOICE)}" id="450cab4c" extractionId="2" deleted="intact">
      <metadata section="File">
        <item name="Local Path"><![CDATA[files\\Audio\\PTT-20241103-WA0101.opus]]></item>
        <item name="SHA256"><![CDATA[{hashlib.sha256(VOICE).hexdigest()}]]></item>
      </metadata>
      <accessInfo>
        <timestamp name="CreationTime">2024-11-03T19:46:47.000+00:00</timestamp>
        <timestamp name="ModifyTime">2024-11-03T21:46:48.123+02:00</timestamp>
      </accessInfo>
    </file>
    <file fs="Samsung SM-G991B (File System)" fsid="f1"
        path="/data/media/0/DCIM/Camera/gone.jpg" size="{len(PHOTO)}"
        id="9bbd" extractionId="2" deleted="deleted">
      <metadata section="File">
        <item name="Local Path"><![CDATA[files\\Image\\gone.jpg]]></item>
      </metadata>
    </file>
  </taggedFiles>
  <decodedData>
    <modelType type="Chat">
{chat}
    </modelType>
{account}
  </decodedData>
</project>'''


@pytest.fixture
def ufdr(tmp_path):
    path = tmp_path / 'phone.ufdr'
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('report.xml', _report())
        archive.writestr('files/Audio/PTT-20241103-WA0101.opus', VOICE)
        archive.writestr('files/Image/gone.jpg', PHOTO)
        archive.writestr('Report.pdf', b'%PDF-1.4 the printable report')
    return str(path)


def _expected_messages():
    """(sent by the owner?, timestamp) of each message, from the chat
    fragment as ElementTree reads it."""
    chat = ET.fromstring(_fragment('ufed-model-chat.xml'))
    out = []
    messages = next(f for f in chat if f.get('name') == 'Messages')
    for message in messages:
        sender = next((f for f in message if f.get('name') == 'From'), None)
        owner = False
        if sender is not None:
            for field in sender.iter('field'):
                if field.get('name') == 'IsPhoneOwner':
                    values = [v.text for v in field if v.tag == 'value']
                    owner = values == ['True']
        stamp = next(f for f in message if f.get('name') == 'TimeStamp')
        out.append((owner, next(v.text for v in stamp if v.tag == 'value')))
    return out


def test_a_ufdr_opens_with_the_phones_files_where_they_were(ufdr):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(ufdr)
    try:
        assert handler.get_image_type() == 'logical' and handler.loaded
        fs = handler.logical_fs
        assert fs.label == 'UFDR'
        facts = fs.facts
        assert facts['Manufacturer'] == 'Samsung'
        assert facts['Device'] == 'Galaxy S21'
        assert facts['IMEI'] == '351234567890123'
        assert 'Logical' in facts['Extractions']
        # The fragments hold one chat and two accounts.
        assert 'Chat 1' in facts['Decoded'] and 'UserAccount 2' in \
            facts['Decoded']
        top = {e['name'] for e in handler.get_directory_contents(0)}
        assert top == {'Samsung SM-G991B (File System)', 'UFDR report'}
        voice = fs.lookup('/Samsung SM-G991B (File System)/data/media/0/'
                          'WhatsApp/Media/WhatsApp Voice Notes/'
                          'PTT-20241103-WA0101.opus')
        assert voice is not None and not voice.deleted
        assert voice.reader(0, voice.size) == VOICE
        assert voice.facts['sha256 (UFDR)'] == \
            hashlib.sha256(VOICE).hexdigest()
        # Times in UTC: +02:00 at 21:46:48 is 19:46:48 UTC.
        assert voice.times['mtime'] == (1730663208, 123000000)
        gone = fs.lookup('/Samsung SM-G991B (File System)/data/media/0/'
                         'DCIM/Camera/gone.jpg')
        assert gone.deleted and gone.reader(0, gone.size) == PHOTO
        report = fs.lookup('/UFDR report/report.xml')
        assert report is not None
        assert fs.lookup('/UFDR report/Report.pdf') is not None
        # What report.xml placed is not repeated under the report folder.
        assert fs.lookup('/UFDR report/files') is None
    finally:
        handler.close_resources()


def test_the_decoded_chat_and_account_become_activity(ufdr):
    from trace_app.core import activity
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.activity import times
    expected = _expected_messages()
    assert len(expected) == 11
    handler = ImageHandler(ufdr)
    try:
        records = activity.collect(handler)
    finally:
        handler.close_resources()
    # Each message keeps its own app: IPED's chat holds nine WhatsApp
    # messages and two Telegram ones (its SourceApplication says so).
    messages = [r for r in records if r['source'].endswith('(UFDR)')
                and r['what'].startswith(('Message', 'Group message'))]
    assert len(messages) == 11
    assert sorted(r['source'] for r in messages) ==         ['Telegram (UFDR)'] * 2 + ['WhatsApp (UFDR)'] * 9
    # Who sent each, and when: the fragment's own TimeStamp values read
    # by Python's ISO parser, written as every activity time is.
    assert sorted((r['what'].startswith(('Message sent',
                                         'Group message sent')), r['time'])
                  for r in messages) == sorted(
        (owner, times.iso(datetime.datetime.fromisoformat(stamp)))
        for owner, stamp in expected)
    for row in messages:
        assert row['detail']['chat id'] == '5511999996666@s.whatsapp.net'
        assert row['path'] == '/UFDR report/report.xml' and row['ref']
    voice = [r for r in messages if 'PTT-20241103-WA0101.opus' in
             r['detail'].get('attachments', '')]
    assert voice and voice[0]['detail']['from'].startswith('Bulbasaur')
    accounts = [r for r in records if r['source'] ==
                'WhatsApp Business (UFDR)']
    assert [r['subject'] for r in accounts] == ['Rattata']
    assert '5511999997777@s.whatsapp.net' in str(accounts[0]['detail'])
    expected_accounts = ET.fromstring(_fragment(
        'ufed-model-useraccount.xml')).findall('model')
    assert len([r for r in records if r['what'].startswith(
        'Account on the phone')]) == len(expected_accounts)


def test_its_messages_are_one_conversation(ufdr):
    from trace_app.core import activity
    from trace_app.core.conversations import thread_key
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(ufdr)
    try:
        records = activity.collect(handler)
    finally:
        handler.close_resources()
    messages = [r for r in records if r['source'].endswith('(UFDR)')
                and 'essage' in r['what']]
    # One chat: one conversation per app it holds messages of.
    assert len({thread_key(r) for r in messages}) ==         len({r['source'] for r in messages}) == 2


def test_a_zip_with_a_report_is_a_ufdr_whatever_its_name(tmp_path, ufdr):
    import shutil
    from trace_app.core.logical_sources import kind_of
    renamed = tmp_path / 'export.zip'
    shutil.copy(ufdr, renamed)
    assert kind_of(str(renamed)) == 'ufdr'
    plain = tmp_path / 'plain.zip'
    with zipfile.ZipFile(plain, 'w') as archive:
        archive.writestr('notes.txt', 'x')
    assert kind_of(str(plain)) == 'zip'
