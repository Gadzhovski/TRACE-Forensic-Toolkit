"""Saved messages and mbox mailboxes browsed like archives
(trace_app/core/mailfiles.py).

Real messages from CPython's email test data: a Mailman digest of five
messages, a GIF attachment, two JPEG attachments with Content-IDs, a
forwarded message and a plain + HTML pair. An mbox is the messages written
the way an mbox is: a From_ line before each, ">From " quoting in bodies.
"""

import io
import os
from email.message import EmailMessage

import pytest

from tests.conftest import ROOT
from tools import testdata

SAMPLES = testdata.SAMPLES
NUMBERS = ('02', '07', '22', '46', '47')


def message(number):
    path = os.path.join(SAMPLES, f'cpython-msg_{number}.eml')
    if not os.path.exists(path):
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(f"{path} missing")
        pytest.skip("run python -m tools.testdata.fetch --group samples")
    with open(path, 'rb') as handle:
        return handle.read()


def as_mbox(messages):
    return b''.join(
        b'From someone@example.com Sat Jan  3 01:05:34 1996\n'
        + m.replace(b'\nFrom ', b'\n>From ') + b'\n' for m in messages)


def names(data):
    from trace_app.core import archives
    return [m['name'] for m in archives.list_members(data)]


def test_a_saved_message_is_browsed_as_its_page_and_attachments():
    from trace_app.core import archives
    data = message('07')
    assert archives.detect_archive(data) == 'eml'
    assert names(data) == ['Here is your dingus fish.html', 'attachments',
                           'attachments/dingusfish.gif']
    gif = archives.read_member(data, 'attachments/dingusfish.gif')
    assert gif.startswith(b'GIF87a') and len(gif) == 3512
    page = archives.read_member(data, 'Here is your dingus fish.html')
    text = page.decode('utf-8')
    assert 'This is the dingus fish.' in text
    # Written in -0400, shown with UTC beside it.
    assert 'Fri, 20 Apr 2001 19:35:02 -0400 (2001-04-20 23:35:02 UTC)' in text
    assert 'dingusfish.gif (3,512 bytes)' in text
    assert 'Headers as received' in text


def test_a_digest_and_a_forward_are_messages_inside_messages():
    from trace_app.core import archives
    digest = message('02')
    inner = [n for n in names(digest) if n.endswith('.eml')]
    assert len(inner) == 5 and 'attachments/[Ppp] testing #1.eml' in inner
    member = archives.read_member(digest, 'attachments/[Ppp] testing #1.eml')
    assert archives.detect_archive(member) == 'eml'   # stepped into in turn
    forward = message('46')
    assert names(forward)[-1] == 'attachments/GroupwiseForwardingTest.eml'


def test_attachments_with_content_ids_and_both_bodies():
    from trace_app.core import archives
    jpegs = message('22')
    assert names(jpegs)[1:] == ['attachments', 'attachments/wibble.JPG',
                                'attachments/wibble2.JPG']
    assert archives.read_member(jpegs, 'attachments/wibble.JPG')[:2] == \
        b'\xff\xd8'
    both = message('47')
    page = archives.read_member(both, names(both)[0]).decode('utf-8')
    # The HTML part is the body; the plain one is not lost.
    assert page.count('<hr>') >= 2


def test_an_inline_picture_is_shown_without_being_fetched():
    from trace_app.core import archives
    mail = EmailMessage()
    mail['From'] = 'a@example.com'
    mail['To'] = 'b@example.com'
    mail['Subject'] = '<script>alert(1)</script>'
    mail['Date'] = 'Mon, 02 Mar 2020 10:00:00 +0100'
    mail['Message-ID'] = '<1@example.com>'
    mail.set_content('plain')
    mail.add_alternative('<html><body><p>Look:</p><img src="cid:pic1">'
                         '<img src="https://example.com/track.gif">'
                         '</body></html>', subtype='html')
    picture = bytes(message('22'))                     # any bytes will do
    mail.get_payload()[1].add_related(picture[:64], 'image', 'png',
                                      cid='<pic1>')
    data = bytes(mail)
    page = archives.read_member(data, names(data)[0]).decode('utf-8')
    assert 'src="data:image/png;base64,' in page and 'cid:pic1' not in page
    assert '<script>alert' not in page.split('<hr>')[0]
    assert '&lt;script&gt;' in page
    assert 'Mon, 02 Mar 2020 10:00:00 +0100 (2020-03-02 09:00:00 UTC)' in page


def test_an_mbox_read_through_a_file_object_in_small_blocks(monkeypatch):
    from trace_app.core import archives, mailfiles
    from trace_app.core.containers import ByteWindow
    raw = [message(n) for n in NUMBERS]
    mbox = as_mbox(raw)
    assert archives.detect_archive(mbox) == 'mbox'
    monkeypatch.setattr(mailfiles, '_SCAN_BLOCK', 61)  # lines cross blocks
    spans = mailfiles.mbox_spans(io.BytesIO(mbox))
    assert len(spans) == 5 and spans[0][0] == 0 and spans[-1][1] == len(mbox)
    stream = ByteWindow(lambda o, n: mbox[o:o + n], 0, len(mbox))
    assert archives.detect_archive(stream) == 'mbox'
    listed = [m['name'] for m in archives.list_members(stream)]
    pages = [n for n in listed if n.endswith('.html')]
    assert pages == ['0001 Ppp digest, Vol 1 #2 - 5 msgs.html',
                     '0002 Here is your dingus fish.html',
                     '0003 (no subject).html',
                     '0004 GroupwiseForwardingTest.html',
                     '0005 (no subject).html']
    gif = archives.read_member(
        stream, '0002 Here is your dingus fish - attachments/dingusfish.gif')
    assert gif == archives.read_member(raw[1], 'attachments/dingusfish.gif')
    page = archives.read_member(stream, pages[2]).decode('utf-8')
    assert 'Message 3 of 5 in an mbox mailbox' in page


def test_a_body_line_starting_from_does_not_split_a_message():
    from trace_app.core import mailfiles
    one = (b'From a@example.com Mon Jan  1 00:00:00 2001\n'
           b'From: a@example.com\nSubject: one\n\n'
           b'From here on it is body text.\n\n'
           b'From the start of 2001 too.\n')
    assert len(mailfiles.mbox_spans(one)) == 1


@pytest.mark.parametrize('text', [
    b'Date: today\nSubject: hello\n\nbody',            # no mail-only header
    b'HTTP/1.1 200 OK\nDate: x\nServer: y\n\n',
    b'From the desk of the editor\nDear reader,\n',
    b'just some text\nFrom: a\nTo: b\n',
])
def test_text_that_is_not_mail(text):
    from trace_app.core import archives
    assert archives.detect_archive(text) is None


def test_the_indexer_finds_words_in_attachments(tmp_path):
    from trace_app.core.indexer import _index_archive
    from trace_app.core.search_index import SearchIndex
    index = SearchIndex(str(tmp_path))
    try:
        data = message('02')
        _index_archive(index, 1, 'p0:i5:s1', data, '/mail/digest.eml', 3)
        index.commit()
        rows = index.search('testing')
        assert any('[Ppp] testing #1.eml' in (r.get('name') or '')
                   for r in rows)
    finally:
        index.close()
