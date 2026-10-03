"""NTFS internals (trace_app/core/ntfs.py): $MFT times, paths, streams and
the change journal.

plaso's test data, fetched and SHA-256 pinned by
tools/fetch_artifact_samples.py: a raw Windows XP $MFT, a $UsnJrnl:$J excerpt,
and a QCOW2 disk with an NTFS volume and its journal. The expected values are
plaso's own test expectations for the same files -- and its 31,642 MFT events
are exactly the $STANDARD_INFORMATION and $FILE_NAME attributes counted here
plus 72 distributed-link-tracking IDs, which TRACE does not report. Paths were
also checked entry by entry against libfsntfs's path hints (all 13,064 agree).
"""

import io
import os
import struct

import pytest

from tests.conftest import ROOT

SAMPLES = os.path.join(ROOT, 'test_images', 'artifact_samples')


def sample(name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        message = (f"{name} is not in test_images/artifact_samples -- run "
                   f"'python tools/fetch_artifact_samples.py'")
        if os.environ.get('TRACE_REQUIRE_IMAGES') == '1':
            pytest.fail(message)
        pytest.skip(message)
    return path


@pytest.fixture(scope='module')
def mft():
    """(entries by index, path table) for plaso's MFT sample."""
    from trace_app.core import ntfs
    path = sample('MFT')
    table, extensions = ntfs.build_path_table(lambda: open(path, 'rb'))
    entries = {}
    with open(path, 'rb') as handle:
        for index, entry in ntfs.iter_records(handle):
            if entry.base_index:
                continue
            for part in extensions.get(index, ()):
                entry.merge(part)
            entries[index] = entry
    return entries, table


def _named(entries, name):
    return [e for e in entries.values()
            if e.best_name() is not None and e.best_name().name == name]


def test_mft_attribute_counts_match_plaso(mft):
    entries, _table = mft
    assert len(entries) == 13064
    assert sum(1 for e in entries.values() if e.si_times) == 13064
    assert sum(len(e.names) for e in entries.values()) == 18506
    # plaso: 31,642 event data = these 31,570 + 72 object-ID events.
    assert 13064 + 18506 + 72 == 31642


def test_mft_regular_file_path_and_times(mft):
    from trace_app.core import ntfs
    entries, table = mft
    (sam,) = [e for e in _named(entries, 'SAM')
              if table.entry_path(e) == '/WINDOWS/system32/config/SAM']
    assert sam.in_use
    # plaso's values are the $FILE_NAME attribute's: all four the same.
    name = sam.best_name()
    assert {ntfs.filetime_text(t) for t in name.times} == \
        {'2007-06-30 12:58:50.2740544'}
    assert ntfs.filetime_text(sam.si_times[0]) == '2007-06-30 12:58:50.2740544'
    events = ntfs.entry_events(sam, '')
    assert ('2007-06-30 12:58:50.2740544', 'MACB', 'FN') in events
    assert ('2007-06-30 12:58:50.2740544', '...B', 'SI') in events


def test_mft_deleted_file_keeps_its_path(mft):
    from trace_app.core import ntfs
    entries, table = mft
    (gone,) = _named(entries, 'CAJA1S19.js')
    assert not gone.in_use
    assert table.entry_path(gone) == (
        '/Documents and Settings/Donald Blake/Local Settings/'
        'Temporary Internet Files/Content.IE5/9EUWFPZ1/CAJA1S19.js')
    assert ntfs.filetime_text(gone.si_times[3]) == '2009-01-14 03:38:58.5869993'


def test_mft_orphan_path_as_plaso_writes_it(mft):
    entries, table = mft
    paths = {table.entry_path(e) for e in _named(entries, 'menu.text.css')}
    assert '$Orphan/session/menu.text.css' in paths


def test_mft_reused_parent_is_not_followed(mft):
    """A file whose parent folder's record was reused does not get the new
    occupant's path."""
    entries, table = mft
    for entry in entries.values():
        if entry.in_use or entry.best_name() is None:
            continue
        name = entry.best_name()
        parent = entries.get(name.parent_index)
        if parent is not None and parent.in_use \
                and parent.sequence != name.parent_sequence:
            assert table.entry_path(entry).startswith('$Orphan')
            return
    pytest.skip("no reused parent in this sample")


def test_timestomp_grading_on_real_mft(mft):
    """Windows XP setup stamps its files with the build date: earlier than
    $FILE_NAME, so recorded -- but routine, not raised."""
    from trace_app.core import ntfs
    entries, table = mft
    graded = {}
    for entry in entries.values():
        for kind, grade, _summary, detail in ntfs.entry_findings(
                entry, table.entry_path(entry)):
            if kind == 'timestomp':
                graded.setdefault(grade, []).append(table.entry_path(entry))
    assert '/WINDOWS/system32/kdcom.dll' in graded['benign']
    assert len(graded['benign']) > 4000
    assert not graded.get('suspicious')


def test_mft_streams_and_mark_of_the_web(mft):
    from trace_app.core import ntfs
    entries, table = mft
    findings = {}
    for entry in entries.values():
        path = table.entry_path(entry)
        for kind, grade, summary, detail in ntfs.entry_findings(entry, path):
            if kind in ('ads', 'motw'):
                findings[(path, kind)] = (grade, summary, detail)
    # The file system's own streams ($BadClus:$Bad, $Secure:$SDS) are not
    # findings.
    assert not any(p in ('/$BadClus', '/$Secure') for p, _k in findings)
    grade, summary, detail = findings[('$Orphan/winzip120[1].exe', 'motw')]
    assert detail['ZoneId'] == '3' and detail['zone'] == 'Internet'
    assert grade == 'notable'           # a program, from the Internet
    grade, summary, _ = findings[(
        '/Documents and Settings/Donald Blake/My Documents/iraq-news.wmv',
        'ads')]
    assert grade == 'notable' and 'Roxio EMC Stream' in summary


# --- synthetic records: fixups, streams, timestomping -------------------------

def _attribute(kind, content, name=''):
    encoded = name.encode('utf-16-le')
    header = 24
    name_offset = header
    content_offset = (header + len(encoded) + 7) // 8 * 8
    length = (content_offset + len(content) + 7) // 8 * 8
    data = bytearray(length)
    struct.pack_into('<IIBBHHH', data, 0, kind, length, 0, len(name),
                     name_offset, 0, 0)
    struct.pack_into('<IH', data, 16, len(content), content_offset)
    data[name_offset:name_offset + len(encoded)] = encoded
    data[content_offset:content_offset + len(content)] = content
    return bytes(data)


def _record(index, sequence, in_use, si, fn, parent=(5, 5), name='a.txt',
            streams=()):
    from trace_app.core import ntfs
    attrs = _attribute(ntfs.ATTR_STANDARD_INFORMATION,
                       struct.pack('<QQQQI', *si, 0x20) + bytes(36))
    encoded = name.encode('utf-16-le')
    fn_content = struct.pack('<QQQQQQQII', parent[0] | parent[1] << 48,
                             *fn, 0, 5, 0x20, 0) + \
        bytes([len(name), 1]) + encoded
    attrs += _attribute(ntfs.ATTR_FILE_NAME, fn_content)
    attrs += _attribute(ntfs.ATTR_DATA, b'hello')
    for stream_name, data in streams:
        attrs += _attribute(ntfs.ATTR_DATA, data, stream_name)
    attrs += struct.pack('<I', ntfs.ATTR_END) + bytes(4)
    record = bytearray(1024)
    first = 56
    record[0:4] = b'FILE'
    struct.pack_into('<HH', record, 4, 48, 3)          # fixup array, 3 words
    struct.pack_into('<HHHHII', record, 16, sequence, 1, first,
                     1 if in_use else 0, first + len(attrs), 1024)
    struct.pack_into('<I', record, 44, index)
    record[first:first + len(attrs)] = attrs
    # Fixups: the last two bytes of each sector move to the array.
    struct.pack_into('<H', record, 48, 0xABCD)
    for stride in (1, 2):
        end = stride * 512
        record[48 + stride * 2:50 + stride * 2] = record[end - 2:end]
        record[end - 2:end] = b'\xcd\xab'
    return bytes(record)


def _ft(text):
    """FILETIME for 'YYYY-MM-DD HH:MM:SS[.fffffff]'."""
    import datetime
    whole, _, fraction = text.partition('.')
    moment = datetime.datetime.strptime(whole, '%Y-%m-%d %H:%M:%S')
    seconds = int((moment - datetime.datetime(1601, 1, 1)).total_seconds())
    return seconds * 10_000_000 + int((fraction or '0').ljust(7, '0'))


def test_record_parse_with_fixups_and_streams():
    from trace_app.core import ntfs
    zone = (b'[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.org/'
            b'\r\nHostUrl=https://example.org/tool.exe\r\n')
    times = [_ft('2024-05-01 10:00:00.1234567')] * 4
    raw = _record(40, 3, True, times, times, name='tool.exe',
                  streams=[('Zone.Identifier', zone),
                           ('payload', b'MZ\x90\x00rest')])
    entry = ntfs.parse_record(raw, 40)
    assert entry.sequence == 3 and entry.in_use
    assert entry.best_name().name == 'tool.exe'
    assert [s.name for s in entry.streams] == ['', 'Zone.Identifier',
                                              'payload']
    found = {kind: (grade, summary, detail) for kind, grade, summary, detail
             in ntfs.entry_findings(entry, '/tool.exe')}
    assert found['motw'][0] == 'notable'
    assert found['motw'][2]['HostUrl'] == 'https://example.org/tool.exe'
    assert found['ads'][0] == 'suspicious'      # a program hidden in a stream
    assert 'timestomp' not in found


def test_torn_record_is_refused():
    from trace_app.core import ntfs
    times = [_ft('2024-05-01 10:00:00.1234567')] * 4
    raw = bytearray(_record(40, 3, True, times, times))
    raw[510:512] = b'\x00\x00'          # a sector written without the rest
    assert ntfs.parse_record(bytes(raw), 40) is None


@pytest.mark.parametrize('si, fn, grade', [
    # Set by a tool: earlier than the file system's own, to the second.
    (['2019-01-01 00:00:00'] * 4, ['2024-05-01 10:00:00.5550000'] * 4,
     'suspicious'),
    # Whole seconds alone.
    (['2024-05-01 10:00:00'] * 4, ['2024-05-01 10:00:00.5550000'] * 4,
     'notable'),
    # Earlier alone: what installers and archive tools do.
    (['2019-01-01 00:00:00.1000000'] * 4, ['2024-05-01 10:00:00.5550000'] * 4,
     'benign'),
    # As NTFS writes them.
    (['2024-05-01 10:00:00.5550000'] * 4, ['2024-05-01 10:00:00.5550000'] * 4,
     None),
])
def test_timestomp_grades(si, fn, grade):
    from trace_app.core import ntfs
    raw = _record(40, 1, True, [_ft(t) for t in si], [_ft(t) for t in fn])
    entry = ntfs.parse_record(raw, 40)
    found = [g for kind, g, _s, _d in ntfs.entry_findings(entry, '/a.txt')
             if kind == 'timestomp']
    assert found == ([grade] if grade else [])


def test_macb_rows_merge_equal_times():
    from trace_app.core import ntfs
    assert ntfs.macb_rows((5, 7, 7, 9)) == [(5, '...B'), (7, 'M.C.'),
                                            (9, '.A..')]
    assert ntfs.macb_rows((0, 3, 0, 3)) == [(3, 'MA..')]


def test_zone_identifier_utf16_and_odd_lines():
    from trace_app.core import ntfs
    text = '[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=about:internet\r\n'
    assert ntfs.parse_zone_identifier(text.encode('utf-16')) == {
        'ZoneId': '3', 'HostUrl': 'about:internet'}
    assert ntfs.parse_zone_identifier(b'') == {}


def test_filetime_keeps_odd_dates():
    """A time set to 1970 or 1601 is evidence, not an empty field."""
    from trace_app.core import ntfs
    assert ntfs.filetime_text(1) == '1601-01-01 00:00:00.0000001'
    assert ntfs.filetime_text(0) is None
    assert ntfs.filetime_text(116444736000000000) == \
        '1970-01-01 00:00:00.0000000'


# --- the change journal --------------------------------------------------------

def test_usn_records_match_plaso():
    from trace_app.core import ntfs
    with open(sample('UsnJrnl.raw'), 'rb') as handle:
        data = handle.read()
    records = list(ntfs.iter_usn(io.BytesIO(data), end=len(data)))
    assert len(records) == 19
    first = records[0]
    assert first.name == 'Nieuw - Tekstdocument.txt'
    assert first.file_reference() == 0x100000000001E
    assert first.parent_reference() == 0x5000000000005
    assert first.reasons == 0x100
    assert ntfs.filetime_text(first.time) == '2015-11-30 21:15:27.2031250'
    assert ntfs.usn_reason_text(first.reasons) == 'Created'
    assert ntfs.usn_reason_names(0x80000100) == ['FILE_CREATE', 'CLOSE']


def test_usn_skips_zero_fill_and_split_records():
    """Real journals start with gigabytes of zeroes where they were trimmed,
    and a record can straddle two reads."""
    from trace_app.core import ntfs
    with open(sample('UsnJrnl.raw'), 'rb') as handle:
        data = handle.read()
    padded = bytes(40960) + data
    records = list(ntfs.iter_usn(io.BytesIO(padded), end=len(padded),
                                 chunk=1000))
    assert len(records) == 19
    assert records[0].offset == 40960


def test_qcow2_volume_end_to_end(tmp_path):
    """The QCOW2 disk opens as evidence, and the module reads its volume's
    $MFT and journal into the case."""
    from trace_app.core import ntfs
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    path = sample('usnjrnl.qcow2')
    handler = ImageHandler(path)
    assert handler.load_image()
    case = Case.create(str(tmp_path / 'case'), name='ntfs')
    evidence = case.add_evidence(path)
    evidence_id = evidence['id'] if isinstance(evidence, dict) else evidence
    try:
        assert ntfs.analyse_evidence(handler, case, evidence_id) > 0
        state = case.ntfs_state(evidence_id)
        assert state['status'] == 'done'
        assert state['journal'] == 19 and state['volumes'] == 1
        records = case.usn_records(evidence_id, limit=100)
        created = [r for r in records if r['usn'] == 0]
        assert created[0]['path'] == '/Nieuw - Tekstdocument.txt'
        assert created[0]['time_utc'] == '2015-11-30 21:15:27.2031250'
        assert created[0]['artifact_ref'] == 'p63:i30:s1'
        # Every file The Sleuth Kit lists has its times under the same ref.
        refs = {row['artifact_ref'] for row in case._db.execute(
            "SELECT artifact_ref FROM fs_events WHERE evidence_id = ?",
            (evidence_id,))}
        fs = handler.get_fs_info(63)
        for entry in fs.open_dir('/'):
            name = entry.info.name.name
            if name in (b'.', b'..') or entry.info.meta is None \
                    or name == b'$OrphanFiles':
                continue
            assert (f"p63:i{entry.info.meta.addr}:"
                    f"s{entry.info.name.meta_seq}") in refs, name
        # Analysis clears its own findings, not these.
        case.add_ntfs_findings(evidence_id, [(
            'p63:i30:s1', 'x', '/x', 1, 'ads', 'notable', 's', '{}')])
        case.clear_analysis(evidence_id)
        assert case.ntfs_counts(evidence_id)['streams'] == 1
        # A second run replaces the first.
        ntfs.analyse_evidence(handler, case, evidence_id)
        assert case.ntfs_counts(evidence_id)['journal'] == 19
        assert case.ntfs_counts(evidence_id)['streams'] == 0
    finally:
        case.close()
        handler.close_resources()


def test_qcow2_description():
    from trace_app.core import containers
    _img, note = containers.open_virtual_disk(sample('usnjrnl.qcow2'))
    assert note == 'QCOW'
