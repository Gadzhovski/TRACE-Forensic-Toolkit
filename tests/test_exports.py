"""Exports for other tools (core/timeline_export.py, core/interchange.py):
Timesketch JSONL, plaso's l2t CSV, the mactime bodyfile, DFXML and
CASE/UCO JSON-LD, from a real two-image case (NTFS E01 + FAT dd) with the
file analysis, the NTFS module and file-system times run.

Checked against what is outside TRACE: the bodyfile's $SI times and the
DFXML's sizes and inodes against The Sleuth Kit's own reading of each
file (pytsk3), the DFXML's SHA-256s against the file's bytes read back,
Timesketch's documented required fields, l2t CSV's 17 columns, and the
CASE graph's own consistency (every reference resolves, every prefix is
declared, every hash is hex).
"""

import csv
import datetime
import hashlib
import json
import os
import re
import sqlite3
import xml.etree.ElementTree as ET

import pytest

from tests.conftest import image_path

IMAGES = ('ntfs1-gen2.E01', '6-fat-undel.dd')


@pytest.fixture(scope='module')
def built(tmp_path_factory):
    from trace_app.core import analysis, fs_times, ntfs
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    folder = str(tmp_path_factory.mktemp('exports') / 'case')
    case = Case.create(folder, 'Export test')
    ids = {}
    try:
        for name in IMAGES:
            path = image_path(name)
            handler = ImageHandler(path)
            assert handler.load_image()
            try:
                ids[name] = case.add_evidence(path)
                analysis.analyse_evidence(handler, case, ids[name],
                                          analysis.MODULES)
                module = ntfs if name.endswith('.E01') else fs_times
                module.analyse_evidence(handler, case, ids[name])
            finally:
                handler.close_resources()
    finally:
        case.close()
    connection = sqlite3.connect(os.path.join(folder, 'case.db'))
    names = dict(connection.execute(
        "SELECT id, COALESCE(display_name, path) FROM evidence"))
    names = {key: os.path.basename(value) for key, value in names.items()}
    yield {'folder': folder, 'connection': connection, 'ids': ids,
           'names': names, 'out': tmp_path_factory.mktemp('out')}
    connection.close()


def _filters():
    from trace_app.core import timeline
    return timeline.default_filters()


def test_timesketch_jsonl_has_what_timesketch_requires(built):
    from trace_app.core import timeline, timeline_export
    path = str(built['out'] / 'timeline.jsonl')
    written = timeline_export.write('jsonl', built['connection'], _filters(),
                                    path, built['names'])
    assert written == timeline.count(built['connection'], _filters()) > 0
    with open(path, encoding='utf-8') as handle:
        events = [json.loads(line) for line in handle]
    assert len(events) == written
    for event in events:
        # Timesketch's CSV/JSONL importer: message, datetime,
        # timestamp_desc are required; timestamp (µs) is used when present.
        assert event['message'] and event['timestamp_desc']
        moment = datetime.datetime.fromisoformat(event['datetime'])
        if event['time_zone'] == 'UTC':
            assert moment.utcoffset() == datetime.timedelta(0)
            assert event['timestamp'] == int(moment.timestamp() * 1e6)
        else:
            assert moment.tzinfo is None      # local, no zone: no offset
    # The FAT image's times have no zone and are said to be local.
    assert any(e['time_zone'] == 'local, no zone' and
               e['evidence'] == '6-fat-undel.dd' for e in events)


def test_l2t_csv_has_plasos_columns(built):
    from trace_app.core import timeline_export
    path = str(built['out'] / 'timeline.l2t.csv')
    written = timeline_export.write('l2tcsv', built['connection'],
                                    _filters(), path, built['names'])
    with open(path, encoding='utf-8', newline='') as handle:
        rows = list(csv.reader(handle))
    assert tuple(rows[0]) == timeline_export.L2T_HEADER
    assert len(rows) - 1 == written > 0
    assert all(len(row) == 17 for row in rows)
    files = [row for row in rows[1:] if row[4] == 'FILE']
    assert files and all(re.fullmatch(r'[M.][A.][C.][B.]', row[3])
                         and row[3] != '....' for row in files)
    assert all(re.fullmatch(r'\d\d/\d\d/\d{4}', row[0]) for row in rows[1:])


def _tsk_times(name):
    """{inode: (atime, mtime, ctime, crtime)} as The Sleuth Kit reads
    each file of the image's first volume ($STANDARD_INFORMATION on
    NTFS)."""
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path(name))
    assert handler.load_image()
    try:
        offset = handler.volume_offsets()[0]
        fs = handler.get_fs_info(offset)
        found = {}

        def walk(directory, depth=0):
            for entry in directory:
                meta = entry.info.meta
                label = entry.info.name.name
                if meta is None or label in (b'.', b'..') or depth > 8:
                    continue
                found[meta.addr] = (meta.atime, meta.mtime, meta.ctime,
                                    meta.crtime)
                if int(meta.type) == 2:          # TSK_FS_META_TYPE_DIR
                    try:
                        walk(entry.as_directory(), depth + 1)
                    except OSError:
                        pass
        walk(fs.open_dir(inode=fs.info.root_inum))
        return found
    finally:
        handler.close_resources()


def test_bodyfile_times_are_the_sleuth_kits(built):
    from trace_app.core import timeline_export
    path = str(built['out'] / 'timeline.body')
    filters = _filters()
    filters['evidence_id'] = built['ids']['ntfs1-gen2.E01']
    written = timeline_export.write('bodyfile', built['connection'], filters,
                                    path, {1: 'ntfs1-gen2.E01'})
    with open(path, encoding='utf-8') as handle:
        lines = [line.rstrip('\n').split('|') for line in handle]
    assert len(lines) == written > 0
    assert all(len(fields) == 11 for fields in lines)
    tsk = _tsk_times('ntfs1-gen2.E01')
    compared = 0
    for fields in lines:
        if not fields[1].endswith('($SI)'):
            continue
        inode = int(fields[2].split('-')[0])
        if inode not in tsk:
            continue
        atime, mtime, ctime, crtime = (int(v) for v in fields[7:11])
        expected = tsk[inode]
        # A time TRACE did not record for this file is 0 in the bodyfile.
        for got, want in zip((atime, mtime, ctime, crtime), expected):
            if got:
                assert got == want, fields
        compared += 1
    assert compared >= 20


def test_dfxml_files_are_what_the_image_holds(built):
    from trace_app.core import interchange
    from trace_app.core.image_handler import ImageHandler
    evidence_id = built['ids']['ntfs1-gen2.E01']
    path = str(built['out'] / 'files.xml')
    written = interchange.write_dfxml(built['connection'], evidence_id, path,
                                      '2.3.0')
    namespace = {'d': interchange.DFXML_NS}
    root = ET.parse(path).getroot()
    objects = root.findall('d:fileobject', namespace)
    assert len(objects) == written == built['connection'].execute(
        "SELECT COUNT(*) FROM file_analysis WHERE evidence_id = ?",
        (evidence_id,)).fetchone()[0]
    handler = ImageHandler(image_path('ntfs1-gen2.E01'))
    assert handler.load_image()
    try:
        fs = handler.get_fs_info(handler.volume_offsets()[0])
        checked = 0
        for node in objects:
            inode = int(node.find('d:inode', namespace).text)
            size = int(node.find('d:filesize', namespace).text)
            digest = {h.get('type'): h.text
                      for h in node.findall('d:hashdigest', namespace)}
            entry = fs.open_meta(inode=inode)
            assert entry.info.meta.size == size
            if 'sha256' in digest and size and checked < 15:
                data = entry.read_random(0, size)
                assert hashlib.sha256(data).hexdigest() == digest['sha256']
                checked += 1
        assert checked >= 5
    finally:
        handler.close_resources()


def test_dfxml_refuses_an_image_not_analysed(built, tmp_path):
    from trace_app.core import interchange
    from trace_app.core.case import Case
    case = Case.create(str(tmp_path / 'empty'), 'Empty')
    try:
        evidence_id = case.add_evidence(image_path('8-jpeg-search.dd'))
    finally:
        case.close()
    connection = sqlite3.connect(str(tmp_path / 'empty' / 'case.db'))
    try:
        with pytest.raises(interchange.NothingToExport):
            interchange.write_dfxml(connection, evidence_id,
                                    str(tmp_path / 'x.xml'), '2.3.0')
    finally:
        connection.close()


def test_case_uco_graph_holds_together(built):
    from trace_app.core import interchange
    path = str(built['out'] / 'case.jsonld')
    files = interchange.write_case_uco(built['connection'], path,
                                       'Export test', built['folder'],
                                       '2.3.0')
    with open(path, encoding='utf-8') as handle:
        document = json.load(handle)
    graph = document['@graph']
    ids = [node['@id'] for node in graph]
    assert len(ids) == len(set(ids))
    known = set(ids)
    prefixes = set(document['@context'])

    def visit(value):
        if isinstance(value, dict):
            for key, inner in value.items():
                if ':' in key and not key.startswith('@'):
                    assert key.split(':', 1)[0] in prefixes, key
                if key == '@type' and isinstance(inner, str):
                    assert inner.split(':', 1)[0] in prefixes, inner
                if key == '@id' and len(value) == 1:
                    assert inner in known, inner         # a reference
                visit(inner)
        elif isinstance(value, list):
            for inner in value:
                visit(inner)
    visit(graph)
    analysed = built['connection'].execute(
        "SELECT COUNT(*) FROM file_analysis").fetchone()[0]
    assert files == analysed
    relationships = [n for n in graph if n['@type'] ==
                     'uco-observable:ObservableRelationship']
    assert len(relationships) == analysed
    findings = built['connection'].execute(
        "SELECT COUNT(*) FROM file_findings").fetchone()[0]
    assert sum(1 for n in graph if n['@type'] == 'uco-core:Annotation') == \
        findings
    hashes = [h for n in graph for f in n.get('uco-core:hasFacet', [])
              for h in f.get('uco-observable:hash', [])]
    assert hashes and all(re.fullmatch(r'[0-9A-F]+',
                                       h['uco-types:hashValue']['@value'])
                          for h in hashes)
    # Exported twice, the same things have the same names.
    again = interchange.case_graph(built['connection'], 'Export test',
                                   built['folder'], '2.3.0')
    assert [n['@id'] for n in again['@graph']] == ids
