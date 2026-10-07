"""Hash sets (trace_app/core/hashsets.py): importing every list format,
linking an NSRL RDS v3 database, matching, and the case's options.

The digests are those of a real image's files (ntfs1-gen2.E01, hashed by the
analysis module); the lists are written here in each format a set arrives
in. The NSRL database is built with RDS v3's own FILE table layout and
indexes, upper-case digests included, because that is how NIST writes them.
"""

import os
import sqlite3

import pytest

from tests.conftest import image_path

pytestmark = pytest.mark.images


@pytest.fixture(scope='module')
def hashed(tmp_path_factory):
    """(case, evidence id, [hashed file rows]) for ntfs1-gen2.E01."""
    from trace_app.core.analysis import analyse_evidence
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    folder = str(tmp_path_factory.mktemp('hashsets') / 'case')
    case = Case.create(folder, 'Hash sets')
    path = image_path('ntfs1-gen2.E01')
    evidence_id = case.add_evidence(path)
    handler = ImageHandler(path)
    analyse_evidence(handler, case, evidence_id, ['hash'])
    handler.close_resources()
    files = case.hashed_files(evidence_id)
    assert len(files) > 10
    yield case, evidence_id, files
    case.close()


def _library(tmp_path):
    from trace_app.core import hashsets
    return hashsets.Library(str(tmp_path / 'library'))


def _nsrl(path, rows):
    connection = sqlite3.connect(path)
    connection.executescript("""
        CREATE TABLE FILE (sha256 VARCHAR NOT NULL, sha1 VARCHAR NOT NULL,
            md5 VARCHAR NOT NULL, crc32 VARCHAR NOT NULL,
            file_name VARCHAR NOT NULL, file_size INTEGER NOT NULL,
            package_id INTEGER NOT NULL);
        CREATE INDEX FILE_SHA1 ON FILE(sha1);
        CREATE INDEX FILE_MD5 ON FILE(md5);
        CREATE INDEX FILE_SHA256 ON FILE(sha256);
        CREATE TABLE VERSION (version VARCHAR, build_set VARCHAR,
            build_date TIMESTAMP, release_date TIMESTAMP,
            description VARCHAR);
    """)
    connection.executemany(
        "INSERT INTO FILE VALUES (?,?,?,?,?,?,?)",
        [(r['sha256'].upper(), r['sha1'].upper(), r['md5'].upper(), '0',
          r['name'], r['size'] or 0, 1) for r in rows])
    connection.commit()
    connection.close()


def test_sha1_is_recorded_by_the_hash_module(hashed):
    import hashlib
    _case, _evidence, files = hashed
    for row in files:
        assert len(row['sha1']) == 40 and len(row['md5']) == 32
    assert hashlib.sha1(b'').hexdigest() not in {r['sha1'] for r in files}


def test_plain_list_reads_every_shape(tmp_path, hashed):
    """VirusShare (comment header, one MD5 per line), sha256sum output
    (upper case here), and lines with no digest -- counted, not fatal."""
    _case, _evidence, files = hashed
    source = tmp_path / 'VirusShare_00000.md5'
    source.write_text(
        '#################################\n# VirusShare.com hash list\n'
        f"{files[0]['md5']}\n"
        f"{files[1]['sha256'].upper()}  *evil.exe\n"
        'no digest on this line\n\n', encoding='utf-8')
    library = _library(tmp_path)
    entry = library.import_list(str(source), 'VirusShare', 'known-bad')
    assert entry['count'] == 2
    assert entry['counts'] == {'md5': 1, 'sha1': 0, 'sha256': 1}
    assert entry['algorithms'] == ['md5', 'sha256']
    assert entry['skipped_lines'] == 1
    import hashlib
    assert entry['source_sha256'] == hashlib.sha256(
        source.read_bytes()).hexdigest()
    assert library.sets()[0]['available']


def test_csv_columns_are_sniffed_and_chosen(tmp_path, hashed):
    """NSRL 2.x NSRLFile.txt: quoted CSV, SHA-1 and MD5 columns, CRC32
    (eight hex digits) not mistaken for a digest."""
    from trace_app.core import hashsets
    _case, _evidence, files = hashed
    source = tmp_path / 'NSRLFile.txt'
    lines = ['"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode",'
             '"OpSystemCode","SpecialCode"']
    for row in files[:3]:
        lines.append(f'"{row["sha1"].upper()}","{row["md5"].upper()}",'
                     f'"0A1B2C3D","{row["name"]}",{row["size"]},1,"WIN",""')
    source.write_text('\r\n'.join(lines) + '\r\n', encoding='utf-8')
    names, found = hashsets.sniff_columns(str(source))
    assert names[:3] == ['SHA-1', 'MD5', 'CRC32']
    assert found == {0: 'sha1', 1: 'md5'}
    library = _library(tmp_path)
    entry = library.import_list(str(source), 'NSRL 2.x', 'known-good',
                                columns=[1])
    assert entry['counts'] == {'md5': 3, 'sha1': 0, 'sha256': 0}


def test_nsrl_v3_is_linked_in_place_read_only(tmp_path, hashed):
    from trace_app.core import hashsets
    _case, _evidence, files = hashed
    database = str(tmp_path / 'RDS_2024.03.1_modern_minimal.db')
    _nsrl(database, files[:4])
    before = os.path.getmtime(database)
    assert hashsets.is_nsrl_database(database)
    library = _library(tmp_path)
    entry = library.link_nsrl(database)
    assert entry['kind'] == 'linked' and entry['category'] == 'known-good'
    assert entry['algorithms'] == ['md5', 'sha1', 'sha256']
    lookup = hashsets.SetLookup(library, entry)
    try:
        assert lookup.match('sha256', [files[0]['sha256'],
                                       'f' * 64]) == {files[0]['sha256']}
    finally:
        lookup.close()
    assert os.path.getmtime(database) == before
    # Removing a linked set leaves the database alone.
    library.remove(entry['id'])
    assert os.path.exists(database) and not library.sets()


def test_unindexed_database_is_refused(tmp_path):
    from trace_app.core import hashsets
    database = str(tmp_path / 'plain.db')
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE FILE (sha256 TEXT, md5 TEXT)")
    connection.commit()
    connection.close()
    with pytest.raises(hashsets.HashSetError, match='indexed'):
        _library(tmp_path).link_nsrl(database)


def test_matching_follows_the_case_options(tmp_path, hashed):
    """Known bad, notable and known good recorded per file; a set switched
    off for the case, an algorithm not chosen, or hash sets switched off
    altogether each change the result -- and every run is audited."""
    from trace_app.core import hashsets
    case, evidence_id, files = hashed
    library = _library(tmp_path)
    bad_list = tmp_path / 'bad.txt'
    bad_list.write_text(f"{files[0]['md5']}\n{files[1]['sha256']}\n")
    bad = library.import_list(str(bad_list), 'Bad', 'known-bad')
    notable_list = tmp_path / 'notable.txt'
    notable_list.write_text(f"{files[2]['sha1']}\n")
    notable = library.import_list(str(notable_list), 'Project',
                                  'notable')
    database = str(tmp_path / 'RDS.db')
    _nsrl(database, files[3:6])
    good = library.link_nsrl(database)

    options = hashsets.case_options(case, library)
    assert options['enabled']           # the library has sets
    summary = hashsets.match_case(case, library, options)
    expected_good = len({r['artifact_ref'] for r in files
                         if r['sha256'] in {f['sha256'] for f in files[3:6]}})
    assert summary['known-bad'] == len(
        {r['artifact_ref'] for r in files
         if r['md5'] == files[0]['md5'] or r['sha256'] == files[1]['sha256']})
    assert summary['known-good'] == expected_good
    assert summary['notable'] >= 1
    matches = case.hash_matches(evidence_id)
    assert matches[0]['category'] == 'known-bad'
    by_ref = case.hash_match_map(evidence_id, [files[0]['artifact_ref']])
    assert by_ref[files[0]['artifact_ref']][0]['set_name'] == 'Bad'

    # The project list switched off for this case.
    options['sets'] = {notable['id']: False}
    assert hashsets.match_case(case, library, options)['notable'] == 0
    # SHA-256 only: the MD5 entry no longer matches.
    options = dict(options, algorithms=['sha256'], sets={})
    hashsets.match_case(case, library, options)
    assert {m['artifact_ref'] for m in case.hash_matches(
        evidence_id, ['known-bad'])} == {
        r['artifact_ref'] for r in files
        if r['sha256'] == files[1]['sha256']}
    # Off altogether: nothing recorded.
    options['enabled'] = False
    hashsets.match_case(case, library, options)
    assert case.hash_match_counts(evidence_id) == {}
    events = [row['action'] for row in case.activity()]
    assert 'hash sets matched' in events
    assert {bad['id'], good['id']} <= {e['id'] for e in library.sets()}


def test_export_round_trips_with_its_category(tmp_path, hashed):
    from trace_app.core import hashsets
    _case, _evidence, files = hashed
    library = _library(tmp_path)
    source = tmp_path / 'list.txt'
    source.write_text('\n'.join(r['sha256'] for r in files[:5]))
    entry = library.import_list(str(source), 'Case 12 contraband', 'notable',
                                'From case 12')
    out = str(tmp_path / 'export.txt')
    assert library.export(entry['id'], out) == entry['count']
    header = hashsets.read_export_header(out)
    assert header == {'name': 'Case 12 contraband', 'category': 'notable',
                      'description': 'From case 12'}
    again = library.import_list(out, header['name'], header['category'])
    assert again['count'] == entry['count']


def test_cancelled_import_leaves_nothing(tmp_path):
    from trace_app.core import hashsets
    source = tmp_path / 'big.txt'
    source.write_text('\n'.join(f'{n:032x}' for n in range(120_000)))
    library = _library(tmp_path)
    with pytest.raises(hashsets.ImportCancelled):
        library.import_list(str(source), 'big', 'notable',
                            should_stop=lambda: True)
    assert library.sets() == []
    assert [f for f in os.listdir(library.folder)
            if f.endswith(('.db', '.partial'))] == []


def test_options_default_off_without_sets(tmp_path, hashed):
    from trace_app.core import hashsets
    case, _evidence, _files = hashed
    empty = _library(tmp_path)
    saved = case.setting('hashsets')
    case.set_setting('hashsets', None)
    try:
        assert not hashsets.case_options(case, empty)['enabled']
    finally:
        case.set_setting('hashsets', saved)
