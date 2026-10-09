"""Keyword lists (trace_app/core/keywords.py).

The real test is DFTT #2 (FAT keyword search, Brian Carrier): an image with
strings planted in files, across files, in slack and in unallocated space,
and a published table of where each one is and which grep regular
expressions should find it. A list made of that table is run over the
image's search index; every string stored inside a file -- allocated or
deleted, and the file name in a directory entry -- is found where the table
says, and so is the one wholly inside a file's slack (3slack3: indexing
reads each live file's slack as an item of its own), and so is the one
in unallocated space (3cross3: free space is indexed in pieces, named by
sector -- DFTT puts it at sector 283, in the piece from 282). Strings that
cross from one file into another or into slack are in no single item, so
a search of the index does not find them; the table marks them as such and
so does this test. 'SECOND' is also a name in the FAT16 root folder
(sector 239): file-system structures are not free space, so that copy is
the file's name, not an "unallocated" hit.
"""

import os

import pytest

from tests.conftest import image_path

#: DFTT #2's table: the term, then the files it is in (empty: in no file).
DFTT_TERMS = [
    ('first', {'/file1.dat'}),
    ('SECOND', {'/file2.dat', '/second'}),     # and a file's name
    ('1cross1', set()),                        # crosses two files
    ('2cross2', {'/file3.dat'}),
    ('3cross3', {'[unallocated]/sectors 282-2329'}),   # free space
    ('1slack1', set()),                        # file into slack
    ('2slack2', set()),
    ('3slack3', {'/file4.dat [slack]'}),       # wholly in file4's slack
    ('1fragment1', {'/file4.dat'}),
    ('2fragment sentence2', {'/file6.dat'}),
    # A deleted file -- whose cluster is free space too: the same bytes,
    # DFTT's sector 276, are an unallocated piece as well.
    ('deleted', {'/_ILE5.DAT', '[unallocated]/sectors 276-276'}),
    (r'a?b\c*d$e#f[g^', {'/file7.dat'}),
    ('FirST', {'/file1.dat'}),                 # case-insensitive
    (r'/f[[:alpha:]]rst/', {'/file1.dat'}),
    (r'/f[a-z]r[0-9]?s[[:space:]]*t/', {'/file1.dat'}),
    (r'/d[a-z]l.?t.?d/', {'/_ILE5.DAT', '[unallocated]/sectors 276-276'}),
    (r'/[r-t][[:space:]]?[j-m][[:space:]]?[a-c]{2,2}[[:space:]]?[j-m]/',
     {'/file4.dat [slack]'}),                  # 3slack3; the others cross
    (r'/[1572943][[:space:]]?fr.{2,3}ent[[:space:]]?/',
     {'/file4.dat', '/file6.dat'}),
    (r'/a\??[a-c]\\*[a-c]\**/', {'/file7.dat'}),
    (r'/[[:alpha:]]\??x?y?Q?[a-c]\\*u*[a-c]\**d\$[0-9]*e#/',
     {'/file7.dat'}),
]


@pytest.fixture
def indexed_case(tmp_path):
    from trace_app.core.case import Case
    from trace_app.core.image_handler import ImageHandler
    from trace_app.core.indexer import index_evidence
    from trace_app.core.search_index import SearchIndex
    path = image_path('fat-img-kw.dd')
    case = Case.create(str(tmp_path / 'case'), 'Keywords')
    evidence_id = case.add_evidence(path)
    handler = ImageHandler(path)
    assert handler.load_image()
    index = SearchIndex(case.folder)
    index_evidence(handler, index, evidence_id)
    index.close()
    handler.close_resources()
    yield case, evidence_id
    case.close()


def test_dftt_keyword_search_answer_key(indexed_case, tmp_path):
    from trace_app.core import keywords
    case, evidence_id = indexed_case
    source = tmp_path / 'dftt.txt'
    source.write_text('# DFTT #2\n' + '\n'.join(t for t, _ in DFTT_TERMS),
                      encoding='utf-8')
    library = keywords.Library(str(tmp_path / 'library'))
    entry = library.import_file(str(source), 'DFTT #2')
    assert len(entry['terms']) == len(DFTT_TERMS)
    assert entry['source_sha256']
    result = keywords.run_case(case, library)
    assert result['not_indexed'] == []

    findings = case.findings(evidence_id, 'keywords', limit=10000)
    found = {}
    for finding in findings:
        found.setdefault(finding['detail']['term'], set()).add(
            finding['path'])
    for term, files in DFTT_TERMS:
        assert found.get(term, set()) == files, term
    assert result['terms_hit'] == sum(1 for _, f in DFTT_TERMS if f)

    first = next(f for f in findings if f['detail']['term'] == 'first')
    assert 'first' in first['detail']['excerpt']
    assert first['grade'] == 'notable' and first['kind'] == 'keyword'
    summary = keywords.term_summary(findings)
    assert summary[0]['files'] == 2           # the most widespread first

    # The report lists each term, then its files with the hit in context.
    from trace_app.core import report
    options = report.default_options(case)
    options.update(formats=['html'], sections=[{'key': 'keywords',
                                                'enabled': True}])
    out = report.write_report(case, options, {})
    page = open(out[0]['path'], encoding='utf-8').read()
    assert 'Keyword hits' in page and '2fragment sentence2' in page
    assert 'a?b\\c*d$e#f[g^' in page and '/_ILE5.DAT' in page

    # Kept when the file analysis runs again; replaced by the next search.
    case.clear_analysis(evidence_id)
    assert case.findings(evidence_id, 'keywords')
    library.update(entry['id'], terms=[keywords.make_term('deleted')])
    keywords.run_case(case, library)
    assert {f['path'] for f in case.findings(evidence_id, 'keywords')} == \
        {'/_ILE5.DAT', '[unallocated]/sectors 276-276'}
    trail = ' '.join(row['detail'] or '' for row in case.activity())
    assert 'keyword search finished' in ' '.join(
        row['action'] for row in case.activity())
    assert 'DFTT #2' in trail


def test_the_job_runs_in_a_child_process_shape(indexed_case, tmp_path):
    from trace_app.core import background, keywords
    case, evidence_id = indexed_case
    library = keywords.Library(str(tmp_path / 'library'))
    library.create('Words', [keywords.make_term('first')])
    items = []
    count = background.JOBS['keywords'](
        {'case_folder': case.folder, 'library': library.folder,
         'evidence_ids': [evidence_id]},
        lambda *a, **k: None, items.append, lambda: False)
    assert count == 1 and items[0]['terms_hit'] == 1


def test_an_image_not_yet_indexed_is_said_to_be(tmp_path):
    from trace_app.core import keywords
    from trace_app.core.case import Case
    case = Case.create(str(tmp_path / 'case'), 'Not indexed')
    evidence_id = case.add_evidence(image_path('fat-img-kw.dd'))
    library = keywords.Library(str(tmp_path / 'library'))
    library.create('Words', [keywords.make_term('first')])
    try:
        assert keywords.run_case(case, library)['not_indexed'] == \
            [evidence_id]
    finally:
        case.close()


def test_lines_and_csv_rows_become_terms():
    from trace_app.core import keywords
    terms, problems = keywords.read_terms(
        b'# comment\n\nalpha\n"two words"\nexfil*\n/\\d{3}-\\d{4}/\n'
        b're:[[:digit:]]+\nalpha\n/([unclosed/\n', 'list.txt')
    assert [(t['term'], t['kind']) for t in terms] == [
        ('alpha', 'text'), ('two words', 'text'), ('exfil', 'prefix'),
        (r'\d{3}-\d{4}', 'regex'), ('[[:digit:]]+', 'regex')]
    assert len(problems) == 1 and problems[0].startswith('Line 9:')
    terms, problems = keywords.read_terms(
        'term,type,note\nsecret,word,project name\n'
        '"^ab+",regex,\nhäßlich,,\n'.encode('utf-8'), 'list.csv')
    assert [(t['term'], t['kind'], t['note']) for t in terms] == [
        ('secret', 'text', 'project name'), ('^ab+', 'regex', ''),
        ('häßlich', 'text', '')]
    assert problems == []


def test_a_list_with_a_bad_term_is_not_imported(tmp_path):
    from trace_app.core import keywords
    source = tmp_path / 'bad.txt'
    source.write_text('good\n/[broken/\n')
    library = keywords.Library(str(tmp_path / 'library'))
    with pytest.raises(keywords.KeywordError, match='Line 2'):
        library.import_file(str(source))
    assert library.lists() == []


def test_export_round_trip_and_options(tmp_path):
    from trace_app.core import keywords
    library = keywords.Library(str(tmp_path / 'library'))
    entry = library.create('Mixed', [keywords.make_term('a b'),
                                     keywords.make_term('pre', 'prefix'),
                                     keywords.make_term('x+y', 'regex')],
                           grade='suspicious')
    out = tmp_path / 'out.txt'
    library.export_text(entry['id'], str(out))
    again = library.import_file(str(out))
    assert [(t['term'], t['kind']) for t in again['terms']] == \
        [(t['term'], t['kind']) for t in entry['terms']]
    options = keywords.case_options(None, library)
    assert options['enabled'] is True
    assert keywords.list_enabled_in(dict(options, lists={entry['id']: False}),
                                    entry) is False


def test_words_are_confirmed_in_the_text(tmp_path):
    """The index splits on punctuation and folds accents; a hit is counted
    only where the term itself is."""
    from trace_app.core import keywords
    from trace_app.core.case import Case
    from trace_app.core.search_index import INDEX_DONE, SearchIndex
    case = Case.create(str(tmp_path / 'case'), 'Words')
    evidence_id = case.add_evidence(image_path('fat-img-kw.dd'))
    index = SearchIndex(case.folder)
    index.add_item(evidence_id, 'p0:i1:s1', 'file', 'a.txt', '/a.txt',
                   'ran evil exe twice; café menu', size=10)
    index.add_item(evidence_id, 'p0:i2:s1', 'file', 'b.txt', '/b.txt',
                   'evil.exe evil.exe evil.exe and the cafe', size=10)
    index.add_item(evidence_id, 'p0:i3:s1', 'archive-member', 'c.html',
                   '/mail.pst!/Inbox/0001 Plans.html',
                   'meet at the exfiltration point', size=10)
    index.set_state(evidence_id, INDEX_DONE)
    index.commit()
    index.close()
    library = keywords.Library(str(tmp_path / 'library'))
    library.create('W', [keywords.make_term('evil.exe'),
                         keywords.make_term('cafe'),
                         keywords.make_term('exfil', 'prefix'),
                         keywords.make_term('mail.pst')])
    try:
        keywords.run_case(case, library)
        by_term = {}
        for f in case.findings(evidence_id, 'keywords'):
            by_term.setdefault(f['detail']['term'], {})[f['name']] = \
                f['detail']['hits']
        assert by_term['evil.exe'] == {'b.txt': 3}
        assert 'mail.pst' not in by_term          # only on the path
        assert by_term['cafe'] == {'a.txt': 1, 'b.txt': 1}   # café too
        assert by_term['exfil*'] == {'c.html': 1}
        # A folder on the path is not a hit for every file under it.
        assert 'Plans' not in str(by_term)
        member = case.findings(evidence_id, 'keywords', kind='keyword')
        assert any(f['path'].startswith('/mail.pst!/') for f in member)
    finally:
        case.close()
