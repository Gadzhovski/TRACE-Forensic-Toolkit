"""Laying the report out as a PDF (trace_app/core/report.py, write_pdf).

MuPDF's Story has two failure modes the report met on a real case
(2020JimmyWilson, every module run): it sizes a table's columns to their
longest word and never shrinks them to the page, so columns after a SHA-256
were not in the PDF at all; and it can start the story over or stall, page
after page, which hung the report job. Every input here is generated.
"""

import datetime
import os
import time
from types import SimpleNamespace

import pytest


def _builder(toc=()):
    return SimpleNamespace(toc=list(toc), options={'title': 'Report'},
                           generated=datetime.datetime.now(
                               datetime.timezone.utc))


def _text(path):
    import pymupdf
    flags = pymupdf.TEXTFLAGS_TEXT & ~pymupdf.TEXT_PRESERVE_LIGATURES
    with pymupdf.open(path) as document:
        return [page.get_text(flags=flags) for page in document]


def test_long_runs_get_break_points_and_markup_stays_whole():
    from trace_app.core.report import _breakable_runs
    run = 'a' * 25
    out = _breakable_runs(f"<td class='x'>{run}&amp;b</td><p>short</p>",
                          20, 10)
    assert out.startswith("<td class='x'>") and out.endswith('<p>short</p>')
    pieces = out[len("<td class='x'>"):-len('</td><p>short</p>')]
    assert pieces.split('​') == ['a' * 10, 'a' * 10, 'aaaaa&amp;b']
    # Below the threshold nothing changes; spaces end a run.
    assert _breakable_runs('<td>abc def</td>', 20, 10) == '<td>abc def</td>'


def test_a_table_of_hashes_is_printed_whole(tmp_path):
    """Every cell of a table with a hash, a long path and seven more
    columns is in the PDF, and nothing is past the right margin."""
    import hashlib
    from trace_app.core.report import write_pdf
    rows = []
    for number in range(30):
        digest = hashlib.sha256(str(number).encode()).hexdigest()
        path = '/Users/Someone/AppData/Local/Microsoft/Windows/' \
               f'INetCache/IE/ABCDEFGH/picture-{number:04d}.jpg'
        rows.append([f'file{number}.jpg', path, digest, 'Evidence.E01',
                     'JPG', 'Complete', f'{number * 4096:,}', '4.0 KB',
                     f'last{number}'])
    head = ''.join(f'<th>{h}</th>' for h in (
        'Name', 'Path', 'SHA-256', 'Evidence', 'Type', 'Status', 'Offset',
        'Size', 'Last'))
    body = ''.join('<tr>' + ''.join(f'<td>{c}</td>' for c in row) + '</tr>'
                   for row in rows)
    html = (f"<div class='cover'><p>Cover</p></div><h1 id='t'>Table</h1>"
            f"<table class='data small'><tr>{head}</tr>{body}</table>")
    path = str(tmp_path / 'wide.pdf')
    write_pdf(_builder([(1, 't', 'Table')]), html, path)
    # A wrapped run comes back with a space where it broke.
    text = ''.join(''.join(_text(path)).split()).replace('​', '')
    for row in rows:
        for cell in row:
            assert ''.join(cell.split()) in text, cell
    import pymupdf
    with pymupdf.open(path) as document:
        for page in document:
            for word in page.get_text('words'):
                assert word[2] <= page.rect.width - 42 + 1, word[4]


def test_a_stalled_layout_is_an_error_not_a_hang(tmp_path):
    """A page break at the very start of a story makes MuPDF place the
    same empty stretch for ever; it is caught in a few pages."""
    from trace_app.core.report import ReportError, write_pdf
    started = time.monotonic()
    with pytest.raises(ReportError):
        write_pdf(_builder([(1, 'a', 'A')]),
                  "<div class='section'><h1 id='a'>A</h1><p>x</p></div>",
                  str(tmp_path / 'stall.pdf'))
    assert time.monotonic() - started < 30


def test_a_pdf_that_fails_leaves_the_other_formats(tmp_path, monkeypatch):
    from trace_app.core import report
    from trace_app.core.case import Case
    case = Case.create(str(tmp_path / 'case'), 'Layout', number='L-1',
                       examiner='Examiner')
    try:
        def refuse(builder, body, path):
            raise report.ReportError("The PDF could not be laid out.")
        monkeypatch.setattr(report, 'write_pdf', refuse)
        options = report.default_options(case)
        options['formats'] = ['html', 'pdf', 'docx']
        folder = str(tmp_path / 'out')
        with pytest.raises(report.ReportError) as raised:
            report.write_report(case, options, {}, folder=folder)
        [made] = os.listdir(folder)
        names = sorted(os.listdir(os.path.join(folder, made)))
        assert names == ['report.docx', 'report.html']
        for name in names:
            assert name in str(raised.value)
        audited = [row for row in case.activity()
                   if row['action'] == 'report created']
        assert len(audited) == 2
    finally:
        case.close()
