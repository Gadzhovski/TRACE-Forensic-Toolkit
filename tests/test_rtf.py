"""RTF documents (core/rtf.py): shown in the Application tab, indexed for
search.

The reference is Windows' own reader, RichEdit: its text of the carving
corpus's sample1.rtf is in tests/expected/rtf_richedit.json (how it was
made is said there). Over 3,871 RTFs here (macOS's Cocoa RTFs in every
language, Word's) TRACE's words equal RichEdit's on 3,746; the rest were
read through -- RichEdit losing letters its string held no room for
(Greek, Hebrew, Vietnamese...), and where it puts a link's target. The
generated documents below state their own answers.
"""

import difflib
import json
import os
import re

from tests.conftest import ROOT, data_path
from trace_app.core import rtf

BACKSLASH = chr(92)


def _words(text):
    # A link's target in angle brackets, as RichEdit writes it.
    text = re.sub(r'<([^<>\s]+:[^<>\s]*|#[^<>\s]*)>', r'\1', text)
    return text.replace(' ', ' ').split()


def _body(document):
    return '\n'.join(''.join(run[0] for run in paragraph)
                     for paragraph in document.paragraphs)


def test_sample1_reads_as_richedit_reads_it():
    path = data_path('corpus', 'sample1.rtf')
    with open(os.path.join(ROOT, 'tests', 'expected', 'rtf_richedit.json'),
              encoding='utf-8') as handle:
        expected = json.load(handle)['sample1.rtf']
    with open(path, 'rb') as handle:
        document = rtf.read(handle.read())
    ours, theirs = _words(_body(document)), _words(expected)
    differences = [(tag, ours[i1:i2], theirs[j1:j2]) for tag, i1, i2, j1, j2
                   in difflib.SequenceMatcher(None, ours, theirs,
                                              autojunk=False).get_opcodes()
                   if tag != 'equal']
    for tag, mine, richedit in differences:
        if tag == 'delete':
            # List bullets and numbers (\pntext): kept, as a reader sees
            # them; RichEdit's text leaves them for the list to redraw.
            assert all(re.fullmatch(r'·|[IVX]+\.', w) for w in mine), mine
        elif mine == ['–'] and richedit == ['-']:
            pass                    # \endash is U+2013; RichEdit writes '-'
        else:
            # A SYMBOL field with an empty result: RichEdit puts the
            # character code (74, 'J' -- a Wingdings smiley) there.
            assert (mine, richedit) == (['()'], ['(J)']), (mine, richedit)
    # The Hungarian pangram, in a Central European font (\fcharset238).
    assert 'árvíztűrő ütvefúrógép' in _body(document)


def _doc(body, fonts=r'{\f0\fswiss\fcharset0 Arial;}', head=''):
    return (r'{\rtf1\ansi\ansicpg1252\deff0{\fonttbl' + fonts + '}' + head +
            body + '}').encode('ascii')


FONTS = (r'{\f0\fswiss\fcharset0 Arial;}{\f1\froman\fcharset204 Times Cyr;}'
         r'{\f2\froman\fcharset161 Times Greek;}'
         r'{\f3\froman\fcharset177 Times Hebrew;}')


def test_each_font_reads_in_its_own_code_page():
    russian, greek, hebrew = 'Привет мир', 'Καλημέρα', 'שלום'
    body = ''.join(
        r'{\f%d %s}\par ' % (font, ''.join(r"\'%02x" % b
                                           for b in text.encode(codec)))
        for font, text, codec in ((1, russian, 'cp1251'),
                                  (2, greek, 'cp1253'),
                                  (3, hebrew, 'cp1255')))
    document = rtf.read(_doc(body, FONTS))
    assert _body(document).split('\n')[:3] == [russian, greek, hebrew]


def test_unicode_with_fallbacks_and_surrogate_pairs():
    # \u with one fallback character (\uc1), then none (\uc0), then an
    # emoji as a UTF-16 surrogate pair; a \'xx fallback counts as one.
    def u(text, fallback='?'):
        return ''.join(BACKSLASH + 'u%d' % ord(c) + fallback for c in text)
    # The fourth fallback is a hex byte: one character too.
    body = (BACKSLASH + 'uc1' + u('При') + u('в', BACKSLASH + "'3f") +
            u('ет') + ' {' + BACKSLASH + 'uc0' + u('中文', '') + '} ' +
            BACKSLASH + 'u-10179?' + BACKSLASH + 'u-8704?')
    text = _body(rtf.read(_doc(body)))
    assert text == 'Привет 中文 😀'


def test_ansi_fonts_are_windows_1252_whatever_the_code_page():
    # macOS writes \ansicpg936 and \mac documents whose fcharset0 fonts
    # hold Windows-1252 bytes, as RichEdit reads them.
    doc = (r"{\rtf1\ansi\ansicpg936\cocoartf1671{\fonttbl\f0\fswiss"
           r"\fcharset0 Helvetica;}\f0 It\'92s \'95 done}").encode()
    assert _body(rtf.read(doc)) == 'It’s • done'
    doc = (r"{\rtf1\mac\ansicpg10000{\fonttbl\f0\fnil\fcharset0 Helvetica;}"
           r"\f0 Vi\'9ae}").encode()
    assert _body(rtf.read(doc)) == 'Više'


def test_what_a_reader_does_not_see_is_kept_and_said():
    head = (r'{\info{\title Quarterly plan}{\author A. Smith}'
            r'{\operator B. Jones}{\creatim\yr2004\mo7\dy2\hr15\min38}}'
            r'{\*\generator Microsoft Word 11.0.6113;}')
    body = (r'Visible {\v secret note} text {\deleted removed words}'
            r'{\revised added} {\*\shppict{\pict\pngblip 89504e47}}'
            r'{\nonshppict{\pict\wmetafile8 0100}}'
            r'{\field{\*\fldinst HYPERLINK "http://evil.example/x"}'
            r'{\fldrslt www.bank.example}} '
            r'{\field{\*\fldinst HYPERLINK "http://same.example/"}'
            r'{\fldrslt http://same.example/}}')
    data = _doc(body, head=head)
    document = rtf.read(data)
    assert _body(document) == ('Visible secret note text removed words'
                               'added www.bank.example '
                               '<http://evil.example/x> http://same.example/')
    assert document.facts == [
        ('Title', 'Quarterly plan'), ('Author', 'A. Smith'),
        ('Last saved by', 'B. Jones'),
        ('Created', '2004-07-02 15:38 (local, no zone)')]
    assert (document.hidden_chars, document.deleted_chars,
            document.inserted_chars, document.pictures) == (11, 13, 5, 1)
    page, notices = rtf.to_html(data)
    assert '<span class="hidden">secret note</span>' in page
    assert '<span class="deleted">removed words</span>' in page
    assert any(n.startswith('Hidden text: 11 character(s)') for n in notices)
    assert any(n.startswith('Tracked changes: 13 deleted') for n in notices)
    assert 'Written by Microsoft Word 11.0.6113.' in notices
    # Searchable: hidden and deleted words, the link's real target, \info.
    words = rtf.text(data)
    for word in ('secret', 'removed', 'evil.example', 'Quarterly',
                 'B. Jones'):
        assert word in words
    # Escaped: document text never becomes markup.
    page, _ = rtf.to_html(_doc(r'<script>alert(1)</script>'))
    assert '<script>' not in page and '&lt;script&gt;' in page


def test_rtf_is_shown_and_indexed_by_content_whatever_its_name():
    from trace_app.core.document_preview import to_html
    from trace_app.core.filetypes import VIEW_OFFICE, plan_view
    from trace_app.core.text_extract import extract_text
    data = _doc(r'{\f1 ' + ''.join(r"\'%02x" % b for b in
                                    'Полиморфизм'.encode('cp1251')) + '}',
                FONTS)
    for name in ('note.rtf', 'Word saved this.doc'):
        plan = plan_view(name, data)
        assert (plan.kind, plan.subtype) == (VIEW_OFFICE, 'rtf'), name
        assert 'Полиморфизм' in extract_text(data, name)
    page, notices = to_html(data, 'rtf')
    assert '<p>Полиморфизм</p>' in page and notices == []


def test_damaged_and_hostile_input_never_raises():
    for data in (b'{\\rtf1', b'{\\rtf1 ' + b'{' * 5000 + b'x' + b'}' * 10,
                 b'{\\rtf1\\u99999999999 \\uc99 a}', b'{\\rtf1\\ansicpg99999 '
                 b"\\'ff}", b'{\\rtf1 }}}}} after'):
        rtf.read(data)
        rtf.to_html(data)
    try:
        rtf.read(b'plain text')
    except rtf.NotRtf:
        pass
    else:
        raise AssertionError('plain text read as RTF')
