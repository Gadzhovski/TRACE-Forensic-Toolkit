"""Windows 11 Notepad's tab state (core/activity/notepad.py), on files
Notepad itself wrote: ogmini's Notepad-State-Library test files and
AbdulRhman Alfaifi's notepad_parser samples (tools/testdata/samples.py).

Expected values come from outside TRACE:
* tests/expected/notepad_parser_key.json -- what notepad_parser (Rust, an
  independent reading of the format) gives for each file it reads;
* Notepad's own SHA-256 of the saved file, stored in each saved tab: it
  must equal the text TRACE decoded, saved as Notepad saves (UTF-8, CRLF);
* the names ogmini gave the older Notepad's files (EncodingUTF16BE.bin,
  UnixLF.bin ...), which notepad_parser does not read.
"""

import hashlib
import json
import os

import pytest

from tests.conftest import data_path
from trace_app.core.activity import notepad

KEY = os.path.join(os.path.dirname(__file__), 'expected',
                   'notepad_parser_key.json')


def _key():
    with open(KEY, encoding='utf-8') as handle:
        return json.load(handle)['tabs']


def _tab(name):
    with open(data_path('samples', name), 'rb') as handle:
        return notepad.parse(handle.read())


_ENCODINGS = {'UTF8': 'UTF-8', 'UTF8BOM': 'UTF-8 with BOM',
              'UTF16LE': 'UTF-16LE', 'UTF16BE': 'UTF-16BE', 'ANSI': 'ANSI'}
_LINES = {'CRLF': 'CRLF (Windows)', 'CR': 'CR (Macintosh)',
          'LF': 'LF (Unix)'}


@pytest.mark.parametrize('name', sorted(_key()))
def test_every_field_notepad_parser_reads(name):
    want = _key()[name]
    tab = _tab(name)
    assert tab['type'] == (1 if want['is_saved_file'] else 0)
    assert tab.get('path', '') == want['path']
    content = tab['content']
    assert len(content) == want['file_content_length']
    assert hashlib.sha256(content.encode('utf-16-le')).hexdigest() == \
        want['file_content_sha256']
    assert tab['unsaved'] == want['contain_unsaved_data']
    assert tab['selection'] == want['cursor']
    assert tab['word_wrap'] == want['config_block']['word_wrap']
    assert tab['right_to_left'] == want['config_block']['rtl']
    chunks = [[c['position'], c['deleted'], c['added']]
              for c in tab['chunks']]
    assert len(chunks) == want['chunk_count']
    assert hashlib.sha256(json.dumps(chunks, ensure_ascii=False)
                          .encode('utf-8')).hexdigest() == \
        want['chunks_sha256']
    if want['is_saved_file']:
        assert tab['saved_size'] == want['file_size']
        assert tab['encoding'] == _ENCODINGS[want['encoding']]
        assert tab['line_endings'] == _LINES[want['cr_type']]
        stored = want['file_hash'].lower()
        assert tab['saved_sha256'] == ('' if set(stored) == {'0'} else stored)
        expected_time = want['last_write_time']
        if expected_time.startswith('1601'):
            assert tab['saved_time'] is None
        else:
            assert tab['saved_time'].strftime('%Y-%m-%dT%H:%M:%SZ') == \
                expected_time


def test_the_text_is_what_notepad_saved():
    """Notepad's own SHA-256 of the file it saved equals TRACE's text saved
    the same way -- for every saved tab that records one."""
    checked = 0
    for name, want in _key().items():
        if not want['is_saved_file'] or set(want['file_hash']) == {'0'}:
            continue
        text = _tab(name)['content'].replace('\r', '\r\n')
        assert hashlib.sha256(text.encode('utf-8')).hexdigest() == \
            want['file_hash'].lower(), name
        checked += 1
    assert checked >= 4


def test_unsaved_edits_are_applied():
    # Typed into a new tab, five characters taken back and retyped.
    tab = _tab('notepad-x-abb3d672-e5d2-4994-9bc3-483a44805b16.bin')
    assert tab['type'] == 0 and tab['content'] == ''
    assert tab['text'] == \
        'This tab has never been saved and should have unsaved buffer'
    # A saved file with a line added and not saved.
    tab = _tab('notepad-rs-saved-english-unsaved_mod-22bb38a5.bin')
    assert tab['content'] == 'This is a test file, this file is saved'
    assert tab['text'] == ("This is a test file, this file is saved\r"
                           "This line isn't saved")


@pytest.mark.parametrize('name, encoding, lines', [
    # Named ANSI, but its text is plain ASCII -- which Notepad opens as
    # UTF-8 (the bytes are the same): the tab records 5, UTF-8.
    ('notepad-old-EncodingANSI.bin', 'UTF-8', 'CRLF (Windows)'),
    ('notepad-old-EncodingUTF16BE.bin', 'UTF-16BE', 'CRLF (Windows)'),
    ('notepad-old-EncodingUTF16LE.bin', 'UTF-16LE', 'CRLF (Windows)'),
    ('notepad-old-EncodingUTF8.bin', 'UTF-8', 'CRLF (Windows)'),
    ('notepad-old-EncodingUTF8BOM.bin', 'UTF-8 with BOM', 'CRLF (Windows)'),
    ('notepad-old-MacintoshCR.bin', 'UTF-8', 'CR (Macintosh)'),
    ('notepad-old-UnixLF.bin', 'UTF-8', 'LF (Unix)'),
    ('notepad-old-WindowsCRLF.bin', 'UTF-8', 'CRLF (Windows)')])
def test_older_notepad_files(name, encoding, lines):
    """Notepad 11.2402's tabs have no option bytes in their configuration
    block; the layout whose CRC32 holds is taken."""
    tab = _tab(name)
    assert tab['type'] == 1
    assert tab['encoding'] == encoding and tab['line_endings'] == lines


def test_state_files_are_not_tabs():
    with pytest.raises(notepad.TabStateError):
        _tab('notepad-x-00bc8eb6-b8bb-459b-973a-a998b734b47c.1.bin')


def test_a_damaged_tab_is_refused():
    with open(data_path('samples', 'notepad-old-EncodingUTF8.bin'),
              'rb') as handle:
        data = bytearray(handle.read())
    data[len(data) // 2] ^= 0xFF
    with pytest.raises(notepad.TabStateError):
        notepad.parse(bytes(data))


def test_records_and_search_text_from_a_profile(tmp_path):
    """Read as evidence: a profile folder holding a Notepad package."""
    from trace_app.core import text_extract
    from trace_app.core.activity import collect
    from trace_app.core.image_handler import ImageHandler
    tabs = tmp_path / 'Users' / 'alex' / 'AppData' / 'Local' / 'Packages' / \
        'Microsoft.WindowsNotepad_8wekyb3d8bbwe' / 'LocalState' / 'TabState'
    tabs.mkdir(parents=True)
    for name in ('notepad-x-abb3d672-e5d2-4994-9bc3-483a44805b16.bin',
                 'notepad-x-00bc8eb6-b8bb-459b-973a-a998b734b47c.1.bin',
                 'notepad-rs-saved-english-unsaved_mod-22bb38a5.bin'):
        with open(data_path('samples', name), 'rb') as source:
            target = name.replace('notepad-x-', '').replace('notepad-rs-', '')
            (tabs / target).write_bytes(source.read())
    handler = ImageHandler(str(tmp_path))
    try:
        rows = [r for r in collect(handler) if r['source'] == 'Notepad tabs']
    finally:
        handler.close_resources()
    assert {r['what'] for r in rows} == {'Notepad tab never saved',
                                         'Notepad tab with unsaved changes'}
    assert all(r['category'] == 'notes' and r['user'] == 'alex'
               for r in rows)
    unsaved = next(r for r in rows if r['what'].endswith('never saved'))
    assert unsaved['detail']['text'].startswith('This tab has never')
    saved = next(r for r in rows if r['what'].endswith('changes'))
    assert saved['subject'] == 'C:\\Windows\\Temp\\notepad_files\\test.txt'
    assert saved['detail']['text'].endswith("This line isn't saved")
    # The index gets the edited text, not the strings of the raw chunks.
    with open(data_path('samples',
                        'notepad-x-abb3d672-e5d2-4994-9bc3-483a44805b16.bin'),
              'rb') as handle:
        text = text_extract.extract_text(handle.read(), 'abb3d672.bin')
    assert 'never been saved and should have unsaved buffer' in text
