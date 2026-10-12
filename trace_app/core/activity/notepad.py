"""Windows 11 Notepad's tab state: the text of tabs never saved.

Notepad (the Store app, 11.2302 on) keeps every open tab in
%LOCALAPPDATA%\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\
TabState\\<GUID>.bin, so a tab survives Notepad closing -- including text
typed and never saved, or saved and changed since. Format as documented by
ogmini (Notepad-State-Library) and read the same way by AbdulRhman Alfaifi's
notepad_parser (tests/test_notepad.py compares the two on their samples):

* 'NP', a sequence number (uLEB128), a type: 0 a tab with no file, 1 a tab
  with a file (its path, the saved file's size in bytes, encoding,
  line endings, last-written FILETIME, the saved file's SHA-256 -- zero
  when nothing is unsaved), 10/11 the state files <GUID>.0.bin / .1.bin
  (selection and settings only: not read);
* the selection, a configuration block -- word wrap, right-to-left, show
  Unicode, then (from 2024's Notepad) a count of option bytes and the
  options (the last: unformatted / Markdown);
* the content (uLEB128 characters, UTF-16LE), an "unsaved" flag, and a
  CRC32 of everything from offset 3. Older and newer Notepads differ only
  in the configuration block, so the layout taken is the one whose CRC32
  holds;
* then the unsaved buffer chunks typed since the content was written:
  cursor position, characters deleted, characters added and their text,
  each with its own CRC32. Applied in order they give the text the tab
  showed. A chunk whose CRC fails ends the list (Notepad was writing it).

Lengths count UTF-16 characters, not bytes (the saved file's size is its
bytes). Notepad ends lines with CR inside the tab, whatever the file uses;
its stored SHA-256 is of the text saved as UTF-8 with CRLF.
"""

import struct
import zlib

from trace_app.core.activity import record, times

TAB_FOLDER = ('AppData', 'Local', 'Packages')
PACKAGE = 'microsoft.windowsnotepad_'
STATE = ('LocalState', 'TabState')
ENCODINGS = {1: 'ANSI', 2: 'UTF-16LE', 3: 'UTF-16BE', 4: 'UTF-8 with BOM',
             5: 'UTF-8'}
LINE_ENDINGS = {1: 'CRLF (Windows)', 2: 'CR (Macintosh)', 3: 'LF (Unix)'}
FORMATTING = {1: 'unformatted', 2: 'Markdown', 3: 'Markdown syntax'}
#: Characters of a tab's text kept in a record.
MAX_TEXT = 256 * 1024


class TabStateError(ValueError):
    pass


def _uleb(data, at):
    value = shift = 0
    while True:
        if at >= len(data):
            raise TabStateError("cut short inside a number")
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, at
        shift += 7
        if shift > 63:
            raise TabStateError("number too long")


def _utf16(data, at, characters):
    end = at + 2 * characters
    if end > len(data):
        raise TabStateError("cut short inside text")
    return data[at:end].decode('utf-16-le', 'replace'), end


def _crc_ok(data, start, end):
    if end + 4 > len(data):
        return False
    return zlib.crc32(data[start:end]) == struct.unpack_from('>I', data,
                                                             end)[0]


def parse(data):
    """The fields of a tab state file: {'type', 'sequence', 'path', ...,
    'content', 'unsaved', 'chunks', 'text'} -- 'text' the content with the
    unsaved chunks applied. A state file (.0/.1.bin) gives only its type
    and sequence. Raises TabStateError."""
    if data[:2] != b'NP':
        raise TabStateError("not a Notepad tab state file")
    sequence, at = _uleb(data, 2)
    kind, at = _uleb(data, at)
    out = {'sequence': sequence, 'type': kind}
    if kind in (10, 11):
        return out
    if kind not in (0, 1):
        raise TabStateError(f"tab type {kind}")
    if kind == 1:
        length, at = _uleb(data, at)
        out['path'], at = _utf16(data, at, length)
        out['saved_size'], at = _uleb(data, at)
        out['encoding'] = ENCODINGS.get(data[at], data[at])
        out['line_endings'] = LINE_ENDINGS.get(data[at + 1], data[at + 1])
        at += 2
        stamp, at = _uleb(data, at)
        out['saved_time'] = times.filetime(stamp)
        digest = data[at:at + 32]
        out['saved_sha256'] = digest.hex() if any(digest) else ''
        at += 32
        at += 2                                 # [0x00, 0x01]
    else:
        at += 1                                 # [0x01]
    out['selection'] = []
    start, at = _uleb(data, at)
    end, at = _uleb(data, at)
    out['selection'] = [start, end]
    flags = data[at:at + 3]
    out['word_wrap'], out['right_to_left'], out['show_unicode'] = \
        (bool(b) for b in flags)
    at += 3
    body = None
    # The configuration block's options (2024 on) or none (before): the
    # layout whose CRC32 holds is the file's.
    for options in (True, False):
        try:
            body = _content(data, at, options)
        except TabStateError:
            continue
        if body is not None:
            break
    if body is None:
        raise TabStateError("no layout of this tab state passes its CRC32")
    content, unsaved, formatting, chunk_start = body
    out['content'] = content
    out['unsaved'] = unsaved
    if formatting is not None:
        out['formatting'] = FORMATTING.get(formatting, formatting)
    out['chunks'] = chunks = _chunks(data, chunk_start)
    out['text'] = apply_chunks(content, chunks)
    return out


def _content(data, at, options):
    formatting = None
    if options:
        count, at = _uleb(data, at)
        if count > 16:
            raise TabStateError("option count")
        block = data[at:at + count]
        if count >= 3:
            formatting = block[2]
        at += count
    length, at = _uleb(data, at)
    content, at = _utf16(data, at, length)
    if at >= len(data):
        raise TabStateError("no unsaved flag")
    unsaved = bool(data[at])
    at += 1
    if not _crc_ok(data, 3, at):
        return None
    return content, unsaved, formatting, at + 4


def _chunks(data, at):
    out = []
    while at < len(data):
        start = at
        try:
            position, at = _uleb(data, at)
            deleted, at = _uleb(data, at)
            added, at = _uleb(data, at)
            text, at = _utf16(data, at, added)
        except TabStateError:
            break
        if not _crc_ok(data, start, at):
            break
        out.append({'position': position, 'deleted': deleted,
                    'added': text})
        at += 4
    return out


def apply_chunks(content, chunks):
    """The text after the unsaved edits: each chunk deletes its characters
    at its cursor position, then inserts what it added there."""
    text = content
    for chunk in chunks:
        position = min(chunk['position'], len(text))
        text = text[:position] + chunk['added'] + \
            text[position + chunk['deleted']:]
    return text


# --- records ------------------------------------------------------------------

def tab_folders(volume, home):
    """TabState folders of every Notepad package in a profile."""
    from trace_app.core.activity import _split
    packages = volume.find(*_split(home.path), *TAB_FOLDER)
    out = []
    for package in volume.children(packages, dirs=True):
        if package.name.lower().startswith(PACKAGE):
            folder = volume.find(*_split(package.path), *STATE)
            if folder is not None:
                out.append(folder)
    return out


def records(volume, user, home, step):
    out = []
    for folder in tab_folders(volume, home):
        for entry in volume.children(folder, '.bin'):
            stem = entry.name[:-4]
            if stem.endswith(('.0', '.1')):
                continue                       # state files
            step(entry.path)
            try:
                tab = parse(volume.read(entry))
            except (TabStateError, IndexError, struct.error):
                continue
            out.append(tab_record(tab, entry, user, volume.ref(entry)))
    return out


def tab_record(tab, entry, user, ref):
    text = tab.get('text', '')
    saved = tab['type'] == 1
    changed = bool(tab.get('chunks')) or tab.get('unsaved') or \
        (saved and tab.get('saved_sha256'))
    if saved:
        what = ("Notepad tab with unsaved changes" if changed
                else "Notepad tab (file as saved)")
        subject = tab.get('path', '')
    else:
        what = "Notepad tab never saved"
        subject = text.splitlines()[0][:120] if text.strip() else \
            '(empty tab)'
    shown = text.replace('\r\n', '\n').replace('\r', '\n')
    detail = {
        'text': shown[:MAX_TEXT],
        'characters': len(text),
        'cut': len(text) > MAX_TEXT or None,
        'file': tab.get('path'),
        'saved size': tab.get('saved_size') or None,
        'saved file SHA-256': tab.get('saved_sha256'),
        'encoding': tab.get('encoding') if saved else None,
        'line endings': tab.get('line_endings') if saved else None,
        'formatting': tab.get('formatting'),
        'unsaved edits': len(tab.get('chunks') or ()) or None,
        'tab file': entry.name,
        'basis': ("the tab file's last-written time; Notepad records no "
                  "time for unsaved text"),
    }
    when = entry.modified
    if saved and tab.get('saved_time'):
        detail['saved file written'] = tab['saved_time']
    return record('notes', 'Notepad tabs', when, what, subject, detail,
                  user=user, path=entry.path, ref=ref)
