"""What a Mac remembers between sessions (no Qt).

* **Saved application state** (~/Library/Saved Application State/
  <bundle>.savedState, and each sandboxed app's container): windows.plist
  lists the windows open when the app last quit -- their titles, often a
  document's name -- with an AES key per window (NSDataKey); data.data
  holds each window's state, AES-128-CBC with that key and a zero IV, in
  records 'NSCR1000' + window id + length (big-endian). A decrypted record
  is 'rchv', a length and an NSKeyedArchiver plist. Decrypted with
  `cryptography` (already TRACE's), in memory; nothing is written out.
* **Terminal** (com.apple.Terminal.savedState): the same, and the archive
  holds each tab's text as it was on screen, its title and working folder
  -- the commands typed and their output.
* **Trash** (~/.Trash/.DS_Store, /.Trashes/<uid>/.DS_Store): where each
  trashed item came from (core/dsstore.put_back), and whether it is still
  in the Trash.
* **sudo** (/private/var/db/sudo/ts/<user>): the user's sudo timestamp
  file; its modification time is when they last authenticated to sudo.
  The records inside count boot-relative (monotonic) time, so only their
  kinds are reported.

The layouts follow mac_apt's savedstate/terminalstate/sudolastrun plugins
(Yogesh Khatri, MIT).
"""

import logging
import plistlib
import struct

from trace_app.core.activity import record

logger = logging.getLogger('TRACE.Activity.macOSState')

RECORD_MAGIC = b'NSCR1000'
#: Text kept from one Terminal tab.
MAX_TERMINAL_TEXT = 20_000


# --- saved application state ------------------------------------------------------

def windows(plist_data):
    """{window id: {'title', 'key', ...}} from a savedState windows.plist."""
    plist = plistlib.loads(plist_data)
    items = plist if isinstance(plist, list) else [plist]
    out = {}
    for item in items:
        if not isinstance(item, dict) or 'NSWindowID' not in item:
            continue
        out[item['NSWindowID']] = {
            'title': item.get('NSTitle'),
            'key': item.get('NSDataKey'),
            'number': item.get('NSWindowNumber'),
            'full screen': item.get('NSIsFullScreen'),
            'frame': item.get('NSWindowFrame') or item.get('NSFrame'),
        }
    return out


def _decrypt(key, encrypted):
    from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms,
                                                        modes)
    if len(key) not in (16, 24, 32) or not encrypted or len(encrypted) % 16:
        return None
    decryptor = Cipher(algorithms.AES(bytes(key)),
                       modes.CBC(bytes(16))).decryptor()
    return decryptor.update(bytes(encrypted)) + decryptor.finalize()


def window_states(data, keys):
    """[(window id, record name, unarchived plist or None)] for every
    record of a data.data; `keys` is {window id: AES key}. A window can
    have several records ('_NSWindow', the app's own)."""
    out = []
    pos = 0
    while pos + 16 <= len(data):
        if data[pos:pos + 8] != RECORD_MAGIC:
            break
        window_id, length = struct.unpack_from('>II', data, pos + 8)
        if length < 16 or pos + length > len(data):
            break
        key = keys.get(window_id)
        plain = _decrypt(key, data[pos + 16:pos + length]) if key else None
        name, archive = _archive(plain) if plain else (None, None)
        out.append((window_id, name, archive))
        pos += length
    return out


def _archive(plain):
    """(record name, unarchived NSKeyedArchiver or None) of a decrypted
    record: 4 bytes, the name's length (big-endian), the name, 'rchv',
    the plist's length, the plist."""
    from trace_app.core.activity.btm import unarchive
    if len(plain) < 16:
        return None, None
    name_length = struct.unpack_from('>I', plain, 4)[0]
    if name_length > 64:
        return None, None               # not decrypted: wrong key
    name = plain[8:8 + name_length].decode('utf-8', 'replace')
    at = 8 + name_length
    if plain[at:at + 4] != b'rchv':
        return name, None
    size = struct.unpack_from('>I', plain, at + 4)[0]
    try:
        return name, unarchive(plain[at + 8:at + 8 + size])
    except Exception:
        return name, None


def _strings(value, out, depth=0, limit=200):
    if depth > 30 or len(out) >= limit:
        return
    if isinstance(value, dict):
        for item in value.values():
            _strings(item, out, depth + 1, limit)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _strings(item, out, depth + 1, limit)
    elif isinstance(value, str) and len(value) > 2:
        out.append(value)


def _url(value):
    if isinstance(value, dict):
        value = value.get('NS.relative') or value.get('NS.base')
    return str(value) if value else None


def saved_state(windows_data, state_data, bundle, user, modified, path,
                ref):
    """One row per window an app had open when it last quit: its title
    (from windows.plist and the window's own record), and the folder or
    document it showed where the app records one (Finder's TargetURL,
    Preview's file)."""
    known = windows(windows_data)
    records = {}
    for window_id, name, archive in window_states(
            state_data or b'', {wid: info['key'] for wid, info in
                                known.items() if info['key']}):
        records.setdefault(window_id, []).append((name, archive))
    out = []
    for window_id, info in known.items():
        decrypted = [a for _n, a in records.get(window_id, ()) if a]
        titles, targets, found = [], [], []
        for archive in decrypted:
            if not isinstance(archive, dict):
                continue
            title = archive.get('NSTitle')
            if isinstance(title, str) and title.strip():
                titles.append(title.strip())
            window_state = archive.get('WindowState')
            if isinstance(window_state, dict):
                targets.append(_url(window_state.get('TargetURL')))
            targets.append(_url(archive.get(
                'currentMediaContainerFileReferenceURL')))
            _strings(archive, found)
        targets = [t for t in dict.fromkeys(targets) if t]
        documents = [s for s in dict.fromkeys(found)
                     if s.startswith(('/', 'file://')) or '://' in s][:10]
        title = info['title'] or next(iter(titles), None)
        out.append(record(
            'programs', 'Saved application state', modified,
            'Window open when the app quit', title or bundle,
            {'app': bundle, 'window title': info['title'],
             'titles in state': ', '.join(dict.fromkeys(titles)) or None,
             'showing': ', '.join(targets) or None,
             'documents and URLs': ', '.join(documents) or None,
             'window id': window_id,
             'state decrypted': 'yes' if decrypted else
             ('no key' if not info['key'] else 'no'),
             'full screen': info['full screen'],
             'basis': "windows.plist's modification time (when the app "
                      "last saved its state)"},
            user=user, path=path, ref=ref))
    return out


def terminal_state(windows_data, state_data, user, modified, path, ref):
    """One row per Terminal tab: the text on screen, its title and
    working folder, when Terminal last saved its state."""
    known = windows(windows_data)
    keys = {wid: info['key'] for wid, info in known.items() if info['key']}
    out = []
    seen = set()
    for window_id, _name, archive in window_states(state_data or b'', keys):
        if archive is None:
            continue
        for tab in _terminal_tabs(archive):
            text = tab['text'][:MAX_TERMINAL_TEXT]
            # data.data can hold a window's record twice (an older copy
            # not yet compacted away): the same tab is one row.
            key = (window_id, tab['title'], tab['folder'], text)
            if key in seen:
                continue
            seen.add(key)
            out.append(record(
                'notes', 'Terminal', modified, 'Terminal window text',
                tab['title'] or (archive.get('NSTitle') if isinstance(
                    archive, dict) else None) or
                (known.get(window_id) or {}).get('title') or 'Terminal',
                {'text': text or None, 'working folder': tab['folder'],
                 'lines': text.count('\n') + 1 if text else 0,
                 'window id': window_id,
                 'basis': "windows.plist's modification time (when "
                          "Terminal last saved its state)"},
                user=user, path=path, ref=ref))
    return out


def _terminal_tabs(archive):
    """[{'text', 'title', 'folder'}] from a Terminal window archive:
    every dict holding a tab's contents ('Tab Contents', 'Tab Contents
    v2'), with its title and working directory beside it."""
    tabs = []

    def visit(value, depth=0):
        if depth > 30:
            return
        if isinstance(value, dict):
            content_keys = [k for k in value if isinstance(k, str)
                            and k.startswith('Tab Contents')]
            if content_keys:
                contents = value[content_keys[-1]]
                if content_keys[-1] == 'Tab Contents v2':
                    contents = _without_style_runs(contents)
                tabs.append({
                    'text': _lines(contents),
                    'title': _first_text(value, ('Tab Title', 'Title',
                                                 'TTWindowTitle')),
                    'folder': _first_text(value, (
                        'Tab Working Directory URL String',
                        'Tab Working Directory URL'))})
            for item in value.values():
                visit(item, depth + 1)
        elif isinstance(value, (list, tuple)):
            for item in value:
                visit(item, depth + 1)

    visit(archive)
    return tabs


def _first_text(mapping, keys):
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, bytes):
            value = value.decode('utf-8', 'replace')
        if isinstance(value, str) and value:
            return value
    return None


#: A style run of 'Tab Contents v2': three little-endian 64-bit words,
#: the middle one the number of characters of the text before it.
STYLE_RUN = 24


def _without_style_runs(items):
    """'Tab Contents v2' alternates a run of text with its style runs
    (24 bytes each, counting the text's characters): the text alone.
    A list not shaped so is returned as it is."""
    if not isinstance(items, (list, tuple)) or len(items) < 2:
        return items
    styles = items[1::2]
    if all(isinstance(item, (bytes, bytearray)) and item and
           len(item) % STYLE_RUN == 0 for item in styles):
        return items[0::2]
    return items


def _lines(value):
    """A tab's contents as text: one string, bytes, or a list of lines."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode('utf-8', 'replace').rstrip('\x00')
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        # Terminal keeps the screen as runs of bytes that carry their own
        # line ends: joined as they are.
        joiner = '' if any(isinstance(item, (bytes, bytearray))
                           for item in value) else '\n'
        return joiner.join(_lines(item) for item in value
                           if item is not None).rstrip()
    if isinstance(value, dict):
        return '\n'.join(_lines(item) for item in value.values()
                         if item is not None).rstrip()
    return ''


# --- Trash ---------------------------------------------------------------------------

def trash(ds_store, present, changed, user, path, ref):
    """Rows for a Trash's .DS_Store: each trashed item's original place.
    `present` is {name in the Trash: its entry} for what is still there;
    `changed` gives an entry's change time (set when it was moved)."""
    from trace_app.core import dsstore
    out = []
    for name, (folder, original) in sorted(dsstore.put_back(ds_store)
                                           .items()):
        place = '/' + (folder or '').strip('/')
        original_path = (place.rstrip('/') + '/' + (original or name))
        entry = present.get(name)
        when = changed(entry) if entry is not None else None
        out.append(record(
            'recycle', 'Trash', when, 'Moved to Trash', original_path,
            {'name in Trash': name, 'original folder': place,
             'original name': original or name,
             'still in Trash': 'yes' if entry is not None else 'no',
             'basis': "the trashed item's change time (set when it was "
                      "moved to the Trash)" if when else
                      'no time: only the .DS_Store names it'},
            user=user, path=path, ref=ref))
    return out


# --- sudo -------------------------------------------------------------------------------

_SUDO_TYPES = {1: 'global', 2: 'terminal', 3: 'parent process', 4: 'lock'}


def sudo_timestamps(data, user, modified, path, ref):
    """A sudo timestamp file (/private/var/db/sudo/ts/<user>): each
    terminal grant (type 2) with its Unix times, as mac_apt's
    sudo_lastrun reads them (40-byte records one time, 56-byte two);
    when none holds a valid time, one row at the file's modification time
    (the last successful sudo authentication)."""
    from trace_app.core.activity import times
    kinds, rows = [], []
    pos = 0
    while pos + 8 <= len(data):
        version, size, kind, flags = struct.unpack_from('<HHHH', data, pos)
        if size < 8 or version not in (1, 2) or pos + size > len(data):
            break
        kinds.append(_SUDO_TYPES.get(kind, str(kind)) +
                     (' (disabled)' if flags & 1 else ''))
        body = data[pos + 8:pos + size]
        if kind == 2 and size in (0x28, 0x38):
            uid = struct.unpack_from('<H', body, 0)[0]
            stamps = [struct.unpack_from('<Q', body, 8)[0]]
            if size == 0x38:
                stamps.append(struct.unpack_from('<Q', body, 24)[0])
            for stamp in stamps:
                when = times.unix(stamp)
                if when:
                    rows.append(record(
                        'logons', 'sudo', when, 'Authenticated to sudo',
                        user, {'uid': uid, 'grant': 'terminal',
                               'basis': 'the time in the sudo timestamp '
                                        'record'},
                        user=user, path=path, ref=ref))
        pos += size
    if rows:
        return rows
    return [record(
        'logons', 'sudo', modified, 'Authenticated to sudo', user,
        {'grants recorded': ', '.join(kinds) or None,
         'basis': "the sudo timestamp file's modification time (the last "
                  "successful sudo authentication)"},
        user=user, path=path, ref=ref)]
