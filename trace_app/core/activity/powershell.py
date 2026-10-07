"""PowerShell: what was typed, and what was run.

* PSReadLine's history, per user and per host -- ConsoleHost_history.txt
  (the console), Visual Studio Code Host_history.txt, Windows PowerShell
  ISE Host_history.txt -- in AppData\\Roaming\\Microsoft\\Windows\\
  PowerShell\\PSReadLine. One command per line; a command spanning lines
  ends each but its last in a backtick. No times are written: the file's
  own last-written time is the latest any command can be.
* Script block logging: event 4104 in Microsoft-Windows-PowerShell/
  Operational records the text of every script block PowerShell compiled
  -- decoded, de-obfuscated as far as PowerShell itself got -- split over
  several events when long (MessageNumber of MessageTotal, one
  ScriptBlockId). The parts are joined in order; a block with parts
  missing says how many. PowerShell logs at Warning level (3) the blocks
  it judges suspicious itself, whether logging was turned on or not; that
  is kept as a flag.
"""

from trace_app.core.activity import record, times

HISTORY_FOLDER = ('AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell',
                  'PSReadLine')
#: Characters of a script block kept in a record.
MAX_SCRIPT = 64 * 1024


def history_commands(text):
    """[(line number, command)] from a PSReadLine history file, commands
    continued with a trailing backtick joined."""
    out = []
    pending, first = [], None
    for number, line in enumerate(text.splitlines(), 1):
        if first is None:
            first = number
        if line.endswith('`'):
            pending.append(line[:-1])
            continue
        pending.append(line)
        command = '\n'.join(pending).strip()
        if command:
            out.append((first, command))
        pending, first = [], None
    if pending and '\n'.join(pending).strip():
        out.append((first, '\n'.join(pending).strip()))
    return out


def history(volume, user, home, step):
    from trace_app.core.activity import _split
    out = []
    folder = volume.find(*_split(home.path), *HISTORY_FOLDER)
    for entry in volume.children(folder, '_history.txt'):
        step(entry.path)
        host = entry.name[:-len('_history.txt')]
        text = volume.read(entry).decode('utf-8-sig', 'replace')
        basis = ("PSReadLine writes no time; the history file was last "
                 f"written {times.iso(entry.modified) or 'at an unknown time'}"
                 " -- no command is later")
        ref = volume.ref(entry)
        for number, command in history_commands(text):
            out.append(record('programs', 'PowerShell history', None,
                              'Command typed', command,
                              {'shell': 'PowerShell', 'host': host,
                               'line': number, 'basis': basis},
                              user=user, path=entry.path, ref=ref))
    return out


def script_blocks(events):
    """[{'id', 'time', 'text', 'parts', 'total', 'path', 'sid', 'warning',
    'record'}] -- the 4104 events joined per script block."""
    blocks = {}
    for event in events:
        if event.get('event_id') != 4104:
            continue
        data = event.get('data') or {}
        block_id = data.get('ScriptBlockId') or f"record {event['record_id']}"
        try:
            number = int(data.get('MessageNumber') or 1)
            total = int(data.get('MessageTotal') or 1)
        except ValueError:
            number, total = 1, 1
        block = blocks.setdefault(block_id, {
            'id': block_id, 'time': event.get('time'), 'parts': {},
            'total': total, 'path': data.get('Path') or '',
            'sid': event.get('user_sid') or '', 'warning': False,
            'record': event.get('record_id')})
        block['parts'][number] = data.get('ScriptBlockText') or ''
        block['warning'] = block['warning'] or event.get('level') == 3
        if event.get('time') and (block['time'] is None or
                                  event['time'] < block['time']):
            block['time'] = event['time']
    out = []
    for block in blocks.values():
        parts = block.pop('parts')
        block['text'] = ''.join(parts[n] for n in sorted(parts))
        block['parts'] = len(parts)
        out.append(block)
    out.sort(key=lambda b: (str(b['time']), b['record'] or 0))
    return out


def script_block_records(events, path, ref, sids=None):
    out = []
    for block in script_blocks(events):
        missing = block['total'] - block['parts']
        text = block['text']
        detail = {
            'script block id': block['id'],
            'parts': f"{block['parts']} of {block['total']}"
                     + (f" ({missing} missing)" if missing > 0 else ''),
            'script file': block['path'] or None,
            'length': len(text),
            'flagged by PowerShell': 'yes -- logged as a warning (its own '
                                     'check for suspicious code)'
            if block['warning'] else None,
            'user SID': block['sid'] or None,
            'script': text[:MAX_SCRIPT],
        }
        what = 'PowerShell script block' + (' (flagged suspicious)'
                                            if block['warning'] else '')
        subject = ' '.join(text.split())[:300]
        out.append(record('programs', 'PowerShell script block logging',
                          block['time'], what, subject, detail,
                          user=(sids or {}).get(block['sid'].upper(),
                                                block['sid']),
                          path=path, ref=ref))
    return out
