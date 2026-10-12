"""Text logs Windows writes that say what was run and what connected.

* **PowerShell transcripts** (Start-Transcript, or the "Turn on PowerShell
  Transcription" policy): PowerShell_transcript.<machine>.<random>.<time>.txt
  in a user's Documents (or the policy's folder, often by date). Each
  transcript opens with a banner of '*' and a header -- start time
  (yyyyMMddHHmmss, local), user, run-as user, configuration, machine, host
  application, process ID, then PSVersion and the other version lines --
  whose labels are translated (German: Startzeit, Benutzername ...) but
  whose order is not, so they are read by position. Commands are the 'PS
  <folder>> ' prompt lines, each with the output after it; with
  -IncludeInvocationHeader a banner before each command gives its start
  time. A file can hold several transcripts (-Append).
* **Windows Firewall log** (System32\\LogFiles\\Firewall\\pfirewall.log and
  its .old): W3C extended format; '#Fields:' names the columns (Windows 11
  adds pid); times are local ('#Time Format: Local'). One record per
  line, ALLOW/DROP/OPEN/CLOSE/INFO-EVENTS-LOST, up to MAX_FIREWALL.
* **Windows Error Reporting** (ProgramData and each user's
  AppData\\Local\\Microsoft\\Windows\\WER\\ReportArchive|ReportQueue\\*\\
  Report.wer): UTF-16 key=value lines -- EventType (APPCRASH, AppHangB1,
  BEX...), EventTime (FILETIME), the signature parameters Sig[n].Name /
  Sig[n].Value (application, version, module, exception code), AppName,
  AppPath, FriendlyEventName.
"""

import re

from trace_app.core.activity import record, times

MAX_FIREWALL = 50000
MAX_OUTPUT = 4000
TRANSCRIPT_PREFIX = 'powershell_transcript.'
#: The header lines after the title, in the order PowerShell writes them
#: whatever the language; the rest are keyed (PSVersion: ...).
_HEADER_ORDER = ('start_time', 'user', 'runas_user', 'configuration',
                 'machine', 'host_application', 'process_id')
_BANNER = re.compile(r'^\*{10,}\s*$')
_PROMPT = re.compile(r'^PS ([^>]*)> ?(.*)$')
_STAMP = re.compile(r':\s*(\d{14})\s*$')


def _local(stamp):
    """A transcript's yyyyMMddHHmmss (local time, no zone)."""
    import datetime
    try:
        return datetime.datetime.strptime(stamp, '%Y%m%d%H%M%S')
    except (TypeError, ValueError):
        return None


def parse_transcripts(text):
    """[{'header': {...}, 'commands': [{'prompt', 'command', 'output',
    'started'}], 'ended'}] -- every transcript in a file."""
    lines = text.lstrip('﻿').splitlines()
    out = []
    current = None
    command = None
    index = 0
    while index < len(lines):
        line = lines[index]
        if _BANNER.match(line):
            # A banner block: a transcript's header, a command's start
            # time, or the end.
            block = []
            index += 1
            while index < len(lines) and not _BANNER.match(lines[index]):
                block.append(lines[index])
                index += 1
            index += 1                         # the closing banner
            if len(block) >= 2 and _STAMP.search(block[1]) and \
                    len(block) > 8:
                header = {}
                for name, entry in zip(_HEADER_ORDER, block[1:]):
                    header[name] = entry.split(':', 1)[1].strip() \
                        if ':' in entry else ''
                for entry in block[1 + len(_HEADER_ORDER):]:
                    if ':' in entry:
                        key, value = entry.split(':', 1)
                        header[key.strip()] = value.strip()
                header['started'] = _local(header.get('start_time'))
                current = {'header': header, 'commands': [], 'ended': None}
                out.append(current)
                command = None
            elif block and current is not None:
                found = _STAMP.search(block[-1])
                if found and len(block) == 1:
                    # "Command start time:" -- or, after the title line,
                    # "End time:".
                    current['next_start'] = _local(found.group(1))
                elif found:
                    current['ended'] = _local(found.group(1))
            continue
        index += 1
        if current is None:
            continue
        prompt = _PROMPT.match(line)
        if prompt:
            command = {'prompt': prompt.group(1),
                       'command': prompt.group(2).strip(),
                       'output': [],
                       'started': current.pop('next_start', None)}
            current['commands'].append(command)
        elif command is not None:
            command['output'].append(line)
    for transcript in out:
        transcript.pop('next_start', None)
        for item in transcript['commands']:
            item['output'] = '\n'.join(item['output']).strip()[:MAX_OUTPUT]
    return out


def transcript_records(volume, user, home, step):
    """Transcripts under a profile's Documents (any depth below it: the
    policy writes date folders)."""
    from trace_app.core.activity import _split
    out = []
    pending = [volume.find(*_split(home.path), 'Documents')]
    seen = 0
    while pending and seen < 2000:
        folder = pending.pop()
        if folder is None:
            continue
        seen += 1
        for entry in volume.listdir(folder.path):
            if entry.is_dir:
                pending.append(entry)
            elif entry.name.lower().startswith(TRANSCRIPT_PREFIX) and \
                    entry.name.lower().endswith('.txt'):
                step(entry.path)
                out += _transcript_file(volume, entry, user)
    return out


def _transcript_file(volume, entry, user):
    data = volume.read(entry)
    text = data.decode('utf-8-sig', 'replace') if not data.startswith(
        b'\xff\xfe') else data.decode('utf-16', 'replace')
    out = []
    ref = volume.ref(entry)
    for transcript in parse_transcripts(text):
        header = transcript['header']
        common = dict(user=user or header.get('user', ''), path=entry.path,
                      ref=ref, local=True)
        out.append(record(
            'programs', 'PowerShell transcript', header['started'],
            'PowerShell session recorded', header.get('host_application'),
            {'account': header.get('user'),
             'run as': header.get('runas_user'),
             'machine': header.get('machine'),
             'process ID': header.get('process_id'),
             'PowerShell': header.get('PSVersion'),
             'commands': len(transcript['commands']),
             'ended': transcript['ended']}, **common))
        for item in transcript['commands']:
            if not item['command']:
                continue
            out.append(record(
                'programs', 'PowerShell transcript',
                item['started'] or header['started'], 'Command run',
                item['command'],
                {'folder': item['prompt'], 'output': item['output'],
                 'account': header.get('user'),
                 'basis': None if item['started'] else
                 "the transcript's start: no invocation header gives the "
                 "command's own time"}, **common))
    return out


# --- Windows Firewall ----------------------------------------------------------

def parse_firewall(text):
    """[{field: value}] of a pfirewall.log, by its '#Fields:' line."""
    fields = None
    out = []
    for line in text.splitlines():
        if line.startswith('#Fields:'):
            fields = line[len('#Fields:'):].split()
            continue
        if not line.strip() or line.startswith('#') or fields is None:
            continue
        values = line.split()
        row = {name: (value if value != '-' else None)
               for name, value in zip(fields, values)}
        out.append(row)
        if len(out) >= MAX_FIREWALL:
            break
    return out


def _firewall_time(row):
    import datetime
    try:
        return datetime.datetime.strptime(
            f"{row.get('date')} {row.get('time')}", '%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError):
        return None


def firewall_records(volume, windows, step):
    from trace_app.core.activity import _split
    folder = volume.find(*_split(windows.path), 'System32', 'LogFiles',
                         'Firewall')
    out = []
    for entry in volume.children(folder):
        if not entry.name.lower().startswith('pfirewall.log'):
            continue
        step(entry.path)
        data = volume.read(entry)
        text = data.decode('utf-16', 'replace') if data[:2] == b'\xff\xfe' \
            else data.decode('utf-8', 'replace')
        ref = volume.ref(entry)
        for row in parse_firewall(text):
            action = (row.get('action') or '').upper()
            protocol = row.get('protocol') or ''
            where = (f"{row.get('src-ip')}:{row.get('src-port')} -> "
                     f"{row.get('dst-ip')}:{row.get('dst-port')}"
                     if row.get('src-ip') else '')
            out.append(record(
                'network', 'Windows Firewall log', _firewall_time(row),
                f"Firewall {action.lower()}" + (f" {protocol}"
                                                if protocol else ''),
                where or action,
                {'direction': {'SEND': 'outbound', 'RECEIVE': 'inbound'}.get(
                    row.get('path'), row.get('path')),
                 'size': row.get('size'), 'TCP flags': row.get('tcpflags'),
                 'ICMP type': row.get('icmptype'),
                 'process ID': row.get('pid'), 'info': row.get('info')},
                path=entry.path, ref=ref, local=True))
    return out


# --- Windows Error Reporting --------------------------------------------------------

def parse_wer(data):
    """{key: value} of a Report.wer, with 'signature' {name: value} from
    the Sig[n] pairs, or None."""
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        text = data.decode('utf-16', 'replace')
    else:
        text = data.decode('utf-8-sig', 'replace')
    values = {}
    for line in text.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip()
    if 'EventType' not in values and not any(k.startswith('Sig[')
                                             for k in values):
        return None
    names, signature = {}, {}
    for key, value in values.items():
        found = re.match(r'Sig\[(\d+)\]\.(Name|Value)$', key)
        if found:
            names.setdefault(int(found.group(1)), {})[found.group(2)] = value
    for _number, pair in sorted(names.items()):
        if 'Name' in pair:
            signature[pair['Name']] = pair.get('Value', '')
    values['signature'] = signature
    try:
        values['time'] = times.filetime(int(values.get('EventTime', '0')))
    except ValueError:
        values['time'] = None
    return values


def wer_records(volume, step, users=()):
    from trace_app.core.activity import _split
    roots = [(volume.find('ProgramData', 'Microsoft', 'Windows', 'WER'), '')]
    for user, home in users:
        roots.append((volume.find(*_split(home.path), 'AppData', 'Local',
                                  'Microsoft', 'Windows', 'WER'), user))
    out = []
    for root, user in roots:
        for store in volume.children(root, dirs=True):
            for report in volume.children(store, dirs=True):
                entry = volume.find(*_split(report.path), 'Report.wer')
                if entry is None:
                    continue
                step(entry.path)
                found = parse_wer(volume.read(entry))
                if found is None:
                    continue
                signature = found['signature']
                application = found.get('AppName') or signature.get(
                    'Application Name') or ''
                out.append(record(
                    'programs', 'Windows Error Reporting', found['time'],
                    found.get('FriendlyEventName') or
                    f"{found.get('EventType', 'Problem')} reported",
                    found.get('AppPath') or application,
                    {'event type': found.get('EventType'),
                     'application': application,
                     'version': signature.get('Application Version'),
                     'faulting module': signature.get('Fault Module Name')
                     or signature.get('Fault Module'),
                     'exception code': signature.get('Exception Code'),
                     'signature': signature,
                     'report folder': f"{store.name}\\{report.name}"},
                    user=user, path=entry.path, ref=volume.ref(entry)))
    return out
