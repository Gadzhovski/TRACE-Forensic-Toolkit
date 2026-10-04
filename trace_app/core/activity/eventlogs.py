"""The event log entries that answer "who logged on, and what changed".

Not every event: a Security log holds tens of thousands, most of them the
system talking to itself. These are the ones an examiner reads first --
logons and failures (by type: console, network, remote desktop), logoffs,
accounts created, changed, enabled, deleted or added to groups, services
installed, logs cleared, the system starting and stopping, and remote
desktop connections with the address they came from.

Service logons (type 5) and the machine's own SYSTEM / computer accounts
are left out of the logon events: they happen at every boot and bury the
people.

Vista+ .evtx logs go through evtx.py; XP .evt logs are read here, with
their events' numbers and string positions.
"""

import datetime
import re
import struct

from trace_app.core.activity import evtx, times

LOGON_TYPES = {
    2: 'console', 3: 'network', 4: 'batch', 5: 'service', 7: 'unlock',
    8: 'network (clear text)', 9: 'new credentials', 10: 'remote desktop',
    11: 'cached console', 12: 'cached remote', 13: 'cached unlock',
}

#: Failure codes of 4625/529-537, the ones that say something.
FAILURE_REASONS = {
    '0xc000006a': 'wrong password', '0xc0000064': 'no such user',
    '0xc000006d': 'bad user name or password', '0xc0000234': 'account locked',
    '0xc0000072': 'account disabled', '0xc000006f': 'outside logon hours',
    '0xc0000070': 'workstation restriction', '0xc0000193': 'account expired',
    '0xc0000071': 'password expired', '0xc0000133': 'clocks out of sync',
    '0xc0000224': 'password must change', '0xc000015b': 'logon type not granted',
}

_SYSTEM_SIDS = {'S-1-5-18', 'S-1-5-19', 'S-1-5-20'}
_SECURITY = 'Microsoft-Windows-Security-Auditing'


def _user(data, prefix='Target'):
    name = data.get(f'{prefix}UserName') or ''
    domain = data.get(f'{prefix}DomainName') or ''
    return f'{domain}\\{name}' if domain and name and name != '-' else name


def _source(data):
    address = data.get('IpAddress') or ''
    workstation = data.get('WorkstationName') or ''
    parts = [p for p in (address, workstation) if p and p not in ('-', '::1',
                                                                   '127.0.0.1')]
    return ' / '.join(parts)


def _logon_type(data):
    try:
        number = int(data.get('LogonType') or 0)
    except ValueError:
        return None, ''
    return number, LOGON_TYPES.get(number, str(number))


def _is_machine(data):
    user = data.get('TargetUserName') or ''
    return (data.get('TargetUserSid') in _SYSTEM_SIDS or user.endswith('$')
            or user.upper() in ('ANONYMOUS LOGON', 'SYSTEM', 'LOCAL SERVICE',
                                'NETWORK SERVICE', 'DWM-1', 'DWM-2', 'UMFD-0',
                                'UMFD-1'))


def describe(event):
    """(what, subject, detail) for an event worth listing, or None."""
    eid = event['event_id']
    data = event['data']
    provider = event['provider']
    channel = event['channel']

    if provider == _SECURITY or channel == 'Security':
        if eid in (4624, 4625):
            number, kind = _logon_type(data)
            if number == 5 or (eid == 4624 and _is_machine(data)):
                return None
            source = _source(data)
            detail = {'logon type': kind, 'from': source,
                      'process': data.get('ProcessName') or
                      data.get('LogonProcessName') or '',
                      'logon id': data.get('TargetLogonId') or ''}
            if eid == 4625:
                status = (data.get('SubStatus') or data.get('Status') or '')
                detail['reason'] = FAILURE_REASONS.get(status.lower(), status)
                return ('Logon failed', _user(data), detail)
            what = 'Remote desktop logon' if number == 10 else \
                f'Logon ({kind})'
            return (what, _user(data), detail)
        if eid == 4647:
            return ('Logoff', _user(data), {'logon id':
                                             data.get('TargetLogonId', '')})
        if eid == 4648:
            if _is_machine(data):
                return None
            return ('Logon with explicit credentials', _user(data),
                    {'by': _user(data, 'Subject'),
                     'target server': data.get('TargetServerName', ''),
                     'from': _source(data),
                     'process': data.get('ProcessName', '')})
        if eid in (4778, 4779):
            return ('Remote session ' + ('reconnected' if eid == 4778
                                         else 'disconnected'),
                    f"{data.get('AccountDomain', '')}\\"
                    f"{data.get('AccountName', '')}",
                    {'from': data.get('ClientAddress', ''),
                     'client': data.get('ClientName', '')})
        accounts = {4720: 'Account created', 4722: 'Account enabled',
                    4723: 'Password change attempted', 4724: 'Password reset',
                    4725: 'Account disabled', 4726: 'Account deleted',
                    4738: 'Account changed', 4740: 'Account locked out',
                    4767: 'Account unlocked', 4781: 'Account renamed'}
        if eid in accounts:
            return (accounts[eid], _user(data),
                    {'by': _user(data, 'Subject'),
                     'new name': data.get('NewTargetUserName', '')})
        groups = {4728: 'global', 4732: 'local', 4756: 'universal'}
        if eid in groups or eid in (4729, 4733, 4757):
            added = eid in groups
            member = data.get('MemberName') or ''
            if member in ('', '-'):
                member = data.get('MemberSid') or ''
            return (('Added to ' if added else 'Removed from ')
                    + f"{groups.get(eid, 'security')} group", member,
                    {'group': _user(data), 'by': _user(data, 'Subject')})
        if eid == 4697:
            return ('Service installed', data.get('ServiceName', ''),
                    {'file': data.get('ServiceFileName', ''),
                     'by': _user(data, 'Subject')})
        if eid == 1102:
            return ('Security log cleared', data.get('SubjectUserName', ''),
                    {'domain': data.get('SubjectDomainName', '')})
        return None

    if eid == 7045 and 'Service Control Manager' in provider:
        return ('Service installed', data.get('ServiceName', ''),
                {'file': data.get('ImagePath', ''),
                 'start': data.get('StartType', ''),
                 'account': data.get('AccountName', '')})
    if eid == 104 and 'Eventlog' in provider:
        return ('Event log cleared', data.get('SubjectUserName', ''),
                {'log': data.get('Channel', '') or
                 data.get('BackupPath', '')})
    if provider == 'EventLog' and eid in (6005, 6006, 6008):
        return ({6005: 'System started', 6006: 'System shut down',
                 6008: 'Unexpected shutdown'}[eid], event['computer'], {})

    if 'Windows Defender' in channel or 'Windows Defender' in provider:
        threat = data.get('Threat Name') or ''
        common = {'path': data.get('Path') or '',
                  'process': data.get('Process Name') or '',
                  'user': data.get('Detection User') or '',
                  'severity': data.get('Severity Name') or '',
                  'category': data.get('Category Name') or '',
                  'action': data.get('Action Name') or ''}
        defender = {1116: 'Threat detected', 1117: 'Threat action taken',
                    1118: 'Threat action failed', 1119: 'Threat action failed',
                    1006: 'Threat detected', 1007: 'Threat action taken',
                    5001: 'Real-time protection turned off',
                    5004: 'Real-time protection settings changed',
                    5007: 'Settings changed', 5010: 'Spyware scanning off',
                    5012: 'Virus scanning off', 1013: 'History deleted'}
        if eid == 5007:
            # Defender rewrites its own settings hundreds of times; what an
            # examiner wants is an exclusion added or protection turned off.
            value = data.get('New Value') or ''
            if '\\Exclusions\\' in value:
                return ('Defender exclusion added', value.split(
                    '\\Exclusions\\', 1)[1],
                        {'old value': data.get('Old Value') or ''})
            if re.search(r'(?i)\\(Real-Time Protection\\Disable\w+|'
                         r'DisableAntiSpyware|DisableAntiVirus) = 0x1$',
                         value):
                return ('Defender protection turned off',
                        value.rsplit('\\', 1)[-1], {})
            return None
        if eid in defender:
            return (defender[eid], threat or data.get('Path') or '', common)
        return None
    if 'LocalSessionManager' in channel:
        names = {21: 'Remote desktop logon', 22: 'Remote desktop shell start',
                 23: 'Remote desktop logoff',
                 24: 'Remote desktop disconnected',
                 25: 'Remote desktop reconnected'}
        if eid in names:
            return (names[eid], data.get('User', ''),
                    {'from': data.get('Address', ''),
                     'session': data.get('SessionID', '')})
    if 'RemoteConnectionManager' in channel and eid == 1149:
        user = data.get('Param1', '')
        domain = data.get('Param2', '')
        return ('Remote desktop authentication',
                f'{domain}\\{user}' if domain else user,
                {'from': data.get('Param3', '')})
    if 'RdpCoreTS' in channel and eid == 131:
        return ('Remote desktop connection', data.get('ClientIP', ''),
                {'transport': data.get('ConnType', '')})
    return None


def from_evtx(data):
    """[(time, what, subject, detail, event)] for the events listed."""
    out = []
    for event in evtx.records(data):
        if event['event_id'] is None:
            continue
        described = describe(event)
        if described:
            what, subject, detail = described
            detail = {k: v for k, v in detail.items() if v not in ('', None)}
            detail['event id'] = event['event_id']
            detail['record'] = event['record_id']
            out.append((event['time'], what, subject, detail, event))
    return out


# --- XP / 2003 .evt -------------------------------------------------------------

_EVT_RECORD = b'LfLe'

_XP_EVENTS = {
    528: 'Logon', 540: 'Logon (network)', 529: 'Logon failed',
    530: 'Logon failed', 531: 'Logon failed', 532: 'Logon failed',
    533: 'Logon failed', 534: 'Logon failed', 535: 'Logon failed',
    536: 'Logon failed', 537: 'Logon failed', 539: 'Logon failed',
    538: 'Logoff', 551: 'Logoff',
    624: 'Account created', 626: 'Account enabled', 627: 'Password changed',
    628: 'Password reset', 629: 'Account disabled', 630: 'Account deleted',
    636: 'Added to local group', 632: 'Added to global group',
    517: 'Security log cleared', 601: 'Service installed',
    6005: 'System started', 6006: 'System shut down',
    6008: 'Unexpected shutdown',
}


def from_evt(data):
    """The same, from an XP/2003 .evt log: records are 'LfLe'-signed with
    the event's strings in order."""
    out = []
    at = data.find(_EVT_RECORD)
    while at != -1 and at >= 4:
        start = at - 4
        try:
            length = struct.unpack_from('<I', data, start)[0]
            if length < 56 or start + length > len(data):
                at = data.find(_EVT_RECORD, at + 4)
                continue
            (number, generated, _written, event_id, _type, count, _category,
             _flags, _closing, string_at, sid_length, sid_at) = \
                struct.unpack_from('<IIIIHHHHIIII', data, start + 8)
            record = data[start:start + length]
            event_id &= 0xFFFF
            what = _XP_EVENTS.get(event_id)
            if what:
                source_end = record.find(b'\x00\x00', 56)
                source_end += source_end % 2
                source = record[56:source_end].decode('utf-16-le', 'replace')
                strings = record[string_at:].decode(
                    'utf-16-le', 'replace').split('\x00')[:count]
                described = _xp_describe(event_id, what, source, strings)
                if described:
                    subject, detail = described
                    detail['event id'] = event_id
                    detail['record'] = number
                    out.append((times.unix(generated), what, subject, detail,
                                {'event_id': event_id}))
            at = data.find(_EVT_RECORD, start + length)
        except struct.error:
            at = data.find(_EVT_RECORD, at + 4)
    return out


def _xp_describe(event_id, what, source, strings):
    def get(index):
        return strings[index] if index < len(strings) else ''

    if event_id in (528, 540, 538, 551) or 529 <= event_id <= 539:
        user, domain = get(0), get(1)
        if user.endswith('$') or user.upper() in ('SYSTEM', 'LOCAL SERVICE',
                                                  'NETWORK SERVICE',
                                                  'ANONYMOUS LOGON'):
            return None
        detail = {}
        if event_id in (528, 540):
            try:
                number = int(get(3))
            except ValueError:
                number = None
            if number == 5:
                return None
            detail['logon type'] = LOGON_TYPES.get(number, get(3))
            detail['from'] = ' / '.join(p for p in (get(13), get(6))
                                        if p and p != '-')
        elif 529 <= event_id <= 539:
            detail['logon type'] = LOGON_TYPES.get(
                int(get(2)) if get(2).isdigit() else None, get(2))
            detail['from'] = get(5) or get(11)
        return (f'{domain}\\{user}' if domain else user, detail)
    if event_id in (624, 626, 627, 628, 629, 630):
        return (f'{get(1)}\\{get(0)}' if get(1) else get(0),
                {'by': f'{get(4)}\\{get(3)}' if get(4) else get(3)})
    if event_id in (632, 636):
        return (get(0), {'group': get(2)})
    if event_id == 517:
        return (get(1), {'domain': get(2)})
    if source == 'EventLog' and event_id in (6005, 6006, 6008):
        return ('', {})
    return None


def to_utc_naive(stamp):
    return stamp.astimezone(times.UTC) if isinstance(
        stamp, datetime.datetime) else stamp
