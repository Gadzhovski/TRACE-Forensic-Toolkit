"""Sigma rules over Windows event logs -- what Hayabusa and Chainsaw do --
in Python, on the events TRACE's own EVTX reader decodes.

Rules are kept in a library in `user_data_dir()/sigma/`, one folder per
imported set (a rule file, a folder of them, or a SigmaHQ release zip),
copied with each file's SHA-256 so results trace to the exact rules. Which
sets a case uses is its setting (`case.setting('sigma')`).

A rule is compiled once:
  * its log source to the event logs it is about -- a service to a
    channel ('security' -> Security, 'sysmon' -> Microsoft-Windows-Sysmon/
    Operational...), a category to the channels and event IDs that record
    it ('process_creation' -> Sysmon 1 and Security 4688, the latter with
    its fields renamed to Sysmon's, as Hayabusa and Chainsaw do);
  * each search identifier to a matcher: maps are ANDed over their fields,
    a field's list of values ORed (ANDed with `|all`), lists of maps ORed,
    plain lists are keywords searched in every value;
  * values as the Sigma specification says: case-insensitive, `*` and `?`
    wildcards (escaped with a backslash), and the modifiers SigmaHQ's rules
    use -- contains, startswith, endswith, all, re (with i/m/s), windash,
    cidr, base64, base64offset, wide/utf16le/utf16be/utf16, fieldref,
    exists, cased, lt/lte/gt/gte;
  * its condition -- and, or, not, parentheses, `1 of x*`, `all of x*`,
    `1 of them`, `all of them` -- to a function.
A rule TRACE cannot run (an aggregation, a correlation, a log source with no
Windows event log, an unknown modifier) is counted with its reason at import
and never run, rather than run wrongly.

A hit is a finding (module 'sigma', one per rule per event, up to
`MAX_HITS_PER_RULE` per log): the rule, its level, ATT&CK tags, and the
event -- time, computer, ID, record number and its data. Graded by level:
critical and high suspicious, medium notable, low and informational kept
as benign.

No Qt here.
"""

import base64
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import uuid
import zipfile

logger = logging.getLogger('TRACE.Sigma')

MODULE_SIGMA = 'sigma'
LIBRARY_FILE = 'library.json'
RULE_EXTENSIONS = ('.yml', '.yaml')
MAX_HITS_PER_RULE = 500
#: Event data kept with a hit: so many fields, each so long.
DETAIL_FIELDS = 60
DETAIL_VALUE = 1000
#: Largest event log read whole.
MAX_LOG_BYTES = 1024 * 1024 * 1024

LEVELS = ('informational', 'low', 'medium', 'high', 'critical')
_GRADES = {'critical': 'suspicious', 'high': 'suspicious',
           'medium': 'notable', 'low': 'benign', 'informational': 'benign'}

SYSMON = 'microsoft-windows-sysmon/operational'
POWERSHELL = 'microsoft-windows-powershell/operational'
POWERSHELL_CLASSIC = 'windows powershell'

#: Sigma services (product windows) -> event log channels, lowercase.
SERVICES = {
    'security': ['security'], 'system': ['system'],
    'application': ['application'], 'sysmon': [SYSMON],
    'powershell': [POWERSHELL], 'powershell-classic': [POWERSHELL_CLASSIC],
    'windefend': ['microsoft-windows-windows defender/operational'],
    'codeintegrity-operational': ['microsoft-windows-codeintegrity/'
                                  'operational'],
    'appxdeployment-server': ['microsoft-windows-appxdeploymentserver/'
                              'operational'],
    'appxpackaging-om': ['microsoft-windows-appxpackaging/operational'],
    'msexchange-management': ['msexchange management'],
    'bits-client': ['microsoft-windows-bits-client/operational'],
    'firewall-as': ['microsoft-windows-windows firewall with advanced '
                    'security/firewall'],
    'dns-client': ['microsoft-windows-dns client events/operational'],
    'taskscheduler': ['microsoft-windows-taskscheduler/operational'],
    'iis-configuration': ['microsoft-iis-configuration/operational'],
    'security-mitigations': ['microsoft-windows-security-mitigations/'
                             'kernel mode',
                             'microsoft-windows-security-mitigations/'
                             'user mode'],
    'dns-server': ['dns server'],
    'dns-server-analytic': ['microsoft-windows-dns-server/analytical'],
    'applocker': ['microsoft-windows-applocker/exe and dll',
                  'microsoft-windows-applocker/msi and script',
                  'microsoft-windows-applocker/packaged app-deployment',
                  'microsoft-windows-applocker/packaged app-execution'],
    'ntlm': ['microsoft-windows-ntlm/operational'],
    'wmi': ['microsoft-windows-wmi-activity/operational'],
    'shell-core': ['microsoft-windows-shell-core/operational'],
    'lsa-server': ['microsoft-windows-lsa/operational'],
    'terminalservices-localsessionmanager': [
        'microsoft-windows-terminalservices-localsessionmanager/'
        'operational'],
    'smbclient-security': ['microsoft-windows-smbclient/security'],
    'smbclient-connectivity': ['microsoft-windows-smbclient/connectivity'],
    'smbserver-connectivity': ['microsoft-windows-smbserver/connectivity'],
    'microsoft-servicebus-client': ['microsoft-servicebus-client'],
    'openssh': ['openssh/operational'],
    'ldap': ['microsoft-windows-ldap-client/debug'],
    'capi2': ['microsoft-windows-capi2/operational'],
    'certificateservicesclient-lifecycle-system': [
        'microsoft-windows-certificateservicesclient-lifecycle-system/'
        'operational'],
    'diagnosis-scripted': ['microsoft-windows-diagnosis-scripted/'
                           'operational'],
    'printservice-admin': ['microsoft-windows-printservice/admin'],
    'printservice-operational': ['microsoft-windows-printservice/'
                                 'operational'],
    'driver-framework': ['microsoft-windows-driverframeworks-usermode/'
                         'operational'],
    'vhdmp': ['microsoft-windows-vhdmp-operational'],
    'kernel-shimengine': ['microsoft-windows-kernel-shimengine/operational',
                          'microsoft-windows-kernel-shimengine/diagnostic'],
}

#: Security 4688 renamed to Sysmon's process creation fields, so the
#: process_creation rules (written for Sysmon) read it too.
_FROM_4688 = {'NewProcessName': 'Image', 'ParentProcessName': 'ParentImage',
              'NewProcessId': 'ProcessId', 'ProcessId': 'ParentProcessId',
              'SubjectUserName': 'User', 'SubjectLogonId': 'LogonId',
              'MandatoryLabel': 'IntegrityLevel'}
_INTEGRITY = {'S-1-16-0': 'Untrusted', 'S-1-16-4096': 'Low',
              'S-1-16-8192': 'Medium', 'S-1-16-8448': 'Medium Plus',
              'S-1-16-12288': 'High', 'S-1-16-16384': 'System',
              'S-1-16-20480': 'Protected'}

#: Sigma categories -> [(channel, event IDs, rename)].
CATEGORIES = {
    'process_creation': [(SYSMON, {1}, None), ('security', {4688}, _FROM_4688)],
    'file_change': [(SYSMON, {2}, None)],
    'network_connection': [(SYSMON, {3}, None)],
    'sysmon_status': [(SYSMON, {4, 16}, None)],
    'process_termination': [(SYSMON, {5}, None)],
    'driver_load': [(SYSMON, {6}, None)],
    'image_load': [(SYSMON, {7}, None)],
    'create_remote_thread': [(SYSMON, {8}, None)],
    'raw_access_thread': [(SYSMON, {9}, None)],
    'process_access': [(SYSMON, {10}, None)],
    'file_event': [(SYSMON, {11}, None)],
    'registry_add': [(SYSMON, {12}, None)],
    'registry_delete': [(SYSMON, {12}, None)],
    'registry_set': [(SYSMON, {13}, None)],
    'registry_rename': [(SYSMON, {14}, None)],
    'registry_event': [(SYSMON, {12, 13, 14}, None)],
    'create_stream_hash': [(SYSMON, {15}, None)],
    'pipe_created': [(SYSMON, {17, 18}, None)],
    'wmi_event': [(SYSMON, {19, 20, 21}, None)],
    'dns_query': [(SYSMON, {22}, None)],
    'file_delete': [(SYSMON, {23, 26}, None)],
    'clipboard_capture': [(SYSMON, {24}, None)],
    'process_tampering': [(SYSMON, {25}, None)],
    'file_block_executable': [(SYSMON, {27}, None)],
    'file_block_shredding': [(SYSMON, {28}, None)],
    'file_executable_detected': [(SYSMON, {29}, None)],
    'sysmon_error': [(SYSMON, {255}, None)],
    'ps_script': [(POWERSHELL, {4104}, None)],
    'ps_module': [(POWERSHELL, {4103}, None)],
    'ps_classic_start': [(POWERSHELL_CLASSIC, {400}, None)],
    'ps_classic_provider_start': [(POWERSHELL_CLASSIC, {600}, None)],
    'ps_classic_script': [(POWERSHELL_CLASSIC, {800}, None)],
}


class SigmaError(Exception):
    """Rules could not be imported."""


class Unsupported(Exception):
    """A rule TRACE does not run, and why."""


class ScanCancelled(Exception):
    pass


def available():
    from trace_app.infra import capabilities
    return capabilities.available('sigma')


def unavailable_reason():
    from trace_app.infra import capabilities
    return capabilities.reason('sigma')


# --- values ------------------------------------------------------------------------

def _pieces(value):
    """A Sigma value as literal strings and wildcards: a backslash escapes
    a wildcard or a backslash; before anything else it is itself.
    [str (literal) | None ('*') | False ('?')]."""
    out = []
    literal = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == '\\' and index + 1 < len(value) and \
                value[index + 1] in '*?\\':
            literal.append(value[index + 1])
            index += 2
            continue
        if char in '*?':
            if literal:
                out.append(''.join(literal))
                literal = []
            out.append(None if char == '*' else False)
        else:
            literal.append(char)
        index += 1
    if literal:
        out.append(''.join(literal))
    return out


def _wildcard_regex(value, flags=re.IGNORECASE):
    """A Sigma value with * and ? wildcards as an anchored regex; `value`
    is its text, or already its pieces."""
    pieces = _pieces(value) if isinstance(value, str) else value
    out = ''.join('.*' if p is None else '.' if p is False else re.escape(p)
                  for p in pieces)
    return re.compile('^' + out + '$', flags | re.DOTALL)


def _windash(value):
    """The value with each dash or slash that starts a word in every form
    Windows command lines accept: - / en dash, em dash, horizontal bar."""
    forms = ['-', '/', '–', '—', '―']
    positions = [i for i, c in enumerate(value) if c in '-/' and
                 (i == 0 or value[i - 1].isspace())]
    if not positions:
        return [value]
    out = []
    for form in forms:
        chars = list(value)
        for i in positions:
            chars[i] = form
        out.append(''.join(chars))
    return out


def _base64offset(raw):
    """The three base64 forms of `raw` at each offset in a stream,
    without the characters its neighbours change."""
    out = []
    for shift in range(3):
        encoded = base64.b64encode(b'\x00' * shift + raw).decode()
        start = (0, 2, 3)[shift]
        end = len(encoded) - ((0, 3, 2)[(len(raw) + shift) % 3])
        out.append(encoded[start:end])
    return out


def _compile_value(raw, modifiers):
    """[test functions] for one rule value -- several when a modifier
    (windash, base64offset) makes several forms of it, ORed."""
    mods = [m.lower() for m in modifiers]
    known = {'contains', 'startswith', 'endswith', 'all', 're', 'i', 'm',
             's', 'windash', 'cidr', 'base64', 'base64offset', 'wide',
             'utf16le', 'utf16be', 'utf16', 'fieldref', 'exists', 'cased',
             'lt', 'lte', 'gt', 'gte'}
    unknown = [m for m in mods if m not in known]
    if unknown:
        raise Unsupported(f"modifier {'|'.join(unknown)}")
    if raw is None:
        return [lambda text, _fields: text is None or text == '']
    if 'exists' in mods:
        wanted = bool(raw)
        return [lambda text, _fields: (text is not None) == wanted]
    if 'fieldref' in mods:
        other = str(raw)
        return [lambda text, fields: text is not None and
                fields.get(other) is not None and
                str(text).lower() == str(fields.get(other)).lower()]
    for op in ('lt', 'lte', 'gt', 'gte'):
        if op in mods:
            limit = float(raw)
            compare = {'lt': float.__lt__, 'lte': float.__le__,
                       'gt': float.__gt__, 'gte': float.__ge__}[op]

            def numeric(text, _fields, compare=compare, limit=limit):
                try:
                    return compare(float(text), limit)
                except (TypeError, ValueError):
                    return False
            return [numeric]
    if isinstance(raw, bool):
        raw = 'true' if raw else 'false'
    value = str(raw)
    if 're' in mods:
        flags = (re.IGNORECASE if 'i' in mods else 0) | \
            (re.MULTILINE if 'm' in mods else 0) | \
            (re.DOTALL if 's' in mods else 0)
        try:
            pattern = re.compile(value, flags)
        except re.error as exc:
            raise Unsupported(f"regex {value!r}: {exc}")
        return [lambda text, _fields: text is not None and
                pattern.search(str(text)) is not None]
    if 'cidr' in mods:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise Unsupported(f"cidr {value!r}: {exc}")

        def in_network(text, _fields):
            try:
                return ipaddress.ip_address(str(text).strip()) in network
            except ValueError:
                return False
        return [in_network]
    forms = _windash(value) if 'windash' in mods else [value]
    encoding = None
    for name, codec in (('wide', 'utf-16-le'), ('utf16le', 'utf-16-le'),
                        ('utf16be', 'utf-16-be'), ('utf16', 'utf-16')):
        if name in mods:
            encoding = codec
    if 'base64offset' in mods:
        forms = [encoded for form in forms for encoded in
                 _base64offset(form.encode(encoding or 'utf-8'))]
    elif 'base64' in mods:
        forms = [base64.b64encode(form.encode(encoding or 'utf-8')).decode()
                 for form in forms]
    cased = 'cased' in mods or 'base64' in mods or 'base64offset' in mods
    tests = []
    for form in forms:
        # The value's own wildcards first; the modifier then wraps them --
        # wrapping the text would let a trailing backslash ('\') escape
        # the '*' contains adds.
        pieces = [form] if 'base64' in mods or 'base64offset' in mods \
            else _pieces(form)
        if 'contains' in mods:
            pieces = [None] + pieces + [None]
        elif 'startswith' in mods:
            pieces = pieces + [None]
        elif 'endswith' in mods:
            pieces = [None] + pieces
        pattern = pieces
        lead = bool(pieces) and pieces[0] is None
        trail = len(pieces) > 1 and pieces[-1] is None
        inner = pieces[1 if lead else 0:len(pieces) - (1 if trail else 0)]
        plain = len(inner) <= 1 and all(isinstance(p, str) for p in inner)
        if plain:
            # The common case, without a regex: contains/startswith/
            # endswith/equals on lower-cased text.
            core = inner[0] if inner else ''
            kind = ('contains' if lead and trail else
                    'endswith' if lead else
                    'startswith' if trail else 'equals')
            if lead and not inner:
                kind = 'contains'           # '*' alone: anything
            needle = core if cased else core.lower()

            def test(text, _fields, kind=kind, needle=needle, cased=cased):
                if text is None:
                    return False
                text = str(text) if cased else str(text).lower()
                if kind == 'contains':
                    return needle in text
                if kind == 'startswith':
                    return text.startswith(needle)
                if kind == 'endswith':
                    return text.endswith(needle)
                return text == needle
            tests.append(test)
        else:
            regex = _wildcard_regex(pattern, 0 if cased else re.IGNORECASE)
            tests.append(lambda text, _fields, regex=regex: text is not None
                         and regex.match(str(text)) is not None)
    return tests


def _field_matcher(key, values):
    """One `field|modifiers: value(s)` of a map, as fn(fields) -> bool."""
    parts = str(key).split('|')
    field, modifiers = parts[0], parts[1:]
    values = values if isinstance(values, list) else [values]
    if not values:
        values = [None]
    every = 'all' in [m.lower() for m in modifiers]
    compiled = [_compile_value(v, modifiers) for v in values]

    def get(fields):
        if field in fields:
            return fields[field]
        lowered = field.lower()
        for name, value in fields.items():
            if name.lower() == lowered:
                return value
        return None

    if not field:                       # a keyword with modifiers
        def keywords(fields):
            texts = [v for v in fields.values() if v is not None]
            hits = [any(t(text, fields) for t in tests for text in texts)
                    for tests in compiled]
            return all(hits) if every else any(hits)
        return keywords

    def match(fields):
        text = get(fields)
        hits = (any(t(text, fields) for t in tests) for tests in compiled)
        return all(hits) if every else any(hits)
    return match


def _search_matcher(definition):
    """A search identifier's definition as fn(fields) -> bool."""
    if isinstance(definition, dict):
        matchers = [_field_matcher(k, v) for k, v in definition.items()]
        return lambda fields: all(m(fields) for m in matchers)
    if isinstance(definition, list):
        if all(isinstance(item, dict) for item in definition):
            alternatives = [_search_matcher(item) for item in definition]
            return lambda fields: any(m(fields) for m in alternatives)
        if any(isinstance(item, (dict, list)) for item in definition):
            raise Unsupported("a list mixing maps and keywords")
        keyword = _field_matcher('|contains', [str(v) for v in definition])
        return keyword
    if isinstance(definition, (str, int, float)):
        return _field_matcher('|contains', [str(definition)])
    raise Unsupported(f"a search of type {type(definition).__name__}")


# --- conditions -----------------------------------------------------------------

_TOKEN = re.compile(r'\s*(\(|\)|[^\s()]+)')


def _tokens(text):
    position, out = 0, []
    text = text.strip()
    while position < len(text):
        match = _TOKEN.match(text, position)
        if not match:
            raise Unsupported(f"condition {text!r}")
        out.append(match.group(1))
        position = match.end()
    return out


def compile_condition(text, searches):
    """The condition as fn(results) -> bool, `results` giving each search
    identifier's outcome (computed lazily)."""
    if '|' in text:
        raise Unsupported("an aggregation in the condition")
    tokens = _tokens(text)
    position = [0]

    def peek():
        return tokens[position[0]].lower() if position[0] < len(tokens) \
            else None

    def take():
        token = tokens[position[0]]
        position[0] += 1
        return token

    def names_for(target):
        if target.lower() == 'them':
            return [n for n in searches if not n.startswith('_')]
        regex = _wildcard_regex(target, 0)
        found = [n for n in searches if regex.match(n)]
        if not found:
            raise Unsupported(f"no search matches {target!r}")
        return found

    def primary():
        token = peek()
        if token is None:
            raise Unsupported(f"condition {text!r} ends early")
        if token == '(':
            take()
            inner = expression()
            if peek() != ')':
                raise Unsupported(f"unbalanced condition {text!r}")
            take()
            return inner
        if token == 'not':
            take()
            inner = primary()
            return lambda r: not inner(r)
        if token in ('1', 'all', 'any') and position[0] + 1 < len(tokens) \
                and tokens[position[0] + 1].lower() == 'of':
            quantity = take().lower()
            take()
            names = names_for(take())
            if quantity == 'all':
                return lambda r: all(r(n) for n in names)
            return lambda r: any(r(n) for n in names)
        name = take()
        if name not in searches:
            raise Unsupported(f"no search named {name!r}")
        return lambda r: r(name)

    def conjunction():
        parts = [primary()]
        while peek() == 'and':
            take()
            parts.append(primary())
        return parts[0] if len(parts) == 1 else \
            (lambda r: all(p(r) for p in parts))

    def expression():
        parts = [conjunction()]
        while peek() == 'or':
            take()
            parts.append(conjunction())
        return parts[0] if len(parts) == 1 else \
            (lambda r: any(p(r) for p in parts))

    result = expression()
    if position[0] != len(tokens):
        raise Unsupported(f"condition {text!r}")
    return result


# --- rules ----------------------------------------------------------------------

class Rule:
    __slots__ = ('id', 'title', 'level', 'status', 'tags', 'description',
                 'falsepositives', 'references', 'author', 'sources',
                 '_searches', '_condition', 'file', 'set_id', 'set_name')

    def matches(self, fields):
        cache = {}

        def result(name):
            if name not in cache:
                cache[name] = self._searches[name](fields)
            return cache[name]
        return any(condition(result) for condition in self._condition)

    @property
    def attack(self):
        return [t[7:].upper() for t in self.tags
                if t.lower().startswith('attack.t')]


def compile_rule(document):
    """A Rule from one parsed rule document; Unsupported says why not."""
    if not isinstance(document, dict) or 'detection' not in document:
        raise Unsupported("not a detection rule")
    if 'correlation' in document:
        raise Unsupported("a correlation rule")
    source = document.get('logsource') or {}
    product = str(source.get('product') or '').lower()
    if product and product != 'windows':
        raise Unsupported(f"product {product} (TRACE reads Windows event "
                          f"logs)")
    sources = []
    category = str(source.get('category') or '').lower()
    service = str(source.get('service') or '').lower()
    if category:
        if category not in CATEGORIES:
            raise Unsupported(f"category {category} has no event log")
        sources = list(CATEGORIES[category])
    if service:
        if service not in SERVICES:
            if not product:
                raise Unsupported(f"service {service} is not a Windows "
                                  f"event log")
            raise Unsupported(f"service {service} is not mapped")
        channels = SERVICES[service]
        if sources:
            sources = [s for s in sources if s[0] in channels] or \
                [(c, None, None) for c in channels]
        else:
            sources = [(c, None, None) for c in channels]
    if not sources:
        if not product:
            raise Unsupported("no Windows log source")
        sources = [(None, None, None)]          # every Windows log
    detection = document['detection']
    condition = detection.get('condition')
    if condition is None:
        raise Unsupported("no condition")
    conditions = condition if isinstance(condition, list) else [condition]
    searches = {name: _search_matcher(value)
                for name, value in detection.items()
                if name not in ('condition', 'timeframe')}
    if 'timeframe' in detection:
        raise Unsupported("a timeframe (aggregation)")
    rule = Rule()
    rule._searches = searches
    rule._condition = [compile_condition(str(c), searches)
                       for c in conditions]
    rule.id = str(document.get('id') or '')
    rule.title = str(document.get('title') or rule.id or 'Untitled rule')
    level = str(document.get('level') or 'medium').lower()
    rule.level = level if level in LEVELS else 'medium'
    rule.status = str(document.get('status') or '')
    rule.tags = [str(t) for t in document.get('tags') or []]
    rule.description = str(document.get('description') or '').strip()
    rule.falsepositives = [str(f) for f in
                           document.get('falsepositives') or []]
    rule.references = [str(r) for r in document.get('references') or []]
    rule.author = str(document.get('author') or '')
    rule.sources = sources
    rule.file = rule.set_id = rule.set_name = ''
    return rule


def load_documents(text):
    import yaml
    return [d for d in yaml.safe_load_all(text) if d is not None]


def compile_text(text, name=''):
    """([Rule], [(name, reason)]) from one rule file's text."""
    rules, skipped = [], []
    try:
        documents = load_documents(text)
    except Exception as exc:
        return [], [(name, f"not YAML: {exc}")]
    for document in documents:
        if isinstance(document, dict) and document.get('action'):
            skipped.append((name, "a rule collection (action: global)"))
            continue
        try:
            rule = compile_rule(document)
        except Unsupported as exc:
            title = document.get('title') if isinstance(document, dict) \
                else ''
            skipped.append((title or name, str(exc)))
            continue
        except Exception as exc:
            skipped.append((name, f"unreadable: {exc}"))
            continue
        rule.file = name
        rules.append(rule)
    return rules, skipped


# --- events --------------------------------------------------------------------

_PADDED_HEX = re.compile(r'0x0+([0-9a-fA-F]+)')


def event_fields(event):
    """An EVTX record (activity/evtx.summarise) as the fields rules name.
    Hex numbers are written as Windows renders them -- '0x100', not the
    zero-padded '0x00000100' the binary XML decodes to -- since that is
    what rules are written against."""
    fields = {}
    for name, value in (event.get('data') or {}).items():
        if isinstance(value, str) and value[:3] == '0x0':
            match = _PADDED_HEX.fullmatch(value)
            if match:
                value = '0x' + match.group(1)
        fields[name] = value
    fields['EventID'] = event.get('event_id')
    fields['Channel'] = event.get('channel') or ''
    fields['Provider_Name'] = event.get('provider') or ''
    fields['Computer'] = event.get('computer') or ''
    fields['EventRecordID'] = event.get('record_id')
    if event.get('user_sid'):
        fields.setdefault('UserID', event['user_sid'])
    return fields


class RuleIndex:
    """Rules by the channel and event ID they apply to, so an event is
    tested only against rules that could match it."""

    def __init__(self, rules):
        self.by_channel = {}
        self.anywhere = []
        for rule in rules:
            for channel, ids, rename in rule.sources:
                if channel is None:
                    self.anywhere.append((rule, None, None))
                else:
                    self.by_channel.setdefault(channel, []).append(
                        (rule, ids, rename))

    def candidates(self, channel, event_id):
        for rule, ids, rename in self.by_channel.get(
                (channel or '').lower(), []):
            if ids is None or event_id in ids:
                yield rule, rename
        for rule, _ids, _rename in self.anywhere:
            yield rule, None


def _renamed(fields, rename):
    out = dict(fields)
    for old, new in rename.items():
        if old in fields:
            out[new] = fields[old]
    label = out.get('IntegrityLevel')
    if label in _INTEGRITY:
        out['IntegrityLevel'] = _INTEGRITY[label]
    return out


def match_events(events, index):
    """[(rule, event, fields)] for every rule an event matches."""
    for event in events:
        fields = event_fields(event)
        renamed = {}
        for rule, rename in index.candidates(fields['Channel'],
                                             fields['EventID']):
            view = fields
            if rename is not None:
                key = id(rename)
                if key not in renamed:
                    renamed[key] = _renamed(fields, rename)
                view = renamed[key]
            try:
                hit = rule.matches(view)
            except Exception as exc:
                logger.debug("Rule %s failed on an event: %s", rule.title,
                             exc)
                continue
            if hit:
                yield rule, event, view


# --- the library ----------------------------------------------------------------

def default_options():
    return {'enabled': False, 'sets': {}, 'min_level': 'low'}


def case_options(case, library=None):
    stored = case.setting('sigma') if case is not None else None
    options = default_options()
    if stored:
        options.update(stored)
    elif library is not None and library.sets():
        options['enabled'] = True
    return options


def set_enabled_in(options, entry):
    chosen = (options.get('sets') or {}).get(entry['id'])
    return entry.get('enabled_by_default', True) if chosen is None \
        else bool(chosen)


class Library:
    def __init__(self, folder=None):
        if folder is None:
            from trace_app.infra.paths import user_data_dir
            folder = os.path.join(user_data_dir(), 'sigma')
        self.folder = folder
        os.makedirs(folder, exist_ok=True)
        self._path = os.path.join(folder, LIBRARY_FILE)

    def _load(self):
        try:
            with open(self._path, encoding='utf-8') as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return {'sets': []}
        except (OSError, ValueError) as exc:
            logger.error("Sigma library unreadable: %s", exc)
            return {'sets': []}
        data.setdefault('sets', [])
        return data

    def _save(self, data):
        temporary = self._path + '.tmp'
        with open(temporary, 'w', encoding='utf-8') as handle:
            json.dump(data, handle, indent=2)
        os.replace(temporary, self._path)

    def sets(self):
        out = []
        for entry in self._load()['sets']:
            entry = dict(entry)
            entry['available'] = os.path.isdir(self.set_folder(entry))
            out.append(entry)
        return out

    def get(self, set_id):
        return next((e for e in self.sets() if e['id'] == set_id), None)

    def set_folder(self, entry):
        return os.path.join(self.folder, entry['id'])

    def update(self, set_id, **fields):
        allowed = {'name', 'description', 'enabled_by_default'}
        if set(fields) - allowed:
            raise ValueError("Not a rule set field")
        data = self._load()
        for entry in data['sets']:
            if entry['id'] == set_id:
                entry.update(fields)
                self._save(data)
                return entry
        raise SigmaError("No such rule set")

    def remove(self, set_id):
        data = self._load()
        gone = [e for e in data['sets'] if e['id'] == set_id]
        data['sets'] = [e for e in data['sets'] if e['id'] != set_id]
        self._save(data)
        for entry in gone:
            shutil.rmtree(self.set_folder(entry), ignore_errors=True)

    def import_rules(self, source, name=None, description=''):
        """Copy a rule file, a folder of them, or a zip (a SigmaHQ release)
        into the library, compiling each to count what runs and what does
        not, and why."""
        source = os.path.abspath(source)
        files = _rule_sources(source)
        if not files:
            raise SigmaError(f"No Sigma rule files (.yml, .yaml) in "
                             f"{os.path.basename(source)}.")
        set_id = uuid.uuid4().hex
        target = os.path.join(self.folder, set_id)
        hashes, count, skipped = {}, 0, []
        try:
            os.makedirs(target)
            for relative, data in files:
                destination = os.path.join(target, *relative.split('/'))
                os.makedirs(os.path.dirname(destination), exist_ok=True)
                with open(destination, 'wb') as handle:
                    handle.write(data)
                hashes[relative] = hashlib.sha256(data).hexdigest()
                rules, unsupported = compile_text(
                    data.decode('utf-8', 'replace'), relative)
                count += len(rules)
                skipped += unsupported
        except Exception:
            shutil.rmtree(target, ignore_errors=True)
            raise
        if not count:
            shutil.rmtree(target, ignore_errors=True)
            raise SigmaError(f"None of the {len(files)} file(s) holds a rule "
                             f"TRACE can run on Windows event logs.")
        reasons = {}
        for _title, reason in skipped:
            key = reason.split(' (')[0].split(':')[0]
            reasons[key] = reasons.get(key, 0) + 1
        entry = {
            'id': set_id,
            'name': name or os.path.splitext(os.path.basename(
                source.rstrip('/\\')))[0],
            'description': description, 'source': source,
            'files': sorted(hashes), 'sha256': hashes,
            'rule_count': count, 'unsupported': len(skipped),
            'unsupported_reasons': reasons,
            'enabled_by_default': True, 'added_utc': _utc_now(),
        }
        data = self._load()
        data['sets'].append(entry)
        self._save(data)
        return entry

    def rules(self, entries):
        """Every runnable rule of these sets."""
        out = []
        for entry in entries:
            folder = self.set_folder(entry)
            for relative in entry.get('files', []):
                path = os.path.join(folder, *relative.split('/'))
                try:
                    with open(path, 'rb') as handle:
                        text = handle.read().decode('utf-8', 'replace')
                except OSError:
                    continue
                rules, _skipped = compile_text(text, relative)
                for rule in rules:
                    rule.set_id, rule.set_name = entry['id'], entry['name']
                out += rules
        return out


def _rule_sources(source):
    """[(relative path, bytes)] of the rule files in a file, folder or
    zip."""
    if os.path.isdir(source):
        out = []
        for folder, _dirs, names in os.walk(source):
            for name in sorted(names):
                if name.lower().endswith(RULE_EXTENSIONS):
                    path = os.path.join(folder, name)
                    with open(path, 'rb') as handle:
                        out.append((os.path.relpath(path, source)
                                    .replace('\\', '/'), handle.read()))
        return sorted(out)
    if source.lower().endswith('.zip'):
        out = []
        with zipfile.ZipFile(source) as archive:
            for info in archive.infolist():
                name = info.filename.replace('\\', '/')
                if info.is_dir() or not name.lower().endswith(
                        RULE_EXTENSIONS) or '..' in name.split('/'):
                    continue
                if info.file_size > 4 * 1024 * 1024:
                    continue
                out.append((name.lstrip('/'), archive.read(info)))
        return sorted(out)
    if source.lower().endswith(RULE_EXTENSIONS):
        with open(source, 'rb') as handle:
            return [(os.path.basename(source), handle.read())]
    return []


# --- the scan -------------------------------------------------------------------

def grade_for(level):
    return _GRADES.get(level, 'notable')


def _iso(stamp):
    if isinstance(stamp, datetime.datetime):
        if stamp.tzinfo is not None:
            stamp = stamp.astimezone(datetime.timezone.utc)
        return stamp.strftime('%Y-%m-%d %H:%M:%S.%f')
    return str(stamp or '')


def describe_hit(rule, event, fields):
    """(kind, grade, summary, detail) of one rule hit."""
    data = {}
    for name, value in list((event.get('data') or {}).items())[:DETAIL_FIELDS]:
        text = '' if value is None else str(value)
        data[name] = text[:DETAIL_VALUE]
    detail = {
        'rule': rule.title, 'rule_id': rule.id, 'level': rule.level,
        'status': rule.status, 'tags': rule.tags, 'attack': rule.attack,
        'description': rule.description[:2000],
        'falsepositives': rule.falsepositives[:10],
        'references': rule.references[:5], 'author': rule.author,
        'set': rule.set_name, 'file': rule.file,
        'time': _iso(event.get('time')),
        'event_id': event.get('event_id'), 'record_id': event.get('record_id'),
        'channel': event.get('channel'), 'computer': event.get('computer'),
        'provider': event.get('provider'), 'data': data,
    }
    summary = (f"{rule.title} ({rule.level}): event {event.get('event_id')} "
               f"at {_iso(event.get('time'))[:19]} UTC")
    return 'sigma', grade_for(rule.level), summary, detail


def _logs(image_handler, should_stop=None):
    """FileEntry of every event log on the evidence (.evtx), wherever it is
    -- System32\\winevt\\Logs on a disk, anywhere in a collection."""
    from trace_app.core import walk
    for entry in walk.iter_files(image_handler, should_stop):
        if entry.name.lower().endswith('.evtx'):
            yield entry


def scan_evidence(image_handler, case, evidence_id, library, options=None,
                  progress=None, should_stop=None):
    """Run the case's Sigma rules over every event log of one image;
    replaces earlier Sigma findings for it. Returns the number of hits."""
    import json as _json
    from trace_app.core import walk
    from trace_app.core.activity import evtx
    options = options or case_options(case, library)
    entries = [e for e in library.sets()
               if set_enabled_in(options, e) and e.get('available')]
    case.clear_findings(evidence_id, MODULE_SIGMA)
    if not options.get('enabled') or not entries:
        return 0
    floor = LEVELS.index(options.get('min_level') or 'low') \
        if (options.get('min_level') or 'low') in LEVELS else 1
    rules = [r for r in library.rules(entries)
             if LEVELS.index(r.level) >= floor]
    index = RuleIndex(rules)
    case.record_event('sigma scan started',
                      f"evidence id={evidence_id} rules={len(rules)} sets="
                      + ', '.join(e['name'] for e in entries))
    try:
        logs = list(_logs(image_handler, should_stop))
    except walk.WalkCancelled:
        raise ScanCancelled() from None
    hits = events_read = 0
    for number, entry in enumerate(logs, 1):
        if should_stop and should_stop():
            raise ScanCancelled()
        if progress:
            progress(number, len(logs), entry.path)
        if entry.size > MAX_LOG_BYTES:
            logger.warning("%s is too large to scan whole", entry.path)
            continue
        try:
            data = entry.read()
            records = list(evtx.records(data))
        except Exception as exc:
            logger.debug("Event log %s unreadable: %s", entry.path, exc)
            continue
        events_read += len(records)
        per_rule = {}
        batch = []
        for rule, event, fields in match_events(records, index):
            if should_stop and should_stop():
                raise ScanCancelled()
            key = rule.id or rule.title
            per_rule[key] = per_rule.get(key, 0) + 1
            if per_rule[key] > MAX_HITS_PER_RULE:
                continue
            kind, grade, summary, detail = describe_hit(rule, event, fields)
            batch.append((entry.ref, entry.name, entry.path, entry.size,
                          kind, grade, summary,
                          _json.dumps(detail, default=str)))
            hits += 1
            if len(batch) >= 200:
                case.add_module_findings(evidence_id, MODULE_SIGMA, batch)
                batch = []
        case.add_module_findings(evidence_id, MODULE_SIGMA, batch)
        capped = {k: v for k, v in per_rule.items() if v > MAX_HITS_PER_RULE}
        if capped:
            logger.info("%s: %d rule(s) matched more than %d events; the "
                        "first %d of each kept", entry.path, len(capped),
                        MAX_HITS_PER_RULE, MAX_HITS_PER_RULE)
    case.record_event('sigma scan finished',
                      f"evidence id={evidence_id} logs={len(logs)} "
                      f"events={events_read} hits={hits}")
    return hits


def scan_bytes(data, rules):
    """[(rule, event)] for one event log's bytes -- for tests and tools."""
    from trace_app.core.activity import evtx
    index = RuleIndex(rules)
    return [(rule, event) for rule, event, _fields in
            match_events(evtx.records(data), index)]


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        '%Y-%m-%dT%H:%M:%S+00:00')

