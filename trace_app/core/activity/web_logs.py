"""What a web server was asked: Apache, nginx, lighttpd and IIS access logs
(no Qt).

A busy server logs millions of requests, and an examiner reads them for
three things, so those are what become records:

* **requests that look like an attack** (`suspicious`: a command or code
  injected into the query, path traversal, SQL, script tags, a template
  or JNDI lookup, a scanner's User-Agent) -- each one a record;
* **requests that change something** (POST, PUT, DELETE, PATCH) -- each
  one a record, as uploads to a web shell arrive that way;
* **who asked**: one record per client address per day, with the number
  of requests, the status codes, the bytes sent, the first and last time
  and the User-Agents seen -- the addresses then reach the index and the
  Indicators like any other text.

Formats: NCSA common and combined (`%h %l %u %t "%r" %>s %b "%{Referer}i"
"%{User-agent}i"`), Apache's vhost_combined (`%v:%p` first) and IIS's W3C
extended log (by its '#Fields:' line; times UTC). A request line may
hold quotes of its own (an attack often does), so it ends where the
status code follows. Times in NCSA logs carry their offset and are kept
as UTC; logrotate's copies (access.log.1, .gz, .xz, .bz2) are read too.

Expected values in the tests are plaso's for its apache_access.log.
"""

import datetime
import logging
import re
import urllib.parse

from trace_app.core.activity import record

logger = logging.getLogger('TRACE.Activity.WebLogs')

#: Where Linux servers keep their logs, and what their names start with.
LOG_FOLDERS = (('var', 'log', 'apache2'), ('var', 'log', 'httpd'),
               ('var', 'log', 'apache'), ('var', 'log', 'nginx'),
               ('var', 'log', 'lighttpd'), ('usr', 'local', 'apache2',
                                            'logs'),
               ('opt', 'lampp', 'logs'), ('xampp', 'apache', 'logs'))
#: IIS: one folder per site under LogFiles (W3SVC1, ...).
IIS_ROOT = ('inetpub', 'logs', 'LogFiles')
#: Records kept per log file for each kind, past which the rest is
#: counted on the summary instead.
MAX_NOTABLE = 20000

_NCSA = re.compile(
    r'^(?:(?P<vhost>[^\s:]+)(?::(?P<port>\d+))? )?'
    r'(?P<client>\S+) (?P<ident>\S+) (?P<user>\S+(?: \S+)*?) '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<request>.*?)" (?P<status>\d{3}|-) (?P<size>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?\s*$')
_TIME = '%d/%b/%Y:%H:%M:%S %z'
_REQUEST = re.compile(r'^(\S+) (.*?)(?: (HTTP/[\d.]+))?$')

#: What an attack leaves in a request (matched on the decoded, lower-case
#: target), and what a scanner calls itself.
_ATTACKS = (
    ('command injection', re.compile(
        r'[?&](?:cmd|exec|command|execute|run|shell)=|'
        r'\b(?:uname|whoami|/bin/(?:ba)?sh|wget|curl|nc|chmod|powershell|'
        r'cmd\.exe)\b[ +;|&]|[;|`]\s*(?:id|ls|cat|uname|whoami)\b')),
    ('path traversal', re.compile(r'\.\./|\.\.\\|/etc/passwd|'
                                  r'/etc/shadow|win\.ini|boot\.ini')),
    ('SQL injection', re.compile(r"\bunion\b.*\bselect\b|'\s*or\s+'?\d|"
                                 r"\bsleep\(\d|\bbenchmark\(|"
                                 r"information_schema|\bwaitfor delay\b|"
                                 r"\bdrop table\b")),
    ('script injection', re.compile(r'<script|javascript:|onerror=|'
                                    r'onload=|<svg|<iframe')),
    ('code injection', re.compile(r'\$\{|%\{|\{\{|jndi:|eval\(|assert\(|'
                                  r'base64_decode|php://|data://|expect://|'
                                  r'system\(|passthru\(|shell_exec')),
)
_SCANNERS = re.compile(
    r'sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|dirb/|wpscan|'
    r'acunetix|nessus|openvas|nuclei|wfuzz|ffuf|hydra|havij|w3af|'
    r'netsparker|qualys|burp|zmeu|morfeus|jorgee', re.IGNORECASE)
_CHANGES = ('POST', 'PUT', 'DELETE', 'PATCH')


def parse(text):
    """([request dicts], [numbers of lines not understood]) of an NCSA
    (common / combined / vhost_combined) access log."""
    out, bad = [], []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = _NCSA.match(line)
        if not match:
            bad.append(number)
            continue
        facts = match.groupdict()
        try:
            when = datetime.datetime.strptime(facts['time'], _TIME)
        except ValueError:
            bad.append(number)
            continue
        method, target, protocol = _split_request(facts['request'])
        out.append({
            'line': number, 'time': when,
            'client': facts['client'],
            'user': None if facts['user'] == '-' else facts['user'],
            'method': method, 'target': target, 'protocol': protocol,
            'status': None if facts['status'] == '-' else
            int(facts['status']),
            'size': None if facts['size'] == '-' else int(facts['size']),
            'referer': None if facts['referer'] in (None, '-')
            else facts['referer'],
            'agent': None if facts['agent'] in (None, '-')
            else facts['agent'],
            'vhost': facts['vhost'],
            'port': int(facts['port']) if facts['port'] else None})
    return out, bad


def _split_request(request):
    match = _REQUEST.match(request or '')
    if not match:
        return None, request or '', None
    return match.group(1), match.group(2), match.group(3)


def parse_w3c(text):
    """[request dicts] of an IIS W3C extended log (times UTC)."""
    from trace_app.core.activity.windows_logs import parse_firewall
    out = []
    for number, row in enumerate(parse_firewall(text), 1):
        try:
            when = datetime.datetime.strptime(
                f"{row.get('date')} {row.get('time')}",
                '%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc)
        except (TypeError, ValueError):
            continue
        stem = row.get('cs-uri-stem') or ''
        query = row.get('cs-uri-query')
        status, size = row.get('sc-status'), row.get('sc-bytes')
        agent = row.get('cs(User-Agent)')
        out.append({
            'line': number, 'time': when, 'client': row.get('c-ip') or '',
            'user': row.get('cs-username'),
            'method': row.get('cs-method'),
            'target': stem + (f'?{query}' if query else ''),
            'protocol': row.get('cs-version'),
            'status': int(status) if status and status.isdigit() else None,
            'size': int(size) if size and size.isdigit() else None,
            'referer': row.get('cs(Referer)'),
            'agent': agent.replace('+', ' ') if agent else None,
            'vhost': row.get('cs-host') or row.get('s-sitename'),
            'port': int(row['s-port']) if (row.get('s-port') or '').isdigit()
            else None})
    return out


def suspicious(request):
    """Why a request looks like an attack, or None."""
    target = request.get('target') or ''
    try:
        decoded = urllib.parse.unquote_plus(urllib.parse.unquote(target))
    except Exception:
        decoded = target
    decoded = decoded.lower()
    reasons = [name for name, pattern in _ATTACKS if pattern.search(decoded)]
    if _SCANNERS.search(request.get('agent') or ''):
        reasons.append('scanner')
    return ', '.join(reasons) or None


def records(requests, source, path, ref):
    """The records an examiner reads a log for (see the module's text)."""
    common = dict(path=path, ref=ref)
    out = []
    kept = 0
    days = {}
    for request in requests:
        why = suspicious(request)
        changes = (request.get('method') or '').upper() in _CHANGES
        day = (request['vhost'], request['client'],
               request['time'].astimezone(datetime.timezone.utc).date())
        summary = days.setdefault(day, {
            'count': 0, 'first': request['time'], 'last': request['time'],
            'statuses': {}, 'bytes': 0, 'agents': [], 'users': set(),
            'paths': set(), 'flagged': 0, 'not_listed': 0})
        summary['count'] += 1
        summary['first'] = min(summary['first'], request['time'])
        summary['last'] = max(summary['last'], request['time'])
        status = request['status']
        summary['statuses'][status] = summary['statuses'].get(status, 0) + 1
        summary['bytes'] += request['size'] or 0
        if request['agent'] and request['agent'] not in summary['agents']:
            summary['agents'].append(request['agent'])
        if request['user']:
            summary['users'].add(request['user'])
        summary['paths'].add((request['target'] or '').split('?', 1)[0])
        if why:
            summary['flagged'] += 1
        if not (why or changes):
            continue
        if kept >= MAX_NOTABLE:
            summary['not_listed'] += 1
            continue
        kept += 1
        what = (f"Suspicious web request ({why})" if why
                else f"Web request ({request['method']})")
        out.append(record(
            'network', source, request['time'], what,
            f"{request['method'] or ''} {request['target']}".strip(),
            {'client': request['client'], 'status': request['status'],
             'bytes sent': request['size'], 'user': request['user'],
             'referer': request['referer'], 'User-Agent': request['agent'],
             'site': _site(request), 'line': request['line'],
             'grade': 'suspicious' if why else None},
            user=request['user'] or '', **common))
    for (vhost, client, _day), summary in sorted(
            days.items(), key=lambda item: item[1]['first']):
        statuses = ', '.join(
            f"{status if status is not None else '-'} x{count}"
            for status, count in sorted(summary['statuses'].items(),
                                        key=lambda item: -item[1]))
        out.append(record(
            'network', source, summary['first'], 'Web requests from client',
            client,
            {'requests': summary['count'], 'last': summary['last'],
             'status codes': statuses, 'bytes sent': summary['bytes'],
             'pages': len(summary['paths']),
             'suspicious requests': summary['flagged'] or None,
             'not listed (limit)': summary['not_listed'] or None,
             'User-Agents': ' | '.join(summary['agents'][:5]),
             'users': ', '.join(sorted(summary['users'])),
             'site': vhost,
             'basis': 'the first request from this address that day (UTC)'},
            **common))
    return out


def _site(request):
    if not request.get('vhost'):
        return None
    port = request.get('port')
    return f"{request['vhost']}:{port}" if port else request['vhost']


def _is_access_log(name):
    name = name.lower()
    return 'access' in name and not name.endswith(('.pid', '.lock'))


def collect(volume, step):
    """Every access log in the places servers keep them."""
    from trace_app.core.activity.linux import log_bytes
    out = []
    for parts in LOG_FOLDERS:
        folder = volume.find(*parts)
        if folder is None or not folder.is_dir:
            continue
        server = parts[-1] if parts[-1] != 'logs' else parts[-2]
        for entry in _log_files(volume, folder):
            if not _is_access_log(entry.name):
                continue
            step(entry.path)
            text = log_bytes(volume, entry).decode('utf-8', 'replace')
            requests, bad = parse(text)
            if bad:
                logger.debug("%s: %d line(s) not understood", entry.path,
                             len(bad))
            out += records(requests, f'web server log ({server})',
                           entry.path, volume.ref(entry))
    iis = volume.find(*IIS_ROOT)
    for site in volume.children(iis, dirs=True) if iis is not None else ():
        for entry in volume.children(site):
            if not entry.name.lower().endswith('.log'):
                continue
            step(entry.path)
            text = volume.read(entry).decode('utf-8', 'replace')
            out += records(parse_w3c(text), f'web server log (IIS '
                           f'{site.name})', entry.path, volume.ref(entry))
    return out


def _log_files(volume, folder, depth=0):
    """A log folder's files, and one level of per-site folders."""
    for entry in volume.children(folder):
        yield entry
    if depth == 0:
        for child in volume.children(folder, dirs=True):
            yield from _log_files(volume, child, 1)
