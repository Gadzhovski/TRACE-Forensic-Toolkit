"""GrayKey's extraction report, read as an acquisition log (no Qt).

GrayKey writes `<UDID>_files_full.zip` (or `_files_bfu.zip`, a .tar) and,
beside it, `<UDID>.pdf`: the device as GrayKey saw it (model, iOS version,
serial, IMEI, phone number, owner, accounts) and, per extraction, its time,
size, SHA-256 and MD5. That is the record of what was acquired, so it is
what a verification of the zip compares with -- and the device facts are
the phone's custody details.

Read conservatively:

* the report must say it is GrayKey's and name the evidence's own UDID;
* hashes come only from the extraction whose recorded size is the
  evidence file's size -- never from the Keychain's block, or another
  extraction's, which the same summary lists;
* only the fields in `DEVICE_FIELDS` are taken. **The passcode (and the
  event log, which repeats passcode attempts) is never read into a value**,
  nor anything a newer report adds that TRACE does not know.

The report's text comes from PyMuPDF (already a dependency, wheels on
every platform). PyMuPDF is not thread-safe: call this on the window's
thread or in a child process, never on a worker thread beside the PDF
viewer.
"""

import logging
import os
import re

logger = logging.getLogger('TRACE.GrayKey')

#: The evidence's name starts with the device's UDID: 40 hex digits, or
#: the newer 8-16 form (iPhone XS and later).
_UDID = re.compile(r'^([0-9a-f]{40}|[0-9a-f]{8}-[0-9a-f]{16})(?=[_.\-]|$)',
                   re.IGNORECASE)
MAX_REPORT_BYTES = 32 << 20
#: Subfolders of the evidence's folder looked into (the report and the
#: zip are sometimes filed apart), at most this many.
MAX_FOLDERS = 200

#: Report label -> the fact's label (Evidence Information's, where it
#: shows the same thing for a backup). Nothing else is taken.
DEVICE_FIELDS = (
    ('Device Name', 'Device name'),
    ('Model', 'Model'),
    ('Software Version', 'iOS version'),
    ('Serial Number', 'Serial number'),
    ('IMEI', 'IMEI'),
    ('IMEI 2', 'IMEI 2'),
    ('MEID', 'MEID'),
    ('Phone Number', 'Phone number'),
    ('Owner Name', 'Owner'),
    ('Accounts', 'Accounts'),
    ('Unique Device ID (UDID)', 'UDID'),
    ('Unique Chip ID (ECID)', 'ECID'),
    ('WiFi MAC Address', 'Wi-Fi MAC address'),
    ('Bluetooth MAC Address', 'Bluetooth MAC address'),
    ('Data Partition Size', 'Data partition size'),
    ('Lock State', 'Lock state'),
    ('Backup State', 'Backup state'),
    ('Agent Version', 'GrayKey agent version'),
)
_LABELS = {label.lower(): fact for label, fact in DEVICE_FIELDS}
#: Lines that end the device table.
_SECTIONS = ('event log', 'extraction result summary')
_HASHES = {'sha256': 64, 'sha1': 40, 'md5': 32}
_SIZE = re.compile(r'\((\d[\d,]*) bytes\)')


def udid_of(path):
    """The UDID GrayKey put at the start of `path`'s name, or None."""
    match = _UDID.match(os.path.basename(path))
    return match.group(1).lower() if match else None


def candidates(path):
    """Where `path`'s report may be: `<UDID>.pdf` in its folder, then in
    that folder's subfolders."""
    udid = udid_of(path)
    if not udid:
        return []
    folder = os.path.dirname(os.path.abspath(path))
    found = []
    wanted = udid + '.pdf'

    def look(where):
        try:
            with os.scandir(where) as entries:
                for entry in entries:
                    if entry.name.lower() == wanted and entry.is_file():
                        found.append(entry.path)
        except OSError:
            pass

    look(folder)
    try:
        with os.scandir(folder) as entries:
            subfolders = [e.path for e in entries if e.is_dir()]
    except OSError:
        subfolders = []
    for sub in sorted(subfolders)[:MAX_FOLDERS]:
        look(sub)
    return found


def report_lines(pdf_path):
    """The report's text lines, or [] for anything that is not a PDF."""
    try:
        if os.path.getsize(pdf_path) > MAX_REPORT_BYTES:
            return []
        with open(pdf_path, 'rb') as handle:
            if handle.read(5) != b'%PDF-':
                return []
        import pymupdf
        with pymupdf.open(pdf_path) as document:
            text = '\n'.join(page.get_text() for page in document)
    except Exception as exc:
        logger.debug("%s not read: %s", pdf_path, exc)
        return []
    return [line.strip() for line in text.splitlines()]


def parse(lines):
    """{'device': {fact: value}, 'acquired_with': {...}, 'extractions':
    [{'name', 'time', 'size', 'sha256', 'md5', ...}]} from the report's
    lines, or None when they are not a GrayKey report."""
    if not any(line.startswith('GrayKey') for line in lines[:5]):
        return None
    tool = {}
    for line in lines[:10]:
        key, _, value = line.partition(':')
        key, value = key.strip().lower(), value.strip()
        if key == 'graykey serial #' and value:
            tool['serial'] = value
        elif key == 'graykey software' and value:
            tool['software'] = value
        elif key == 'report generation time' and value:
            tool['report time'] = value
    device = {}
    try:
        start = [l.lower() for l in lines].index('target device information')
    except ValueError:
        start = None
    if start is not None:
        index = start + 1
        while index < len(lines):
            line = lines[index]
            low = line.lower()
            if low in _SECTIONS:
                break
            fact = _LABELS.get(low)
            if fact is None:
                # An unknown label (the passcode's among them) and its
                # value are skipped, unread.
                index += 1
                continue
            values = []
            index += 1
            while index < len(lines):
                value = lines[index]
                low = value.lower()
                if not value:
                    index += 1
                    continue
                if low in _LABELS or low in _SECTIONS or 'passcode' in low:
                    break
                values.append(value)
                index += 1
                if fact != 'Accounts':
                    break
                # Accounts: one per line, while they look like accounts.
                if index < len(lines) and '@' not in lines[index]:
                    break
            if values and not any('passcode' in v.lower() for v in values):
                device[fact] = ', '.join(values)
    return {'device': device, 'acquired_with': tool,
            'extractions': _extractions(lines)}


def _extractions(lines):
    """The 'Extraction Result Summary' blocks: a name, details (its time,
    a description), then size and hashes -- label on one line and value on
    the next, or both on one."""
    try:
        start = [l.lower() for l in lines].index('extraction result summary')
    except ValueError:
        return []
    blocks = []
    block = None
    index = start + 1
    while index < len(lines):
        line = lines[index]
        index += 1
        if not line or re.fullmatch(r'Page \d+/\d+', line):
            continue
        match = re.match(r'(extraction size|sha-?256|sha-?1|md5)\b:?\s*(.*)',
                         line, re.IGNORECASE)
        if match:
            name = match.group(1).lower().replace('-', '')
            rest = match.group(2).strip()
            value = rest or (lines[index] if index < len(lines) else '')
            if not rest:
                index += 1
            if block is None:
                continue
            if name == 'extraction size':
                size = _SIZE.search(value)
                if size:
                    block['size'] = int(size.group(1).replace(',', ''))
            elif re.fullmatch(f'[0-9a-fA-F]{{{_HASHES[name]}}}', value):
                block[name] = value.lower()
            continue
        if block is None or any(n in block for n in _HASHES):
            block = {'name': line}
            blocks.append(block)
        elif 'time' not in block and re.match(r'\d{4}-\d\d-\d\d \d', line):
            block['time'] = line
    return blocks


def read_report(pdf_path):
    """parse() of the report at `pdf_path`, or None."""
    return parse(report_lines(pdf_path))


def for_evidence(path):
    """(report, the extraction that is `path`, pdf path) for GrayKey's
    report beside `path`; (None, None, None) when there is none. The
    extraction is the one whose recorded size is the file's (None when no
    extraction's is): only then are its hashes the evidence's."""
    udid = udid_of(path)
    if not udid or not os.path.isfile(path):
        return None, None, None
    size = os.path.getsize(path)
    for pdf in candidates(path):
        report = read_report(pdf)
        if report is None:
            continue
        named = report['device'].get('UDID', '').lower()
        if named != udid:
            logger.info("%s names device %s, not %s: not used", pdf,
                        named or 'none', udid)
            continue
        extraction = next((e for e in report['extractions']
                           if e.get('size') == size), None)
        if extraction is None:
            logger.info("No extraction in %s is %s bytes: its hashes are "
                        "not the evidence's", pdf, f"{size:,}")
        return report, extraction, pdf
    return None, None, None


def logged_hashes(path):
    """({algorithm: hex}, report path) -- acquisition_log's shape."""
    _report, extraction, pdf = for_evidence(path)
    if not extraction:
        return {}, None
    hashes = {name: extraction[name] for name in ('md5', 'sha1', 'sha256')
              if extraction.get(name)}
    return (hashes, pdf) if hashes else ({}, None)


def acquisition_facts(path):
    """{label: value} for the evidence's custody and Evidence
    Information's Source section: the tool, the extraction and its time,
    the stored hashes, the report. {} without a report."""
    report, extraction, pdf = for_evidence(path)
    if report is None:
        return {}
    tool = report['acquired_with']
    device = report['device']
    facts = {'Acquired with': ' '.join(p for p in (
        'GrayKey', f"serial {tool['serial']}" if tool.get('serial') else '',
        f"({tool['software']})" if tool.get('software') else '') if p),
        'Acquisition report': os.path.basename(pdf)}
    if extraction:
        facts['Description'] = ' '.join(p for p in (
            f"GrayKey {extraction['name']} extraction",
            f"of {device['Model']}" if device.get('Model') else '') if p)
        if extraction.get('time'):
            facts['Acquired'] = extraction['time']
        for name, label in (('md5', 'Stored MD5'), ('sha1', 'Stored SHA-1'),
                            ('sha256', 'Stored SHA-256')):
            if extraction.get(name):
                facts[label] = extraction[name]
    elif tool.get('report time'):
        facts['Report generated'] = tool['report time']
    return facts


def device_facts(path):
    """{label: value} of the phone, from the report beside `path`."""
    report, _extraction, _pdf = for_evidence(path)
    return dict(report['device']) if report else {}
