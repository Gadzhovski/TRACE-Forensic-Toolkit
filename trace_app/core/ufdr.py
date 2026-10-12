"""Cellebrite UFDR reports, read without Cellebrite (no Qt).

A .ufdr is a ZIP that Physical Analyzer writes: the extracted files (under
files/, by category) and report.xml, which says what each file was on the
phone and holds what Physical Analyzer decoded. report.xml:

* <project> -- the report's name and version, with
  <sourceExtractions><extractionInfo id= name= .../> per extraction;
* <metadata section="Device Info"> (and "Extraction Data", ...): <item
  name="DeviceInfoSelectedManufacturer">value</item> per fact;
* <taggedFiles><file fs= path= size= id= deleted= extractionId=> per
  file: its file system and its path there; <metadata section="File">
  <item name="Local Path">files\\Image\\x.jpg</item> (where it is in the
  ZIP), MD5/SHA256 items; <accessInfo><timestamp name="CreationTime">;
* <decodedData><modelType type="Chat">: <model type= id= deleted_state=>
  per thing decoded -- <field name=><value type=>...</value></field> (or
  <empty/>), <multiField> (several values), <modelField> /
  <multiModelField> (models inside: a chat's Participants and Messages, a
  message's From Party and Attachments), <nodeField><id> (a tagged file).

The element and attribute names follow Physical Analyzer's own report.xml
as the open-source readers that handle it read them (IPED's UfedXmlReader,
DFIRScience's UFDR2DIR), and IPED's test data -- report.xml fragments of
real decoded chats and accounts -- is what tests/test_ufdr.py is built
around. Namespaces vary by version and are ignored.

`open_ufdr(path)` is the logical evidence (core/logical): the phone's files
at their own paths, one folder per file system, each read from its ZIP
member; what report.xml names nowhere stays under "UFDR report/".
`records(path)` turns the decoded models into activity records: chats and
their messages, SMS, calls, contacts, accounts, email, web history and
searches, locations -- what the Activity tab, Conversations and the Map
show for a phone read by TRACE itself.
"""

import datetime
import logging
import posixpath
import zipfile
import xml.etree.ElementTree as ET

logger = logging.getLogger('TRACE.UFDR')

REPORT = 'report.xml'
#: Where members report.xml does not place go.
REPORT_FOLDER = 'UFDR report'


class UfdrError(Exception):
    pass


def _local(tag):
    """A tag without its namespace."""
    return tag.rsplit('}', 1)[-1]


def report_member(archive):
    """The report.xml member of a UFDR ZIP (at its root; any case), or
    None."""
    for info in archive.infolist():
        name = info.filename.replace('\\', '/')
        if '/' not in name.strip('/') and name.lower() == REPORT:
            return info
    return None


def is_ufdr(path):
    """A .ufdr, or any ZIP with Physical Analyzer's report.xml at its
    root."""
    try:
        with zipfile.ZipFile(path) as archive:
            member = report_member(archive)
            if member is None:
                return False
            with archive.open(member) as handle:
                head = handle.read(4096)
            return b'<project' in head or path.lower().endswith('.ufdr')
    except (OSError, zipfile.BadZipFile):
        return False


def parse_time(text):
    """A report's timestamp ('2024-09-28T14:59:35.230+00:00', sometimes
    without a zone) as an aware UTC datetime, or None."""
    text = (text or '').strip()
    if not text:
        return None
    try:
        value = datetime.datetime.fromisoformat(text.replace('Z', '+00:00'))
    except ValueError:
        # Python 3.10 takes 0, 3 or 6 fractional digits only.
        head, _, rest = text.partition('.')
        zone = ''
        for sign in ('+', '-'):
            if sign in rest:
                digits, _, zone = rest.partition(sign)
                zone = sign + zone
                break
        else:
            digits = rest
        digits = (digits + '000000')[:6]
        try:
            value = datetime.datetime.fromisoformat(f"{head}.{digits}{zone}")
        except ValueError:
            return None
    if value.tzinfo is None:
        return value                 # as recorded, no zone (kept naive)
    return value.astimezone(datetime.timezone.utc)


# --- models -------------------------------------------------------------------

class Model:
    """One decoded thing: its type, fields, and the models inside it."""

    __slots__ = ('type', 'id', 'deleted', 'fields', 'models', 'nodes')

    def __init__(self, element):
        self.type = element.get('type') or ''
        self.id = element.get('id') or ''
        self.deleted = (element.get('deleted_state') or '').lower() == \
            'deleted'
        self.fields, self.models, self.nodes = {}, {}, {}
        for child in element:
            tag, name = _local(child.tag), child.get('name') or ''
            if tag == 'field':
                values = [v.text or '' for v in child
                          if _local(v.tag) == 'value']
                self.fields[name] = values[0] if values else None
            elif tag == 'multiField':
                self.fields[name] = [v.text or '' for v in child
                                     if _local(v.tag) == 'value']
            elif tag in ('modelField', 'multiModelField'):
                self.models[name] = [Model(m) for m in child
                                     if _local(m.tag) == 'model']
            elif tag == 'nodeField':
                self.nodes[name] = [i.text or '' for i in child
                                    if _local(i.tag) == 'id']

    def get(self, name, default=None):
        value = self.fields.get(name)
        return default if value in (None, '', []) else value

    def first(self, name):
        found = self.models.get(name) or []
        return found[0] if found else None

    def all(self, name):
        return self.models.get(name) or []


def _party(model):
    """'Name <identifier>' -- or whichever there is -- for a Party."""
    if model is None:
        return ''
    name, identifier = model.get('Name', ''), model.get('Identifier', '')
    if name and identifier and name != identifier:
        return f"{name} <{identifier}>"
    return name or identifier


def _owner(model):
    return model is not None and str(model.get('IsPhoneOwner', '')).lower() \
        == 'true'


# --- reading report.xml -------------------------------------------------------

class Report:
    """What report.xml says, from one streaming pass: `project`, `device`
    ([(section, name, value)]), `extractions` ({id: name}), `files`
    ([dict]), `counts` ({model type: n}). With `models=True` the decoded
    models are kept too, as `models` ([Model])."""

    def __init__(self, handle, models=False):
        self.project, self.device, self.extractions = {}, [], {}
        self.files, self.counts, self.models = [], {}, []
        self._read(handle, models)

    def _read(self, handle, keep_models):
        stack = []
        section = None
        item_name = None
        current_file = None
        for event, element in ET.iterparse(handle, events=('start', 'end')):
            tag = _local(element.tag)
            if event == 'start':
                stack.append(tag)
                if tag == 'project':
                    self.project = dict(element.attrib)
                elif tag == 'extractionInfo':
                    self.extractions[element.get('id') or ''] = \
                        element.get('name') or ''
                elif tag == 'metadata':
                    section = element.get('section') or ''
                elif tag == 'file' and 'taggedFiles' in stack:
                    current_file = {
                        'fs': element.get('fs') or '',
                        'path': element.get('path') or '',
                        'size': int(element.get('size') or 0),
                        'id': element.get('id') or '',
                        'deleted': (element.get('deleted') or '').lower()
                        == 'deleted',
                        'extraction': element.get('extractionId') or '',
                        'items': {}, 'times': {}}
                elif tag == 'item':
                    item_name = element.get('name') or ''
                continue
            stack.pop()
            if tag == 'item':
                value = (element.text or '').strip()
                if current_file is not None and section == 'File':
                    current_file['items'][item_name] = value
                elif current_file is None and value:
                    self.device.append((section or '', item_name, value))
            elif tag == 'timestamp' and current_file is not None:
                current_file['times'][element.get('name') or ''] = \
                    (element.text or '').strip()
            elif tag == 'metadata':
                section = None
            elif tag == 'file' and current_file is not None:
                self.files.append(current_file)
                current_file = None
                element.clear()
            elif tag == 'model' and stack and stack[-1] == 'modelType':
                kind = element.get('type') or ''
                self.counts[kind] = self.counts.get(kind, 0) + 1
                if keep_models:
                    self.models.append(Model(element))
                element.clear()
            elif tag == 'modelType':
                element.clear()

    def device_info(self):
        """{name: value} of the Device Info section, the first value of
        each (an extraction can repeat one)."""
        out = {}
        for section, name, value in self.device:
            if section == 'Device Info':
                out.setdefault(name, value)
        return out


def read_report(path, models=False):
    with zipfile.ZipFile(path) as archive:
        member = report_member(archive)
        if member is None:
            raise UfdrError(f"{posixpath.basename(path)} has no report.xml")
        with archive.open(member) as handle:
            return Report(handle, models)


#: Device Info items worth a line of their own, in the order shown.
DEVICE_FACTS = (
    ('DeviceInfoSelectedManufacturer', 'Manufacturer'),
    ('DeviceInfoSelectedDeviceName', 'Device'),
    ('DeviceInfoDetectedModel', 'Model'),
    ('DeviceInfoDetectedPhoneModel', 'Model'),
    ('DeviceInfoOSVersion', 'OS version'),
    ('DeviceInfoOSType', 'OS'),
    ('IMEI', 'IMEI'), ('DeviceInfoIMEI', 'IMEI'),
    ('ICCID', 'ICCID'), ('IMSI', 'IMSI'),
    ('DeviceInfoSerial', 'Serial number'),
    ('MSISDN', 'Phone number'), ('DeviceInfoMSISDN', 'Phone number'),
    ('DeviceInfoTimeZone', 'Time zone'),
)


# --- the files ----------------------------------------------------------------

def _seconds(text):
    value = parse_time(text)
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=datetime.timezone.utc)
    return int(value.timestamp()), value.microsecond * 1000


def open_ufdr(path):
    """The UFDR as logical evidence (core/logical.LogicalFileSystem)."""
    from trace_app.core.logical import LogicalFileSystem
    from trace_app.core.logical_sources import _Members, _zip_reader
    handle = open(path, 'rb')
    try:
        archive = zipfile.ZipFile(handle)
        member = report_member(archive)
        if member is None:
            raise UfdrError(f"{posixpath.basename(path)} has no report.xml")
        with archive.open(member) as source:
            report = Report(source)
    except Exception:
        handle.close()
        raise
    fs = LogicalFileSystem('UFDR', path)
    members = _Members()
    by_name = {}
    for info in archive.infolist():
        if not info.is_dir():
            by_name[info.filename.replace('\\', '/').lower()] = info
    placed = set()
    for entry in report.files:
        local = (entry['items'].get('Local Path') or '').replace('\\', '/')
        info = by_name.get(local.lower()) if local else None
        folder = (entry['fs'] or 'Device').replace('/', '∕')
        inner = entry['path'].replace('\\', '/').lstrip('/')
        if not inner:
            continue
        times = {}
        for name, slot in (('ModifyTime', 'mtime'), ('AccessTime', 'atime'),
                           ('CreationTime', 'crtime'),
                           ('ChangeTime', 'ctime')):
            stamp = _seconds(entry['times'].get(name))
            if stamp is not None:
                times[slot] = stamp
        facts = {'original path': entry['path']}
        for item, label in (('MD5', 'md5 (UFDR)'), ('SHA256',
                                                    'sha256 (UFDR)'),
                            ('SHA1', 'sha1 (UFDR)')):
            if entry['items'].get(item):
                facts[label] = entry['items'][item]
        if local:
            facts['in the UFDR'] = local
        if info is None:
            facts['attributes'] = 'not in the UFDR (listed by report.xml)'
        else:
            placed.add(info.filename.replace('\\', '/').lower())
        fs.add_file(f"{folder}/{inner}",
                    size=info.file_size if info is not None
                    else entry['size'], times=times,
                    deleted=entry['deleted'], facts=facts,
                    reader=_zip_reader(archive, info, members)
                    if info is not None and not info.flag_bits & 0x1
                    else None)
    for key, info in by_name.items():
        if key in placed:
            continue
        fs.add_file(f"{REPORT_FOLDER}/{info.filename.replace(chr(92), '/')}",
                    size=info.file_size, facts={},
                    reader=_zip_reader(archive, info, members))
    device = report.device_info()
    facts = {'Format': 'Cellebrite UFDR (Physical Analyzer report)'}
    if report.project.get('name'):
        facts['Report'] = report.project['name']
    if report.project.get('reportVersion'):
        facts['Report version'] = report.project['reportVersion']
    for key, label in DEVICE_FACTS:
        if device.get(key) and label not in facts:
            facts[label] = device[key]
    if report.extractions:
        facts['Extractions'] = '; '.join(
            name or ident for ident, name in report.extractions.items())
    facts['Files listed'] = f"{len(report.files):,}"
    if report.counts:
        facts['Decoded'] = ', '.join(
            f"{kind} {count:,}" for kind, count in
            sorted(report.counts.items(), key=lambda kv: -kv[1])[:12])
    facts['Times'] = "UTC, as report.xml gives them"
    facts['_ufdr'] = path
    facts['_close'] = lambda: (archive.close(), handle.close())
    fs.facts.update(facts)
    missing = sum(1 for e in report.files
                  if not e['items'].get('Local Path'))
    if missing:
        fs.problems.append(f"{missing:,} file(s) report.xml lists without "
                           f"their content in the UFDR")
    return fs


# --- what was decoded, as activity records ----------------------------------------

def _source(model, fallback):
    return (model.get('Source') or model.get('SourceApplication')
            or fallback)


def _message_record(message, chat=None, path='', ref=''):
    from trace_app.core.activity import record
    sender = message.first('From')
    receivers = message.all('To')
    mine = _owner(sender)
    app = _source(message, _source(chat, 'Messages') if chat else 'Messages')
    detail = {}
    if chat is not None:
        detail['chat'] = chat.get('Name') or chat.get('Id')
        detail['chat id'] = chat.get('Id')
        if not mine:
            others = [p for p in chat.all('Participants') if not _owner(p)]
            if len(others) == 1 and not receivers:
                receivers = others
    if mine:
        detail['to'] = ', '.join(filter(None, map(_party, receivers))) or \
            detail.get('chat')
    else:
        detail['from'] = _party(sender)
    attachments = [a.get('Filename') or a.get('attachment_extracted_path')
                   for a in message.all('Attachments')]
    if attachments:
        detail['attachments'] = ', '.join(filter(None, attachments))
    for field, key in (('Status', 'status'), ('Type', 'type'),
                       ('Identifier', 'message id')):
        if message.get(field):
            detail[key] = message.get(field)
    if message.deleted:
        detail['state'] = 'deleted (UFDR)'
    group = chat is not None and len(chat.all('Participants')) > 2
    what = ('Group message sent' if group else 'Message sent') if mine \
        else ('Group message received' if group else 'Message received')
    if message.deleted:
        what += ' (deleted)'
    body = message.get('Body') or ('[' + detail['attachments'] + ']'
                                   if attachments else '')
    return record('communication', f"{app} (UFDR)",
                  parse_time(message.get('TimeStamp')), what, body, detail,
                  path=path, ref=ref)


def _entries(model):
    """{domain or category: [values]} of a Contact's / account's
    entries (PhoneNumber, EmailAddress, UserID...)."""
    out = {}
    for entry in model.all('Entries'):
        value = entry.get('Value')
        if not value:
            continue
        kind = {'PhoneNumber': 'phone', 'EmailAddress': 'email'}.get(
            entry.type, (entry.get('Category') or entry.type).lower())
        out.setdefault(kind, []).append(value)
    return out


def _records_of(model, path, ref):
    from trace_app.core.activity import record
    kind = model.type
    deleted = ' (deleted)' if model.deleted else ''
    if kind == 'Chat':
        return [_message_record(m, model, path, ref)
                for m in model.all('Messages')]
    if kind == 'InstantMessage':
        return [_message_record(model, None, path, ref)]
    if kind in ('SMS', 'MMS'):
        parties = model.all('Parties')
        sender = next((p for p in parties
                       if p.get('Role') == 'From'), None)
        folder = (model.get('Folder') or '').lower()
        mine = folder in ('sent', 'outbox') or _owner(sender)
        detail = {}
        if mine:
            detail['to'] = ', '.join(_party(p) for p in parties
                                     if p.get('Role') == 'To')
        else:
            detail['from'] = _party(sender)
        detail['folder'] = model.get('Folder')
        detail['status'] = model.get('Status')
        what = f"{kind} {'sent' if mine else 'received'}{deleted}"
        return [record('communication', f"{_source(model, kind)} (UFDR)",
                       parse_time(model.get('TimeStamp')), what,
                       model.get('Body') or '', detail, path=path,
                       ref=ref)]
    if kind == 'Call':
        parties = model.all('Parties')
        direction = (model.get('Direction') or model.get('Type') or '')
        other = next((p for p in parties if not _owner(p)), None)
        detail = {'duration': model.get('Duration'),
                  'status': model.get('Status'), 'type': model.get('Type'),
                  'video': model.get('VideoCall')}
        outgoing = direction.lower().startswith('out')
        detail['to' if outgoing else 'from'] = _party(other)
        return [record('communication', f"{_source(model, 'Phone')} (UFDR)",
                       parse_time(model.get('TimeStamp')),
                       f"Call {direction.lower() or 'made'}{deleted}",
                       _party(other), detail, path=path, ref=ref)]
    if kind == 'Email':
        sender = model.first('From')
        receivers = model.all('To')
        mine = _owner(sender)
        detail = {'subject': model.get('Subject'),
                  'folder': model.get('Folder')}
        if mine:
            detail['to'] = ', '.join(map(_party, receivers))
        else:
            detail['from'] = _party(sender)
        return [record('communication', f"{_source(model, 'Email')} (UFDR)",
                       parse_time(model.get('TimeStamp')),
                       f"Email {'sent' if mine else 'received'}{deleted}",
                       model.get('Subject') or model.get('Body') or '',
                       detail, path=path, ref=ref)]
    if kind == 'Contact':
        entries = _entries(model)
        detail = {key: ', '.join(values) for key, values in entries.items()}
        detail['basis'] = "no time is recorded for a contact"
        return [record('communication', f"{_source(model, 'Contacts')} "
                       f"(UFDR)", parse_time(model.get('TimeContacted')),
                       f"Contact{deleted}", model.get('Name') or '', detail,
                       path=path, ref=ref)]
    if kind == 'UserAccount':
        entries = _entries(model)
        detail = {key: ', '.join(values) for key, values in entries.items()}
        detail['username'] = model.get('Username')
        detail['basis'] = "no time is recorded for this account"
        return [record('system', f"{_source(model, 'Accounts')} (UFDR)",
                       None, f"Account on the phone: "
                       f"{_source(model, 'account')}{deleted}",
                       model.get('Name') or model.get('Username') or '',
                       detail, path=path, ref=ref)]
    if kind in ('VisitedPage', 'WebBookmark'):
        return [record('browser', f"{_source(model, 'Browser')} (UFDR)",
                       parse_time(model.get('LastVisited')
                                  or model.get('TimeStamp')),
                       ('Page visited' if kind == 'VisitedPage'
                        else 'Bookmark') + deleted,
                       model.get('Url') or model.get('URL') or '',
                       {'title': model.get('Title'),
                        'visits': model.get('VisitCount')},
                       path=path, ref=ref)]
    if kind == 'SearchedItem':
        return [record('searches', f"{_source(model, 'Search')} (UFDR)",
                       parse_time(model.get('TimeStamp')),
                       f"Searched{deleted}", model.get('Value') or '', {},
                       path=path, ref=ref)]
    if kind == 'Location':
        position = model.first('Position')
        detail = {}
        if position is not None:
            try:
                detail['latitude'] = float(position.get('Latitude'))
                detail['longitude'] = float(position.get('Longitude'))
            except (TypeError, ValueError):
                pass
        detail['description'] = model.get('Description')
        detail['category'] = model.get('Category')
        return [record('locations', f"{_source(model, 'Location')} (UFDR)",
                       parse_time(model.get('TimeStamp')),
                       f"Location{deleted}", model.get('Name') or
                       model.get('Address') or '', detail, path=path,
                       ref=ref)]
    return []


def records(path, report_ref='', report_path=''):
    """Activity records of everything the UFDR decoded that TRACE shows:
    each refers to report.xml (`report_ref`, `report_path`)."""
    report = read_report(path, models=True)
    out = []
    for model in report.models:
        try:
            out += _records_of(model, report_path, report_ref)
        except Exception as exc:          # one odd model, not the report
            logger.debug("UFDR %s %s: %s", model.type, model.id, exc)
    return out
