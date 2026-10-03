"""Outlook mailboxes (PST, OST) browsed like an archive, never written out.

libpff reads the mailbox -- from bytes, or lazily through a file object on
the image, since mailboxes are often many gigabytes. Each folder becomes a
directory and each message a member: a page of HTML built here with every
header escaped and the body inside, viewed by TRACE's offline HTML viewer
(no scripts, nothing fetched). Attachments are members beside it, so a
document, a picture or a ZIP in an email opens in the viewers like any other
file. Items no folder points to any more (orphans: often deleted mail) are
listed under [Orphan items].

archives.py calls into this for the 'pst' kind; no Qt here.
"""

import datetime
import html
import io
import logging
import re

logger = logging.getLogger('TRACE.Mailbox')

#: '!BDN' then, at byte 8, the content type: SM a PST, SO an OST.
SIGNATURE = b'!BDN'
CONTENT_TYPES = {b'SM': 'PST', b'SO': 'OST'}

ORPHANS = '[Orphan items]'

#: MAPI property tags read from a message or recipient record set.
_PR_DISPLAY_TO = 0x0E04
_PR_DISPLAY_CC = 0x0E03
_PR_DISPLAY_BCC = 0x0E02
_PR_SENDER_EMAIL = 0x0C1F
_PR_SENDER_SMTP = 0x5D01
_PR_MESSAGE_CLASS = 0x001A
_PR_RECIPIENT_TYPE = 0x0C15
_PR_DISPLAY_NAME = 0x3001
_PR_EMAIL_ADDRESS = 0x3003
_PR_SMTP_ADDRESS = 0x39FE
_PR_ATTACH_FILENAME = 0x3704
_PR_ATTACH_LONG_FILENAME = 0x3707
_PR_ATTACH_MIME = 0x370E


class MailboxError(Exception):
    """The mailbox could not be read."""


def is_mailbox(header):
    return bool(header) and header[:4] == SIGNATURE and \
        header[8:10] in CONTENT_TYPES


def _open(data):
    import pypff
    handle = pypff.file()
    source = io.BytesIO(data) if isinstance(data, (bytes, bytearray)) \
        else data
    try:
        handle.open_file_object(source)
    except (IOError, OSError) as exc:
        raise MailboxError(f"Not a readable Outlook mailbox: {exc}") from exc
    return handle


def _clean(text, limit=90):
    text = re.sub(r'[\x00-\x1f/\\:*?"<>|]+', ' ', text or '').strip()
    return (text[:limit].rstrip() + '…') if len(text) > limit else text


def _text_of(value):
    if value is None:
        return ''
    if isinstance(value, bytes):
        for codec in ('utf-8', 'cp1252'):
            try:
                return value.decode(codec)
            except UnicodeDecodeError:
                continue
        return value.decode('latin-1')
    return str(value)


def _properties(item):
    """{tag: value} from an item's first record set (the MAPI properties)."""
    out = {}
    try:
        if not item.number_of_record_sets:
            return out
        record_set = item.get_record_set(0)
        for index in range(record_set.number_of_entries):
            entry = record_set.get_entry(index)
            tag = entry.entry_type
            try:
                value = entry.get_data_as_string()
            except Exception:
                try:
                    value = entry.get_data_as_integer()
                except Exception:
                    value = None
            out[tag] = value
    except Exception as exc:
        logger.debug("Could not read properties: %s", exc)
    return out


def _time(value):
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    return str(value)


class Mailbox:
    """A mailbox's members, and the bytes of any one of them."""

    def __init__(self, data):
        import pypff
        self._pypff = pypff
        self.handle = _open(data)
        self.kind = 'OST' if self.handle.get_content_type() == 111 else 'PST'
        self.members = []
        self._where = {}             # member name -> how to reach it
        self._build()

    # --- the listing -------------------------------------------------------

    def _add(self, name, kind, ref, size=0, modified=None, is_dir=False):
        base, suffix = (name.rsplit('.', 1) + [''])[:2] if not is_dir \
            else (name, '')
        candidate = name
        count = 2
        while candidate in self._where:      # two messages, one subject
            candidate = f"{base} ({count}).{suffix}" if suffix else \
                f"{name} ({count})"
            count += 1
        self._where[candidate] = (kind, ref)
        self.members.append({
            'name': candidate, 'size': size, 'compressed_size': size,
            'is_dir': is_dir, 'modified': modified, 'encrypted': False,
            'crc': None})
        return candidate

    def _build(self):
        root = self.handle.get_root_folder()
        self._walk(root, [], '')
        orphans = 0
        try:
            orphans = self.handle.get_number_of_orphan_items()
        except (IOError, OSError):
            pass
        if orphans:
            self._add(ORPHANS, 'folder', None, is_dir=True)
            for index in range(orphans):
                try:
                    item = self.handle.get_orphan_item(index)
                except (IOError, OSError):
                    continue
                if isinstance(item, self._pypff.message):
                    self._message_members(item, ORPHANS, index,
                                          ('orphan', index))

    def _walk(self, folder, route, path):
        try:
            count = folder.number_of_sub_folders
        except (IOError, OSError):
            return
        for index in range(count):
            try:
                sub = folder.get_sub_folder(index)
            except (IOError, OSError):
                continue
            name = _clean(sub.name, 60) or f'Folder {index + 1}'
            sub_path = f'{path}/{name}' if path else name
            sub_route = route + [index]
            self._add(sub_path, 'folder', None, is_dir=True)
            try:
                messages = sub.number_of_sub_messages
            except (IOError, OSError):
                messages = 0
            for position in range(messages):
                try:
                    item = sub.get_sub_message(position)
                except (IOError, OSError):
                    continue
                if isinstance(item, self._pypff.message):
                    self._message_members(item, sub_path, position,
                                          ('folder', tuple(sub_route),
                                           position))
            self._walk(sub, sub_route, sub_path)

    def _message_members(self, message, folder_path, position, ref):
        subject = _clean(_safe(message, 'subject')) or '(no subject)'
        when = _time(_safe(message, 'delivery_time')) or \
            _time(_safe(message, 'client_submit_time')) or \
            _time(_safe(message, 'creation_time'))
        stem = f"{folder_path}/{position + 1:04d} {subject}"
        body = len(_safe(message, 'html_body') or b'') or \
            len(_safe(message, 'plain_text_body') or b'') or \
            len(_safe(message, 'rtf_body') or b'')
        stem_name = self._add(f'{stem}.html', 'message', ref, body, when)
        attachments = _safe(message, 'number_of_attachments') or 0
        if attachments:
            folder = stem_name[:-5] + ' - attachments'
            self._add(folder, 'folder', None, is_dir=True)
            for index in range(attachments):
                try:
                    attachment = message.get_attachment(index)
                except (IOError, OSError):
                    continue
                name, size = _attachment_name(attachment, index)
                self._add(f'{folder}/{name}', 'attachment', (ref, index),
                          size, when)

    # --- reading -------------------------------------------------------------

    def _message(self, ref):
        if ref[0] == 'orphan':
            return self.handle.get_orphan_item(ref[1])
        folder = self.handle.get_root_folder()
        for index in ref[1]:
            folder = folder.get_sub_folder(index)
        return folder.get_sub_message(ref[2])

    def read(self, name, limit):
        where = self._where.get(name)
        if where is None:
            raise MailboxError(f"No member {name}")
        kind, ref = where
        if kind == 'folder':
            raise MailboxError(f"{name} is a folder")
        if kind == 'message':
            return render_message(self._message(ref), self.kind)
        message_ref, index = ref
        attachment = self._message(message_ref).get_attachment(index)
        size = attachment.get_size() or 0
        if size > limit:
            raise MailboxError(f"{name} is {size:,} bytes, over the "
                               f"{limit:,}-byte limit for reading in memory")
        try:
            return attachment.read_buffer(size) if size else b''
        except (IOError, OSError) as exc:
            raise MailboxError(f"{name} could not be read: {exc}") from exc

    def close(self):
        try:
            self.handle.close()
        except (IOError, OSError):
            pass


def _safe(item, attribute):
    try:
        return getattr(item, attribute)
    except (IOError, OSError, AttributeError):
        return None


def _attachment_name(attachment, index):
    props = _properties(attachment)
    name = _clean(_text_of(_safe(attachment, 'long_filename'))
                  or _text_of(props.get(_PR_ATTACH_LONG_FILENAME))
                  or _text_of(props.get(_PR_ATTACH_FILENAME)), 120)
    try:
        size = attachment.get_size() or 0
    except (IOError, OSError):
        size = 0
    return name or f'attachment {index + 1}', size


# --- one message as a page --------------------------------------------------------

def _recipients(message):
    """{'To': [...], 'Cc': [...], 'Bcc': [...]} from the recipient table."""
    out = {}
    try:
        table = message.recipients
        if table is None:
            return out
        for index in range(table.number_of_record_sets):
            record_set = table.get_record_set(index)
            values = {}
            for entry_index in range(record_set.number_of_entries):
                entry = record_set.get_entry(entry_index)
                try:
                    values[entry.entry_type] = entry.get_data_as_string()
                except Exception:
                    try:
                        values[entry.entry_type] = entry.get_data_as_integer()
                    except Exception:
                        pass
            name = values.get(_PR_DISPLAY_NAME) or ''
            address = values.get(_PR_SMTP_ADDRESS) or \
                values.get(_PR_EMAIL_ADDRESS) or ''
            label = f'{name} <{address}>' if name and address and \
                name != address else (name or address)
            kind = {1: 'To', 2: 'Cc', 3: 'Bcc'}.get(
                values.get(_PR_RECIPIENT_TYPE), 'To')
            if label:
                out.setdefault(kind, []).append(label)
    except Exception as exc:
        logger.debug("Could not read recipients: %s", exc)
    return out


def rtf_text(rtf):
    """Readable text from an RTF body: controls dropped, escapes decoded."""
    text = _text_of(rtf)
    text = re.sub(r'\\par[d]?\b ?', '\n', text)
    text = re.sub(r"\\'([0-9a-fA-F]{2})",
                  lambda m: bytes([int(m.group(1), 16)]).decode('cp1252',
                                                                  'replace'),
                  text)
    text = re.sub(r'\\u(-?\d+)\??',
                  lambda m: chr(int(m.group(1)) % 65536), text)
    text = re.sub(r'\{\\\*[^{}]*\}', '', text)
    text = re.sub(r'\\[a-zA-Z]+-?\d* ?', '', text)
    text = re.sub(r'[{}]', '', text)
    return re.sub(r'\n{3,}', '\n\n', text).strip()


_BODY = re.compile(r'<body[^>]*>(.*)</body>', re.IGNORECASE | re.DOTALL)


def render_message(message, kind='PST'):
    """The message as one HTML page: headers (escaped), recipients,
    attachments, the body, then the transport headers as received."""
    props = _properties(message)
    e = html.escape
    subject = _text_of(_safe(message, 'subject'))
    sender = _text_of(_safe(message, 'sender_name'))
    address = _text_of(props.get(_PR_SENDER_SMTP) or
                       props.get(_PR_SENDER_EMAIL))
    if address and address != sender:
        sender = f'{sender} <{address}>' if sender else address
    recipients = _recipients(message)
    for kind_name, tag in (('To', _PR_DISPLAY_TO), ('Cc', _PR_DISPLAY_CC),
                           ('Bcc', _PR_DISPLAY_BCC)):
        if not recipients.get(kind_name) and props.get(tag):
            recipients[kind_name] = [_text_of(props[tag])]
    rows = [('From', sender), ('Subject', subject)]
    rows += [(k, '; '.join(v)) for k, v in recipients.items()]
    rows += [('Sent', _time(_safe(message, 'client_submit_time'))),
             ('Delivered', _time(_safe(message, 'delivery_time'))),
             ('Created', _time(_safe(message, 'creation_time'))),
             ('Modified', _time(_safe(message, 'modification_time'))),
             ('Class', _text_of(props.get(_PR_MESSAGE_CLASS)))]
    attachments = _safe(message, 'number_of_attachments') or 0
    if attachments:
        names = []
        for index in range(attachments):
            try:
                names.append(_attachment_name(message.get_attachment(index),
                                              index))
            except (IOError, OSError):
                continue
        rows.append(('Attachments', '; '.join(
            f'{name} ({size:,} bytes)' for name, size in names)))
    html_body = _safe(message, 'html_body')
    plain = _safe(message, 'plain_text_body')
    rtf = _safe(message, 'rtf_body')
    if html_body:
        body_text = _text_of(html_body)
        inner = _BODY.search(body_text)
        body = inner.group(1) if inner else body_text
        note = ''
    elif plain:
        body = f'<pre style="white-space: pre-wrap">{e(_text_of(plain))}</pre>'
        note = ''
    elif rtf:
        body = f'<pre style="white-space: pre-wrap">{e(rtf_text(rtf))}</pre>'
        note = '<p><i>The body is stored as RTF; shown here as text.</i></p>'
    else:
        body, note = '<p><i>No body.</i></p>', ''
    headers = _text_of(_safe(message, 'transport_headers'))
    return message_page(f'Message from an Outlook {kind} mailbox', subject,
                        rows, body, note, headers)


def message_page(origin, subject, rows, body, note='', headers='',
                 label='Transport headers'):
    """One message as a page of HTML -- the page every mail format shares.

    `rows` are (name, value) header pairs, escaped here; `body` is HTML
    already (a message's own HTML body, or escaped text), shown by the
    offline viewer, which runs no script and fetches nothing. `headers` is
    the raw header block, shown as received."""
    e = html.escape
    table = ''.join(f'<tr><th align="left" valign="top">{e(k)}:&nbsp;</th>'
                    f'<td>{e(v)}</td></tr>' for k, v in rows if v)
    transport = (f'<hr><p><b>{e(label)}</b></p>'
                 f'<pre style="white-space: pre-wrap">{e(headers)}</pre>'
                 if headers else '')
    page = (f'<html><head><meta charset="utf-8"><title>{e(subject)}</title>'
            f'</head><body><p><small>{e(origin)}</small></p>'
            f'<table cellspacing="0" cellpadding="2">'
            f'{table}</table><hr>{note}{body}{transport}</body></html>')
    return page.encode('utf-8')


# --- the archive interface -----------------------------------------------------

_CACHE = []                 # [(data, Mailbox)] most recent last
_CACHE_SIZE = 4


def mailbox_for(data):
    """The opened mailbox for `data`, parsed once while it stays in use."""
    for index, (held, mailbox) in enumerate(_CACHE):
        if held is data:
            _CACHE.append(_CACHE.pop(index))
            return mailbox
    mailbox = Mailbox(data)
    _CACHE.append((data, mailbox))
    while len(_CACHE) > _CACHE_SIZE:
        _held, old = _CACHE.pop(0)
        old.close()
    return mailbox


def list_members(data):
    return list(mailbox_for(data).members)


def read_member(data, name, limit):
    return mailbox_for(data).read(name, limit)
