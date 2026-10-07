"""Saved messages (.eml) and mbox mailboxes, browsed like an archive.

A message becomes a page of HTML -- the same page an Outlook message gets
(mailbox.message_page): headers escaped, the body inside, the header block
as received at the bottom -- shown by the offline HTML viewer, which runs no
script and fetches nothing. Pictures a message carries inline (cid:) are put
in the page as data: URIs, so it looks as it did to its reader without
anything being fetched. Attachments are members beside the page; a
forwarded message is an .eml member, browsed the same way.

An mbox is many messages, each starting at a "From " line after a blank
line. It is scanned for those lines through a file object, so a mailbox of
many gigabytes on the image is never held in memory; a message is read when
it is listed or opened.

Python's email package does the parsing (policy.default: encoded words,
charsets, transfer encodings). archives.py calls into this for the 'eml' and
'mbox' kinds; no Qt here.
"""

import base64
import datetime
import email
import email.policy
import email.utils
import html
import io
import logging
import mimetypes
import re

from trace_app.core.mailbox import _clean, message_page

logger = logging.getLogger('TRACE.MailFiles')

#: Headers that make a block of "Name: value" lines a message's header. A
#: block with two of them, every line header-shaped, is mail.
_MAIL_HEADERS = {
    'from', 'to', 'cc', 'subject', 'date', 'message-id', 'received',
    'return-path', 'mime-version', 'delivered-to', 'reply-to', 'sender',
    'x-mailer', 'user-agent', 'content-type', 'in-reply-to', 'references',
    'x-original-to', 'dkim-signature', 'authentication-results',
    'thread-index', 'thread-topic', 'x-mozilla-status', 'x-originating-ip',
    'list-id', 'envelope-to', 'x-gmail-labels', 'x-gm-thrid',
}
#: ...and at least one of these, which only mail has.
_DECISIVE = {'from', 'received', 'return-path', 'message-id', 'delivered-to',
             'x-mozilla-status'}

_HEADER = re.compile(rb'^([!-9;-~]{1,76}):')

#: The separator line of an mbox: "From sender asctime" (Thunderbird writes
#: "From - Sat Jan  3 01:05:34 1996"). Checked whole, so a body line that
#: begins "From " without a date does not split a message.
_FROM_LINE = re.compile(
    rb'From \S* +(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) +(?:Jan|Feb|Mar|Apr|May|'
    rb'Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} +\d{1,2}:\d\d(?::\d\d)? +'
    rb'(?:[A-Z]{2,5} +)?\d{4}')

#: A message larger than this is listed but not parsed.
MAX_MESSAGE_BYTES = 64 * 1024 * 1024
#: An inline picture larger than this keeps its cid: reference.
MAX_INLINE_IMAGE = 4 * 1024 * 1024

_SCAN_BLOCK = 4 * 1024 * 1024


class MailFileError(Exception):
    """The message or mailbox could not be read."""


# --- recognising ----------------------------------------------------------------

def _header_names(block):
    """The header names of a header block, or None if any complete line is
    not a header line (or a folded continuation)."""
    lines = block.replace(b'\r\n', b'\n').split(b'\n')
    if len(lines) > 1:
        lines = lines[:-1]                 # the last one may be cut short
    names = []
    for line in lines:
        if not line:
            break                          # the blank line ends the headers
        if line[:1] in (b' ', b'\t'):
            if not names:
                return None
            continue
        match = _HEADER.match(line)
        if not match:
            return None
        names.append(match.group(1).decode('ascii').lower())
    return names


def mail_kind(header):
    """'mbox', 'eml' or None, from the first bytes of a file."""
    if not header:
        return None
    header = bytes(header[:4096])
    if header.startswith(b'From '):
        line, _, rest = header.partition(b'\n')
        if not _FROM_LINE.match(line.rstrip(b'\r')):
            return None
        names = _header_names(rest)
        return 'mbox' if names and set(names) & _MAIL_HEADERS else None
    names = _header_names(header)
    if not names or len(names) < 2:
        return None
    known = set(names) & _MAIL_HEADERS
    return 'eml' if len(known) >= 2 and known & _DECISIVE else None


# --- one message ----------------------------------------------------------------

def parse(raw):
    """A message from its bytes (an mbox's From_ line already removed)."""
    return email.message_from_bytes(raw, policy=email.policy.default)


def _header(message, name):
    try:
        value = message.get(name)
    except Exception:                  # a header the parser cannot model
        value = None
        for key, raw in message.raw_items():
            if key.lower() == name.lower():
                value = raw
                break
    return ' '.join(str(value).split()) if value is not None else ''


def message_date(message):
    """(the Date header as written, the same in UTC or '')."""
    written = _header(message, 'Date')
    if not written:
        return '', ''
    try:
        when = email.utils.parsedate_to_datetime(written)
    except (TypeError, ValueError, IndexError):
        return written, ''
    if when is None:
        return written, ''
    if when.tzinfo is None:
        return written, ''             # "-0000": the zone is not known
    return written, when.astimezone(datetime.timezone.utc).strftime(
        '%Y-%m-%d %H:%M:%S')


def _leaves(part, parents=()):
    """Every leaf part with its chain of multipart parents. A forwarded
    message (message/rfc822) is a leaf: it is an attachment, not more
    body."""
    if part.get_content_type() == 'message/rfc822' or \
            not part.is_multipart():
        yield part, parents
        return
    payload = part.get_payload()
    for sub in payload if isinstance(payload, list) else ():
        yield from _leaves(sub, parents + (part,))


def _text(part):
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except (LookupError, UnicodeError, ValueError, AssertionError):
        pass
    data = part.get_payload(decode=True) or b''
    for codec in ('utf-8', 'cp1252'):
        try:
            return data.decode(codec)
        except UnicodeDecodeError:
            continue
    return data.decode('latin-1')


def _bytes(part):
    if part.get_content_type() == 'message/rfc822':
        payload = part.get_payload()
        inner = payload[0] if isinstance(payload, list) and payload else None
        return inner.as_bytes() if inner is not None else b''
    return part.get_payload(decode=True) or b''


def _attachment_name(part, number):
    try:
        name = part.get_filename()
    except Exception:
        name = None
    if part.get_content_type() == 'message/rfc822' and not name:
        payload = part.get_payload()
        inner = payload[0] if isinstance(payload, list) and payload else None
        subject = _header(inner, 'Subject') if inner is not None else ''
        name = f'{subject or "forwarded message"}.eml'
    if not name:
        extension = mimetypes.guess_extension(part.get_content_type()) or \
            '.bin'
        name = f'part {number}{extension}'
    return _clean(name, 120) or f'part {number}'


def _is_inline_text(part):
    return part.get_content_maintype() == 'text' and \
        part.get_content_subtype() in ('plain', 'html') and \
        part.get_content_disposition() != 'attachment' and \
        not part.get_filename()


def structure(message):
    """(body part or None, extra inline text parts, attachments)."""
    try:
        body = message.get_body(preferencelist=('html', 'plain'))
    except Exception:
        body = None
    alternatives = set()
    if body is not None:
        for leaf, parents in _leaves(message):
            if leaf is body and parents and \
                    parents[-1].get_content_subtype() == 'alternative':
                alternatives = {id(p) for p, _ in _leaves(parents[-1])}
    extra, attachments = [], []
    for leaf, _parents in _leaves(message):
        if leaf is body or id(leaf) in alternatives:
            continue
        if _is_inline_text(leaf):
            extra.append(leaf)
        else:
            attachments.append(leaf)
    return body, extra, attachments


def _inline_images(attachments):
    """{content id: data URI} for the pictures a body shows inline."""
    out = {}
    for part in attachments:
        cid = (part.get('Content-ID') or '').strip().strip('<>')
        if not cid or part.get_content_maintype() != 'image':
            continue
        data = part.get_payload(decode=True) or b''
        if not data or len(data) > MAX_INLINE_IMAGE:
            continue
        out[cid] = (f'data:{part.get_content_type()};base64,'
                    f'{base64.b64encode(data).decode("ascii")}')
    return out


_BODY = re.compile(r'<body[^>]*>(.*)</body>', re.IGNORECASE | re.DOTALL)
_CID = re.compile(r'cid:([^"\'\s>)]+)', re.IGNORECASE)


def render(message, raw, origin):
    """The message as one page of HTML (bytes)."""
    e = html.escape
    body, extra, attachments = structure(message)
    written, utc = message_date(message)
    rows = [(name, _header(message, name))
            for name in ('From', 'Sender', 'Reply-To', 'Subject', 'To', 'Cc',
                         'Bcc')]
    rows.append(('Date', f'{written} ({utc} UTC)' if utc else written))
    rows += [(name, _header(message, name))
             for name in ('Message-ID', 'In-Reply-To', 'X-Mailer',
                          'User-Agent')]
    if attachments:
        rows.append(('Attachments', '; '.join(
            f'{_attachment_name(p, n + 1)} ({len(_bytes(p)):,} bytes)'
            for n, p in enumerate(attachments))))
    note = ''
    if body is None:
        page_body = '<p><i>No body.</i></p>'
    elif body.get_content_subtype() == 'html':
        text = _text(body)
        inner = _BODY.search(text)
        page_body = inner.group(1) if inner else text
        images = _inline_images(attachments)
        if images:
            page_body = _CID.sub(
                lambda m: images.get(m.group(1), m.group(0)), page_body)
    else:
        page_body = (f'<pre style="white-space: pre-wrap">'
                     f'{e(_text(body))}</pre>')
    for part in extra:
        shown = _text(part)
        if part.get_content_subtype() == 'html':
            inner = _BODY.search(shown)
            page_body += f'<hr>{inner.group(1) if inner else shown}'
        else:
            page_body += (f'<hr><pre style="white-space: pre-wrap">'
                          f'{e(shown)}</pre>')
    defects = getattr(message, 'defects', None)
    if defects:
        note = (f'<p><i>The message is malformed: '
                f'{e("; ".join(type(d).__name__ for d in defects[:5]))}. '
                f'It is shown as Python\'s email package reads it.</i></p>')
    end = re.search(rb'\r?\n\r?\n', raw)
    headers = (raw[:end.start()] if end else raw[:65536]).decode(
        'utf-8', 'replace')
    return message_page(origin, _header(message, 'Subject'), rows, page_body,
                        note, headers, label='Headers as received')


# --- the archive view -------------------------------------------------------------

def _size_of(data):
    if isinstance(data, (bytes, bytearray, memoryview)):
        return len(data)
    data.seek(0, io.SEEK_END)
    size = data.tell()
    data.seek(0)
    return size


def _read(data, start, length):
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data[start:start + length])
    data.seek(start)
    return data.read(length)


def mbox_spans(data, should_stop=None):
    """[(start, end)] of every message in an mbox, the From_ line included.

    Read a block at a time, so the mailbox is never in memory whole. A
    message starts at a line that is a whole From_ line (sender and date):
    writers that leave out the blank line before it are common enough not
    to require one, and a body line that happens to begin "From " has no
    date after it -- mboxo and mboxrd quote it as ">From " anyway."""
    size = _size_of(data)
    starts = []
    position = 0
    previous = b''
    while position < size:
        if should_stop and should_stop():
            break
        chunk = _read(data, position, _SCAN_BLOCK + 256)
        if not chunk:
            break
        text = previous + chunk
        origin = position - len(previous)
        end = len(previous) + min(_SCAN_BLOCK, len(chunk)) + 4
        search = len(previous)
        while True:
            found = text.find(b'From ', search, end)
            if found == -1:
                break
            search = found + 1
            if origin + found and text[found - 1:found] != b'\n':
                continue
            line = text[found:found + 256].split(b'\n', 1)[0].rstrip(b'\r')
            if _FROM_LINE.match(line):
                starts.append(origin + found)
        previous = chunk[_SCAN_BLOCK - 1:_SCAN_BLOCK]
        position += _SCAN_BLOCK
    starts = sorted(set(starts))
    return list(zip(starts, starts[1:] + [size]))


class MailFile:
    """The members of an .eml or an mbox, and the bytes of any one."""

    def __init__(self, data, kind):
        self.data = data
        self.kind = kind
        self.members = []
        self._where = {}
        self._parsed = {}               # message start -> (message, raw)
        if kind == 'eml':
            raw = _read(data, 0, MAX_MESSAGE_BYTES)
            self._messages = [(0, len(raw))]
            self._add_message(0, '', single=True)
        else:
            self._messages = mbox_spans(data)
            if not self._messages:
                raise MailFileError("No messages found in the mailbox.")
            for number, (start, end) in enumerate(self._messages, 1):
                self._add_message(number, f'{number:04d} ')

    def _add(self, name, kind, ref, size=0, modified=None, is_dir=False):
        base, dot, suffix = name.rpartition('.') if not is_dir and \
            '.' in name else (name, '', '')
        candidate, count = name, 2
        while candidate in self._where:
            candidate = f'{base} ({count}){dot}{suffix}' if dot else \
                f'{name} ({count})'
            count += 1
        self._where[candidate] = (kind, ref)
        self.members.append({
            'name': candidate, 'size': size, 'compressed_size': size,
            'is_dir': is_dir, 'modified': modified, 'encrypted': False,
            'crc': None})
        return candidate

    def message(self, index):
        """(parsed message, its raw bytes) for message `index`."""
        if index in self._parsed:
            return self._parsed[index]
        start, end = self._messages[index]
        if end - start > MAX_MESSAGE_BYTES:
            raise MailFileError(
                f"Message {index + 1} is {end - start:,} bytes, over the "
                f"{MAX_MESSAGE_BYTES:,}-byte limit for reading in memory")
        raw = _read(self.data, start, end - start)
        if self.kind == 'mbox':
            raw = raw.split(b'\n', 1)[1] if b'\n' in raw else b''
        parsed = (parse(raw), raw)
        if len(self._parsed) > 64:
            self._parsed.clear()
        self._parsed[index] = parsed
        return parsed

    def _add_message(self, number, prefix, single=False):
        index = max(0, number - 1)
        start, end = self._messages[index]
        try:
            message, raw = self.message(index)
        except MailFileError:
            self._add(f'{prefix}(too large to read).eml', 'raw', index,
                      end - start)
            return
        subject = _clean(_header(message, 'Subject')) or '(no subject)'
        _written, utc = message_date(message)
        page = self._add(f'{prefix}{subject}.html', 'message', index,
                         len(raw), utc or None)
        _body, _extra, attachments = structure(message)
        if not attachments:
            return
        folder = 'attachments' if single else page[:-5] + ' - attachments'
        self._add(folder, 'folder', None, is_dir=True)
        for position, part in enumerate(attachments):
            self._add(f'{folder}/{_attachment_name(part, position + 1)}',
                      'attachment', (index, position), len(_bytes(part)),
                      utc or None)

    def read(self, name, limit):
        where = self._where.get(name)
        if where is None:
            raise MailFileError(f"No member {name}")
        kind, ref = where
        if kind == 'folder':
            raise MailFileError(f"{name} is a folder")
        if kind == 'raw':
            start, end = self._messages[ref]
            if end - start > limit:
                raise MailFileError(f"{name} is {end - start:,} bytes, over "
                                    f"the {limit:,}-byte limit")
            return _read(self.data, start, end - start)
        if kind == 'message':
            message, raw = self.message(ref)
            origin = 'Saved message (.eml)' if self.kind == 'eml' else \
                f'Message {ref + 1} of {len(self._messages)} in an mbox ' \
                f'mailbox (bytes {self._messages[ref][0]:,}-' \
                f'{self._messages[ref][1]:,})'
            return render(message, raw, origin)
        index, position = ref
        message, _raw = self.message(index)
        part = structure(message)[2][position]
        content = _bytes(part)
        if len(content) > limit:
            raise MailFileError(f"{name} is {len(content):,} bytes, over the "
                                f"{limit:,}-byte limit")
        return content


_CACHE = []                 # [(data, MailFile)] most recent last
_CACHE_SIZE = 4


def mail_file(data, kind=None):
    for index, (held, opened) in enumerate(_CACHE):
        if held is data:
            _CACHE.append(_CACHE.pop(index))
            return opened
    kind = kind or mail_kind(_read(data, 0, 4096))
    if kind not in ('eml', 'mbox'):
        raise MailFileError("Not a saved message or an mbox mailbox.")
    opened = MailFile(data, kind)
    _CACHE.append((data, opened))
    del _CACHE[:-_CACHE_SIZE]
    return opened


def list_members(data, kind=None):
    return list(mail_file(data, kind).members)


def read_member(data, name, limit, kind=None):
    return mail_file(data, kind).read(name, limit)
