"""Outlook .msg messages, read in memory (no Qt; olefile -- BSD, already a
dependency -- and the format specs; extract-msg is GPL).

A .msg is a compound (OLE) file (MS-OXMSG): the message's properties are
streams named __substg1.0_<id><type> beside a __properties_version1.0
stream of the fixed-size ones; recipients and attachments are storages of
their own, built the same way, and an attached message is a storage
holding a whole message again. Bodies come as plain text (0x1000), HTML
(0x1013) and/or compressed RTF (0x1009, MS-OXRTFCP); an RTF body made from
HTML carries the HTML inside it (MS-OXRTFEX) and is turned back into it.

The message is shown with the page every mail format shares
(mailbox.message_page) and browsed like an archive: the page, then each
attachment as a member ('attachments/<name>'), an attached message as its
own page.
"""

import datetime
import html
import io
import re
import struct

OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
MAX_ATTACHMENT = 256 * 1024 * 1024

#: Property ids (MS-OXPROPS) TRACE shows.
SUBJECT, MESSAGE_CLASS = 0x0037, 0x001A
SENDER_NAME, SENDER_EMAIL, SENDER_SMTP = 0x0C1A, 0x0C1F, 0x5D01
SENT_REPR_NAME, SENT_REPR_EMAIL, SENT_REPR_SMTP = 0x0042, 0x0065, 0x5D02
DISPLAY_TO, DISPLAY_CC, DISPLAY_BCC = 0x0E04, 0x0E03, 0x0E02
SUBMIT_TIME, DELIVERY_TIME = 0x0039, 0x0E06
CREATION_TIME, MODIFICATION_TIME = 0x3007, 0x3008
HEADERS, MESSAGE_ID, IN_REPLY_TO = 0x007D, 0x1035, 0x1042
BODY, HTML_BODY, RTF_BODY = 0x1000, 0x1013, 0x1009
MESSAGE_CODEPAGE, INTERNET_CPID = 0x3FFD, 0x3FDE
RECIPIENT_NAME, RECIPIENT_EMAIL, RECIPIENT_SMTP = 0x3001, 0x3003, 0x39FE
RECIPIENT_TYPE = 0x0C15
ATTACH_DATA, ATTACH_LONG_NAME, ATTACH_NAME = 0x3701, 0x3707, 0x3704
ATTACH_DISPLAY, ATTACH_METHOD, ATTACH_MIME = 0x3001, 0x3705, 0x370E
ATTACH_CONTENT_ID, ATTACH_HIDDEN = 0x3712, 0x7FFE

PT_LONG, PT_BOOLEAN, PT_I8, PT_SYSTIME = 0x0003, 0x000B, 0x0014, 0x0040
PT_STRING8, PT_UNICODE, PT_BINARY, PT_OBJECT = 0x001E, 0x001F, 0x0102, 0x000D
ATTACH_EMBEDDED_MSG = 5


class MsgError(ValueError):
    pass


def is_msg(data):
    """An OLE file holding a message's property streams. Cheap first: the
    stream names are in the directory, in UTF-16."""
    if not isinstance(data, (bytes, bytearray)) or \
            not data.startswith(OLE_MAGIC):
        return False
    names = ('__substg1.0_'.encode('utf-16-le'),
             '__properties_version1.0'.encode('utf-16-le'))
    if not all(name in data for name in names):
        return False
    try:
        Message.open(bytes(data))
    except MsgError:
        return False
    return True


# --- property streams ----------------------------------------------------------

class _Node:
    """One property bag: the message, a recipient, an attachment, an
    embedded message -- a storage path in the OLE file."""

    def __init__(self, ole, prefix, header, codepage=None):
        self.ole, self.prefix = ole, prefix
        self.codepage = codepage
        self.fixed = {}
        try:
            raw = ole.openstream(prefix + ['__properties_version1.0']).read()
        except (OSError, IOError):
            raw = b''
        for offset in range(header, len(raw) - 15, 16):
            tag, _flags = struct.unpack_from('<II', raw, offset)
            self.fixed[tag] = raw[offset + 8:offset + 16]
        if self.codepage is None:
            for pid in (INTERNET_CPID, MESSAGE_CODEPAGE):
                value = self.long(pid)
                if value:
                    self.codepage = value
                    break

    def stream(self, pid, ptype):
        name = f'__substg1.0_{pid:04X}{ptype:04X}'
        path = self.prefix + [name]
        if not self.ole.exists('/'.join(path)):
            return None
        return self.ole.openstream(path).read()

    def text(self, pid):
        raw = self.stream(pid, PT_UNICODE)
        if raw is not None:
            return raw.decode('utf-16-le', 'replace').rstrip('\0')
        raw = self.stream(pid, PT_STRING8)
        if raw is not None:
            return _decode8(raw.rstrip(b'\0'), self.codepage)
        return ''

    def binary(self, pid):
        return self.stream(pid, PT_BINARY)

    def long(self, pid):
        value = self.fixed.get(pid << 16 | PT_LONG)
        return struct.unpack('<i', value[:4])[0] if value else None

    def boolean(self, pid):
        value = self.fixed.get(pid << 16 | PT_BOOLEAN)
        return bool(value[0]) if value else None

    def time(self, pid):
        value = self.fixed.get(pid << 16 | PT_SYSTIME)
        if not value:
            return ''
        ticks = struct.unpack('<Q', value)[0]
        if not ticks:
            return ''
        try:
            moment = datetime.datetime(1601, 1, 1) + datetime.timedelta(
                microseconds=ticks // 10)
        except OverflowError:
            return ''
        return moment.strftime('%Y-%m-%d %H:%M:%S')


def _decode8(raw, codepage):
    for name in (f'cp{codepage}' if codepage else None,
                 'cp65001' if codepage == 65001 else None, 'cp1252'):
        if not name:
            continue
        try:
            return raw.decode('utf-8' if name == 'cp65001' else name)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode('latin-1')


# --- the message ------------------------------------------------------------------

class Message:
    """A message: its properties, recipients, attachments and body."""

    def __init__(self, ole, prefix=(), header=32, codepage=None):
        self.ole = ole
        self.prefix = list(prefix)
        self.props = _Node(ole, self.prefix, header, codepage)

    @classmethod
    def open(cls, data):
        import olefile
        try:
            ole = olefile.OleFileIO(io.BytesIO(data))
        except (OSError, IOError, ValueError) as exc:
            raise MsgError(f"Not a compound file: {exc}") from exc
        message = cls(ole)
        if not message.props.fixed and not message._has_streams():
            raise MsgError("No message properties")
        return message

    def _has_streams(self):
        depth = len(self.prefix)
        return any(len(path) == depth + 1 and
                   path[-1].startswith('__substg1.0_')
                   for path in self.ole.listdir())

    def _children(self, kind):
        depth = len(self.prefix)
        found = set()
        for path in self.ole.listdir(streams=True, storages=True):
            if len(path) > depth and path[:depth] == self.prefix and \
                    path[depth].startswith(f'__{kind}_version1.0_#'):
                found.add(path[depth])
        return sorted(found)

    # --- what it says ---------------------------------------------------------

    @property
    def subject(self):
        return self.props.text(SUBJECT)

    def sender(self):
        """'Name <address>'. Inside an Exchange organisation the stored
        address is a directory name ('/O=.../CN=...'): the SMTP address is
        looked for first (the SMTP properties, then the transport headers'
        From:), and a directory name that remains is labelled as one."""
        name = self.props.text(SENDER_NAME) or \
            self.props.text(SENT_REPR_NAME)
        email = self.props.text(SENDER_SMTP) or \
            self.props.text(SENT_REPR_SMTP)
        if not email:
            headers = self.props.text(HEADERS)
            match = re.search(r'^From:\s*(.+)$', headers, re.MULTILINE |
                              re.IGNORECASE) if headers else None
            if match:
                from email.utils import parseaddr
                email = parseaddr(match.group(1).strip())[1]
        if not email:
            email = self.props.text(SENDER_EMAIL) or \
                self.props.text(SENT_REPR_EMAIL)
            if email.startswith('/'):
                email = f'Exchange: {email}'
        if name and email and email.lower() != name.lower():
            return f'{name} <{email}>'
        return name or email

    def recipients(self):
        """[(type 'To'/'Cc'/'Bcc', 'Name <address>')]."""
        out = []
        for storage in self._children('recip'):
            node = _Node(self.ole, self.prefix + [storage], 8,
                         self.props.codepage)
            name = node.text(RECIPIENT_NAME)
            email = node.text(RECIPIENT_SMTP) or node.text(RECIPIENT_EMAIL)
            kind = {1: 'To', 2: 'Cc', 3: 'Bcc'}.get(
                node.long(RECIPIENT_TYPE), 'To')
            shown = f'{name} <{email}>' if name and email and \
                email.lower() != name.lower() else (name or email)
            out.append((kind, shown))
        return out

    def attachments(self):
        """[{'name', 'data' (bytes, or None), 'message' (an embedded
        Message, or None), 'mime', 'content_id', 'hidden'}]."""
        out = []
        for number, storage in enumerate(self._children('attach'), 1):
            prefix = self.prefix + [storage]
            node = _Node(self.ole, prefix, 8, self.props.codepage)
            name = node.text(ATTACH_LONG_NAME) or node.text(ATTACH_NAME) or \
                node.text(ATTACH_DISPLAY) or f'attachment {number}'
            entry = {'name': name, 'data': None, 'message': None,
                     'mime': node.text(ATTACH_MIME),
                     'content_id': node.text(ATTACH_CONTENT_ID),
                     'hidden': bool(node.boolean(ATTACH_HIDDEN))}
            embedded = prefix + [f'__substg1.0_{ATTACH_DATA:04X}'
                                 f'{PT_OBJECT:04X}']
            if node.long(ATTACH_METHOD) == ATTACH_EMBEDDED_MSG and \
                    self.ole.exists('/'.join(embedded)):
                entry['message'] = Message(self.ole, embedded, header=24,
                                           codepage=self.props.codepage)
            else:
                data = node.binary(ATTACH_DATA)
                if data is not None and len(data) <= MAX_ATTACHMENT:
                    entry['data'] = data
            out.append(entry)
        return out

    def body(self):
        """(kind 'html'/'text', body text, where it came from)."""
        raw = self.props.binary(HTML_BODY)
        if raw is None:
            text = self.props.text(HTML_BODY)
            raw = text.encode('utf-8') if text else None
            codepage = 65001
        else:
            codepage = self.props.codepage
        if raw:
            return 'html', _decode8(raw, codepage), 'HTML body'
        rtf = self.props.binary(RTF_BODY)
        if rtf:
            try:
                decoded = decompress_rtf(rtf)
            except MsgError:
                decoded = b''
            if b'\\fromhtml' in decoded[:4096]:
                return 'html', deencapsulate_html(decoded), \
                    'HTML recovered from the RTF body'
        text = self.props.text(BODY)
        if text:
            return 'text', text, 'plain-text body'
        if rtf:
            try:
                return 'text', rtf_to_text(decompress_rtf(rtf)), \
                    'text of the RTF body'
            except MsgError:
                pass
        return 'text', '', ''

    def facts(self):
        p = self.props
        return [('Message class', p.text(MESSAGE_CLASS)),
                ('From', self.sender()),
                ('Subject', self.subject)] + [
            (kind, '; '.join(r for k, r in self.recipients() if k == kind)
             or {'To': p.text(DISPLAY_TO), 'Cc': p.text(DISPLAY_CC),
                 'Bcc': p.text(DISPLAY_BCC)}[kind])
            for kind in ('To', 'Cc', 'Bcc')] + [
            ('Sent (UTC)', p.time(SUBMIT_TIME)),
            ('Received (UTC)', p.time(DELIVERY_TIME)),
            ('Created (UTC)', p.time(CREATION_TIME)),
            ('Modified (UTC)', p.time(MODIFICATION_TIME)),
            ('Message-ID', p.text(MESSAGE_ID)),
            ('In-Reply-To', p.text(IN_REPLY_TO))]

    def page(self, origin='Outlook message (.msg)'):
        """The message as one page of HTML (bytes)."""
        from trace_app.core.mailbox import message_page
        kind, text, source = self.body()
        attachments = self.attachments()
        if kind == 'html':
            inner = re.search(r'<body[^>]*>(.*)</body>', text,
                              re.IGNORECASE | re.DOTALL)
            body = inner.group(1) if inner else text
            body = _inline_images(body, attachments)
        else:
            body = (f'<pre style="white-space: pre-wrap">'
                    f'{html.escape(text)}</pre>' if text
                    else '<p><i>No body.</i></p>')
        rows = self.facts()
        if attachments:
            rows.append(('Attachments', '; '.join(
                f"{a['name']} ({_size(a)})" + (' [hidden]' if a['hidden']
                                               else '')
                for a in attachments)))
        note = (f'<p><small>Body: {html.escape(source)}.</small></p>'
                if source else '')
        return message_page(origin, self.subject, rows, body, note,
                            self.props.text(HEADERS),
                            label='Transport headers')


def _size(attachment):
    if attachment['message'] is not None:
        return 'attached message'
    data = attachment['data']
    return f'{len(data):,} bytes' if data is not None else 'no data'


def _inline_images(body, attachments):
    """cid: pictures become data: URIs, as for EML."""
    import base64
    images = {a['content_id'].strip('<>'): a for a in attachments
              if a['content_id'] and a['data'] and
              len(a['data']) <= 8 * 1024 * 1024}
    if not images:
        return body

    def swap(match):
        found = images.get(match.group(1))
        if not found:
            return match.group(0)
        mime = found['mime'] or 'image/png'
        return (f"data:{mime};base64,"
                f"{base64.b64encode(found['data']).decode('ascii')}")
    return re.sub(r'cid:([^"\'\s>)]+)', swap, body)


# --- compressed RTF (MS-OXRTFCP) and HTML inside RTF (MS-OXRTFEX) ---------------

_RTF_PREBUF = (b'{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil '
               b'\\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSy'
               b'mbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blu'
               b'e0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx')


def decompress_rtf(data):
    """MS-OXRTFCP: 'LZFu' (compressed) or 'MELA' (stored) RTF."""
    if len(data) < 16:
        raise MsgError("RTF body too short")
    size, raw_size, magic, _crc = struct.unpack_from('<IIII', data)
    body = data[16:size + 4]
    if magic == 0x414C454D:                     # 'MELA'
        return bytes(body[:raw_size])
    if magic != 0x75465A4C:                     # 'LZFu'
        raise MsgError("Unknown RTF compression")
    window = bytearray(4096)
    window[:len(_RTF_PREBUF)] = _RTF_PREBUF
    write = len(_RTF_PREBUF)
    out = bytearray()
    position = 0
    while position < len(body) and len(out) < raw_size:
        control = body[position]
        position += 1
        for bit in range(8):
            if position >= len(body) or len(out) >= raw_size:
                break
            if control & (1 << bit):
                if position + 1 >= len(body):
                    break
                ref = body[position] << 8 | body[position + 1]
                position += 2
                offset, length = ref >> 4, (ref & 0xF) + 2
                if offset == write:
                    return bytes(out)
                for i in range(length):
                    byte = window[(offset + i) % 4096]
                    out.append(byte)
                    window[write] = byte
                    write = (write + 1) % 4096
            else:
                byte = body[position]
                position += 1
                out.append(byte)
                window[write] = byte
                write = (write + 1) % 4096
    return bytes(out)


_RTF_TOKEN = re.compile(rb"\\'([0-9a-fA-F]{2})|\\([a-zA-Z]+)(-?\d+)? ?|"
                        rb"\\([^a-zA-Z])|([{}])|([^\\{}\r\n]+)|[\r\n]")


def deencapsulate_html(rtf):
    """The HTML an RTF body carries (\\fromhtml1): the text of
    {\\*\\htmltag ...} groups and the text outside \\htmlrtf blocks."""
    out, stack = [], []
    skip = False                    # inside \\htmlrtf ... \\htmlrtf0
    destination = 'rtf'
    for match in _RTF_TOKEN.finditer(rtf):
        hexbyte, word, number, symbol, brace, text = match.groups()
        if brace == b'{':
            stack.append((skip, destination))
            continue
        if brace == b'}':
            if stack:
                skip, destination = stack.pop()
            continue
        if word is not None:
            word = word.decode('ascii')
            if word == 'htmlrtf':
                skip = number != b'0'
            elif word == 'htmltag':
                destination = 'html'
            elif word in ('fonttbl', 'colortbl', 'stylesheet', 'info',
                          'pict', 'mhtmltag'):
                destination = 'skip'
            elif not skip and destination != 'skip':
                if word in ('par', 'line'):
                    out.append(b'\r\n')
                elif word == 'tab':
                    out.append(b'\t')
            continue
        if destination == 'skip' or (skip and destination != 'html'):
            continue
        if hexbyte is not None:
            out.append(bytes([int(hexbyte, 16)]))
        elif symbol is not None:
            if symbol in (b'\\', b'{', b'}'):
                out.append(symbol)
            elif symbol == b'~':
                out.append(b'\xa0')
        elif text is not None:
            out.append(text)
    data = b''.join(out)
    match = re.search(rb'\\ansicpg(\d+)', rtf[:2048])
    return _decode8(data, int(match.group(1)) if match else 1252)


def rtf_to_text(rtf):
    """Readable text of an RTF body that was not made from HTML."""
    out, depth_skip, stack = [], False, []
    for match in _RTF_TOKEN.finditer(rtf):
        hexbyte, word, _number, symbol, brace, text = match.groups()
        if brace == b'{':
            stack.append(depth_skip)
        elif brace == b'}':
            depth_skip = stack.pop() if stack else False
        elif word is not None:
            if word in (b'fonttbl', b'colortbl', b'stylesheet', b'info',
                        b'pict', b'generator'):
                depth_skip = True
            elif word in (b'par', b'line') and not depth_skip:
                out.append(b'\n')
        elif depth_skip:
            continue
        elif hexbyte is not None:
            out.append(bytes([int(hexbyte, 16)]))
        elif symbol == b'*':
            depth_skip = True
        elif text is not None:
            out.append(text)
    return _decode8(b''.join(out), 1252).strip()


# --- the archive interface ----------------------------------------------------------

def _clean(name):
    return re.sub(r'[\\/:*?"<>|\x00-\x1f]', '_', name).strip(' .') or 'item'


def _members(message, prefix=''):
    """[(member name, kind, payload)]: the page, attachments, attached
    messages (their own page and attachments, nested)."""
    subject = _clean(message.subject or '(no subject)')
    items = [(f'{prefix}{subject}.html', 'page', message)]
    attachments = message.attachments()
    if attachments:
        folder = f'{prefix}attachments'
        items.append((folder, 'folder', None))
        used = set()
        for attachment in attachments:
            name = _clean(attachment['name'])
            base, number = name, 2
            while name in used:
                stem, dot, extension = base.rpartition('.')
                name = f'{stem} ({number}).{extension}' if dot else \
                    f'{base} ({number})'
                number += 1
            used.add(name)
            if attachment['message'] is not None:
                items += _members(attachment['message'],
                                  f'{folder}/{name} - ')
            else:
                items.append((f'{folder}/{name}', 'data',
                              attachment['data'] or b''))
    return items


def list_members(data):
    message = Message.open(data)
    out = []
    for name, kind, payload in _members(message):
        size = len(payload) if kind == 'data' else 0
        out.append({'name': name, 'size': size, 'compressed_size': size,
                    'is_dir': kind == 'folder',
                    'modified': message.props.time(SUBMIT_TIME) or
                    message.props.time(CREATION_TIME),
                    'encrypted': False, 'crc': ''})
    return out


def read_member(data, name, limit=None):
    message = Message.open(data)
    for member, kind, payload in _members(message):
        if member != name:
            continue
        if kind == 'folder':
            raise MsgError(f"{name} is a folder")
        content = payload.page() if kind == 'page' else payload
        return content if limit is None else content[:limit]
    raise MsgError(f"No member {name!r}")
