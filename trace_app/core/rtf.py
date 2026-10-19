"""RTF documents read as a reader sees them -- and what a reader does not.

Word writes non-ASCII letters into RTF as `\\'xx` bytes in the code page of
the font in use (each font names its character set: `\\fcharset204` is
Cyrillic, 161 Greek, 177 Hebrew...) or as `\\uN` with a fallback that a
Unicode reader skips (`\\ucN`). Read as plain text, an RTF's Russian is a
row of `\\'cf\\'f0\\'e8`: neither shown nor searchable. X-Ways' NTFS
training image keeps two Word RTFs whose font tables declare a dozen
character sets.

`read(data)` -> `Document`: paragraphs of runs (text, hidden, deleted,
inserted), the `\\info` group as facts (title, author, dates as written --
RTF times have no zone), what is embedded (pictures, objects) and counts of
what a reader would not see: hidden text (`\\v`) and tracked deletions.
`text(data)` is the words for the search index, hidden and deleted text
included; `to_html(data)` is escaped static HTML for the Application tab.
Pure Python; no Qt.
"""

import html
import re

#: \\fcharset -> Python codec (the Windows code page Word uses). 0 (ANSI)
#: is Windows-1252 whatever \\ansicpg says, as Windows' RichEdit reads it:
#: macOS writes `\\mac\\ansicpg10000` or `\\ansicpg936` documents whose
#: fcharset0 fonts hold `\\'92` for ’ and `\\'9a` for š.
CHARSET_CODECS = {
    0: 'cp1252',
    1: None,            # default: the document's \\ansicpg
    2: 'latin-1',       # Symbol: bytes as they are
    77: 'mac_roman', 78: 'shift_jis', 79: 'euc_kr', 80: 'gb2312',
    81: 'big5', 128: 'cp932', 129: 'cp949', 130: 'johab', 134: 'gb18030',
    136: 'cp950', 161: 'cp1253', 162: 'cp1254', 163: 'cp1258',
    177: 'cp1255', 178: 'cp1256', 186: 'cp1257', 204: 'cp1251',
    222: 'cp874', 238: 'cp1250', 254: 'cp437', 255: 'cp850',
}

#: Groups whose text is not the document's (formatting tables, pictures'
#: hex, field codes, shape properties). `\\*` groups are skipped as well.
_SKIPPED = frozenset((
    'colortbl', 'stylesheet', 'listtable', 'listoverridetable', 'rsidtbl',
    'revtbl', 'filetbl', 'pgdsctbl', 'themedata', 'colorschememapping',
    'datastore', 'latentstyles', 'xmlnstbl', 'bkmkstart',
    'bkmkend', 'nonshppict', 'objdata', 'objclass', 'sp', 'sn',
    'sv', 'xe', 'tc', 'template', 'userprops', 'docvar', 'pntxta',
    'pntxtb', 'mmathPr', 'panose', 'falt', 'atnid', 'atnauthor',
    'atntime', 'atnref', 'listpicture', 'fchars', 'lchars', 'wgrffmtfilter',
    'pgptbl', 'protusertbl', 'ftnsep', 'ftnsepc', 'aftnsep', 'aftnsepc',
))

_INFO_TEXT = {'title': 'Title', 'subject': 'Subject', 'author': 'Author',
              'operator': 'Last saved by', 'manager': 'Manager',
              'company': 'Company', 'category': 'Category',
              'keywords': 'Keywords', 'comment': 'Comments',
              'doccomm': 'Comments', 'hlinkbase': 'Link base'}
_INFO_TIMES = {'creatim': 'Created', 'revtim': 'Revised',
               'printim': 'Printed', 'buptim': 'Backed up'}
_INFO_NUMBERS = {'version': 'Version', 'edmins': 'Editing minutes',
                 'nofpages': 'Pages', 'nofwords': 'Words'}

_SYMBOLS = {'emdash': '\u2014', 'endash': '\u2013', 'bullet': '\u2022',
            'lquote': '\u2018', 'rquote': '\u2019', 'ldblquote': '\u201c',
            'rdblquote': '\u201d', 'emspace': '\u2003',
            'enspace': '\u2002', 'qmspace': '\u2005', 'tab': '\t',
            'cell': '\t', 'zwj': '\u200d', 'zwnj': '\u200c'}
_BREAKS = frozenset(('par', 'line', 'row', 'sect', 'page'))

_TOKEN = re.compile(
    rb"\\([a-zA-Z]{1,32})(-?\d{1,10})? ?"      # control word
    rb"|\\'([0-9a-fA-F]{2})"                   # a byte in hex
    rb"|\\([^a-zA-Z'])"                        # control symbol
    rb"|([{}])"
    rb"|[\r\n]+"
    rb"|([^\\{}\r\n]+)", re.S)

#: Groups nested deeper are read as text of the group they are in: a
#: crafted file could otherwise make the state stack grow without end.
MAX_DEPTH = 1000


class NotRtf(ValueError):
    """The bytes do not open an RTF document."""


def is_rtf(data):
    return bytes(data[:16]).lstrip()[:5] == b'{\\rtf'


class _State:
    __slots__ = ('skip', 'font', 'uc', 'hidden', 'deleted', 'inserted',
                 'target', 'link')

    def __init__(self):
        self.skip = False
        self.font = None
        self.uc = 1
        self.hidden = False
        self.deleted = False
        self.inserted = False
        # body | fonttbl | info:<key> | header | generator | fldinst
        self.target = 'body'
        self.link = None         # in a hyperlink's shown text: (url, start)

    def copy(self):
        other = _State.__new__(_State)
        for name in self.__slots__:
            setattr(other, name, getattr(self, name))
        return other


class Document:
    def __init__(self):
        self.paragraphs = [[]]    # [[(text, hidden, deleted, inserted)]]
        self.headers = []         # header/footer/footnote text
        self.facts = []           # [(label, value)]
        self.pictures = 0
        self.objects = 0
        self.hidden_chars = 0
        self.deleted_chars = 0
        self.inserted_chars = 0
        self.generator = ''

    def text(self):
        lines = [''.join(run[0] for run in paragraph)
                 for paragraph in self.paragraphs]
        body = '\n'.join(lines).strip('\n')
        extra = '\n'.join(self.headers)
        facts = '\n'.join(value for _label, value in self.facts)
        return '\n'.join(part for part in (body, extra, facts) if part)


def read(data):
    """`Document` of the RTF bytes `data` (raises NotRtf)."""
    data = bytes(data)
    if not is_rtf(data):
        raise NotRtf("This is not an RTF document.")
    return _Reader(data).run()


def text(data):
    """The document's words, hidden and deleted text included, then its
    headers, footers, footnotes and \\info values."""
    return read(data).text()


def to_html(data):
    """(html, notices) for the Application tab: escaped static HTML."""
    document = read(data)
    out = []
    for paragraph in document.paragraphs:
        pieces = []
        for chunk, hidden, deleted, inserted in paragraph:
            piece = html.escape(chunk).replace('\t', '&emsp;')
            if deleted:
                piece = f'<span class="deleted">{piece}</span>'
            elif inserted:
                piece = f'<span class="inserted">{piece}</span>'
            if hidden:
                piece = f'<span class="hidden">{piece}</span>'
            pieces.append(piece)
        line = ''.join(pieces)
        out.append(f'<p>{line}</p>' if line.strip() else '<p>&nbsp;</p>')
    while out and out[-1] == '<p>&nbsp;</p>':
        out.pop()
    if document.headers:
        out.append('<h2>Headers, footers and footnotes</h2>')
        out.extend(f'<p>{html.escape(line)}</p>'
                   for line in document.headers)
    if document.facts:
        out.append('<h2>Document information (\\info)</h2><table>')
        out.extend(f'<tr><th>{html.escape(label)}</th>'
                   f'<td>{html.escape(value)}</td></tr>'
                   for label, value in document.facts)
        out.append('</table>')
    notices = []
    if document.hidden_chars:
        notices.append(
            f"Hidden text: {document.hidden_chars:,} character(s) "
            f"formatted not to show (\\v); shown here in purple, "
            f"underlined.")
    if document.deleted_chars or document.inserted_chars:
        notices.append(
            f"Tracked changes: {document.deleted_chars:,} deleted and "
            f"{document.inserted_chars:,} inserted character(s) are still "
            f"in the file. Deleted text is shown struck through in red, "
            f"insertions underlined in green.")
    embedded = []
    if document.pictures:
        embedded.append(f"{document.pictures} picture(s)")
    if document.objects:
        embedded.append(f"{document.objects} embedded object(s)")
    if embedded:
        notices.append(f"Holds {' and '.join(embedded)}, not drawn here: "
                       f"Listing ▸ Show Embedded Files lists objects.")
    if document.generator:
        notices.append(f"Written by {document.generator}.")
    return ''.join(out), notices


class _Reader:
    def __init__(self, data):
        self.data = data
        self.doc = Document()
        self.codec = 'cp1252'          # \\ansicpg, \\mac, \\pc
        self.fonts = {}                # font number -> codec
        self.default_font = None
        self.font_number = None        # font being defined in \\fonttbl
        self.pending = bytearray()     # \\'xx bytes waiting to be decoded
        self.pending_state = None
        self.info_text = []
        self.time_parts = {}
        self.header_text = []
        self.next_link = None          # a HYPERLINK field's target

    # -- output ------------------------------------------------------------

    def _codec_of(self, state):
        font = state.font if state.font is not None else self.default_font
        return self.fonts.get(font) or self.codec

    def _flush(self):
        if not self.pending:
            return
        state = self.pending_state
        data = bytes(self.pending)
        self.pending.clear()
        try:
            chunk = data.decode(self._codec_of(state), 'replace')
        except LookupError:
            chunk = data.decode('cp1252', 'replace')
        self._emit(chunk, state)

    def _bytes(self, data, state):
        if self.pending and self.pending_state is not state:
            self._flush()
        self.pending_state = state
        self.pending += data

    def _emit(self, chunk, state):
        if not chunk:
            return
        target = state.target
        if target == 'body':
            run = (chunk, state.hidden, state.deleted, state.inserted)
            self.doc.paragraphs[-1].append(run)
            if state.hidden:
                self.doc.hidden_chars += len(chunk)
            if state.deleted:
                self.doc.deleted_chars += len(chunk)
            elif state.inserted:
                self.doc.inserted_chars += len(chunk)
        elif target == 'header':
            self.header_text.append(chunk)
        elif target == 'fonttbl':
            pass                       # font names are not the document's
        elif target.startswith('info:') or target in ('generator',
                                                      'fldinst'):
            self.info_text.append(chunk)

    def _break(self, state):
        self._flush()
        if state.target == 'body':
            self.doc.paragraphs.append([])
        elif state.target == 'header':
            self.header_text.append('\n')

    # -- groups -----------------------------------------------------------

    def _close_group(self, state, parent):
        """`state`'s group ends; `parent` is what follows."""
        self._flush()
        if state.link is not None and parent.link is None:
            self._link_shown(state)
        target = state.target
        if target == parent.target:
            return
        if target == 'fldinst':
            self.next_link = _link_target(''.join(self.info_text))
            self.info_text = []
        elif target.startswith('info:'):
            key = target[5:]
            value = _clean(''.join(self.info_text))
            self.info_text = []
            if key in _INFO_TEXT and value:
                self.doc.facts.append((_INFO_TEXT[key], value))
            elif key in _INFO_TIMES:
                stamp = _stamp(self.time_parts)
                if stamp:
                    self.doc.facts.append((_INFO_TIMES[key], stamp))
            self.time_parts = {}
        elif target == 'generator':
            self.doc.generator = _clean(''.join(self.info_text)).rstrip(';')
            self.info_text = []
        elif target == 'header':
            value = _clean(''.join(self.header_text))
            self.header_text = []
            if value:
                self.doc.headers.append(value)

    def _link_shown(self, state):
        """A hyperlink's shown text ended: its target follows it, as
        ' <target>', when the two differ -- a link reading one address
        and going to another is worth seeing (RichEdit writes it so)."""
        url, (paragraph, run) = state.link
        if state.target != 'body':
            return
        runs = self.doc.paragraphs[paragraph][run:] + [
            r for p in self.doc.paragraphs[paragraph + 1:] for r in p]
        shown = ''.join(r[0] for r in runs).strip()
        if url and url != shown:
            parent = state.copy()
            parent.link = None
            self._emit(f' <{url}>', parent)

    def run(self):
        stack = []
        state = _State()
        skipping = 0                   # \\uN fallback characters left
        ignorable = False              # last token was \\*
        group_start = False            # first token of a group
        depth_lost = 0
        for match in _TOKEN.finditer(self.data):
            word, number, hexbyte, symbol, brace, plain = match.groups()
            if brace == b'{':
                skipping = 0
                if len(stack) >= MAX_DEPTH:
                    depth_lost += 1
                    continue
                self._flush()
                stack.append(state)
                state = state.copy()
                group_start = True
                ignorable = False
                continue
            if brace == b'}':
                skipping = 0
                if depth_lost:
                    depth_lost -= 1
                    continue
                if not stack:
                    break              # the document's own group ended
                parent = stack.pop()
                self._close_group(state, parent)
                state = parent
                group_start = False
                continue
            first, group_start = group_start, False
            if word is not None:
                word = word.decode('ascii')
                value = int(number) if number is not None else None
                if skipping:
                    skipping -= 1
                    continue
                if ignorable:
                    # {\*\word ...}: a group a reader may ignore -- all
                    # of them but the program that wrote the file and a
                    # field's code (a hyperlink's target).
                    ignorable = False
                    if word in ('generator', 'fldinst') and not state.skip:
                        self._flush()
                        state.target = word
                        continue
                    if word == 'shppict' and not state.skip:
                        self.doc.pictures += 1
                    state.skip = True
                    continue
                if state.skip:
                    continue
                skipping = self._word(word, value, state, first)
                continue
            if hexbyte is not None:
                if skipping:
                    skipping -= 1
                    continue
                if not state.skip:
                    self._bytes(bytes((int(hexbyte, 16),)), state)
                continue
            if symbol is not None:
                if symbol == b'*':
                    ignorable = True
                    continue
                if skipping:
                    skipping -= 1
                    continue
                if state.skip:
                    continue
                if symbol in b'\\{}':
                    self._bytes(symbol, state)
                elif symbol == b'~':
                    self._flush()
                    self._emit('\u00a0', state)
                elif symbol == b'_':
                    self._flush()
                    self._emit('\u2011', state)
                elif symbol in b'\r\n':
                    self._break(state)
                # \\- (optional hyphen), \\: (index), anything else: nothing
                continue
            if plain is not None:
                if skipping:
                    cut = min(skipping, len(plain))
                    skipping -= cut
                    plain = plain[cut:]
                if plain and not state.skip:
                    self._bytes(plain, state)
        self._flush()
        doc = self.doc
        # Runs alike are one run, and surrogate pairs (written as two \\uN,
        # so two runs) one character.
        doc.paragraphs = [[(_join_surrogates(t), *marks)
                           for t, marks in _merged(paragraph)]
                          for paragraph in doc.paragraphs]
        return doc

    def _word(self, word, value, state, first):
        """Act on a control word outside skipped groups; returns how many
        fallback characters follow (`\\uN`)."""
        if word == 'u' and value is not None:
            self._flush()
            self._emit(chr(value + 65536 if value < 0 else value)
                       if -32768 <= value <= 65535 else '\ufffd', state)
            return state.uc
        if word == 'uc' and value is not None:
            state.uc = max(0, min(value, 16))
        elif word in _BREAKS:
            self._break(state)
        elif word in _SYMBOLS:
            self._flush()
            self._emit(_SYMBOLS[word], state)
        elif word == 'f' and value is not None:
            if state.target == 'fonttbl':
                self.font_number = value
            else:
                self._flush()
                state.font = value
        elif word == 'fcharset' and value is not None and \
                state.target == 'fonttbl' and self.font_number is not None:
            codec = CHARSET_CODECS.get(value)
            if codec:
                self.fonts[self.font_number] = codec
        elif word == 'cpg' and value is not None and \
                state.target == 'fonttbl' and self.font_number is not None:
            self.fonts[self.font_number] = _codepage(value) or \
                self.fonts.get(self.font_number)
        elif word == 'ansicpg' and value is not None:
            self.codec = _codepage(value) or self.codec
        elif word == 'mac':
            self.codec = 'mac_roman'
        elif word == 'pc':
            self.codec = 'cp437'
        elif word == 'pca':
            self.codec = 'cp850'
        elif word == 'deff' and value is not None:
            self.default_font = value
        elif word == 'v':
            self._flush()
            state.hidden = value != 0
        elif word == 'deleted':
            self._flush()
            state.deleted = value != 0
        elif word == 'revised':
            self._flush()
            state.inserted = value != 0
        elif word == 'plain':
            self._flush()
            state.hidden = state.deleted = state.inserted = False
        elif first:
            self._destination(word, state)
        elif state.target.startswith('info:') and word in (
                'yr', 'mo', 'dy', 'hr', 'min', 'sec'):
            self.time_parts[word] = value or 0
        elif state.target == 'info' and word in _INFO_NUMBERS and \
                value is not None:
            self.doc.facts.append((_INFO_NUMBERS[word], str(value)))
        return 0

    def _destination(self, word, state):
        """The first word of a group may name what the group holds."""
        self._flush()
        if word == 'fonttbl':
            state.target = 'fonttbl'
        elif word == 'info':
            state.target = 'info'
        elif state.target == 'info' and (word in _INFO_TEXT or
                                         word in _INFO_TIMES):
            state.target = 'info:' + word
        elif word == 'fldinst':
            state.target = 'fldinst'
        elif word == 'fldrslt':
            if self.next_link and state.target == 'body':
                paragraphs = self.doc.paragraphs
                state.link = (self.next_link, (len(paragraphs) - 1,
                                               len(paragraphs[-1])))
            self.next_link = None
        elif word == 'pict':
            self.doc.pictures += 1
            state.skip = True
        elif word == 'object':
            self.doc.objects += 1
            state.skip = True
        elif word in ('header', 'footer', 'headerl', 'headerr', 'headerf',
                      'footerl', 'footerr', 'footerf', 'footnote',
                      'annotation'):
            state.target = 'header'
        elif word in _SKIPPED:
            state.skip = True


def _codepage(number):
    codec = {10000: 'mac_roman', 10007: 'mac_cyrillic', 10006: 'mac_greek',
             10029: 'mac_latin2', 20866: 'koi8_r', 21866: 'koi8_u',
             65001: 'utf-8', 936: 'gb18030'}.get(number, f'cp{number}')
    try:
        ''.encode(codec)
    except LookupError:
        return None
    return codec


_HYPERLINK = re.compile(
    r'^\s*HYPERLINK\s+(?:\\l\s+"(?P<anchor>[^"]*)"|"(?P<url>[^"]*)"'
    r'(?:\s+\\l\s+"(?P<more>[^"]*)")?|(?P<bare>\S+))', re.I)


def _link_target(code):
    """A HYPERLINK field's target ('#bookmark' for a place in the
    document), or None for any other field."""
    match = _HYPERLINK.match(code)
    if match is None:
        return None
    if match['anchor'] is not None:
        return '#' + match['anchor']
    url = match['url'] if match['url'] is not None else match['bare']
    if match['more']:
        url += '#' + match['more']
    return url.strip() or None


def _clean(value):
    return ' '.join(value.replace('\u00a0', ' ').split())


def _stamp(parts):
    if not parts.get('yr'):
        return ''
    text = (f"{parts['yr']:04d}-{parts.get('mo', 1):02d}-"
            f"{parts.get('dy', 1):02d} {parts.get('hr', 0):02d}:"
            f"{parts.get('min', 0):02d}")
    if 'sec' in parts:
        text += f":{parts['sec']:02d}"
    return text + ' (local, no zone)'


def _merged(paragraph):
    """[(text, (hidden, deleted, inserted))] with neighbours alike joined."""
    out = []
    for text, *marks in paragraph:
        marks = tuple(marks)
        if out and out[-1][1] == marks:
            out[-1][0].append(text)
        else:
            out.append(([text], marks))
    return [(''.join(texts), marks) for texts, marks in out]


def _join_surrogates(text):
    if not any('\ud800' <= c <= '\udfff' for c in text):
        return text
    return text.encode('utf-16-le', 'surrogatepass').decode(
        'utf-16-le', 'replace')
