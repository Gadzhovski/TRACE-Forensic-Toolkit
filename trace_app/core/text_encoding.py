"""Which encoding a text file was written in -- the one answer for the Text
tab, the search index and document previews.

A byte-order mark decides; then UTF-16 without one (the NULs' side gives
the byte order); then strict UTF-8. Anything else was written in a legacy
code page, and the bytes do not say which: charset_normalizer (pure
Python, MIT) decodes a sample in each plausible one and ranks them by how
much the result reads like a language. chardet, used before, named the
Arabic Windows-1256 note KOI8-R and the Mac Cyrillic one Windows-1251 --
on X-Ways' NTFS training image both came out as mojibake.

Twin code pages (Windows-1251 / Mac Cyrillic share their lower case) can
rank in the wrong order on a short sample, so the candidates are ranked
again by `_misfits`: a symbol sitting against a letter ('‚нешний',
'¬нешний') is what decoding in the wrong twin leaves.

Some files cannot be told at all (a Greek alphabet in Windows-1253 is a
Thai one in TIS-620): the Text tab lets the examiner choose
(`CHOICES`), and the guess is always named.
"""

import codecs
import unicodedata
from collections import namedtuple

#: Bytes read to guess a legacy code page (the whole file is decoded).
SAMPLE_BYTES = 65536
#: Share of printable characters for bytes to count as text.
PRINTABLE = 0.97

Guess = namedtuple('Guess', 'codec bom name')

#: Python codec -> the name shown. Codecs guessed under another name are
#: folded to the superset Windows uses (GB2312 -> GB18030, Big5 -> 950...).
NAMES = {
    'utf-8': 'UTF-8', 'utf-16-le': 'UTF-16LE', 'utf-16-be': 'UTF-16BE',
    'utf-32-le': 'UTF-32LE', 'utf-32-be': 'UTF-32BE',
    'cp1250': 'Windows-1250 (Central European)',
    'cp1251': 'Windows-1251 (Cyrillic)',
    'cp1252': 'Windows-1252',
    'cp1253': 'Windows-1253 (Greek)',
    'cp1254': 'Windows-1254 (Turkish)',
    'cp1255': 'Windows-1255 (Hebrew)',
    'cp1256': 'Windows-1256 (Arabic)',
    'cp1257': 'Windows-1257 (Baltic)',
    'cp1258': 'Windows-1258 (Vietnamese)',
    'cp874': 'Windows-874 (Thai)',
    'cp437': 'DOS 437', 'cp850': 'DOS 850', 'cp866': 'DOS 866 (Cyrillic)',
    'koi8_r': 'KOI8-R', 'koi8_u': 'KOI8-U',
    'mac_roman': 'Mac Roman', 'mac_cyrillic': 'Mac Cyrillic',
    'mac_greek': 'Mac Greek', 'mac_latin2': 'Mac Central European',
    'iso8859_2': 'ISO-8859-2', 'iso8859_5': 'ISO-8859-5 (Cyrillic)',
    'iso8859_6': 'ISO-8859-6 (Arabic)', 'iso8859_7': 'ISO-8859-7 (Greek)',
    'iso8859_8': 'ISO-8859-8 (Hebrew)', 'iso8859_9': 'ISO-8859-9',
    'latin_1': 'ISO-8859-1',
    'gb18030': 'GB18030 (Simplified Chinese)',
    'cp950': 'Big5 / 950 (Traditional Chinese)',
    'big5hkscs': 'Big5-HKSCS',
    'cp932': 'Shift_JIS / 932 (Japanese)', 'euc_jp': 'EUC-JP',
    'iso2022_jp': 'ISO-2022-JP',
    'cp949': 'EUC-KR / 949 (Korean)', 'johab': 'Johab',
}
_FOLDED = {'gb2312': 'gb18030', 'gbk': 'gb18030', 'hz': 'gb18030',
           'big5': 'cp950', 'shift_jis': 'cp932', 'euc_kr': 'cp949',
           'ascii': 'utf-8', 'tis_620': 'cp874', 'iso8859_11': 'cp874',
           'utf_8': 'utf-8', 'windows_1252': 'cp1252'}
#: What the Text tab offers by hand: automatic first, then by script.
CHOICES = ('utf-8', 'utf-16-le', 'utf-16-be', 'cp1252', 'cp1250',
           'cp1251', 'cp866', 'koi8_r', 'koi8_u', 'mac_cyrillic',
           'cp1253', 'cp1254', 'cp1255', 'cp1256', 'cp1257', 'cp1258',
           'cp874', 'gb18030', 'cp950', 'cp932', 'euc_jp', 'cp949',
           'mac_roman', 'cp437', 'latin_1')
_BOMS = ((b'\xef\xbb\xbf', 'utf-8'), (b'\xff\xfe\x00\x00', 'utf-32-le'),
         (b'\x00\x00\xfe\xff', 'utf-32-be'), (b'\xff\xfe', 'utf-16-le'),
         (b'\xfe\xff', 'utf-16-be'))
#: Typography that sits against letters in real text.
_JOINERS = set("'’‘-–—.,;:!?()[]«»“”„\"/…·%")
#: Code pages a guess may name: what systems actually write. Left to
#: itself charset_normalizer also tries EBCDIC and rare DOS pages, and on a
#: short sample one of those can win (Shift_JIS read as EBCDIC 037).
#: Most written first: the order breaks a tie.
CANDIDATES = ('cp1252', 'cp1251', 'cp1250', 'gb18030', 'cp932', 'big5',
              'cp949', 'cp1256', 'cp1253', 'cp1254', 'cp1255', 'cp1257',
              'cp874', 'cp1258', 'koi8_r', 'mac_cyrillic', 'cp866', 'koi8_u',
              'euc_jp', 'mac_roman', 'cp437', 'cp850', 'iso8859_2',
              'iso8859_5', 'iso8859_7', 'iso8859_15', 'latin_1')
_PREFERENCE = {normal_name: index for index, normal_name in enumerate(
    {'big5': 'cp950', 'latin_1': 'latin_1'}.get(c, c) for c in CANDIDATES)}
#: The letters beyond ASCII of languages written in Latin script, lower
#: case. Latin code pages share most letters and differ in a few
#: (Windows-1252's ð þ ý are Windows-1254's ğ ş ı), so the reading whose
#: letters all belong to one language is the right one.
LATIN_ALPHABETS = (
    'àâæçéèêëîïôœùûüÿ', 'äöüß', 'áéíñóúü', 'áâãàçéêíóôõú', 'àèéìíòóù',
    'çğıöşü', 'ąćęłńóśźż', 'áčďéěíňóřšťúůýž', 'áäčďéíĺľňóôŕšťúýž',
    'áéíóöőúüű', 'ăâîșțşţ', 'čćđšž', 'åäöæøé', 'áéíóúýþæöð',
    'ąčęėįšųūž', 'āčēģīķļņšūž', 'äõöüšž')
_EAST_ASIAN = {'CJK', 'HIRAGANA', 'KATAKANA', 'HANGUL', 'HALFWIDTH',
               'FULLWIDTH', 'IDEOGRAPHIC'}
#: Scripts that sit inside words of any other (combining accents...).
_ANY_SCRIPT = {'COMBINING', 'MODIFIER', '?'}


def name_of(codec):
    codec = normal(codec)
    return NAMES.get(codec, codec.upper().replace('_', '-'))


def normal(codec):
    """`codec` as this module names it (lower case, folded to Windows'
    superset)."""
    try:
        codec = codecs.lookup(codec).name
    except LookupError:
        return codec
    codec = codec.replace('-', '_')
    codec = _FOLDED.get(codec, codec)
    return {'utf_16_le': 'utf-16-le', 'utf_16_be': 'utf-16-be',
            'utf_32_le': 'utf-32-le', 'utf_32_be': 'utf-32-be',
            'iso8859_1': 'latin_1'}.get(codec, codec)


def bom_of(data, codec):
    """Length of `codec`'s byte-order mark at the start of `data`."""
    for mark, own in _BOMS:
        if own == codec and data.startswith(mark):
            return len(mark)
    return 0


def printable_share(text):
    if not text:
        return 1.0
    # U+FFFD is printable to Python, but here it is a byte the code page
    # does not define: a PDF's streams read as Windows-1252 were "text"
    # with a thousand of them (X-Ways' NTFS image).
    good = sum(1 for c in text
               if (c.isprintable() and c != '�') or c in '\r\n\t\f')
    return good / len(text)


def guess(data):
    """`Guess(codec, bom, name)` when `data` reads as text, else None."""
    if not data:
        return Guess('utf-8', 0, 'empty')
    for mark, codec in _BOMS:
        if data.startswith(mark):
            return Guess(codec, len(mark), NAMES[codec])
    head = data[:4096]
    wide = _utf16_order(head)
    if wide:
        return Guess(wide, 0, NAMES[wide])
    if b'\x00' in head:
        return None                       # binary
    sample = data[:SAMPLE_BYTES]
    if _is_utf8(sample, cut=len(data) > SAMPLE_BYTES):
        text = sample.decode('utf-8', 'ignore')
        return Guess('utf-8', 0, 'UTF-8') \
            if printable_share(text) >= PRINTABLE else None
    codec = _legacy(sample)
    if codec is None:
        return None
    return Guess(codec, 0, name_of(codec))


def decode(data, codec=None):
    """(text, Guess) -- `data` in `codec`, else in its guessed encoding;
    text that is not text decodes as Windows-1252 (a Guess named so)."""
    if codec:
        codec = normal(codec)
        found = Guess(codec, bom_of(data, codec), name_of(codec))
    else:
        found = guess(data) or Guess('cp1252', 0, 'Windows-1252')
    return data[found.bom:].decode(found.codec, 'replace'), found


def _utf16_order(head):
    """'utf-16-le' / 'utf-16-be' for UTF-16 without a mark, else None:
    one side of the byte pairs mostly NUL (Latin text), or the whole
    sample decoding to letters of one script (Asian text has no NULs)."""
    if len(head) < 8:
        return None
    even, odd = head[0::2], head[1::2]
    for zeros, other, codec in ((odd, even, 'utf-16-le'),
                                (even, odd, 'utf-16-be')):
        if zeros.count(0) >= len(zeros) * 0.4 and \
                other.count(0) <= len(other) * 0.05:
            text = head[:len(head) // 2 * 2].decode(codec, 'replace')
            if printable_share(text) >= 0.9:
                return codec
    return None


def _is_utf8(sample, cut):
    try:
        sample.decode('utf-8')
        return True
    except UnicodeDecodeError as error:
        # A sample cut through a character is still UTF-8.
        return cut and error.start >= len(sample) - 3 and \
            error.reason == 'unexpected end of data'


def _legacy(sample):
    """The code page `sample` was most likely written in, or None."""
    candidates = {}
    try:
        import charset_normalizer
        # A generous threshold: odd but real text (a pangram, a list of
        # names) is otherwise refused outright; the scoring below judges.
        for rank, match in enumerate(charset_normalizer.from_bytes(
                sample, cp_isolation=list(CANDIDATES), threshold=0.5)):
            # Code pages that decode the sample alike come as one match.
            for name in [match.encoding] + list(match.could_be_from_charset):
                codec = normal(name)
                if codec in _PREFERENCE:
                    candidates.setdefault(codec, (match.chaos, rank))
    except Exception:                   # never stops a file being shown
        candidates = {}
    if 'latin_1' in candidates:
        # ISO-8859-1 and Windows-1252 agree from 0xA0 up; below it Latin-1
        # has only C1 controls, which real text never holds -- an eBay.de
        # page's thirteen 0x80 bytes are euro signs. Windows-1252 whenever
        # it defines every byte.
        try:
            sample.decode('cp1252')
        except UnicodeDecodeError:
            pass
        else:
            found = candidates.pop('latin_1')
            candidates.setdefault('cp1252', found)
    best = None
    for codec, (chaos, rank) in candidates.items():
        text = sample.decode(codec, 'replace')
        if printable_share(text) < PRINTABLE:
            continue
        # Then charset_normalizer's ranking (how like a language it
        # reads); alike on every count, the code page more often written.
        score = (_misfits(text), -_one_language(text), chaos, rank,
                 _PREFERENCE[codec])
        if best is None or score < best[0]:
            best = (score, codec)
    if best is not None:
        return best[1]
    text = sample.decode('cp1252', 'replace')
    return 'cp1252' if printable_share(text) >= PRINTABLE else None


def _script(char):
    if char < '':
        return 'LATIN'
    script = unicodedata.name(char, '?').split(' ')[0]
    return 'CJK' if script in _EAST_ASIAN else script


def _misfits(text):
    """What decoding in the wrong code page leaves: a symbol against a
    letter ('‚нешний', '¬нешний'), a capital inside a word after small
    letters ('ЮШС ен ПжбЙ'), a word changing script ('cafй', 'cafι')."""
    count = 0
    previous_letter = None              # its script, inside a word
    previous_lower = False
    pending = False                     # a symbol right after a letter
    for char in text:
        if char.isalpha() or (previous_letter and
                              unicodedata.category(char).startswith('M')):
            if pending:
                count += 1
            pending = False
            if previous_lower and char.isupper() and char > '':
                count += 1
            script = _script(char)
            if previous_letter and script != previous_letter and                     script not in _ANY_SCRIPT and                     previous_letter not in _ANY_SCRIPT:
                count += 1
            previous_lower = char.islower()
            if char.isalpha():
                previous_letter = script
            continue
        if char > '' and char not in _JOINERS and                 not 0x3000 <= ord(char) <= 0x303f and                 not 0xff00 <= ord(char) <= 0xffef and                 not char.isspace() and not char.isdigit():
            if previous_letter:
                count += 1
            else:
                pending = True
        else:
            pending = False
        previous_letter = None
        previous_lower = False
    return count


def _one_language(text):
    """Share of the letters beyond ASCII that one language uses: Latin
    letters against `LATIN_ALPHABETS`, any other script by script."""
    letters = [c.lower() for c in text if ord(c) > 0x7f and c.isalpha()]
    if not letters:
        return 1.0
    latin = [c for c in letters if 'LATIN' in unicodedata.name(c, '')]
    best = max(sum(1 for c in latin if c in alphabet)
               for alphabet in LATIN_ALPHABETS) if latin else 0
    scripts = {}
    for c in letters:
        if c in latin:
            continue
        # Japanese mixes kana and kanji, Korean hangul and hanja: one
        # family (`_script`), so a reading as Chinese does not win for
        # being 'purer'.
        script = _script(c)
        scripts[script] = scripts.get(script, 0) + 1
    other = max(scripts.values()) if scripts else 0
    return max(best, other) / len(letters)
