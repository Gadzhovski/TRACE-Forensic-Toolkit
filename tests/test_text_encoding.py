"""Which encoding a text file was written in (core/text_encoding.py): the
Text tab, the search index and document previews share it.

Expected values are the encodings each text was written in. X-Ways' NTFS
training image holds one note in many languages, each in a legacy code
page *and* in Unicode: the Unicode copy is the answer for the other
(local only -- the image is private).
"""

import os

import pytest

from tests.conftest import pump
from tools import testdata
from trace_app.core import text_encoding
from trace_app.ui.viewers import text as text_view

NTFS_IMAGE = os.path.join(testdata.PRIVATE, 'X-WaysTrainingImages', 'NTFS',
                          'NTFSImage.e01')

SAMPLES = {
    'cp1252': "Ça été très agréable, naïve façade. It’s €5 — “quoted”. ",
    'cp1250': "Příliš žluťoučký kůň úpěl ďábelské ódy. ",
    'cp1251': "Внешний полиморфизм может быть обусловлен как "
              "внутривидовыми генетическими. ",
    'mac_cyrillic': "Внешний полиморфизм может быть обусловлен. Я знаю. ",
    'koi8_r': "Внешний полиморфизм может быть обусловлен. ",
    'cp866': "Внешний полиморфизм может быть обусловлен. ",
    'cp1253': "Η Ελλάδα είναι χώρα της νοτιοανατολικής Ευρώπης. ",
    'cp1254': "Türkiye Cumhuriyeti, güneydoğu Avrupa ve batı Asya. ",
    'cp1255': "שלום עולם, זהו מאמר נבחר. ",
    'cp1256': "قطر هي دولة عربية تقع في شرق شبه الجزيرة العربية. ",
    'gb18030': "盘面显示，早盘两市股指继续惯性高开，在经历了短暂的震荡之后。",
    'cp950': "行政長官董建華再度委任吳光正為貿易發展局主席，任期兩年。",
    'cp932': "スズメバチは、ハチ目スズメバチ科の昆虫。",
    'cp949': "한화측이 수사담당자 매수 시도. ",
}


@pytest.mark.parametrize('codec', sorted(SAMPLES))
def test_a_legacy_code_page_is_named(codec):
    data = (SAMPLES[codec] * 5).encode(codec)
    found = text_encoding.guess(data)
    assert found.codec == codec
    assert text_encoding.decode(data)[0] == SAMPLES[codec] * 5


def test_marks_utf16_without_a_mark_and_binary():
    text = "Notes – über alles\r\n"
    for codec, mark in (('utf-8', b'\xef\xbb\xbf'),
                        ('utf-16-le', b'\xff\xfe'),
                        ('utf-16-be', b'\xfe\xff')):
        found = text_encoding.guess(mark + text.encode(codec))
        assert (found.codec, found.bom) == (codec, len(mark))
    for codec in ('utf-16-le', 'utf-16-be'):
        assert text_encoding.guess(text.encode(codec) * 4).codec == codec
    assert text_encoding.guess(text.encode('utf-8')).codec == 'utf-8'
    # A sample cut through a character is still UTF-8.
    long = ('é' * (text_encoding.SAMPLE_BYTES // 2 + 1)).encode('utf-8')
    assert text_encoding.guess(b'a' + long).codec == 'utf-8'
    assert text_encoding.guess(b'MZ\x90\x00\x03\x00\x00\x00' * 8) is None
    assert text_encoding.guess(bytes(range(1, 32)) * 50) is None


def test_the_text_tab_names_the_encoding_and_maps_bytes_through_it(qapp):
    data = ("This is Russian:\r\n\r\n" + SAMPLES['mac_cyrillic'] * 3
            ).encode('mac_cyrillic')
    manager = text_view.TextViewerManager()
    manager.load_text_content(data)
    assert manager.description == 'Text · Mac Cyrillic'
    assert 'Внешний полиморфизм' in manager.text_content
    begin = manager.text_content.index('полиморфизм')
    first, end = manager.byte_range(begin, begin + 11)
    assert data[first:end].decode('mac_cyrillic') == 'полиморфизм'

    viewer = text_view.TextViewer()
    viewer.resize(1200, 300)
    viewer.show()
    try:
        greek = 'ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ\r\nαβγδεζηθικλμνξοπρστυφχψω'
        viewer.display_text_content(greek.encode('cp1253'))
        # A bare alphabet reads as Thai as well; the examiner chooses.
        viewer.encoding_combo.setCurrentIndex(
            viewer.encoding_combo.findData('cp1253'))
        pump(qapp)
        assert viewer.manager.text_content == greek
        assert viewer.mode_label.text().strip() == \
            'Text · Windows-1253 (Greek) (chosen)'
        # The next file is guessed afresh.
        viewer.display_text_content(data)
        assert viewer.encoding_combo.currentData() is None
        assert viewer.mode_label.text().strip() == 'Text · Mac Cyrillic'
    finally:
        viewer.close()
        viewer.deleteLater()


def test_search_text_and_html_previews_use_the_same_guess():
    from trace_app.core.document_preview import decode_html
    from trace_app.core.text_extract import _from_plain
    data = (SAMPLES['cp1256'] * 4).encode('cp1256')
    assert _from_plain(data) == SAMPLES['cp1256'] * 4
    page = b'<html><body><p>' + (SAMPLES['cp1251'] * 3).encode('cp1251') + \
        b'</p></body></html>'
    text, codec = decode_html(page)
    assert codec == 'cp1251' and SAMPLES['cp1251'] in text


def _languages(handler):
    """{name: bytes} of /Docs/Languages on the image."""
    offset = handler.volume_offsets()[0]
    inode = handler.get_root_inode(offset)
    for part in ('Docs', 'Languages'):
        inode = next(e['inode_number'] for e in
                     handler.get_directory_contents(offset, inode)
                     if e['name'] == part)
    files = {}
    for entry in handler.get_directory_contents(offset, inode):
        if entry['name'].endswith('.txt'):
            files[entry['name']] = handler.get_file_content(
                entry['inode_number'], offset)[0]
    return files


@pytest.mark.skipif(not os.path.exists(NTFS_IMAGE),
                    reason='X-Ways training image not here (local only)')
def test_xways_language_notes_read_as_their_unicode_copies():
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(NTFS_IMAGE)
    try:
        files = _languages(handler)
    finally:
        handler.close_resources()

    def text(name, codec=None):
        return text_encoding.decode(files[name], codec)[0].replace(
            '\r\n', '\n').strip()

    pairs = [('Полиморфизм ANSI Cyrillic.txt', 'Полиморфизм.txt'),
             ('Полиморфизм Mac Cyrillic.txt', 'Полиморфизм.txt'),
             ('قطرمن ويكيبيديا، الموسوعة الحرة ANSI.txt',
              'قطرمن ويكيبيديا، الموسوعة الحرة Unicode.txt'),
             ('分歧加大 沪深大盘重演天量震荡 CP 936.txt',
              '分歧加大 沪深大盘重演天量震荡 UTF-8.txt'),
             ('吳光正續任貿發局主席 CP 936.txt', '吳光正續任貿發局主席 UTF-8.txt'),
             ('吳光正續任貿發局主席 CP 950.txt', '吳光正續任貿發局主席 UTF-8.txt'),
             ('スズメバチ UTF-8.txt', 'スズメバチ.txt')]
    for legacy, unicode in pairs:
        assert text(legacy) == text(unicode), legacy
    # Every Unicode note (UTF-16 with a mark) reads without a lost character.
    for name, data in files.items():
        decoded = text(name)
        assert '�' not in decoded, name
    # The Greek alphabet alone cannot be told from Thai: chosen, it reads.
    # (The ANSI copy was saved without the last letter, omega.)
    assert text('ΑΒΓ Greek ANSI.txt', 'cp1253') + 'ω' == \
        text('ΑΒΓ Greek Unicode.txt')
