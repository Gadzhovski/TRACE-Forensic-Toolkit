"""What a file is taken for by its name (ImageHandler.get_image_type):
dd writes whatever name it is given, so a file with no extension (or
.bin) is a raw image; an X-Ways evidence container is recognised and
explained, not reported as an unknown extension."""

import pytest


def test_a_file_with_no_extension_is_raw(tmp_path):
    from trace_app.core.image_handler import ImageHandler
    for name in ('sda', 'disk.bin'):
        path = tmp_path / name
        path.write_bytes(b'\0' * 4096)
        handler = ImageHandler(str(path))
        try:
            assert handler.loaded and handler.get_image_type() == 'raw'
        finally:
            handler.close_resources()


def test_an_xways_container_says_what_it_is(tmp_path):
    from trace_app.core.evidence_probe import probe
    from trace_app.core.image_handler import ImageHandler, \
        UnsupportedEvidence
    for name in ('case.ctr', 'renamed.dd'):
        path = tmp_path / name
        path.write_bytes(b'XWFS' + b'\0' * 4092)
        with pytest.raises(UnsupportedEvidence, match='X-Ways'):
            ImageHandler(str(path))
        assert 'X-Ways evidence file container' in probe(str(path))['error']


def test_other_extensions_are_still_refused(tmp_path):
    from trace_app.core.image_handler import ImageHandler
    path = tmp_path / 'report.doc'
    path.write_bytes(b'\0' * 512)
    with pytest.raises(ValueError, match='Unsupported image type'):
        ImageHandler(str(path))


# --- E01 segment sets (core/ewf_check.py) ------------------------------------

def _segment(path, number, sections, cut=0):
    """An EWF version 1 segment file: the header, then each named section
    descriptor chained to the next; `cut` bytes chopped off the end."""
    import struct
    data = bytearray(b'EVF\x09\x0d\x0a\xff\x00\x01' +
                     struct.pack('<H', number) + b'\0\0')
    for index, kind in enumerate(sections):
        here = len(data)
        last = index == len(sections) - 1
        following = here if last else here + 76 + 100
        data += kind.encode().ljust(16, b'\0') + struct.pack(
            '<QQ', following, 76 if last else 176) + b'\0' * 44
        if not last:
            data += b'\xab' * 100
    path.write_bytes(bytes(data[:len(data) - cut]))
    return str(path)


def test_a_whole_segment_set_passes(tmp_path):
    from trace_app.core import ewf_check
    one = _segment(tmp_path / 'a.E01', 1, ['header', 'volume', 'sectors',
                                           'table', 'next'])
    two = _segment(tmp_path / 'a.E02', 2, ['data', 'sectors', 'table',
                                           'hash', 'done'])
    assert ewf_check.problem([one, two]) is None
    # Not EWF version 1 (a raw file, an Ex01): not judged.
    raw = tmp_path / 'x.E01'
    raw.write_bytes(b'\0' * 512)
    assert ewf_check.problem([str(raw)]) is None


def test_a_set_with_a_gap_says_what_is_missing(tmp_path):
    from trace_app.core import ewf_check
    sections = ['header', 'sectors', 'table', 'next']
    one = _segment(tmp_path / 'a.E01', 1, sections)
    three = _segment(tmp_path / 'a.E03', 3, ['sectors', 'done'])
    assert ewf_check.problem([one, three]) == \
        "segment 2 of the set is missing"
    # The last file present still expects another.
    two = _segment(tmp_path / 'a.E02', 2, sections)
    assert 'segment 3 onwards' in ewf_check.problem([one, two])
    # A file cut short inside its chain.
    cut = _segment(tmp_path / 'b.E01', 1, ['header', 'sectors', 'table',
                                           'done'], cut=120)
    assert "breaks off after its 'table' section" in \
        ewf_check.problem([cut])


def test_data_end_finds_where_reads_stop():
    from trace_app.core import ewf_check
    end = 5 * 32768

    def read(offset, size):
        if offset >= end:
            raise OSError('missing segment file')
        return b'\0' * size
    assert ewf_check.data_end(read, 100 * 32768) == end
    assert ewf_check.data_end(lambda o, n: b'\0' * n, 1000) == 1000


def test_xways_truncated_e01_says_why_reads_fail():
    """Private, local only: X-Ways' '12 TB NTFS.e01' is one segment file
    cut short after 3.5 GB of a 12 TB disk."""
    import os
    from tests.conftest import ROOT
    from trace_app.core.image_handler import (ImageHandler,
                                              IncompleteEvidence)
    path = os.path.join(ROOT, 'test_images', 'X-WaysTrainingImages',
                        '12 TB NTFS.e01')
    if not os.path.exists(path):
        pytest.skip("private X-Ways training images (local only)")
    handler = ImageHandler(path)
    try:
        assert handler.loaded
        assert handler.container_note.startswith('Incomplete E01')
        assert handler.img_info.incomplete[1] == 3756032000
        assert handler.read(0, 512)
        with pytest.raises(IncompleteEvidence, match='holds data up to'):
            handler.img_info.read(4 * 2**30, 512)
        assert 'incomplete' in handler.calculate_hashes()['error']
    finally:
        handler.close_resources()
