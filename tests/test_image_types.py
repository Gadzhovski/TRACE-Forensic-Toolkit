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
