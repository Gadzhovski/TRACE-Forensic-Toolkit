"""The image information's disk layout (core/disk_layout.py,
ui/widgets/disk_map.py)."""

import os

import pytest

import tests.conftest  # noqa: F401  (sets up isolation)
from tools import testdata

EXTENDED = testdata.locate('ext-part-test-2.dd') or 'ext-part-test-2.dd'
PLAIN = testdata.locate('8-jpeg-search.dd') or '8-jpeg-search.dd'


@pytest.mark.skipif(not os.path.exists(EXTENDED),
                    reason='ext-part-test-2.dd not downloaded')
def test_every_sector_belongs_to_one_region_in_disk_order():
    """TSK's slots overlap (extended partitions contain their logical ones
    and tables; sector 0's table sits in an unallocated run): the regions
    do not, and add up to the image exactly."""
    from trace_app.core import disk_layout
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(EXTENDED)
    try:
        regions = disk_layout.regions(handler)
        assert sum(r['sectors'] for r in regions) * 512 == handler.get_size()
        for before, after in zip(regions, regions[1:]):
            assert before['start'] + before['sectors'] == after['start']
        labels = [disk_layout.label(r) for r in regions]
        assert labels[:3] == ['Partition table', 'Unallocated',
                              'FAT16 volume']
        assert labels.count('FAT16 volume') == 6
        assert labels.count('Partition table') == 3      # MBR + 2 EBRs
        assert not any('Extended' in label for label in labels)
    finally:
        handler.close_resources()


@pytest.mark.skipif(not os.path.exists(PLAIN),
                    reason='8-jpeg-search.dd not downloaded')
def test_an_unpartitioned_image_is_one_volume():
    from trace_app.core import disk_layout
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(PLAIN)
    try:
        [region] = disk_layout.regions(handler)
        assert disk_layout.label(region) == 'NTFS volume'
        assert region['bytes'] == handler.get_size()
    finally:
        handler.close_resources()


def test_tiny_regions_are_drawn_and_shares_stay_true(qapp):
    from trace_app.ui.widgets import disk_map
    regions = [{'kind': 'table', 'start': 0, 'sectors': 1, 'bytes': 512,
                'name': None, 'slot': 0, 'description': 'Primary Table',
                'encryption': None},
               {'kind': 'volume', 'start': 1, 'sectors': 10 ** 9,
                'bytes': 512 * 10 ** 9, 'name': 'NTFS', 'slot': 1,
                'description': 'NTFS', 'encryption': None}]
    fractions = disk_map._fractions(regions, 3 / 360)
    assert fractions[0] == pytest.approx(3 / 360)
    assert sum(fractions) == pytest.approx(1)
    assert disk_map.share_text(100 * 512 / (512 * 10 ** 9)) == '< 0.01%'
    view = disk_map.DiskMap()
    view.resize(700, 320)
    view.set_regions(regions)
    view.show()
    try:
        assert view.table.item(0, 0).text() == 'Partition table'
        assert view.table.item(0, 2).text() == '< 0.01%'
        # The sliver is there to point at, on the platter and the bar.
        start, sweep = view.platter._spans[0]
        assert abs(sweep) == pytest.approx(3.0)
        assert view.bar._cells[0][0].width() >= disk_map.MIN_BAR_PIXELS - 0.01
        # Choosing a region marks it everywhere.
        view.select(1)
        assert view.platter.highlight == 1 and view.bar.highlight == 1
        assert 'Sectors 1 –' in disk_map.describe(regions[1], 512 + 512e9)
        # Zoomed to the one-sector table, it fills a third of the bar.
        view.bar.zoom_to(0)
        lo, hi = view.bar.span()
        assert hi - lo == view.bar.MIN_SPAN and lo == 0
        [(cell, index)] = [c for c in view.bar._cells if c[1] == 0]
        assert cell.width() > view.bar.width() / 10
        assert 'of the disk' in view.caption.text()
        view.bar.zoom(0.5)                      # out
        assert view.bar.span()[1] - view.bar.span()[0] == 16
        view.fit_button.click()
        assert view.bar.window is None
        assert view.caption.text().startswith('Whole disk')
    finally:
        view.close()
        view.deleteLater()


@pytest.mark.skipif(not os.path.exists(EXTENDED),
                    reason='ext-part-test-2.dd not downloaded')
def test_the_image_information_window_draws_the_disk(qapp, monkeypatch):
    from PySide6.QtWidgets import QDialog
    from trace_app.ui.main_window import MainWindow
    window = MainWindow()
    shown = []
    monkeypatch.setattr(QDialog, 'exec',
                        lambda dialog: shown.append(dialog) or 0)
    try:
        assert window.open_evidence_image(EXTENDED)
        window.show_image_information_for(EXTENDED)
        assert shown
        disk = window.disk_map
        assert disk.table.rowCount() == len(disk.regions) == 13
        assert disk.platter._spans and disk.bar.regions
    finally:
        window.cleanup_resources()
