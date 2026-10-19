"""The picture viewer's and the player's examiner tools, offscreen.

Pictures are generated; the video is a CI clip (VP9test.webm, CC0) and
the sound a WAV written here, so every expected value is known: the pixel
under a point, the bytes Save Image writes (the file's, unchanged
whatever the view), what an adjusted view's audit line names, the label a
bookmarked moment gets, the frames a contact sheet holds, and the
waveform's peaks.
"""

import hashlib
import io
import math
import os
import struct
import wave

import pytest

from tests.conftest import image_path, pump


@pytest.fixture
def audit():
    """What the audited writers record (evidence_export.set_recorder)."""
    from trace_app.core import evidence_export
    lines = []
    evidence_export.set_recorder(lambda what, detail: lines.append(
        (what, detail)))
    yield lines
    evidence_export.set_recorder(None)


def _jpeg(width=64, height=48, orientation=None):
    from PIL import Image
    image = Image.new('RGB', (width, height), (10, 20, 30))
    image.putpixel((5, 6), (200, 100, 50))
    buffer = io.BytesIO()
    options = {}
    if orientation:
        exif = Image.Exif()
        exif[0x0112] = orientation
        options['exif'] = exif
    image.save(buffer, 'PNG' if orientation is None else 'JPEG', **options)
    return buffer.getvalue()


@pytest.fixture
def picture_viewer(qapp):
    from trace_app.ui.viewers.media.picture import PictureViewer
    viewer = PictureViewer()
    viewer.resize(700, 500)
    viewer.show()
    yield viewer
    viewer.shutdown()
    viewer.deleteLater()


def test_the_pixel_readout_is_the_files_colour(qapp, picture_viewer):
    from PySide6.QtCore import QPoint
    viewer = picture_viewer
    assert viewer.display(_jpeg()) == ''
    assert pump(qapp, 5, lambda: 'PNG' in viewer.facts_label.text())
    viewer._hovered(QPoint(5, 6))
    assert 'x 5  y 6  RGB(200, 100, 50) #C86432' in viewer.pixel_label.text()
    point = viewer.canvas.image_point(viewer.canvas.transform().map(
        QPoint(5, 6)) + QPoint(0, 0))
    assert (point.x(), point.y()) == (5, 6)


def test_an_adjusted_view_says_so_and_save_image_writes_the_file(
        qapp, picture_viewer, tmp_path, audit, monkeypatch):
    from PySide6.QtWidgets import QFileDialog
    from trace_app.ui.dialogs import message
    viewer = picture_viewer
    data = _jpeg(64, 32, orientation=6)
    viewer.source_name = 'IMG_0001.JPG'
    viewer.display(data)
    assert pump(qapp, 5, lambda: viewer.upright_action.isEnabled())
    viewer.upright_action.setChecked(True)
    assert pump(qapp, 5, lambda: bool(viewer._parts))
    assert (viewer._shown.width(), viewer._shown.height()) == (32, 64)
    assert not viewer._derived          # turned, still the file's pixels
    viewer.adjust_panel.sliders['contrast'].setValue(150)
    assert pump(qapp, 5, lambda: viewer._derived)
    assert "not the file's pixels" in viewer.view_badge.text()
    assert 'contrast 1.50' in viewer.view_badge.text()

    monkeypatch.setattr(message, 'information', lambda *a, **k: None)
    original = tmp_path / 'original.jpg'
    monkeypatch.setattr(QFileDialog, 'getSaveFileName',
                        lambda *a, **k: (str(original), ''))
    viewer.export_original_image()
    assert hashlib.sha256(original.read_bytes()).digest() == \
        hashlib.sha256(data).digest()

    view = tmp_path / 'view.png'
    monkeypatch.setattr(QFileDialog, 'getSaveFileName',
                        lambda *a, **k: (str(view), ''))
    viewer.save_view()
    assert view.exists()
    what, detail = audit[-1]
    assert what == 'picture view saved'
    assert "not the file's bytes" in detail
    assert 'turned upright' in detail and 'contrast 1.50' in detail

    viewer.adjust_panel.reset()
    viewer.upright_action.setChecked(False)
    assert pump(qapp, 5, lambda: not viewer.view_badge.isVisible())


def test_a_region_is_exported_and_bookmarked(qapp, picture_viewer, tmp_path,
                                             audit, monkeypatch):
    from PySide6.QtCore import QRect
    from PySide6.QtGui import QImage
    from PySide6.QtWidgets import QFileDialog
    from trace_app.ui.dialogs import message
    viewer = picture_viewer
    viewer.source_name = 'scan.png'
    viewer.display(_jpeg())
    labels = []
    viewer.bookmark_hook = labels.append
    viewer.canvas.selection = QRect(4, 5, 10, 8)
    viewer.bookmark_region()
    assert labels == ['scan: region x 4, y 5, 10 × 8 px']
    monkeypatch.setattr(message, 'information', lambda *a, **k: None)
    target = tmp_path / 'region.png'
    monkeypatch.setattr(QFileDialog, 'getSaveFileName',
                        lambda *a, **k: (str(target), ''))
    viewer.export_region()
    region = QImage(str(target))
    assert (region.width(), region.height()) == (10, 8)
    assert region.pixelColor(1, 1).getRgb()[:3] == (200, 100, 50)
    assert audit[-1][0] == 'picture region exported'
    assert 'region x 4, y 5, 10 × 8 px' in audit[-1][1]


def test_animation_frames_step(qapp, picture_viewer):
    from PIL import Image
    frames = [Image.new('RGB', (16, 16), colour) for colour in
              ((255, 0, 0), (0, 255, 0), (0, 0, 255))]
    buffer = io.BytesIO()
    frames[0].save(buffer, 'GIF', save_all=True, append_images=frames[1:],
                   duration=120, loop=0)
    viewer = picture_viewer
    viewer.display(buffer.getvalue())
    assert pump(qapp, 5, lambda: viewer.frame_count() == 3)
    assert viewer.next_frame_action.isVisible()
    viewer.show_frame(2)
    assert pump(qapp, 5, lambda: viewer._parts == ['frame 3'])
    assert viewer._shown.pixelColor(3, 3).getRgb()[:3] == (0, 0, 255)
    assert 'Frame 3 of 3' in viewer.frame_label.text()


# --- the player ------------------------------------------------------------

def test_positions_typed_by_the_examiner():
    from trace_app.ui.viewers.media.audiovideo import (frame_number,
                                                       parse_position)
    assert parse_position('83.4', 25) == 83400
    assert parse_position('01:23.4', 25) == 83400
    assert parse_position('1:02:03', 25) == 3723000
    assert parse_position('f2071', 25) == 82840
    assert parse_position('#50', 25) == 2000
    assert parse_position('1:75', 25) is None
    assert parse_position('soon', 25) is None
    assert frame_number(2000, 29.97) == 59
    assert frame_number(1000, 25) == 25


@pytest.fixture
def video(qapp):
    from trace_app.ui.viewers.media import UnifiedViewer
    with open(image_path('VP9test.webm'), 'rb') as handle:
        content = handle.read()
    viewer = UnifiedViewer()
    viewer.resize(900, 400)
    viewer.show()
    viewer.display_application_content(content, 'VP9test.webm')
    player = viewer._audio_video_player
    assert pump(qapp, 10, lambda: player._first_frame is not None)
    pump(qapp, 0.3)
    yield viewer, player, content
    viewer.shutdown()
    viewer.deleteLater()


def test_a_marked_moment_becomes_a_bookmark_label(qapp, video):
    viewer, player, _content = video
    labels = []
    viewer.bookmark_hook = labels.append
    player.media_player.setPosition(1000)
    assert pump(qapp, 5, lambda: player.media_player.position() == 1000)
    player.add_marker('car turns')
    assert player.markers == [(1000, 'car turns')]
    assert player.position_slider.markers == [1000]
    player.marker_list.setCurrentRow(0)
    player.bookmark_moment()
    assert labels == ['VP9test.webm @ 00:01.0 (frame 25) — car turns']
    assert 'f 25' in player.current_time_label.text()


def test_the_container_says_the_frame_rate(qapp, video):
    _viewer, player, _content = video
    rate, source = player.frame_rate_and_source()
    assert source in ('container', 'decoder')
    assert round(rate) == 25
    assert 'Matroska' in player.info_text() or 'WebM' in player.info_text()
    # A section per track, each fact on its own row.
    rows = [player.info_view.item(row, 0).text()
            for row in range(player.info_view.rowCount())]
    assert 'Video track · V_VP9' in rows and 'Size' in rows


def test_a_contact_sheet_holds_the_frames_asked_for(qapp, video, tmp_path,
                                                    audit, monkeypatch):
    from PySide6.QtGui import QImage
    from PySide6.QtWidgets import QFileDialog, QInputDialog
    _viewer, player, content = video
    monkeypatch.setattr(QInputDialog, 'getInt', lambda *a, **k: (4, True))
    target = tmp_path / 'sheet.png'
    monkeypatch.setattr(QFileDialog, 'getSaveFileName',
                        lambda *a, **k: (str(target), ''))
    player.make_contact_sheet()
    assert pump(qapp, 30, lambda: player.last_sheet is not None)
    sheet = player.last_sheet
    assert sheet['frames'] == 4 and sheet['missing'] == 0
    assert sheet['file_sha256'] == hashlib.sha256(content).hexdigest()
    assert hashlib.sha256(target.read_bytes()).hexdigest() == sheet['sha256']
    picture = QImage(str(target))
    assert picture.width() > 4 * 300          # four columns of frames
    assert audit[-1][0] == 'contact sheet saved'
    assert '4 frames spread evenly' in audit[-1][1]


def test_frames_export_with_a_manifest(qapp, video, tmp_path, audit,
                                       monkeypatch):
    import csv
    from PySide6.QtWidgets import QDialog, QFileDialog
    from trace_app.ui.viewers.media import audiovideo
    _viewer, player, _content = video
    monkeypatch.setattr(audiovideo._ExportFramesDialog, 'exec',
                        lambda self: (self.start.setText('0'),
                                      self.end.setText('2'),
                                      self.every.setValue(1),
                                      QDialog.Accepted)[-1])
    monkeypatch.setattr(QFileDialog, 'getExistingDirectory',
                        lambda *a, **k: str(tmp_path))
    player.export_frames()
    assert pump(qapp, 30, lambda: audit and
                audit[-1][0] == 'video frames exported')
    folder = tmp_path / 'VP9test frames'
    with open(folder / 'manifest.csv', newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    assert [row['time asked'] for row in rows] == ['00:00.0', '00:01.0',
                                                   '00:02.0']
    for row in rows:
        assert hashlib.sha256((folder / row['file']).read_bytes()) \
            .hexdigest() == row['sha256']


def test_save_frame_is_audited(qapp, video, tmp_path, audit):
    _viewer, player, _content = video
    saved = player.save_frame(str(tmp_path / 'frame.png'))
    assert saved and os.path.exists(saved)
    what, detail = audit[-1]
    assert what == 'video frame saved'
    assert 'VP9test.webm @ 00:00.0 (frame 0), as decoded' in detail


def test_a_paused_frame_is_adjusted_and_says_so(qapp, video):
    _viewer, player, _content = video
    player.adjust_panel.sliders['brightness'].setValue(160)
    assert pump(qapp, 5, lambda: bool(player._adjusted_steps))
    assert player.view_badge.isVisible()
    assert 'brightness 1.60' in player.view_badge.text()
    assert player.save_adjusted_button.isEnabled()
    player.adjust_panel.reset()
    assert pump(qapp, 2, lambda: not player.view_badge.isVisible())


def _sine_wav(seconds=2, rate=8000):
    """Silence for the first second, then a sine at 3/4 of full scale."""
    out = io.BytesIO()
    with wave.open(out, 'wb') as writer:
        writer.setnchannels(1)
        writer.setsampwidth(2)
        writer.setframerate(rate)
        frames = bytearray()
        for index in range(seconds * rate):
            value = 0 if index < rate else \
                int(24576 * math.sin(2 * math.pi * 440 * index / rate))
            frames += struct.pack('<h', value)
        writer.writeframes(bytes(frames))
    return out.getvalue()


def test_the_waveform_is_the_sounds_loudness(qapp):
    from trace_app.ui.viewers.media import UnifiedViewer
    from trace_app.ui.viewers.media.waveform import BUCKET_MS
    viewer = UnifiedViewer()
    viewer.resize(800, 300)
    viewer.show()
    try:
        viewer.display_application_content(_sine_wav(), 'tone.wav')
        player = viewer._audio_video_player
        assert pump(qapp, 10, lambda: len(player.waveform.decoded()) >=
                    1900 // BUCKET_MS)
        assert pump(qapp, 5, lambda: player.waveform._state == '')
        pairs = player.waveform.decoded()
        quiet = pairs[:1000 // BUCKET_MS - 5]
        loud = pairs[1000 // BUCKET_MS + 5:]
        assert max(max(abs(low), abs(high)) for low, high in quiet) < 200
        assert all(high > 20000 and low < -20000 for low, high in loud)
        assert player.waveform.isVisibleTo(viewer)
    finally:
        viewer.shutdown()
        viewer.deleteLater()


def test_reduce_samples_carries_what_is_left():
    from array import array
    from trace_app.ui.viewers.media.waveform import _SAMPLES, reduce_samples
    carry = array('h')
    first = struct.pack(f'<{_SAMPLES + 3}h', *([5] * _SAMPLES + [-7, 9, 1]))
    assert reduce_samples(first, carry) == [(5, 5)]
    assert list(carry) == [-7, 9, 1]
    rest = struct.pack(f'<{_SAMPLES - 3}h', *([0] * (_SAMPLES - 3)))
    assert reduce_samples(rest, carry) == [(-7, 9)]
