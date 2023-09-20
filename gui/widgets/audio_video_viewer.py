from ctypes import cast, POINTER

from PySide6.QtCore import Qt, QUrl, Slot
from PySide6.QtMultimedia import QMediaPlayer, QAudioOutput
from PySide6.QtMultimediaWidgets import QVideoWidget
from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QSlider, QStyle, QLabel, QHBoxLayout, QComboBox, \
    QSpacerItem, QSizePolicy
from comtypes import CLSCTX_ALL
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume


class AudioVideoViewer(QWidget):
    def __init__(self, parent=None):
        super(AudioVideoViewer, self).__init__(parent)

        # Initialize the volume control interface once
        devices = AudioUtilities.GetSpeakers()
        self.volume_interface = devices.Activate(
            IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        self.volume = cast(self.volume_interface, POINTER(IAudioEndpointVolume))

        self.layout = QVBoxLayout(self)

        self._audio_output = QAudioOutput()
        self._player = QMediaPlayer()
        self._player.setAudioOutput(self._audio_output)

        self._video_widget = QVideoWidget(self)
        self.layout.addWidget(self._video_widget)
        self._player.setVideoOutput(self._video_widget)

        # Progress layout
        self.progress_layout = QHBoxLayout()

        # Progress Slider
        self.progress_slider = QSlider(Qt.Horizontal, self)
        self.progress_slider.setToolTip("Progress")
        self.progress_slider.setRange(0, self._player.duration())
        self.progress_slider.sliderMoved.connect(self.set_media_position)
        self.progress_slider.mousePressEvent = self.slider_clicked
        self.progress_layout.addWidget(self.progress_slider)

        # Progress label
        self.progress_label = QLabel("00:00", self)
        self.progress_layout.addWidget(self.progress_label)

        self.layout.addLayout(self.progress_layout)

        # Controls layout
        self.controls_layout = QHBoxLayout()

        # Spacer to push media control buttons to the center
        self.controls_layout.addSpacerItem(QSpacerItem(20, 10, QSizePolicy.Expanding, QSizePolicy.Minimum))

        # Volume label
        self.controls_layout.addWidget(QLabel("Volume"))

        # Volume slider
        self.volume_slider = QSlider(Qt.Horizontal, self)
        self.volume_slider.setToolTip("Volume")
        self.volume_slider.setRange(0, 100)
        self.volume_slider.setValue(self.get_system_volume())
        self.volume_slider.setFixedWidth(150)
        self.volume_slider.valueChanged.connect(self.update_volume_display)
        self.volume_slider.valueChanged.connect(self.set_volume)
        self.controls_layout.addWidget(self.volume_slider)

        # Volume display label
        self.volume_display = QLabel(f"{self.get_system_volume()}%", self)
        self.volume_display.setToolTip("Volume Percentage")
        self.controls_layout.addWidget(self.volume_display)

        # Spacer to separate media controls and volume controls
        self.controls_layout.addSpacerItem(QSpacerItem(370, 10, QSizePolicy.Fixed, QSizePolicy.Minimum))

        # Media control buttons
        self.play_btn = QPushButton(self)
        self.play_btn.setToolTip("Play")
        self.play_btn.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        self.play_btn.clicked.connect(self._player.play)
        self.controls_layout.addWidget(self.play_btn)

        self.pause_btn = QPushButton(self)
        self.pause_btn.setToolTip("Pause")
        self.pause_btn.setIcon(self.style().standardIcon(QStyle.SP_MediaPause))
        self.pause_btn.clicked.connect(self._player.pause)
        self.controls_layout.addWidget(self.pause_btn)

        self.stop_btn = QPushButton(self)
        self.stop_btn.setToolTip("Stop")
        self.stop_btn.setIcon(self.style().standardIcon(QStyle.SP_MediaStop))
        self.stop_btn.clicked.connect(self._player.stop)
        self.controls_layout.addWidget(self.stop_btn)

        # Spacer to separate volume controls and speed controls
        self.controls_layout.addSpacerItem(QSpacerItem(370, 10, QSizePolicy.Fixed, QSizePolicy.Minimum))

        # Speed label
        self.controls_layout.addWidget(QLabel("Speed"))

        # Playback speed dropdown
        self.playback_speed_combo = QComboBox(self)
        self.playback_speed_combo.setToolTip("Playback Speed")
        speeds = ["0.25x", "0.5x", "0.75x", "1.0x", "1.25x", "1.5x", "1.75x", "2.0x"]
        self.playback_speed_combo.addItems(speeds)
        self.playback_speed_combo.setCurrentText("1.0x")
        self.playback_speed_combo.currentTextChanged.connect(self.change_playback_speed)
        self.controls_layout.addWidget(self.playback_speed_combo)

        # Spacer to push speed controls to the right
        self.controls_layout.addSpacerItem(QSpacerItem(20, 10, QSizePolicy.Expanding, QSizePolicy.Minimum))

        self.layout.addLayout(self.controls_layout)

        self._player.positionChanged.connect(self.update_position)
        self._player.positionChanged.connect(self.update_slider_position)
        self._player.durationChanged.connect(self.update_duration)

    def display(self, content, file_type="video"):
        self.playback_speed_combo.setCurrentText("1.0x")
        self._player.setPlaybackRate(1.0)
        self._player.setSource(QUrl.fromLocalFile(content))
        self._player.play()

    def update_position(self, position):
        self.progress_label.setText("{:02d}:{:02d}".format(position // 60000, (position // 1000) % 60))

    def update_duration(self, duration):
        self.progress_slider.setRange(0, duration)
        self.progress_label.setText("{:02d}:{:02d} / {:02d}:{:02d}".format(self._player.position() // 60000,
                                                                           (self._player.position() // 1000) % 60,
                                                                           duration // 60000,
                                                                           (duration // 1000) % 60))

    def clear(self):
        self._player.stop()


    def change_playback_speed(self, speed_text):
        speed = float(speed_text.replace("x", ""))
        self._player.setPlaybackRate(speed)

    def update_slider_position(self, position):
        self.progress_slider.setValue(position)

    def set_media_position(self, position):
        self._player.setPosition(position)

    def slider_clicked(self, event):
        # Update the slider position when clicked
        new_value = int(event.x() / self.progress_slider.width() * self.progress_slider.maximum())

        # Ensure the value is within range
        new_value = max(0, min(new_value, self.progress_slider.maximum()))

        self.progress_slider.setValue(new_value)
        self.set_media_position(new_value)

    def get_system_volume(self):
        """Return the current system volume as a value between 0 and 100."""
        current_volume = self.volume.GetMasterVolumeLevelScalar()
        return int(current_volume * 100)

    @Slot(int)
    def set_volume(self, value):
        """Set the system volume based on the slider's value."""
        self.volume.SetMasterVolumeLevelScalar(value / 100.0, None)

    @Slot(int)
    def set_position(self, position):
        """Set the position of the media playback based on the slider's position."""
        self._player.setPosition(position)

    @Slot(int)
    def update_slider_position(self, position):
        """Update the slider's position based on the media's playback position."""
        self.progress_slider.setValue(position)

    @Slot(int)
    def update_volume_display(self, value):
        """Update the volume display label based on the slider's value."""
        self.volume_display.setText(f"{value}%")
