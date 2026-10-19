"""The Adjust controls shared by the picture viewer and the video player's
paused frame: brightness, contrast, gamma, equalised levels, invert, one
channel (core/image_forensics.adjust does the work).

What they make is a view. Each viewer says so beside the picture while
any of them is off neutral, and Save Image still writes the file's bytes.
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFormLayout, QHBoxLayout,
                               QLabel, QPushButton, QSlider, QVBoxLayout,
                               QWidget)

from trace_app.core.image_forensics import CHANNELS, NEUTRAL

#: (key, label, lowest, highest) of each slider, in hundredths.
SLIDERS = (('brightness', "Brightness", 10, 400),
           ('contrast', "Contrast", 10, 400),
           ('gamma', "Gamma", 20, 500))


class AdjustPanel(QWidget):
    """Sliders and switches; `changed(settings)` on every change."""

    changed = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("imageAdjustPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)
        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        form.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.sliders = {}
        self.readouts = {}
        for key, label, low, high in SLIDERS:
            slider = QSlider(Qt.Horizontal, self)
            slider.setObjectName(f"adjust_{key}")
            slider.setRange(low, high)
            slider.setValue(100)
            slider.setPageStep(10)
            slider.setToolTip(f"{label}: 1.00 is the file as stored. "
                              "Double-click the value to reset it.")
            readout = QLabel("1.00", self)
            readout.setObjectName("adjustReadout")
            readout.setMinimumWidth(36)
            readout.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            slider.valueChanged.connect(self._slid)
            row = QHBoxLayout()
            row.setContentsMargins(0, 0, 0, 0)
            row.addWidget(slider, 1)
            row.addWidget(readout)
            form.addRow(label, row)
            self.sliders[key] = slider
            self.readouts[key] = readout
        self.channel = QComboBox(self)
        self.channel.setObjectName("adjustChannel")
        for key, label in CHANNELS:
            self.channel.addItem(label, key)
        self.channel.setToolTip(
            "Show one channel alone. Alpha only shows what transparency "
            "hides: pixels a transparent layer still holds.")
        self.channel.currentIndexChanged.connect(self._emit)
        form.addRow("Channel", self.channel)
        layout.addLayout(form)
        self.equalise = QCheckBox("Equalise levels", self)
        self.equalise.setToolTip(
            "Spread the picture's levels over the whole range: detail in "
            "a dark or washed-out picture becomes visible.")
        self.equalise.toggled.connect(self._emit)
        self.invert = QCheckBox("Invert", self)
        self.invert.toggled.connect(self._emit)
        layout.addWidget(self.equalise)
        layout.addWidget(self.invert)
        self.reset_button = QPushButton("Reset", self)
        self.reset_button.setObjectName("adjustReset")
        self.reset_button.setToolTip("Back to the file as stored")
        self.reset_button.clicked.connect(self.reset)
        layout.addWidget(self.reset_button, 0, Qt.AlignLeft)
        note = QLabel("A view only: the file is unchanged, and Save Image "
                      "still writes its bytes as stored.", self)
        note.setObjectName("adjustNote")
        note.setWordWrap(True)
        layout.addWidget(note)
        layout.addStretch(1)
        self._quiet = False

    def settings(self):
        values = {key: slider.value() / 100
                  for key, slider in self.sliders.items()}
        values.update(equalise=self.equalise.isChecked(),
                      invert=self.invert.isChecked(),
                      channel=self.channel.currentData() or 'all')
        return values

    def set_settings(self, settings):
        settings = {**NEUTRAL, **(settings or {})}
        self._quiet = True
        try:
            for key, slider in self.sliders.items():
                slider.setValue(round(settings[key] * 100))
            self.equalise.setChecked(bool(settings['equalise']))
            self.invert.setChecked(bool(settings['invert']))
            index = self.channel.findData(settings['channel'])
            self.channel.setCurrentIndex(max(0, index))
        finally:
            self._quiet = False
        self._emit()

    def reset(self):
        self.set_settings(NEUTRAL)

    def _slid(self, _value):
        for key, slider in self.sliders.items():
            self.readouts[key].setText(f"{slider.value() / 100:.2f}")
        self._emit()

    def _emit(self, *_args):
        if not self._quiet:
            self.changed.emit(self.settings())
