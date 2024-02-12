import os
import tempfile
from ctypes import cast, POINTER
from fitz import open as fitz_open, Matrix


from PySide6.QtCore import Qt, QUrl, Slot, QByteArray, QBuffer, QTemporaryFile

from PySide6.QtGui import QIcon, QPixmap, QImage, QAction, QPageLayout
from PySide6.QtGui import QTransform
from PySide6.QtMultimedia import QMediaPlayer, QAudioOutput
from PySide6.QtMultimediaWidgets import QVideoWidget
from PySide6.QtPrintSupport import QPrinter, QPrintDialog
from PySide6.QtWidgets import (QToolBar, QMessageBox, QScrollArea, QLineEdit, QFileDialog)
from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QSlider, QStyle, QLabel, QHBoxLayout, QComboBox, \
    QSpacerItem, QSizePolicy
from comtypes import CLSCTX_ALL
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume


class UnifiedViewer(QWidget):
    def __init__(self, parent=None):
        super(UnifiedViewer, self).__init__(parent)

        self.layout = QVBoxLayout(self)

        # Initialize the viewers
        self.pdf_viewer = PDFViewer()
        self.picture_viewer = PictureViewer(self)
        self.audio_video_viewer = AudioVideoViewer(self)

        # Add the viewers to the layout
        self.layout.addWidget(self.pdf_viewer)
        self.layout.addWidget(self.picture_viewer)
        self.layout.addWidget(self.audio_video_viewer)

        # Hide all viewers initially
        self.pdf_viewer.hide()
        self.picture_viewer.hide()
        self.audio_video_viewer.hide()

    def load(self, content, file_type="text", file_extension=".txt"):
        # Clear all views first
        self.pdf_viewer.clear()
        self.picture_viewer.clear()
        self.audio_video_viewer.clear()

        # Determine content type and show the appropriate viewer
        if file_type == "text":
            if content.startswith(b"%PDF"):
                self.picture_viewer.hide()
                self.audio_video_viewer.hide()
                self.pdf_viewer.show()
                self.pdf_viewer.display(content)
            else:
                self.pdf_viewer.hide()
                self.audio_video_viewer.hide()
                self.picture_viewer.show()
                self.picture_viewer.display(content)
        elif file_type == "audio" or file_type == "video":
            self.pdf_viewer.hide()
            self.picture_viewer.hide()
            self.audio_video_viewer.show()

            # Save content to a temporary file
            # temp_file_path = os.path.join(os.getcwd(), f'temp/temp_media_file{file_extension}')
            #
            # with open(temp_file_path, 'wb') as f:
            #     f.write(content)
            #
            # # Pass the path to AudioVideoViewer's display method
            # self.audio_video_viewer.display(temp_file_path)

            # temp_file = QTemporaryFile(f"{file_name}{file_extension}")
            # if temp_file.open():
            #     temp_file.write(content)
            #     temp_file_path = temp_file.fileName()  # Get the path of the temporary file
            #     temp_file.close()  # Close the file (in this case, the file remains until the QTemporaryFile object is deleted)
            #
            #     # Pass the path to AudioVideoViewer's display method
            #     self.audio_video_viewer.display(temp_file_path)

            with tempfile.NamedTemporaryFile(delete=False, suffix=file_extension) as tmp_file:
                tmp_file.write(content)
                temp_file_path = tmp_file.name  # Save the temporary file path

                # Make sure to display the correct viewer and pass the file path
            self.audio_video_viewer.display(temp_file_path)

    def clear(self):
        self.pdf_viewer.clear()
        self.picture_viewer.clear()
        self.audio_video_viewer.clear()


class PictureViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.original_pixmap = None  # Store the original QPixmap
        self.original_image_bytes = None  # Store the original image bytes
        self.initialize_ui()

    def initialize_ui(self):
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        self.layout.setAlignment(Qt.AlignCenter)

        # Create a container for the toolbar and the application viewer
        container_widget = QWidget(self)
        container_widget.setStyleSheet("border: none; margin: 0px; padding: 0px;")  # Set style for the container widget

        container_layout = QVBoxLayout()
        container_layout.setContentsMargins(0, 0, 0, 0)  # Remove any margins
        container_layout.setSpacing(0)  # Remove spacing between toolbar and viewer

        # Create and set up the toolbar
        self.setup_toolbar()

        # Add the toolbar to the container layout
        container_layout.addWidget(self.toolbar)

        self.image_label = QLabel(self)
        self.image_label.setContentsMargins(0, 0, 0, 0)
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setStyleSheet("border: none; margin: 0px; padding: 0px;")

        self.scroll_area = QScrollArea(self)
        self.scroll_area.setContentsMargins(0, 0, 0, 0)
        self.scroll_area.setStyleSheet("border: none; margin: 0px; padding: 0px;")
        self.scroll_area.setWidget(self.image_label)
        self.scroll_area.setWidgetResizable(True)

        container_layout.addWidget(self.scroll_area)
        container_widget.setLayout(container_layout)
        self.layout.addWidget(container_widget)
        self.setLayout(self.layout)

    def setup_toolbar(self):
        self.toolbar = QToolBar(self)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.toolbar.setStyleSheet("QToolBar { background-color: lightgray; border: 0px solid gray; }")

        # Create actions for the toolbar
        zoom_in_icon = QIcon("gui/nav_icons/icons8-zoom-in-50.png")
        zoom_out_icon = QIcon("gui/nav_icons/icons8-zoom-out-50.png")
        rotate_left_icon = QIcon("gui/nav_icons/icons8-rotate-left-50.png")
        rotate_right_icon = QIcon("gui/nav_icons/icons8-rotate-right-50.png")
        reset_icon = QIcon("gui/nav_icons/icons8-no-rotation-50.png")
        export_icon = QIcon("gui/nav_icons/icons8-download-50.png")

        zoom_in_action = QAction(zoom_in_icon, 'Zoom In', self)
        zoom_out_action = QAction(zoom_out_icon, 'Zoom Out', self)
        rotate_left_action = QAction(rotate_left_icon, 'Rotate Left', self)
        rotate_right_action = QAction(rotate_right_icon, 'Rotate Right', self)
        reset_action = QAction(reset_icon, 'Reset', self)
        self.export_action = QAction(export_icon, 'Export Image', self)

        zoom_in_action.triggered.connect(self.zoom_in)
        zoom_out_action.triggered.connect(self.zoom_out)
        rotate_left_action.triggered.connect(self.rotate_left)
        rotate_right_action.triggered.connect(self.rotate_right)
        reset_action.triggered.connect(self.reset)
        self.export_action.triggered.connect(self.export_original_image)

        # Add actions to the toolbar
        self.toolbar.addAction(zoom_in_action)
        self.toolbar.addAction(zoom_out_action)
        self.toolbar.addAction(rotate_left_action)
        self.toolbar.addAction(rotate_right_action)
        self.toolbar.addAction(reset_action)
        self.toolbar.addAction(self.export_action)

    def display(self, content):
        self.original_image_bytes = content  # Save the original image bytes
        # Convert byte data to QPixmap
        qt_image = QImage.fromData(content)
        pixmap = QPixmap.fromImage(qt_image)
        self.original_pixmap = pixmap.copy()  # Save the original pixmap
        self.image_label.setPixmap(pixmap)

    def clear(self):
        self.image_label.clear()

    def zoom_in(self):
        self.image_label.setPixmap(self.image_label.pixmap().scaled(
            self.image_label.width() * 1.2, self.image_label.height() * 1.2, Qt.KeepAspectRatio,
            Qt.SmoothTransformation))

    def zoom_out(self):
        self.image_label.setPixmap(self.image_label.pixmap().scaled(
            self.image_label.width() * 0.8, self.image_label.height() * 0.8, Qt.KeepAspectRatio,
            Qt.SmoothTransformation))

    def rotate_left(self):
        transform = QTransform().rotate(-90)
        pixmap = self.image_label.pixmap().transformed(transform)
        self.image_label.setPixmap(pixmap)

    def rotate_right(self):
        transform = QTransform().rotate(90)
        pixmap = self.image_label.pixmap().transformed(transform)
        self.image_label.setPixmap(pixmap)

    def reset(self):
        if self.original_pixmap:
            self.image_label.setPixmap(self.original_pixmap)

    def export_original_image(self):
        # Ensure that an image is currently loaded
        if not self.original_image_bytes:
            QMessageBox.warning(self, "Export Error", "No image is currently loaded.")
            return

        # Ask the user where to save the exported image
        file_name, _ = QFileDialog.getSaveFileName(self, "Export Image", "",
                                                   "PNG (*.png);;JPEG (*.jpg *.jpeg);;All Files (*)")

        # If a location is chosen, save the image
        if file_name:
            with open(file_name, 'wb') as f:
                f.write(self.original_image_bytes)
            QMessageBox.information(self, "Export Success", "Image exported successfully!")


class PDFViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pdf = None
        self.current_page = 0
        self.zoom_factor = 1.0  # Initialize the zoom factor here
        self.rotation_angle = 0
        self.is_panning = False
        self.pan_start_x = 0
        self.pan_start_y = 0
        self.pan_mode = False

        self.initialize_ui()
        if self.pdf:
            self.show_page(self.current_page)

    def initialize_ui(self):
        # Set up the main layout
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        self.layout.setAlignment(Qt.AlignCenter)

        # Create a container for the toolbar and the application viewer
        container_widget = QWidget(self)
        container_layout = QVBoxLayout()
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(0)

        # Create and set up the toolbar
        self.setup_toolbar()

        # Add the toolbar to the container layout
        container_layout.addWidget(self.toolbar)

        # Set up the PDF display area
        self.setup_pdf_display_area()
        container_layout.addWidget(self.scroll_area)

        container_widget.setLayout(container_layout)
        self.layout.addWidget(container_widget)

        self.setLayout(self.layout)
        self.update_navigation_states()

    def setup_toolbar(self):
        self.toolbar = QToolBar(self)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.toolbar.setStyleSheet("QToolBar { background-color: lightgray; border: 0px solid gray; }")

        # Navigation buttons
        self.first_action = QAction(QIcon("gui/nav_icons/icons8-thick-arrow-pointing-up-50.png"), "First", self)
        self.first_action.triggered.connect(self.show_first_page)
        self.toolbar.addAction(self.first_action)

        self.prev_action = QAction(QIcon("gui/nav_icons/icons8-left-arrow-50.png"), "Previous", self)
        self.prev_action.triggered.connect(self.show_previous_page)
        self.toolbar.addAction(self.prev_action)

        # Page entry
        self.page_entry = QLineEdit(self)
        self.page_entry.setMaximumWidth(20)
        self.page_entry.setAlignment(Qt.AlignRight)
        self.page_entry.returnPressed.connect(self.go_to_page)
        self.toolbar.addWidget(self.page_entry)

        # Total pages label
        self.total_pages_label = QLabel(f"of {len(self.pdf)}" if self.pdf else "of 0")
        self.toolbar.addWidget(self.total_pages_label)

        # Navigation buttons
        self.next_action = QAction(QIcon("gui/nav_icons/icons8-right-arrow-50.png"), "Next", self)
        self.next_action.triggered.connect(self.show_next_page)
        self.toolbar.addAction(self.next_action)

        self.last_action = QAction(QIcon("gui/nav_icons/icons8-down-50.png"), "Last", self)
        self.last_action.triggered.connect(self.show_last_page)
        self.toolbar.addAction(self.last_action)

        # Zoom actions
        self.zoom_in_action = QAction(QIcon("gui/nav_icons/icons8-zoom-in-50.png"), "Zoom In", self)
        self.zoom_in_action.triggered.connect(self.zoom_in)
        self.toolbar.addAction(self.zoom_in_action)

        # QLineEdit for zoom percentage
        self.zoom_percentage_entry = QLineEdit(self)
        self.zoom_percentage_entry.setFixedWidth(40)  # Set a fixed width for consistency
        self.zoom_percentage_entry.setAlignment(Qt.AlignRight)
        self.zoom_percentage_entry.setPlaceholderText("100%")  # Default zoom is 100%
        self.zoom_percentage_entry.returnPressed.connect(self.set_zoom_from_entry)
        self.toolbar.addWidget(self.zoom_percentage_entry)

        self.zoom_out_action = QAction(QIcon("gui/nav_icons/icons8-zoom-out-50.png"), "Zoom Out", self)
        self.zoom_out_action.triggered.connect(self.zoom_out)
        self.toolbar.addAction(self.zoom_out_action)

        # Create a reset zoom button with its icon and add it to the toolbar
        reset_zoom_icon = QIcon("gui/nav_icons/icons8-zoom-to-actual-size-50.png")  # Replace with your icon path
        self.reset_zoom_action = QAction(reset_zoom_icon, "Reset Zoom", self)
        self.reset_zoom_action.triggered.connect(self.reset_zoom)
        self.toolbar.addAction(self.reset_zoom_action)

        # Fit in window
        fit_window_icon = QIcon("gui/nav_icons/icons8-enlarge-50.png")  # Replace with your icon path
        self.fit_window_action = QAction(fit_window_icon, "Fit in Window", self)
        self.fit_window_action.triggered.connect(self.fit_window)
        self.toolbar.addAction(self.fit_window_action)

        # Fit in width
        fit_width_icon = QIcon("gui/nav_icons/icons8-resize-horizontal-50.png")  # Replace with your icon path
        self.fit_width_action = QAction(fit_width_icon, "Fit in Width", self)
        self.fit_width_action.triggered.connect(self.fit_width)
        self.toolbar.addAction(self.fit_width_action)

        # Rotate left
        rotate_left_icon = QIcon("gui/nav_icons/icons8-rotate-left-50.png")  # Replace with your icon path
        self.rotate_left_action = QAction(rotate_left_icon, "Rotate Left", self)
        self.rotate_left_action.triggered.connect(self.rotate_left)
        self.toolbar.addAction(self.rotate_left_action)

        # Rotate right
        rotate_right_icon = QIcon("gui/nav_icons/icons8-rotate-right-50.png")  # Replace with your icon path
        self.rotate_right_action = QAction(rotate_right_icon, "Rotate Right", self)
        self.rotate_right_action.triggered.connect(self.rotate_right)
        self.toolbar.addAction(self.rotate_right_action)

        # Pan tool button
        self.pan_tool_icon = QIcon("gui/nav_icons/icons8-drag-50.png")  # Replace with your pan icon path
        self.pan_tool_action = QAction(self.pan_tool_icon, "Pan Tool", self)
        self.pan_tool_action.setCheckable(True)
        self.pan_tool_action.toggled.connect(self.toggle_pan_mode)
        self.toolbar.addAction(self.pan_tool_action)

        # Print button
        self.print_icon = QIcon("gui/nav_icons/icons8-print-50.png")  # Replace with your print icon path
        self.print_action = QAction(self.print_icon, "Print", self)
        self.print_action.triggered.connect(self.print_pdf)
        self.toolbar.addAction(self.print_action)

        self.save_pdf_action = QAction(QIcon("gui/nav_icons/icons8-download-50.png"), "Save PDF", self)
        self.save_pdf_action.triggered.connect(self.save_pdf)
        self.toolbar.addAction(self.save_pdf_action)

    def setup_pdf_display_area(self):
        self.page_label = QLabel(self)
        self.page_label.setContentsMargins(0, 0, 0, 0)
        self.page_label.setAlignment(Qt.AlignCenter)

        self.scroll_area = QScrollArea(self)
        self.scroll_area.setStyleSheet("border: 0px;")
        self.scroll_area.setContentsMargins(0, 0, 0, 0)
        self.scroll_area.setWidget(self.page_label)
        self.scroll_area.setWidgetResizable(True)

    def set_current_page(self, page_num):
        max_pages = len(self.pdf)
        if 0 <= page_num < max_pages:
            self.current_page = page_num
            self.show_page(page_num)

    def go_to_page(self):
        try:
            page_num = int(self.page_entry.text()) - 1  # Minus 1 because pages start from 0
            self.set_current_page(page_num)
        except ValueError:
            QMessageBox.warning(self, "Invalid Page Number", "Please enter a valid page number.")

    def update_navigation_states(self):
        if not self.pdf:
            self.prev_action.setEnabled(False)
            self.next_action.setEnabled(False)
            return

        self.prev_action.setEnabled(self.current_page > 0)
        self.next_action.setEnabled(self.current_page < len(self.pdf) - 1)
        self.total_pages_label.setText(f"of {len(self.pdf)}")
        self.page_entry.setText(str(self.current_page + 1))

    def show_previous_page(self):
        self.set_current_page(self.current_page - 1)
        self.update_navigation_states()

    def show_next_page(self):
        self.set_current_page(self.current_page + 1)
        self.update_navigation_states()

    def show_page(self, page_num):
        try:
            page = self.pdf[page_num]
            mat = Matrix(self.zoom_factor, self.zoom_factor).prerotate(self.rotation_angle)
            image = page.get_pixmap(matrix=mat)

            qt_image = QImage(image.samples, image.width, image.height, image.stride, QImage.Format_RGB888)
            pixmap = QPixmap.fromImage(qt_image)
            self.page_label.setPixmap(pixmap)
            self.update_navigation_states()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to render page: {e}")

    def display(self, content):
        if self.pdf:
            self.pdf.close()
            self.pdf = None

        if content:
            try:
                self.pdf = fitz_open(stream=content, filetype="pdf")
                self.current_page = 0
                self.show_page(self.current_page)
                self.update_navigation_states()
            except Exception as e:
                print(f"Failed to load PDF: {e}")
        else:
            self.page_label.clear()

    def clear(self):
        if self.pdf:
            self.pdf.close()
            self.pdf = None
        self.page_label.clear()

    def show_first_page(self):
        self.set_current_page(0)

    def show_last_page(self):
        self.set_current_page(len(self.pdf) - 1)

    def zoom_in(self):
        self.zoom_factor *= 1.2  # Assuming you have initialized zoom_factor as 1 in your __init__ method
        self.update_zoom()

    def zoom_out(self):
        self.zoom_factor *= 0.8
        self.update_zoom()

    def update_zoom(self):
        # Always zoom on the original high-quality image
        page = self.pdf[self.current_page]
        mat = Matrix(self.zoom_factor, self.zoom_factor)
        image = page.get_pixmap(matrix=mat)

        qt_image = QImage(image.samples, image.width, image.height, image.stride, QImage.Format_RGB888)
        pixmap = QPixmap.fromImage(qt_image)

        self.page_label.setPixmap(pixmap)

    def set_zoom_from_entry(self):
        try:
            # Extract the percentage from the QLineEdit
            percentage = float(self.zoom_percentage_entry.text().strip('%')) / 100
            print(f"Entered Percentage: {percentage}")  # Debug print statement

            if 0.1 <= percentage <= 5:  # Just to ensure reasonable zoom limits, you can adjust these values
                self.zoom_factor = percentage
                self.show_page(self.current_page)
            else:
                QMessageBox.warning(self, "Invalid Zoom", "Please enter a zoom percentage between 10% and 500%.")
        except ValueError:
            QMessageBox.warning(self, "Invalid Zoom", "Please enter a valid zoom percentage.")

    def reset_zoom(self):
        self.zoom_factor = 1.0
        self.show_page(self.current_page)
        self.zoom_percentage_entry.setText("100")

    def fit_window(self):
        page = self.pdf[self.current_page]
        zoom_x = self.scroll_area.width() / page.rect.width
        zoom_y = self.scroll_area.height() / page.rect.height
        self.zoom_factor = min(zoom_x, zoom_y)
        self.show_page(self.current_page)

    def fit_width(self):
        page = self.pdf[self.current_page]
        self.zoom_factor = self.scroll_area.width() / page.rect.width
        self.show_page(self.current_page)

    def rotate_left(self):
        self.rotation_angle -= 90
        self.show_page(self.current_page)

    def rotate_right(self):
        self.rotation_angle += 90
        self.show_page(self.current_page)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.pan_mode:
            # Set the is_panning flag to True
            self.is_panning = True
            # Store the initial mouse position
            self.pan_start_x = event.x()
            self.pan_start_y = event.y()
            # Change the cursor to an open hand symbol
            self.setCursor(Qt.OpenHandCursor)
        event.accept()

    def mouseMoveEvent(self, event):
        if self.is_panning and self.pan_mode:
            # Calculate the distance moved by the mouse
            dx = event.x() - self.pan_start_x
            dy = event.y() - self.pan_start_y

            # Scroll the QScrollArea accordingly
            self.scroll_area.horizontalScrollBar().setValue(self.scroll_area.horizontalScrollBar().value() - dx)
            self.scroll_area.verticalScrollBar().setValue(self.scroll_area.verticalScrollBar().value() - dy)

            # Update the initial mouse position for the next mouse move event
            self.pan_start_x = event.x()
            self.pan_start_y = event.y()
        event.accept()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton and self.is_panning and self.pan_mode:
            # Reset the is_panning flag
            self.is_panning = False
            # Reset the cursor
            self.setCursor(Qt.ArrowCursor)
        event.accept()

    def toggle_pan_mode(self, checked):
        if checked:
            self.pan_mode = True
            self.setCursor(Qt.OpenHandCursor)
        else:
            self.pan_mode = False
            self.setCursor(Qt.ArrowCursor)

    def print_pdf(self):
        if not self.pdf:
            QMessageBox.warning(self, "No Document", "No document available to print.")
            return

        printer = QPrinter()
        printer.setFullPage(True)
        printer.setPageOrientation(QPageLayout.Portrait)

        print_dialog = QPrintDialog(printer, self)
        if print_dialog.exec_() == QPrintDialog.Accepted:
            from PySide6.QtGui import QPainter

            painter = QPainter()
            if not painter.begin(printer):
                return

            num_pages = len(self.pdf)
            for i in range(num_pages):
                if i != 0:  # start a new page after the first one
                    printer.newPage()
                page = self.pdf[i]
                image = page.get_pixmap()
                qt_image = QImage(image.samples, image.width, image.height, image.stride, QImage.Format_RGB888)
                pixmap = QPixmap.fromImage(qt_image)
                rect = painter.viewport()
                size = pixmap.size()
                size.scale(rect.size(), Qt.KeepAspectRatio)
                painter.setViewport(rect.x(), rect.y(), size.width(), size.height())
                painter.setWindow(pixmap.rect())
                painter.drawPixmap(0, 0, pixmap)

            painter.end()

    def save_pdf(self):
        if not self.pdf:
            QMessageBox.warning(self, "No Document", "No document available to save.")
            return

        options = QFileDialog.Options()
        filePath, _ = QFileDialog.getSaveFileName(self, "Save PDF", "", "PDF Files (*.pdf);;All Files (*)",
                                                  options=options)

        if not filePath:
            return  # user cancelled the dialog

        if not filePath.endswith(".pdf"):
            filePath += ".pdf"

        try:
            self.pdf.save(filePath)  # save the PDF to the specified path
            QMessageBox.information(self, "Success", "PDF saved successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save PDF: {e}")


class AudioVideoViewer(QWidget):
    def __init__(self, parent=None):
        super(AudioVideoViewer, self).__init__(parent)

        # Initialize the volumes control interface once
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

        # Spacer to separate media controls and volumes controls
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

        # Spacer to separate volumes controls and speed controls
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
        #very_old# self._player.play()


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
        # clear the thumbnail of the video or audio file

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
        """Return the current system volumes as a value between 0 and 100."""
        current_volume = self.volume.GetMasterVolumeLevelScalar()
        return int(current_volume * 100)

    @Slot(int)
    def set_volume(self, value):
        """Set the system volumes based on the slider's value."""
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
        """Update the volumes display label based on the slider's value."""
        self.volume_display.setText(f"{value}%")
