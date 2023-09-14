import fitz
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon, QPixmap, QImage, QAction, QPageLayout
from PySide6.QtPrintSupport import QPrinter, QPrintDialog
from PySide6.QtWidgets import (QToolBar, QLabel, QMessageBox, QVBoxLayout, QWidget, QScrollArea, QLineEdit, QFileDialog,
                               QDockWidget, QListWidget, QListWidgetItem)


class PDFViewer(QWidget):
    def __init__(self, pdf_content=None, parent=None):
        super().__init__(parent)
        self.pdf = fitz.open(stream=pdf_content, filetype="pdf") if pdf_content else None
        self.current_page = 0
        self.zoom_factor = 1.0  # Initialize the zoom factor here
        self.rotation_angle = 0
        self.is_panning = False
        self.pan_start_x = 0
        self.pan_start_y = 0
        self.pan_mode = False

        if self.pdf:
            self.initialize_ui()
            self.show_page(self.current_page)
        else:
            self.initialize_ui()

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

        # Create and setup the toolbar
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
        self.first_action = QAction(QIcon("gui/icons/go-up.png"), "First", self)
        self.first_action.triggered.connect(self.show_first_page)
        self.toolbar.addAction(self.first_action)

        self.prev_action = QAction(QIcon("gui/icons/go-previous.png"), "Previous", self)
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
        self.next_action = QAction(QIcon("gui/icons/go-next.png"), "Next", self)
        self.next_action.triggered.connect(self.show_next_page)
        self.toolbar.addAction(self.next_action)

        self.last_action = QAction(QIcon("gui/icons/go-down.png"), "Last", self)
        self.last_action.triggered.connect(self.show_last_page)
        self.toolbar.addAction(self.last_action)

        # Zoom actions
        self.zoom_in_action = QAction(QIcon("gui/icons/zoom-in.png"), "Zoom In", self)
        self.zoom_in_action.triggered.connect(self.zoom_in)
        self.toolbar.addAction(self.zoom_in_action)

        # QLineEdit for zoom percentage
        self.zoom_percentage_entry = QLineEdit(self)
        self.zoom_percentage_entry.setFixedWidth(40)  # Set a fixed width for consistency
        self.zoom_percentage_entry.setAlignment(Qt.AlignRight)
        self.zoom_percentage_entry.setPlaceholderText("100%")  # Default zoom is 100%
        self.zoom_percentage_entry.returnPressed.connect(self.set_zoom_from_entry)
        self.toolbar.addWidget(self.zoom_percentage_entry)


        self.zoom_out_action = QAction(QIcon("gui/icons/zoom-out.png"), "Zoom Out", self)
        self.zoom_out_action.triggered.connect(self.zoom_out)
        self.toolbar.addAction(self.zoom_out_action)

        # Create a reset zoom button with its icon and add it to the toolbar
        reset_zoom_icon = QIcon("gui/icons/document-revert.png")  # Replace with your icon path
        self.reset_zoom_action = QAction(reset_zoom_icon, "Reset Zoom", self)
        self.reset_zoom_action.triggered.connect(self.reset_zoom)
        self.toolbar.addAction(self.reset_zoom_action)

        # Fit in window
        fit_window_icon = QIcon("gui/icons/fit-window.png")  # Replace with your icon path
        self.fit_window_action = QAction(fit_window_icon, "Fit in Window", self)
        self.fit_window_action.triggered.connect(self.fit_window)
        self.toolbar.addAction(self.fit_window_action)

        # Fit in width
        fit_width_icon = QIcon("gui/icons/fit-width.png")  # Replace with your icon path
        self.fit_width_action = QAction(fit_width_icon, "Fit in Width", self)
        self.fit_width_action.triggered.connect(self.fit_width)
        self.toolbar.addAction(self.fit_width_action)

        # Rotate left
        rotate_left_icon = QIcon("gui/icons/object-rotate-left.png")  # Replace with your icon path
        self.rotate_left_action = QAction(rotate_left_icon, "Rotate Left", self)
        self.rotate_left_action.triggered.connect(self.rotate_left)
        self.toolbar.addAction(self.rotate_left_action)

        # Rotate right
        rotate_right_icon = QIcon("gui/icons/object-rotate-right.png")  # Replace with your icon path
        self.rotate_right_action = QAction(rotate_right_icon, "Rotate Right", self)
        self.rotate_right_action.triggered.connect(self.rotate_right)
        self.toolbar.addAction(self.rotate_right_action)

        # Pan tool button
        self.pan_tool_icon = QIcon("gui/icons/pan.png")  # Replace with your pan icon path
        self.pan_tool_action = QAction(self.pan_tool_icon, "Pan Tool", self)
        self.pan_tool_action.setCheckable(True)  # Make the action checkable
        self.pan_tool_action.toggled.connect(self.toggle_pan_mode)
        self.toolbar.addAction(self.pan_tool_action)

        # Print button
        self.print_icon = QIcon("gui/icons/printer.png")  # Replace with your print icon path
        self.print_action = QAction(self.print_icon, "Print", self)
        self.print_action.triggered.connect(self.print_pdf)
        self.toolbar.addAction(self.print_action)

        self.save_pdf_action = QAction(QIcon("gui/icons/folder-download.png"), "Save PDF", self)
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
            mat = fitz.Matrix(self.zoom_factor, self.zoom_factor).prerotate(self.rotation_angle)
            image = page.get_pixmap(matrix=mat)

            qt_image = QImage(image.samples, image.width, image.height, image.stride, QImage.Format_RGB888)
            pixmap = QPixmap.fromImage(qt_image)
            self.page_label.setPixmap(pixmap)
            self.update_navigation_states()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to render page: {e}")

    def display(self, pdf_content):
        if self.pdf:
            self.pdf.close()
        self.pdf = fitz.open(stream=pdf_content, filetype="pdf")
        self.current_page = 0
        self.show_page(self.current_page)
        self.update_navigation_states()  # Add this line

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
        mat = fitz.Matrix(self.zoom_factor, self.zoom_factor)
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
