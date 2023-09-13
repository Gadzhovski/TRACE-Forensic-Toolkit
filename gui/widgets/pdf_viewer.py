import fitz
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon, QPixmap, QImage, QAction
from PySide6.QtWidgets import (QToolBar, QLabel, QMessageBox, QVBoxLayout, QWidget, QScrollArea, QLineEdit)


class PDFViewer(QWidget):
    def __init__(self, pdf_content=None, parent=None):
        super().__init__(parent)
        self.pdf = fitz.open(stream=pdf_content, filetype="pdf") if pdf_content else None
        self.current_page = 0
        if self.pdf:
            self.initialize_ui()
            self.show_page(self.current_page)
        else:
            self.initialize_ui()

    def initialize_ui(self):
        self.layout = QVBoxLayout()
        self.layout.setAlignment(Qt.AlignCenter)

        # Create toolbar with page navigation controls
        self.toolbar = QToolBar(self)

        # Create actions for previous and next buttons with icons and add them to the toolbar
        self.prev_action = QAction(QIcon("gui/icons/go-previous.png"), "Previous", self)  # Replace with your icon path
        self.prev_action.triggered.connect(self.show_previous_page)
        self.toolbar.addAction(self.prev_action)

        # Create QLineEdit for page entry
        self.page_entry = QLineEdit(self)
        self.page_entry.setMaximumWidth(20)
        self.page_entry.setAlignment(Qt.AlignRight)
        self.page_entry.returnPressed.connect(self.go_to_page)
        self.toolbar.addWidget(self.page_entry)

        # Create a label displaying the total number of pages
        self.total_pages_label = QLabel(f"of {len(self.pdf)}" if self.pdf else "of 0")

        self.toolbar.addWidget(self.total_pages_label)

        self.next_action = QAction(QIcon("gui/icons/go-next.png"), "Next", self)  # Replace with your icon path
        self.next_action.triggered.connect(self.show_next_page)
        self.toolbar.addAction(self.next_action)

        self.layout.addWidget(self.toolbar)

        # Create QLabel for displaying the PDF page
        self.page_label = QLabel(self)
        self.page_label.setAlignment(Qt.AlignCenter)
        self.scroll_area = QScrollArea(self)
        self.scroll_area.setWidget(self.page_label)
        self.scroll_area.setWidgetResizable(True)
        self.layout.addWidget(self.scroll_area)

        self.setLayout(self.layout)
        self.update_navigation_states()

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
            image = page.get_pixmap()
            qt_image = QImage(image.samples, image.width, image.height, image.stride, QImage.Format_RGB888)
            pixmap = QPixmap.fromImage(qt_image)
            self.page_label.setPixmap(pixmap)
            self.update_navigation_states()  # Add this line
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