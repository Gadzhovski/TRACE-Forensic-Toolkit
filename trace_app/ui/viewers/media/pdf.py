"""PDF viewer: paging, zoom, fit modes, pan and print."""

import logging

from PySide6.QtCore import Qt, QSize, QPoint
from PySide6.QtGui import QIcon, QPixmap, QImage, QAction, QPageLayout, QPainter
from PySide6.QtPrintSupport import QPrinter, QPrintDialog
from PySide6.QtWidgets import (QApplication, QFileDialog, QHBoxLayout, QLabel,
                               QLineEdit, QMenu, QMessageBox, QPushButton,
                               QScrollArea, QSizePolicy, QToolBar, QToolButton,
                               QVBoxLayout, QWidget)

from fitz import open as fitz_open, Matrix

from trace_app.infra.paths import resource_path
from trace_app.infra.constants import CONTROL_HEIGHT, GROUP_SPACING, TOOLBAR_HEIGHT, TOOLBAR_ICON_SIZE
from trace_app.ui import icons
from trace_app.ui.widgets.export_button import ExportButton
from trace_app.ui.widgets.toolbars import align_controls, prepare_toolbar

logger = logging.getLogger('TRACE.Viewer.PDF')


class PDFViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pdf = None
        self.current_page = 0
        self.zoom_factor = 1.0
        self.rotation_angle = 0
        self.is_panning = False
        self.pan_start_x = 0
        self.pan_start_y = 0
        self.pan_mode = False

        # Optimize performance with page caching
        self._page_cache = {}  # Cache for rendered pages
        self._cache_size = 5  # Maximum number of pages to cache

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
        prepare_toolbar(self.toolbar)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QSize(TOOLBAR_ICON_SIZE, TOOLBAR_ICON_SIZE))
        # Disable right click
        self.toolbar.setContextMenuPolicy(Qt.PreventContextMenu)

        # Navigation buttons
        self.first_action = icons.action(icons.UP, "First", self)
        self.first_action.triggered.connect(self.show_first_page)
        self.toolbar.addAction(self.first_action)

        self.prev_action = icons.action(icons.BACK, "Previous", self)
        self.prev_action.triggered.connect(self.show_previous_page)
        self.toolbar.addAction(self.prev_action)

        # Page entry
        self.page_entry = QLineEdit(self)
        self.page_entry.setMaximumWidth(40)
        self.page_entry.setAlignment(Qt.AlignRight)
        self.page_entry.returnPressed.connect(self.go_to_page)
        self.toolbar.addWidget(self.page_entry)

        # Total pages label
        self.total_pages_label = QLabel(f"of {len(self.pdf)}" if self.pdf else "of 0")
        self.toolbar.addWidget(self.total_pages_label)

        # Navigation buttons
        self.next_action = icons.action(icons.FORWARD, "Next", self)
        self.next_action.triggered.connect(self.show_next_page)
        self.toolbar.addAction(self.next_action)

        self.last_action = icons.action(icons.DOWN, "Last", self)
        self.last_action.triggered.connect(self.show_last_page)
        self.toolbar.addAction(self.last_action)

        # Add small spacer
        spacer = QWidget(self)
        spacer.setFixedSize(GROUP_SPACING, 0)
        self.toolbar.addWidget(spacer)

        # Zoom actions
        self.zoom_in_action = icons.action(icons.ZOOM_IN, "Zoom In", self)
        self.zoom_in_action.triggered.connect(self.zoom_in)
        self.toolbar.addAction(self.zoom_in_action)

        # QLineEdit for zoom percentage
        self.zoom_percentage_entry = QLineEdit(self)
        self.zoom_percentage_entry.setFixedWidth(64)
        self.zoom_percentage_entry.setAlignment(Qt.AlignRight)
        self.zoom_percentage_entry.setPlaceholderText("100%")  # Default zoom is 100%
        self.zoom_percentage_entry.returnPressed.connect(self.set_zoom_from_entry)
        self.toolbar.addWidget(self.zoom_percentage_entry)

        self.zoom_out_action = icons.action(icons.ZOOM_OUT, "Zoom Out", self)
        self.zoom_out_action.triggered.connect(self.zoom_out)
        self.toolbar.addAction(self.zoom_out_action)

        # Create a reset zoom button with its icon and add it to the toolbar
        reset_zoom_icon = icons.icon(icons.ZOOM_ACTUAL)
        self.reset_zoom_action = QAction(reset_zoom_icon, "Reset Zoom", self)
        self.reset_zoom_action.triggered.connect(self.reset_zoom)
        self.toolbar.addAction(self.reset_zoom_action)

        # Add small spacer
        spacer = QWidget(self)
        spacer.setFixedSize(GROUP_SPACING, 0)
        self.toolbar.addWidget(spacer)

        # Fit in window
        fit_window_icon = icons.icon(icons.FIT_WINDOW)
        self.fit_window_action = QAction(fit_window_icon, "Fit in Window", self)
        self.fit_window_action.triggered.connect(self.fit_window)
        self.toolbar.addAction(self.fit_window_action)

        # Fit in width
        fit_width_icon = icons.icon(icons.FIT_WIDTH)
        self.fit_width_action = QAction(fit_width_icon, "Fit in Width", self)
        self.fit_width_action.triggered.connect(self.fit_width)
        self.toolbar.addAction(self.fit_width_action)

        # Add small spacer
        spacer = QWidget(self)
        spacer.setFixedSize(GROUP_SPACING, 0)
        self.toolbar.addWidget(spacer)

        # Pan tool button
        self.pan_tool_icon = icons.icon(icons.PAN)
        self.pan_tool_action = QAction(self.pan_tool_icon, "Pan Tool", self)
        self.pan_tool_action.setCheckable(True)
        self.pan_tool_action.toggled.connect(self.toggle_pan_mode)
        self.toolbar.addAction(self.pan_tool_action)

        # Add a spacer to push the following buttons to the right
        spacer = QWidget(self)
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(spacer)

        # One Save button with a format menu, rather than a bare "Save PDF"
        # action. Saving the original document and exporting its extracted
        # text are different operations, so both are offered here.
        self.save_button = QToolButton(self)
        self.save_button.setObjectName("exportButton")
        self.save_button.setIcon(icons.icon(icons.SAVE_AS))
        self.save_button.setToolTip("Save the document, or export its text")
        self.save_button.setToolButtonStyle(Qt.ToolButtonIconOnly)
        self.save_button.setPopupMode(QToolButton.InstantPopup)

        save_menu = QMenu(self)
        save_original = QAction("PDF (original document)", self)
        save_original.triggered.connect(self.save_pdf)
        save_menu.addAction(save_original)

        save_text = QAction("Text (extracted)", self)
        save_text.triggered.connect(lambda: self.export_extracted("txt"))
        save_menu.addAction(save_text)

        save_html = QAction("HTML (extracted)", self)
        save_html.triggered.connect(lambda: self.export_extracted("html"))
        save_menu.addAction(save_html)
        self.save_button.setMenu(save_menu)
        self.toolbar.addWidget(self.save_button)

        # Print stays its own control: it sends pages to a printer rather than
        # writing a file, so it does not belong in a Save menu.
        self.print_action = icons.action(icons.PRINT, "Print", self)
        self.print_action.triggered.connect(self.print_pdf)
        self.toolbar.addAction(self.print_action)
        # Every control in this toolbar gets the shared height, once it is built.
        align_controls(self.toolbar)

    def setup_pdf_display_area(self):
        self.page_label = QLabel(self)
        self.page_label.setContentsMargins(0, 0, 0, 0)
        self.page_label.setAlignment(Qt.AlignCenter)

        self.scroll_area = QScrollArea(self)
        self.scroll_area.setContentsMargins(0, 0, 0, 0)
        self.scroll_area.setWidget(self.page_label)
        self.scroll_area.setWidgetResizable(True)

    def set_current_page(self, page_num):
        """Set the current page and update the view."""
        if not self.pdf:
            return

        max_pages = len(self.pdf)
        if 0 <= page_num < max_pages:
            self.current_page = page_num
            self.show_page(page_num)

    def go_to_page(self):
        """Navigate to the page entered in the page entry field."""
        try:
            page_num = int(self.page_entry.text()) - 1  # Minus 1 because pages start from 0
            self.set_current_page(page_num)
        except ValueError:
            QMessageBox.warning(self, "Invalid Page Number", "Please enter a valid page number.")

    def update_navigation_states(self):
        """Update UI elements based on current PDF and page."""
        if not self.pdf:
            self.prev_action.setEnabled(False)
            self.next_action.setEnabled(False)
            self.first_action.setEnabled(False)
            self.last_action.setEnabled(False)
            self.total_pages_label.setText("of 0")
            self.page_entry.setText("")
            return

        self.prev_action.setEnabled(self.current_page > 0)
        self.next_action.setEnabled(self.current_page < len(self.pdf) - 1)
        self.first_action.setEnabled(self.current_page > 0)
        self.last_action.setEnabled(self.current_page < len(self.pdf) - 1)
        self.total_pages_label.setText(f"of {len(self.pdf)}")
        self.page_entry.setText(str(self.current_page + 1))

    def show_previous_page(self):
        """Navigate to the previous page."""
        self.set_current_page(self.current_page - 1)
        self.update_navigation_states()

    def show_next_page(self):
        """Navigate to the next page."""
        self.set_current_page(self.current_page + 1)
        self.update_navigation_states()

    def show_page(self, page_num):
        """Display the specified page with caching for better performance."""
        if not self.pdf:
            return

        try:
            # Check if the page is in the cache
            cache_key = (page_num, self.zoom_factor, self.rotation_angle)
            if cache_key in self._page_cache:
                # Use cached pixmap
                self.page_label.setPixmap(self._page_cache[cache_key])
            else:
                # Render the page and cache it
                page = self.pdf[page_num]
                mat = Matrix(self.zoom_factor, self.zoom_factor).prerotate(self.rotation_angle)
                image = page.get_pixmap(matrix=mat)

                qt_image = QImage(image.samples, image.width, image.height, image.stride, QImage.Format_RGB888)
                pixmap = QPixmap.fromImage(qt_image)

                # Cache the pixmap
                self._page_cache[cache_key] = pixmap

                # Manage cache size
                if len(self._page_cache) > self._cache_size:
                    # Remove oldest entry (first key)
                    oldest_key = next(iter(self._page_cache))
                    del self._page_cache[oldest_key]

                self.page_label.setPixmap(pixmap)

            self.update_navigation_states()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to render page: {e}")

    def display(self, content):
        """Load and display a PDF from content bytes."""
        # Clear existing PDF and cache
        self.clear()

        if content:
            try:
                # Try to open PDF directly first
                self.pdf = fitz_open(stream=content, filetype="pdf")
                self.current_page = 0
                self.zoom_factor = 1.0
                self.rotation_angle = 0
                self.show_page(self.current_page)
                self.update_navigation_states()
            except Exception as e:
                # If direct open fails, try to clean up the PDF (common with carved files)
                logger.error(f"Initial PDF load failed: {e}, attempting cleanup...")
                try:
                    cleaned_content = self.cleanup_pdf_content(content)
                    self.pdf = fitz_open(stream=cleaned_content, filetype="pdf")
                    self.current_page = 0
                    self.zoom_factor = 1.0
                    self.rotation_angle = 0
                    self.show_page(self.current_page)
                    self.update_navigation_states()
                    logger.debug("Successfully loaded PDF after cleanup")
                except Exception as e2:
                    logger.error(f"Failed to load PDF even after cleanup: {e2}")
        else:
            self.page_label.clear()

    @staticmethod
    def cleanup_pdf_content(content):
        """Clean up PDF content by removing trailing garbage after %%EOF.

        Common issue with carved PDFs - extra bytes after the EOF marker
        cause PyMuPDF to reject the file even though the PDF is valid.
        """
        try:
            # Find the last occurrence of %%EOF
            eof_marker = b'%%EOF'
            last_eof = content.rfind(eof_marker)

            if last_eof != -1:
                # Include the EOF marker plus a small buffer for trailing whitespace
                # PDF spec allows whitespace/newlines after %%EOF, but not much else
                end_position = last_eof + len(eof_marker)

                # Look ahead a bit to include any trailing newlines (up to 10 bytes)
                max_end = min(end_position + 10, len(content))
                trailing_section = content[end_position:max_end]

                # Count how many whitespace bytes follow EOF
                whitespace_count = 0
                for byte in trailing_section:
                    if byte in (0x0A, 0x0D, 0x20, 0x09):  # \n, \r, space, tab
                        whitespace_count += 1
                    else:
                        break

                # Truncate after EOF + whitespace
                cleaned_content = content[:end_position + whitespace_count]

                logger.debug(f"PDF cleanup: Truncated {len(content) - len(cleaned_content)} trailing bytes")
                return cleaned_content
            else:
                # No EOF marker found, return original
                logger.debug("PDF cleanup: No %%EOF marker found, returning original content")
                return content

        except Exception as e:
            logger.error(f"Error during PDF cleanup: {e}")
            return content

    def clear(self):
        """Close the PDF and clear all resources."""
        if self.pdf:
            self.pdf.close()
            self.pdf = None

        # Clear the cache
        self._page_cache.clear()
        self.page_label.clear()
        self.update_navigation_states()

    def show_first_page(self):
        """Navigate to the first page."""
        self.set_current_page(0)

    def show_last_page(self):
        """Navigate to the last page."""
        if self.pdf:
            self.set_current_page(len(self.pdf) - 1)

    def zoom_in(self):
        """Increase zoom level."""
        # Don't allow extreme zoom levels
        if self.zoom_factor < 5.0:
            self.zoom_factor *= 1.2
            # Clear cache on zoom change
            self._page_cache.clear()
            self.show_page(self.current_page)
            # Update zoom display
            self.zoom_percentage_entry.setText(f"{int(self.zoom_factor * 100)}%")

    def zoom_out(self):
        """Decrease zoom level."""
        # Don't allow extreme zoom levels
        if self.zoom_factor > 0.1:
            self.zoom_factor *= 0.8
            # Clear cache on zoom change
            self._page_cache.clear()
            self.show_page(self.current_page)
            # Update zoom display
            self.zoom_percentage_entry.setText(f"{int(self.zoom_factor * 100)}%")

    def set_zoom_from_entry(self):
        """Set zoom level from the entry field."""
        try:
            # Extract the percentage from the QLineEdit
            text = self.zoom_percentage_entry.text().strip('%')
            percentage = float(text) / 100

            if 0.1 <= percentage <= 5:  # Enforce reasonable zoom limits
                self.zoom_factor = percentage
                # Clear cache on zoom change
                self._page_cache.clear()
                self.show_page(self.current_page)
            else:
                QMessageBox.warning(self, "Invalid Zoom", "Please enter a zoom percentage between 10% and 500%.")
                # Reset the entry to the current zoom
                self.zoom_percentage_entry.setText(f"{int(self.zoom_factor * 100)}%")
        except ValueError:
            QMessageBox.warning(self, "Invalid Zoom", "Please enter a valid zoom percentage.")
            # Reset the entry to the current zoom
            self.zoom_percentage_entry.setText(f"{int(self.zoom_factor * 100)}%")

    def reset_zoom(self):
        """Reset zoom to original size."""
        self.zoom_factor = 1.0
        # Clear cache on zoom change
        self._page_cache.clear()
        self.show_page(self.current_page)
        self.zoom_percentage_entry.setText("100%")

    def fit_window(self):
        """Adjust zoom to fit the entire page in the window."""
        if not self.pdf or self.current_page >= len(self.pdf):
            return

        page = self.pdf[self.current_page]
        zoom_x = self.scroll_area.width() / page.rect.width
        zoom_y = self.scroll_area.height() / page.rect.height
        self.zoom_factor = min(zoom_x, zoom_y) * 0.95  # 95% to add a small margin
        # Clear cache on zoom change
        self._page_cache.clear()
        self.show_page(self.current_page)
        # Update zoom display
        self.zoom_percentage_entry.setText(f"{int(self.zoom_factor * 100)}%")

    def fit_width(self):
        """Adjust zoom to fit the page width in the window."""
        if not self.pdf or self.current_page >= len(self.pdf):
            return

        page = self.pdf[self.current_page]
        self.zoom_factor = self.scroll_area.width() / page.rect.width * 0.95  # 95% to add a small margin
        # Clear cache on zoom change
        self._page_cache.clear()
        self.show_page(self.current_page)
        # Update zoom display
        self.zoom_percentage_entry.setText(f"{int(self.zoom_factor * 100)}%")

    def rotate_left(self):
        """Rotate the page 90 degrees counterclockwise."""
        self.rotation_angle -= 90
        # Clear cache on rotation change
        self._page_cache.clear()
        self.show_page(self.current_page)

    def rotate_right(self):
        """Rotate the page 90 degrees clockwise."""
        self.rotation_angle += 90
        # Clear cache on rotation change
        self._page_cache.clear()
        self.show_page(self.current_page)

    def toggle_pan_mode(self, checked):
        """Enable or disable panning mode."""
        self.pan_mode = checked
        self.setCursor(Qt.OpenHandCursor if checked else Qt.ArrowCursor)

    def mousePressEvent(self, event):
        """Handle mouse press events for panning."""
        if event.button() == Qt.LeftButton and self.pan_mode:
            self.is_panning = True
            self.pan_start_x = event.x()
            self.pan_start_y = event.y()
            self.setCursor(Qt.ClosedHandCursor)  # Change to closed hand cursor while panning
        event.accept()

    def mouseMoveEvent(self, event):
        """Handle mouse move events for panning."""
        if self.is_panning and self.pan_mode:
            # Calculate the distance moved
            dx = event.x() - self.pan_start_x
            dy = event.y() - self.pan_start_y

            # Update scroll position
            self.scroll_area.horizontalScrollBar().setValue(self.scroll_area.horizontalScrollBar().value() - dx)
            self.scroll_area.verticalScrollBar().setValue(self.scroll_area.verticalScrollBar().value() - dy)

            # Update the mouse position for the next move
            self.pan_start_x = event.x()
            self.pan_start_y = event.y()
        event.accept()

    def mouseReleaseEvent(self, event):
        """Handle mouse release events for panning."""
        if event.button() == Qt.LeftButton and self.is_panning and self.pan_mode:
            self.is_panning = False
            self.setCursor(Qt.OpenHandCursor)  # Change back to open hand cursor
        event.accept()

    def export_extracted(self, suffix):
        """Write the document's extracted text as .txt or .html.

        Distinct from saving the PDF itself: this is the text content, useful
        for searching or quoting in a report.
        """
        if not self.pdf:
            QMessageBox.warning(self, "No Document", "No document available to export.")
            return

        try:
            text = "\n\n".join(page.get_text() for page in self.pdf)
        except Exception as e:
            logger.error("Could not extract text from PDF: %s", e)
            QMessageBox.critical(self, "Export failed", f"Could not read the document:\n{e}")
            return

        button = ExportButton(lambda: text, "PDF Text", self)
        button.hide()
        button.export(suffix)

    def print_pdf(self):
        """Print the current PDF."""
        if not self.pdf:
            QMessageBox.warning(self, "No Document", "No document available to print.")
            return

        printer = QPrinter()
        printer.setFullPage(True)
        printer.setPageOrientation(QPageLayout.Portrait)

        print_dialog = QPrintDialog(printer, self)
        if print_dialog.exec_() == QPrintDialog.Accepted:
            from PySide6.QtGui import QPainter

            try:
                painter = QPainter()
                if not painter.begin(printer):
                    QMessageBox.critical(self, "Error", "Failed to initialize printer.")
                    return

                num_pages = len(self.pdf)
                for i in range(num_pages):
                    if i != 0:  # start a new page after the first one
                        printer.newPage()

                    # Render the page at a higher resolution for printing
                    page = self.pdf[i]
                    image = page.get_pixmap(matrix=Matrix(2.0, 2.0))  # Higher resolution for print

                    qt_image = QImage(image.samples, image.width, image.height, image.stride, QImage.Format_RGB888)
                    pixmap = QPixmap.fromImage(qt_image)

                    # Scale to printer page
                    rect = painter.viewport()
                    size = pixmap.size()
                    size.scale(rect.size(), Qt.KeepAspectRatio)
                    painter.setViewport(rect.x(), rect.y(), size.width(), size.height())
                    painter.setWindow(pixmap.rect())
                    painter.drawPixmap(0, 0, pixmap)

                painter.end()
                QMessageBox.information(self, "Print Complete", "Document was sent to the printer.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to print document: {e}")
                if painter.isActive():
                    painter.end()

    def save_pdf(self):
        """Save the current PDF to a file."""
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
