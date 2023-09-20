from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QToolBar, QLineEdit, QSizePolicy, QComboBox, QLabel
from PySide6.QtGui import QAction, QIcon, QTextCursor, QTextCharFormat, QColor
from managers.text_viewer_manager import TextViewerManager


class TextViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.manager = TextViewerManager()

        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        # Set up toolbar
        self.toolbar = QToolBar(self)
        self.toolbar.setContentsMargins(0, 0, 0, 0)
        self.toolbar.setStyleSheet("QToolBar { background-color: lightgray; border: 0px solid gray; }")
        self.layout.addWidget(self.toolbar)

        # Add toolbar buttons for paging
        self.jump_to_start_action = QAction(QIcon("gui/icons/go-up.png"), 'Jump to Start', self)
        self.toolbar.addAction(self.jump_to_start_action)

        self.prev_page_action = QAction(QIcon("gui/icons/go-previous.png"), 'Previous Page', self)
        self.toolbar.addAction(self.prev_page_action)

        self.next_page_action = QAction(QIcon("gui/icons/go-next.png"), 'Next Page', self)
        self.toolbar.addAction(self.next_page_action)

        self.jump_to_end_action = QAction(QIcon("gui/icons/go-down.png"), 'Jump to End', self)
        self.toolbar.addAction(self.jump_to_end_action)

        # Add label for font size
        self.toolbar.addWidget(QLabel("Font Size: "))

        # Add font size combobox
        self.font_size_combobox = QComboBox(self)
        self.font_size_combobox.addItems(["8", "10", "12", "14", "16", "18", "20", "24", "28", "32", "36"])
        #self.font_size_combobox.setCurrentText("10")  # Default font size
        self.font_size_combobox.currentTextChanged.connect(self.update_font_size)
        self.toolbar.addWidget(self.font_size_combobox)

        # Add spacer to push search input to the right
        spacer = QWidget(self)
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.toolbar.addWidget(spacer)

        # Add search buttons
        self.search_prev_action = QAction(QIcon("gui/icons/go-previous.png"), 'Search Previous', self)
        self.toolbar.addAction(self.search_prev_action)

        self.search_next_action = QAction(QIcon("gui/icons/go-next.png"), 'Search Next', self)
        self.toolbar.addAction(self.search_next_action)

        # Add search input
        self.search_input = QLineEdit(self)
        self.search_input.setPlaceholderText("Search...")
        self.search_input.setMaximumWidth(200)
        self.search_input.setContentsMargins(10, 0, 10, 0)
        self.search_input.returnPressed.connect(self.perform_search)
        self.toolbar.addWidget(self.search_input)

        # Text edit to display content
        self.text_edit = QTextEdit(self)
        self.text_edit.setReadOnly(True)
        self.layout.addWidget(self.text_edit)

        self.setLayout(self.layout)

        # Connect toolbar actions to functions
        self.jump_to_start_action.triggered.connect(self.manager.jump_to_start)
        self.prev_page_action.triggered.connect(self.manager.prev_page)
        self.next_page_action.triggered.connect(self.manager.next_page)
        self.jump_to_end_action.triggered.connect(self.manager.jump_to_end)
        self.search_prev_action.triggered.connect(self.search_prev)
        self.search_next_action.triggered.connect(self.search_next)

    def display_text_content(self, file_content):
        # Use the manager to load and display text content
        self.manager.load_text_content(file_content)
        text_content = self.manager.get_text_content_for_current_page()
        self.text_edit.setPlainText(text_content)

    def clear_content(self):
        self.text_edit.clear()
        self.manager.clear_content()

    def search_prev(self):
        search_str = self.search_input.text()
        self.manager.search_for_string(search_str, direction="prev")
        self.update_highlighted_text()

    def search_next(self):
        search_str = self.search_input.text()
        self.manager.search_for_string(search_str, direction="next")
        self.update_highlighted_text()

    def update_highlighted_text(self):
        # Clear any previous highlights
        cursor = self.text_edit.textCursor()
        cursor.select(QTextCursor.Document)
        cursor.setCharFormat(QTextCharFormat())
        cursor.clearSelection()

        # Calculate start and end positions of the current match
        if self.manager.matches and 0 <= self.manager.current_match_index < len(self.manager.matches):
            start_pos = self.manager.matches[self.manager.current_match_index] % self.manager.PAGE_SIZE
            end_pos = start_pos + len(self.search_input.text())

            # Highlight the current match
            highlight_format = QTextCharFormat()
            highlight_format.setBackground(QColor("yellow"))

            cursor.setPosition(start_pos, QTextCursor.MoveAnchor)
            cursor.setPosition(end_pos, QTextCursor.KeepAnchor)
            cursor.setCharFormat(highlight_format)

    def perform_search(self):
        self.search_next()

    def update_font_size(self):
        selected_size = int(self.font_size_combobox.currentText())
        current_font = self.text_edit.font()
        current_font.setPointSize(selected_size)
        self.text_edit.setFont(current_font)

    # Clear the content when the