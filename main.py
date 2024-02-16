from PySide6.QtWidgets import QApplication
from gui.mainwindow import MainWindow


if __name__ == '__main__':
    app = QApplication([])

    # global_stylesheet = """
    #     QWidget {
    #         font-size: 14px;
    #         color: #333333;
    #     }
    #     QTableWidget, QListWidget {
    #         border: 1px solid #d7d7d7;
    #         border-radius: 2px;
    #         background-color: #ffffff;
    #     }
    #     QTableWidget::item, QListWidget::item {
    #         padding: 5px;
    #     }
    #     QTableWidget::item:selected, QListWidget::item:selected {
    #         background-color: #e7e7e7;
    #     }
    #     QToolBar {
    #         background-color: #f5f5f5;
    #         border-bottom: 1px solid #d7d7d7;
    #         padding: 5px;
    #     }
    #     QToolBar::item:hover {
    #         background-color: #e7e7e7;
    #     }
    #     QToolBar::item:pressed {
    #         background-color: #d7d7d7;
    #     }
    #     QPushButton {
    #         border: 1px solid #ced4da;
    #         border-radius: 2px;
    #         padding: 5px 15px;
    #         background-color: #ffffff;
    #         margin-left: 8px;
    #         margin-right: 8px;
    #     }
    #     QPushButton:hover {
    #         background-color: #e7e7e7;
    #     }
    #     QPushButton:pressed {
    #         background-color: #d7d7d7;
    #     }
    #
    #     QTabWidget {
    #         border: 1px solid #d7d7d7;
    #         border-radius: 2px;
    #         background-color: #ffffff;
    #     }
    #
    #     QTabBar::tab {
    #         background: #f5f5f5;
    #         border: 1px solid #d7d7d7;
    #         border-top-left-radius: 4px;
    #         border-top-right-radius: 4px;
    #         min-width: 8ex;
    #         padding: 2px;
    #     }
    #     QTabBar::tab:selected, QTabBar::tab:hover {
    #         background: #ffffff;
    #     }
    #     QTabBar::tab:selected {
    #         border-color: #9B9B9B;
    #         border-bottom-color: #C2C7CB;
    #     }
    #     QTabBar::tab:!selected {
    #         margin-top: 2px;
    #     }
    #
    #     QCheckBox {
    #         spacing: 5px;
    #     }
    #     QCheckBox::indicator {
    #         width: 13px;
    #         height: 13px;
    #         border-radius: 6px;  /* Add this line to make the checkboxes rounded */
    #     }
    #     QCheckBox::indicator:unchecked {
    #         border: 1px solid #d7d7d7;
    #         background-color: #ffffff;
    #
    #     }
    #     QCheckBox::indicator:checked {
    #         image: url('Icons/icons8-tick-48.png');
    #     }
    #
    #     QComboBox {
    #         border: 1px solid #ced4da;
    #         border-radius: 2px;
    #         padding: 5px 10px;
    #         background-color: #ffffff;
    #         selection-background-color: #56CCF2;
    #         }
    #     QComboBox::drop-down {
    #         subcontrol-origin: padding;
    #         subcontrol-position: top right;
    #         width: 25px;
    #         border-left-width: 1px;
    #         border-left-color: #ced4da;
    #         border-left-style: solid;
    #         border-top-right-radius: 4px;
    #         border-bottom-right-radius: 4px;
    #     }
    #     QComboBox::down-arrow {
    #         image: url('Icons/icons8-dropdown-48.png');
    #         width: 16px;  /* Adjust the width of the image */
    #         height: 16px;  /* Adjust the height of the image */
    #     }
    #     QComboBox::hover {
    #         border: 1px solid #a2a9b1;
    #         }
    #
    #     QComboBox::drop-down:hover {
    #         background-color: #f5f5f5;
    #         }
    #
    #
    #     QScrollBar:vertical {
    #         border: none;
    #         background: none;
    #         width: 14px;
    #         margin: 15px 0 15px 0;
    #     }
    #
    #     QScrollBar::handle:vertical {
    #         background: #d3d3d3;
    #         min-height: 30px;
    #         border-radius: 7px;
    #     }
    #
    #     QScrollBar::handle:vertical:hover {
    #         background: #a9a9a9;
    #     }
    #
    #     QScrollBar::add-line:vertical {
    #         border: none;
    #         background: none;
    #     }
    #
    #     QScrollBar::sub-line:vertical {
    #         border: none;
    #         background: none;
    #     }
    #
    #     QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    #         background: none;
    #         }
    #
    #     QScrollBar:horizontal {
    #         border: none;
    #         background: none;
    #         height: 14px;
    #         margin: 0 15px 0 15px;
    #     }
    #
    #     QScrollBar::handle:horizontal {
    #         background: #d3d3d3;
    #         min-width: 30px;
    #         border-radius: 7px;
    #     }
    #
    #     QScrollBar::handle:horizontal:hover {
    #         background: #a9a9a9;
    #     }
    #
    #     QScrollBar::add-line:horizontal {
    #         border: none;
    #         background: none;
    #     }
    #
    #     QScrollBar::sub-line:horizontal {
    #         border: none;
    #         background: none;
    #     }
    #
    #     QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
    #         background: none;
    #         }
    #
    #
    #     QDockWidget {
    #         border: 1px solid #d7d7d7;
    #         border-radius: 2px;
    #         background-color: #ffffff;
    #         }
    #     QDockWidget::title {
    #         background: #f5f5f5;
    #         padding: 1px;
    #         border-top-left-radius: 2px;
    #         border-top-right-radius: 2px;
    #         }
    #     QDockWidget::close-button, QDockWidget::float-button {
    #         border: 1px solid transparent;
    #         border-radius: 5px;
    #         background: #f5f5f5;
    #         }
    #     QDockWidget::close-button:hover, QDockWidget::float-button:hover {
    #         background: #e7e7e7;
    #         }
    #     QDockWidget::close-button:pressed, QDockWidget::float-button:pressed {
    #         background: #d7d7d7;
    #         }
    #
    #     QMenuBar {
    #         background-color: white;
    #         border-bottom: 1px solid #d7d7d7;
    #         }
    #     QMenuBar::item {
    #         padding: 5px 8px;
    #         border-radius: 2px;
    #         }
    #     QMenuBar::item:selected {
    #         background-color: #e7e7e7;
    #         }
    #     QMenuBar::item:pressed {
    #         background-color: #d7d7d7;
    #         }
    #
    #     QMessageBox {
    #         background-color: #ffffff;
    #         border: 1px solid #d7d7d7;
    #         }
    #
    #     QLineEdit {
    #         border: 1px solid #ced4da;
    #         border-radius: 2px;
    #         padding: 5px 10px;
    #         background-color: #ffffff;
    #         }
    #     QLineEdit:hover {
    #         border: 1px solid #a2a9b1;
    #         }
    #     QLineEdit:focus {
    #         border: 1px solid #56CCF2;
    #         }
    #
    #     QTreeWidget {
    #         border: 1px solid #d7d7d7;
    #         border-radius: 2px;
    #         background-color: #ffffff;
    #     }
    #
    #     QTextEdit {
    #         border: 1px solid #d7d7d7;
    #         border-radius: 2px;
    #         background-color: #ffffff;
    #         }
    #
    #
    #     QTextEdit::item {
    #         padding: 5px;
    #     }
    #
    #     QAction {
    #         padding: px 10px;
    #         border: 1px solid #ced4da;
    #         border-radius: 4px;
    #         background-color: #ffffff;
    #     }
    #
    #     QAction:hover {
    #         background-color: #f5f5f5;
    #         border: 1px solid #a2a9b1;
    #     }
    #
    #     QAction:pressed {
    #         background-color: #e7e7e7;
    #         border: 1px solid #56CCF2;
    #     }
    #
    #
    #     QAudioWidget {
    #         border: 1px solid #d7d7d7;
    #         border-radius: 2px;
    #         background-color: #ffffff;
    #     }
    #
    #
    #     QSlider::groove:horizontal {
    #         border: 1px solid #d7d7d7;
    #         height: 8px;
    #         background: #ffffff;
    #         margin: 2px 0;
    #         border-radius: 4px;
    #     }
    #
    #     QSlider::handle:horizontal {
    #         background: #ffffff;
    #
    #         border: 1px solid #d7d7d7;
    #         width: 14px;
    #         margin: -2px 0;
    #         border-radius: 7px;
    #     }
    #
    #     QSlider::handle:horizontal:hover {
    #         background: #b7b7b7;
    #     }
    #
    #     QSlider::handle:horizontal:pressed {
    #         background: #c7c7c7;
    #     }
    #
    #     QSlider::add-page:horizontal {
    #         background: #e7e7e7;
    #         border: 1px solid #d7d7d7;
    #         height: 8px;
    #         border-radius: 4px;
    #     }
    # """
    #app.setStyleSheet(global_stylesheet)

    app.setStyleSheet(open('styles/global.qss').read())

    window = MainWindow()
    window.show()
    app.exec()
