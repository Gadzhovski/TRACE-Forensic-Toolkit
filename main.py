from PySide6.QtWidgets import QApplication
from gui.mainwindow import DetailedAutopsyGUI
from gui.mainwindow import DatabaseManager


if __name__ == '__main__':
    app = QApplication([])
    app.setStyleSheet("""
        QToolTip {
            background-color: #f9f9f9;
            border: 1px solid black;
            color: black;
        }
    """)
    db_manager = DatabaseManager('icon_mappings.db')  # Replace 'icon_mappings.db' with your actual database path
    window = DetailedAutopsyGUI(db_manager)
    window.show()
    app.exec()
