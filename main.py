from PySide6.QtWidgets import QApplication
from gui.mainwindow import MainWindow


if __name__ == '__main__':
    app = QApplication([])
    # app.setStyleSheet("""
    #     QToolTip {
    #         background-color: #f9f9f9;
    #         border: 1px solid black;
    #         color: black;
    #     }
    # """)
    window = MainWindow()
    window.show()
    app.exec()
