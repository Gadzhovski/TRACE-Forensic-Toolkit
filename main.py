from PySide6.QtWidgets import QApplication
from gui.mainwindow import MainWindow


if __name__ == '__main__':
    app = QApplication([])
    app.setStyleSheet(open('styles/global.qss').read())

    window = MainWindow()
    window.show()
    app.exec()
