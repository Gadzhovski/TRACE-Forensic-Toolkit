from PySide6.QtWidgets import QApplication
from gui.mainwindow import DetailedAutopsyGUI

if __name__ == '__main__':
    app = QApplication([])
    window = DetailedAutopsyGUI()
    window.show()
    app.exec()
