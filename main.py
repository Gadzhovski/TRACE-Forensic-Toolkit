from PySide6.QtWidgets import QApplication
from modules.mainwindow import MainWindow

# Run the application
if __name__ == '__main__':
    app = QApplication([]) # Create the application
    app.setStyleSheet(open('styles/global.qss').read()) # Load the global stylesheet

    window = MainWindow() # Create the main window
    window.show() # Show the main window
    app.exec() # Execute the application
