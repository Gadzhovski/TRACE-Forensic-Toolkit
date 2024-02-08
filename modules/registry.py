from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QScrollArea, QSizePolicy


class RegistryExtractor(QWidget):
    def __init__(self, image_handler):
        super().__init__()
        self.image_handler = image_handler
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Scroll Area Setup
        self.scrollArea = QScrollArea(self)
        self.scrollArea.setWidgetResizable(True)
        self.scrollAreaWidgetContents = QWidget()
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        layout.addWidget(self.scrollArea)

        self.scrollLayout = QVBoxLayout(self.scrollAreaWidgetContents)

        # Label for displaying registry information
        self.label = QLabel("Registry Information:")
        self.label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        self.scrollLayout.addWidget(self.label)

        # Button to update registry information
        self.update_button = QPushButton("Update")
        self.update_button.clicked.connect(self.update_registry_information)
        layout.addWidget(self.update_button)

    def extract_registry_information(self):
        # Limit the amount of data or implement data fetching in a background thread
        partitions = self.image_handler.get_partitions()
        registry_hives = []

        for partition in partitions:
            start_offset = partition[2]
            registry_data = self.image_handler.get_all_registry_hives(start_offset)
            if registry_data:
                registry_hives.append(registry_data)
        return registry_hives

    def update_registry_information(self):
        registry_information = self.extract_registry_information()
        # Clear the existing text
        self.label.setText("Registry Information:\n")

        # Adjusted display logic to match tuple structure
        for hive_data in registry_information:
            # Assuming hive_data is a tuple like (software_data, system_data, sam_data, security_data)
            for hive_name, hive_content in zip(["SOFTWARE", "SYSTEM", "SAM", "SECURITY"], hive_data):
                if hive_content:  # Check if hive_content is not None or empty
                    self.label.setText(self.label.text() + f"\n{hive_name}: Available\n")
                else:
                    self.label.setText(self.label.text() + f"\n{hive_name}: Not Available\n")

