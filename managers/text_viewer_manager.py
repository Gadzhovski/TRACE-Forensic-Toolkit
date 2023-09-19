# text_viewer_manager.py

class TextViewerManager:
    def __init__(self):
        self.text_content = ""

    # def load_text_content(self, file_content):
    #     # Check if the file is a text file
    #     try:
    #         text_content = file_content.decode('utf-8')
    #         self.text_content = text_content
    #     except UnicodeDecodeError:
    #         self.text_content = "Non-text file"
    def load_text_content(self, file_content):
        # Attempt to decode the file content as text
        text_content = file_content.decode('utf-8', errors='ignore')  # Use 'errors' parameter to handle non-text data
        self.text_content = text_content

    def get_text_content(self):
        return self.text_content

    def clear_content(self):
        self.text_content = ""

