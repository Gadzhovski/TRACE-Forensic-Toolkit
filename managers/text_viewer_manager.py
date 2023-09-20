# text_viewer_manager.py

# class TextViewerManager:
#     def __init__(self):
#         self.text_content = ""
#
#     # def load_text_content(self, file_content):
#     #     # Check if the file is a text file
#     #     try:
#     #         text_content = file_content.decode('utf-8')
#     #         self.text_content = text_content
#     #     except UnicodeDecodeError:
#     #         self.text_content = "Non-text file"
#     def load_text_content(self, file_content):
#         # Attempt to decode the file content as text
#         text_content = file_content.decode('utf-8', errors='ignore')  # Use 'errors' parameter to handle non-text data
#         self.text_content = text_content
#
#     def get_text_content(self):
#         return self.text_content
#
#     def clear_content(self):
#         self.text_content = ""
#


import re

class TextViewerManager:
    PAGE_SIZE = 2000

    def __init__(self):
        self.text_content = ""
        self.current_page = 0
        self.last_search_str = ""
        self.current_match_index = -1
        self.matches = []

    def load_text_content(self, file_content):
        text_content = file_content.decode('utf-8', errors='ignore')
        self.text_content = text_content
        self.current_page = 0

    def get_text_content_for_current_page(self):
        start_idx = self.current_page * self.PAGE_SIZE
        end_idx = (self.current_page + 1) * self.PAGE_SIZE
        return self.text_content[start_idx:end_idx]

    def next_page(self):
        if (self.current_page + 1) * self.PAGE_SIZE < len(self.text_content):
            self.current_page += 1

    def prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1

    def jump_to_start(self):
        self.current_page = 0

    def jump_to_end(self):
        self.current_page = len(self.text_content) // self.PAGE_SIZE

    def search_for_string(self, search_str, direction="next"):
        if not search_str:  # If search string is empty, do nothing
            return

        if search_str != self.last_search_str:
            # New search string, so reset matches and current index
            self.matches = []
            self.current_match_index = -1
            self.last_search_str = search_str

        # Search direction: next
        if direction == "next":
            # Start searching from the position after the last found match
            start_pos = self.matches[self.current_match_index] + 1 if self.matches else 0
            next_match = self.text_content.find(search_str, start_pos)

            if next_match != -1:
                self.matches.append(next_match)
                self.current_match_index += 1
            else:
                # If no more matches, wrap the search from the beginning
                next_match = self.text_content.find(search_str)

                if next_match != -1:
                    self.matches = [next_match]
                    self.current_match_index = 0

        # Search direction: previous
        elif direction == "prev":
            # Start searching backward from the position before the last found match
            end_pos = self.matches[self.current_match_index] - 1 if self.matches else len(self.text_content) - 1
            prev_match = self.text_content.rfind(search_str, 0, end_pos)

            if prev_match != -1:
                self.matches.insert(0, prev_match)
                self.current_match_index = 0
            else:
                # If no more matches, wrap the search from the end
                prev_match = self.text_content.rfind(search_str)

                if prev_match != -1:
                    self.matches = [prev_match]
                    self.current_match_index = 0

        if self.matches:
            match_position = self.matches[self.current_match_index]
            self.current_page = match_position // self.PAGE_SIZE

    def clear_content(self):
        self.text_content = ""
        self.current_page = 0
        self.last_search_str = ""
        self.current_match_index = -1
        self.matches = []
