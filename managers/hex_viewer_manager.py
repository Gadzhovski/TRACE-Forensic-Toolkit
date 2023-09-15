# class HexFormatter:
#
#     PAGE_SIZE = 4096 * 256  # updated page size
#     LINES_PER_PAGE = 1024
#
#     def __init__(self, hex_content):
#         self.hex_content = hex_content
#         self.num_total_pages = len(hex_content) // self.PAGE_SIZE + (1 if len(hex_content) % self.PAGE_SIZE else 0)
#         self.current_page = 0
#
#     def format_hex(self, page=0):
#         start_index = page * self.LINES_PER_PAGE * 32  # because each line has 32 characters of hex data
#         end_index = start_index + (self.LINES_PER_PAGE * 32)  # the end of this page's content
#
#         lines = []
#         chunk_starts = range(start_index, end_index, 32)
#
#         for start in chunk_starts:
#             if start >= len(self.hex_content):  # stop if there's no more content
#                 break
#             lines.append(self.format_hex_chunk(start))
#
#         return '\n'.join(lines)
#
#     def next_page(self):
#         if self.current_page < self.num_total_pages - 1:
#             self.current_page += 1
#             return self.format_hex()
#         return None
#
#     def prev_page(self):
#         if self.current_page > 0:
#             self.current_page -= 1
#             return self.format_hex()
#         return None
#
#     def first_page(self):
#         # Reset to the beginning of the hex content
#         self.current_offset = 0
#         return self.format_hex(0)
#
#     def last_page(self):
#         # Calculate the last page number
#         total_lines = len(self.hex_content) // 32
#         lines_per_page = 16  # This should match the value in format_hex method
#         last_page = (total_lines // lines_per_page) - 1
#         if total_lines % lines_per_page > 0:
#             last_page += 1
#         return self.format_hex(last_page)
#
#
#     def format_hex_chunk(self, start):
#         hex_part = []
#         ascii_repr = []
#         for j in range(start, start + 32, 2):
#             chunk = self.hex_content[j:j + 2]
#             if not chunk:
#                 break
#             try:
#                 chunk_int = int(chunk, 16)
#             except ValueError:
#                 print(f"Invalid chunk at index {j}: {chunk}")  # Debugging print statement
#                 continue  # Skip this chunk
#             hex_part.append(chunk.upper())
#             ascii_repr.append(chr(chunk_int) if 32 <= chunk_int <= 126 else '.')
#
#         hex_line = ' '.join(hex_part)
#         padding = ' ' * (48 - len(hex_line))
#         ascii_line = ''.join(ascii_repr)
#         line = f'0x{start // 2:08x}: {hex_line}{padding}  {ascii_line}'
#         return line
#
#     def total_pages(self):
#         total_chunks = len(self.hex_content) // 32
#         total_pages = total_chunks // self.LINES_PER_PAGE
#         if total_chunks % self.LINES_PER_PAGE != 0:  # If there are any remaining lines that don't fill a full page
#             total_pages += 1
#         return total_pages
#
#


class HexFormatter:
    LINES_PER_PAGE = 1024

    def __init__(self, hex_content):
        self.hex_content = hex_content
        self.num_total_pages = (len(hex_content) // 32) // self.LINES_PER_PAGE
        if (len(hex_content) // 32) % self.LINES_PER_PAGE:
            self.num_total_pages += 1

    def format_hex(self, page=0):
        start_index = page * self.LINES_PER_PAGE * 32
        end_index = start_index + (self.LINES_PER_PAGE * 32)

        lines = []
        chunk_starts = range(start_index, end_index, 32)

        for start in chunk_starts:
            if start >= len(self.hex_content):
                break
            lines.append(self.format_hex_chunk(start))

        return '\n'.join(lines)

    def format_hex_chunk(self, start):
        hex_part = []
        ascii_repr = []
        for j in range(start, start + 32, 2):
            chunk = self.hex_content[j:j + 2]
            if not chunk:
                break
            chunk_int = int(chunk, 16)
            hex_part.append(chunk.upper())
            ascii_repr.append(chr(chunk_int) if 32 <= chunk_int <= 126 else '.')

        hex_line = ' '.join(hex_part)
        padding = ' ' * (48 - len(hex_line))
        ascii_line = ''.join(ascii_repr)
        line = f'0x{start // 2:08x}: {hex_line}{padding}  {ascii_line}'
        return line

    def total_pages(self):
        return self.num_total_pages
