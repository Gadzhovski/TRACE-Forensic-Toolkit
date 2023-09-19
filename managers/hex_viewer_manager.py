class HexViewerManager:
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

    def search(self, query):
        # Convert query to hex
        query_hex = ''.join([f'{ord(c):02x}' for c in query])

        # Search the hex content for the query
        matches = []
        start = 0
        while start < len(self.hex_content):
            start = self.hex_content.find(query_hex, start)
            if start == -1:
                break

            # Convert byte index to line number
            line_number = start // 32
            matches.append(line_number)

            start += len(query_hex)

        return matches

    def get_line_by_address(self, address):
        """Convert an address to a line number."""
        if not address.startswith("0x"):
            return None
        try:
            byte_address = int(address, 16)
            line = byte_address // 16
            return line
        except ValueError:
            return None

