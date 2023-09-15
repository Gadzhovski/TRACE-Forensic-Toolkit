class HexFormatter:

    def __init__(self, hex_content):
        self.hex_content = hex_content

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

    def format_hex(self):
        lines = []
        chunk_starts = range(0, len(self.hex_content), 32)
        for start in chunk_starts:
            lines.append(self.format_hex_chunk(start))
        return '\n'.join(lines)