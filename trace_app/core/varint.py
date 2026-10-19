"""Unsigned LEB128 ("base-128 varint"): seven bits a byte, low bits first,
the top bit set on every byte but the last.

LevelDB, protobuf, Snappy's length preamble and Notepad's TabState files
all write numbers this way; each reader raises its own error type, so
`error` names it."""


def uleb128(data: bytes | bytearray | memoryview, position: int,
            error: type[Exception] = ValueError,
            bits: int = 64) -> tuple[int, int]:
    """(value, position after) of the number at `position` in `data`.

    Raises `error` when the data ends inside the number or the number runs
    past `bits` (64 for 64-bit fields; Snappy's length is 32-bit)."""
    result = shift = 0
    end = len(data)
    while True:
        if position >= end:
            raise error("number cut short at the end of the data")
        byte = data[position]
        position += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, position
        shift += 7
        if shift >= bits:
            raise error(f"number longer than {bits} bits")
