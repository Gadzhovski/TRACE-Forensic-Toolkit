"""File slack: what is left in the last cluster of a live file, after its
end.

A file of 5,000 bytes on 4,096-byte clusters holds two clusters; the last
3,192 bytes of the second are not the file's. Whatever was in that cluster
before -- part of a deleted document, a page of a browser cache, a
password typed into something -- stays there until it is overwritten. The
file system keeps no record of it; only the file's size and its clusters
say where it is.

`slack_ranges` lists those regions for every live file with its data in
clusters (resident NTFS files have none), with the file they belong to.
Carving can search them (source 'slack'), and indexing extracts their text
so keyword lists and indicators reach them.

No Qt here.
"""

import logging
import re

logger = logging.getLogger('TRACE.Slack')

#: Shortest run of text worth keeping from slack.
MIN_TEXT = 6
_ASCII = re.compile(rb'[\x20-\x7e\t\r\n]{%d,}' % MIN_TEXT)
_UTF16 = re.compile(rb'(?:[\x20-\x7e]\x00){%d,}' % MIN_TEXT)


def file_slack(handle, size, block_size, base):
    """(byte offset in the image, length) of one file's slack, or None."""
    from trace_app.core.deleted import data_runs
    if not size or size % block_size == 0:
        return None
    runs, resident = data_runs(handle, block_size, base)
    if resident or not runs:
        return None
    remaining = size
    for begin, length in runs:
        if remaining <= length:
            start = begin + remaining
            end = begin + ((remaining + block_size - 1) // block_size) \
                * block_size
            return (start, end - start) if end > start else None
        remaining -= length
    return None


def slack_ranges(image_handler, should_stop=None):
    """[(offset, length, path, artifact ref)] for every live file's slack,
    in image order."""
    from trace_app.core import walk
    out, bases = [], {}
    for entry in walk.iter_files(image_handler, should_stop):
        if entry.deleted:
            continue
        if entry.offset not in bases:
            try:
                bases[entry.offset] = \
                    image_handler.partition_bytes(entry.offset)[0]
            except Exception:
                bases[entry.offset] = None
        base = bases[entry.offset]
        if base is None:
            continue
        try:
            handle = entry.fs.open_meta(inode=entry.inode)
            region = file_slack(handle, entry.size,
                                entry.fs.info.block_size, base)
        except Exception as exc:
            logger.debug("Slack of %s unreadable: %s", entry.path, exc)
            continue
        if region:
            out.append((region[0], region[1], entry.path, entry.ref))
    out.sort()
    return out


def text_of(data):
    """The readable text in slack (or unallocated) bytes: ASCII and
    UTF-16LE runs, and UTF-16 in a non-Latin alphabet in either byte order
    (text_extract.script_runs), one per line, in the order they lie."""
    from trace_app.core.text_extract import script_runs
    if not data.strip(b'\x00'):
        # Zeroed space holds no text, and is most of an image's free space
        # (2,634 of the 2,639 pieces of ntfs1-gen2's): checked in C, rather
        # than by four regular expressions a byte at a time -- indexing it
        # took four times as long as indexing the files.
        return ''
    found = [(m.start(), m.group().decode('ascii', 'replace').strip())
             for m in _ASCII.finditer(data)]
    found += [(m.start(), m.group().decode('utf-16-le', 'replace').strip())
              for m in _UTF16.finditer(data)]
    found += [(start, text.strip()) for start, text in script_runs(data)]
    found.sort()
    return '\n'.join(text for _start, text in found if len(text) >= MIN_TEXT)
