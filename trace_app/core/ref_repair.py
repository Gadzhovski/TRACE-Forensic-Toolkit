"""Bring artifact refs an older Listing wrote in line with the rest (no Qt).

Until 2.3 the Listing made a file's ref from its MFT entry's sequence, the
rest of TRACE (the walk, the analysis, core/deleted.py, and The Sleuth Kit's
fls) from the name entry's. For a live file they are one number. For a
deleted NTFS file they are not: TSK gives a deleted name no metadata, so the
Listing's ref had no sequence at all ('p0:i29'), and an entry freed and
taken again carried the new file's. A bookmark, tag, note or Project VIC
category put on a deleted file from the Listing therefore named it in a way
nothing else did -- the Deleted Files tab, the VICS export and the Listing
itself (which now reads the name's sequence) did not find it.

`resolve(handler, ref, path)` re-reads the name entry at the place the row
recorded (`path`, volume-relative, as the Listing writes it) and gives the
ref everything else makes; Case.repair_file_refs applies it, audited. Only
an entry whose inode is the ref's own is taken -- a name now pointing
elsewhere leaves the row as it was.
"""

import logging
import posixpath

from trace_app.core.case import make_artifact_ref, parse_artifact_ref

logger = logging.getLogger('TRACE.RefRepair')


class Resolver:
    """resolve(ref, path) -> the name entry's ref, or None (unchanged or not
    found). Folders are listed once."""

    def __init__(self, handler):
        self.handler = handler
        self._folders = {}

    def _entries(self, offset, folder):
        key = (offset, folder)
        if key not in self._folders:
            found = []
            try:
                fs = self.handler.get_fs_info(offset)
                directory = fs.open_dir(path=folder or '/') if fs else ()
                for entry in directory:
                    name = entry.info.name
                    if name is None:
                        continue
                    found.append((name.name.decode('utf-8', 'replace'),
                                  getattr(name, 'meta_addr', None),
                                  getattr(name, 'meta_seq', None)))
            except Exception as exc:
                logger.debug("%s on %s not listed: %s", folder, offset, exc)
            self._folders[key] = found
        return self._folders[key]

    def __call__(self, ref, path):
        parsed = parse_artifact_ref(ref)
        if parsed.get('kind') != 'file' or not path or '!/' in path:
            return None
        folder, name = posixpath.split('/' + path.strip('/'))
        matches = {sequence for entry_name, address, sequence in
                   self._entries(parsed['start_offset'], folder)
                   if entry_name == name and address == parsed['inode']
                   and sequence is not None}
        if len(matches) != 1:
            # Not there, or two names for one entry with different
            # sequences: nothing says which the row meant.
            return None
        fixed = make_artifact_ref(parsed['start_offset'], parsed['inode'],
                                  matches.pop())
        return fixed if fixed != ref else None
