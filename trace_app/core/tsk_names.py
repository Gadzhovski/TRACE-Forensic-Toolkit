"""File names as the file system stores them, not as The Sleuth Kit cuts
them.

TSK keeps a name in 256 bytes of UTF-8 (`TSK_FS_NAME.name`, name_size
257). NTFS allows 255 UTF-16 characters, up to 765 bytes of UTF-8: a
253-character German photo name on X-Ways' NTFS training image came out
of TSK as '... den Club betritt.jp' -- the extension cut, so the file
was no picture to anything that judged it by name. The whole name is in
the MFT entry's $FILE_NAME attribute; `entry_name` reads it from there
when TSK's name fills its buffer (rare: one file in that image).

TSK finds a path by its own cut names, so a path holding a whole long
name is opened through `tsk_path`, which cuts each part the way TSK did.
"""

import logging

logger = logging.getLogger('TRACE.TskNames')

#: Bytes of UTF-8 TSK keeps of a name.
TSK_NAME_BYTES = 256
_FILE_NAME = 0x30            # NTFS $FILE_NAME
_DOS_NAMESPACE = 2           # the 8.3 alias


def entry_name(entry, fs=None, errors='replace'):
    """The name of a pytsk3 directory entry, whole even where TSK cut it
    (NTFS, read from `fs`, the entry's FS_Info)."""
    raw = entry.info.name.name
    text = raw.decode('utf-8', errors)
    if len(raw) < TSK_NAME_BYTES - 3 or fs is None:
        return text
    return _whole_name(entry, fs, raw) or text


def _whole_name(entry, fs, raw):
    meta = entry.info.meta
    address = meta.addr if meta is not None else \
        getattr(entry.info.name, 'meta_addr', None)
    if not address:
        return None
    prefix = raw.decode('utf-8', 'ignore')        # a cut character dropped
    try:
        file = fs.open_meta(inode=address)
        for attribute in file:
            info = attribute.info
            if int(info.type) != _FILE_NAME or not info.size:
                continue
            data = file.read_random(0, info.size, info.type, info.id)
            if len(data) < 66 or data[65] == _DOS_NAMESPACE:
                continue
            name = data[66:66 + 2 * data[64]].decode('utf-16-le', 'replace')
            # The entry may have been reused: only a name TSK's begins.
            if len(name) > len(prefix) and name.startswith(prefix):
                return name
    except Exception as exc:      # a damaged entry keeps TSK's name
        logger.debug("Whole name of entry %s not read: %s", address, exc)
    return None


def tsk_name(name):
    """`name` as TSK holds it: UTF-8, cut to `TSK_NAME_BYTES` at a
    character's end."""
    data = name.encode('utf-8')
    if len(data) <= TSK_NAME_BYTES:
        return name
    return data[:TSK_NAME_BYTES].decode('utf-8', 'ignore')


def tsk_path(path):
    """`path` with every part as TSK holds it (see `tsk_name`)."""
    return '/'.join(tsk_name(part) for part in path.split('/'))


def open_path(fs, path):
    """`fs.open(path)`, for a path that may hold whole long names."""
    try:
        return fs.open(path=path)
    except (IOError, OSError):
        cut = tsk_path(path)
        if cut == path:
            raise
        return fs.open(path=cut)
