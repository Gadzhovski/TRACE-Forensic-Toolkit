"""Page, swap and hibernation files: memory written to disk (no Qt).

Windows writes RAM to `pagefile.sys` and `swapfile.sys` as it needs room,
and all of it to `hiberfil.sys` on hibernation and fast start-up. What was
in memory -- URLs, chat lines, documents being edited, passwords typed --
lands there in no structure a file reader understands, much as it lands
in free space. So they are treated as free space is: indexed in pieces
(core/indexer.py, kind 'memory') and carved as a source of their own
(core/carving.py, source 'memory'), each hit referring to its bytes on
the image, so it previews from there.

hiberfil.sys is read as stored: Windows 8 and later compress most of it
(Xpress), and that is not decompressed here -- its uncompressed parts and
older hibernation files still yield their text and files.
"""

import logging

logger = logging.getLogger('TRACE.MemoryFiles')

NAMES = ('pagefile.sys', 'swapfile.sys', 'hiberfil.sys')


def find(image_handler, should_stop=None):
    """[{'path', 'name', 'ref', 'size', 'runs': [(image offset, length)]}]
    for each memory file at the root of a volume TRACE reads through The
    Sleuth Kit (their data runs on the image)."""
    from trace_app.core.case import make_artifact_ref
    from trace_app.core.deleted import data_runs
    from trace_app.core.libyal_fs import is_libyal
    from trace_app.core.logical import is_logical
    out = []
    try:
        offsets = image_handler.volume_offsets()
    except Exception as exc:
        logger.debug("No volumes: %s", exc)
        return out
    for offset in offsets:
        if should_stop and should_stop():
            break
        try:
            fs = image_handler.get_fs_info(offset)
            if fs is None or is_logical(fs) or is_libyal(fs):
                continue
            base = image_handler.partition_bytes(offset)[0]
            root = fs.open_dir(path='/')
        except Exception as exc:
            logger.debug("Volume at %s not searched for memory files: %s",
                         offset, exc)
            continue
        for entry in root:
            info = entry.info
            if info.name is None or info.meta is None:
                continue
            name = info.name.name.decode('utf-8', 'replace')
            if name.lower() not in NAMES or not info.meta.size:
                continue
            try:
                handle = fs.open_meta(inode=info.meta.addr)
                runs, resident = data_runs(handle, fs.info.block_size, base)
            except Exception as exc:
                logger.debug("%s unreadable: %s", name, exc)
                continue
            if resident or not runs:
                continue
            out.append({'path': f"/{name}", 'name': name,
                        'offset': offset, 'size': int(info.meta.size),
                        'ref': make_artifact_ref(
                            offset, info.meta.addr,
                            getattr(info.name, 'meta_seq', None)),
                        'runs': _trim(runs, int(info.meta.size))})
    return out


def _trim(runs, size):
    """The runs cut to the file's size (the last cluster is partly
    slack, which is not the file)."""
    out, left = [], size
    for begin, length in runs:
        if left <= 0:
            break
        out.append((begin, min(length, left)))
        left -= length
    return out


def ranges(image_handler, should_stop=None):
    """[(image offset, length, path, ref)] of every memory file's data, in
    image order -- what slack.slack_ranges is to slack."""
    out = []
    for item in find(image_handler, should_stop):
        for begin, length in item['runs']:
            out.append((begin, length, item['path'], item['ref']))
    out.sort()
    return out
