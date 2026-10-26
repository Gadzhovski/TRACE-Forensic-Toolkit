"""The files inside a file -- archive members, the files a document
embeds, the objects a browser cache keeps in its block files -- for the
media exports (core/vics.py) (no Qt).

The M57 'Jean' image held 211 pictures Griffeye listed inside archives
(ZIP skins, .jar, .wmz, Thumbs.db); TRACE's export walked files only, so
it had none of them. (Firefox's cache block files are read by
core/firefox_cache.py.)

`members(content, depth)` yields `Member`s in the order found, nested
members after their container. The archive readers are archives.py's
(every kind it browses), the document readers embedded.py's; nothing is
written to disk.
"""

import logging

from trace_app.core import archives, embedded

logger = logging.getLogger('TRACE.MediaInside')

#: Documents whose embedded files are read (embedded.kind_of); 'exif' --
#: a photo's own thumbnail -- is left out: every camera picture has one.
DOCUMENT_KINDS = ('pdf', 'ole', 'rtf', 'office')


class Member:
    """One file found inside another. `chain` is the names from the
    outermost container's first member down to this one."""

    __slots__ = ('chain', 'content', 'modified', 'kind')

    def __init__(self, chain, content, modified=None, kind=''):
        self.chain, self.content = chain, content
        self.modified, self.kind = modified, kind

    @property
    def name(self):
        return self.chain[-1].replace('\\', '/').rstrip('/').rsplit(
            '/', 1)[-1] or 'member'


def kind_of(head_or_content):
    """'archive:<kind>' / 'document:<kind>' when the bytes are a container
    whose members are read here, else None. Cheap: the header only."""
    try:
        kind = archives.detect_archive(head_or_content)
    except Exception:
        kind = None
    if kind is not None:
        return f'archive:{kind}'
    try:
        kind = embedded.kind_of(head_or_content)
    except Exception:
        kind = None
    if kind in DOCUMENT_KINDS:
        return f'document:{kind}'
    return None


def members(content, depth=None, should_stop=None, chain=()):
    """Every member of `content` (bytes, or a file object for a mailbox),
    and of the containers among them, to `depth` levels (the case's
    archive nesting setting, archives.MAX_NESTING, by default: a picture
    in a .zip in an attachment of a message in a mailbox is 3 deep)."""
    if depth is None:
        depth = archives.MAX_NESTING
    if depth <= 0 or content is None:
        return
    found = kind_of(content)
    if found is None:
        return
    family, _, kind = found.partition(':')
    if family == 'archive':
        listing = _archive_members(content, kind)
    else:
        listing = _document_members(content)
    for name, member_bytes, modified in listing:
        if should_stop is not None and should_stop():
            return
        here = chain + (name,)
        yield Member(here, member_bytes, modified, kind)
        if depth > 1 and member_bytes:
            yield from members(member_bytes, depth - 1, should_stop, here)


def _archive_members(content, kind):
    try:
        for member, member_bytes in archives.iter_members(content, kind):
            if member.get('is_dir') or member_bytes is None:
                continue
            if isinstance(member_bytes, Exception):
                logger.debug("Member %s not read: %s", member.get('name'),
                             member_bytes)
                continue
            yield member['name'], member_bytes, member.get('modified')
    except archives.ArchiveError as exc:
        logger.debug("Archive (%s) not listed: %s", kind, exc)
    except Exception as exc:                # a damaged container
        logger.debug("Archive (%s) not read whole: %s: %s", kind,
                     type(exc).__name__, exc)


def _document_members(content):
    try:
        for member, member_bytes in embedded.iter_members(bytes(content)):
            yield member['name'], member_bytes, None
    except Exception as exc:
        logger.debug("Embedded files not read: %s", exc)
