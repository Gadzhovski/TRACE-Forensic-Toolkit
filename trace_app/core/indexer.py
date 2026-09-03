"""Walking evidence and feeding it to the search index.

The work itself is here rather than in the UI so it can be driven from a script
or a test. The Qt thread that runs it lives in the search panel.

Indexing is resumable by design: a large image takes minutes, an examiner will
cancel one, and starting again from the beginning after a cancel is the kind of
behaviour that stops people using a feature at all.
"""

import logging

import pytsk3

from trace_app.core.archives import (ArchiveError, detect_archive,
                                     list_members, read_member)
from trace_app.core.case import make_artifact_ref
from trace_app.core.search_index import (INDEX_CANCELLED, INDEX_DONE,
                                         INDEX_FAILED, INDEX_RUNNING,
                                         MAX_FILE_BYTES, MAX_TEXT_PER_FILE)
from trace_app.core.text_extract import extract_text

logger = logging.getLogger('TRACE.Indexer')

#: How deep the walk follows directories. Matches the allocation-map walk.
MAX_DEPTH = 64

#: Archives are opened and their members indexed, up to this many levels.
#: One level covers the common case -- a ZIP of documents -- without letting a
#: constructed archive dominate the run.
ARCHIVE_DEPTH = 2


class IndexerCancelled(Exception):
    """The caller asked the run to stop."""


def index_evidence(image_handler, index, evidence_id, progress=None,
                   should_stop=None):
    """Index every file in one piece of evidence.

    `progress(done, total, path)` is called as the walk proceeds, and
    `should_stop()` is consulted often enough that Cancel feels immediate.

    Returns the number of items indexed.
    """
    index.clear_evidence(evidence_id)
    index.set_state(evidence_id, INDEX_RUNNING, files_done=0)

    partitions = image_handler.get_partitions()
    offsets = [p[2] for p in partitions] if partitions else [0]

    total = 0
    done = 0

    try:
        # Counting first means the progress bar is honest rather than a
        # spinner pretending to know how far along it is.
        for offset in offsets:
            if image_handler.get_fs_type(offset) in ('N/A', 'Unknown'):
                continue
            total += _count_files(image_handler, offset, should_stop)

        index.set_state(evidence_id, INDEX_RUNNING, files_total=total)

        for offset in offsets:
            if image_handler.get_fs_type(offset) in ('N/A', 'Unknown'):
                continue
            done = _index_partition(
                image_handler, index, evidence_id, offset,
                done, total, progress, should_stop)

        index.commit()
        index.set_state(evidence_id, INDEX_DONE, files_done=done,
                        files_total=total)
        logger.info("Indexed %d item(s) for evidence %s", done, evidence_id)
        return done

    except IndexerCancelled:
        index.commit()      # keep what was already read; the run resumes
        index.set_state(evidence_id, INDEX_CANCELLED, files_done=done,
                        files_total=total)
        logger.info("Indexing cancelled after %d item(s)", done)
        return done

    except Exception as exc:
        index.commit()
        index.set_state(evidence_id, INDEX_FAILED, files_done=done,
                        last_error=str(exc))
        logger.error("Indexing failed: %s", exc)
        raise


def _count_files(image_handler, offset, should_stop):
    """How many files the walk will visit, for an honest progress bar."""
    count = 0
    fs_info = image_handler.get_fs_info(offset)
    if fs_info is None:
        return 0

    def walk(directory, depth):
        nonlocal count
        if depth > MAX_DEPTH:
            return
        for entry in directory:
            if should_stop and should_stop():
                raise IndexerCancelled()
            if entry.info.name is None or entry.info.meta is None:
                continue
            name = entry.info.name.name.decode('utf-8', 'replace')
            if name in ('.', '..'):
                continue
            if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    walk(entry.as_directory(), depth + 1)
                except Exception:
                    continue
            elif entry.info.meta.size:
                count += 1

    try:
        walk(fs_info.open_dir(path='/'), 0)
    except IndexerCancelled:
        raise
    except Exception as exc:
        logger.debug("Could not count files at %s: %s", offset, exc)
    return count


def _index_partition(image_handler, index, evidence_id, offset, done, total,
                     progress, should_stop):
    fs_info = image_handler.get_fs_info(offset)
    if fs_info is None:
        return done

    visited = set()

    def walk(directory, path, depth):
        nonlocal done
        if depth > MAX_DEPTH:
            return
        for entry in directory:
            if should_stop and should_stop():
                raise IndexerCancelled()
            if entry.info.name is None or entry.info.meta is None:
                continue
            name = entry.info.name.name.decode('utf-8', 'replace')
            if name in ('.', '..'):
                continue

            meta = entry.info.meta
            inode = meta.addr
            if inode in visited:
                continue        # hard links, and directory cycles
            visited.add(inode)

            child_path = f"{path}/{name}".replace('//', '/')

            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    walk(entry.as_directory(), child_path, depth + 1)
                except IndexerCancelled:
                    raise
                except Exception:
                    continue
                continue

            if not meta.size:
                continue

            done += 1
            if progress:
                progress(done, total, child_path)

            _index_file(image_handler, index, evidence_id, offset, inode,
                        getattr(meta, 'seq', None), name, child_path,
                        meta.size)

            # Committing periodically means a cancel or a crash keeps most of
            # the work rather than none of it.
            if done % 200 == 0:
                index.commit()
                index.set_state(evidence_id, INDEX_RUNNING, files_done=done,
                                files_total=total, last_path=child_path)

    walk(fs_info.open_dir(path='/'), '', 0)
    return done


def _index_file(image_handler, index, evidence_id, offset, inode, sequence,
                name, path, size):
    """Index one file, and the members of it if it is an archive."""
    ref = make_artifact_ref(offset, inode, sequence)

    if size > MAX_FILE_BYTES:
        # Too large to read; still worth finding by name.
        index.add_item(evidence_id, ref, 'file', name, path, '', size)
        return

    try:
        content, _meta = image_handler.get_file_content(inode, offset)
    except Exception as exc:
        logger.debug("Could not read %s: %s", path, exc)
        index.add_item(evidence_id, ref, 'file', name, path, '', size)
        return

    if not content:
        index.add_item(evidence_id, ref, 'file', name, path, '', size)
        return

    text = extract_text(content, name, limit=MAX_TEXT_PER_FILE)
    index.add_item(evidence_id, ref, 'file', name, path, text, size)

    # An archive's members are what an examiner is looking for; the archive
    # itself is just the container they arrived in.
    if detect_archive(content):
        _index_archive(index, evidence_id, ref, content, path, ARCHIVE_DEPTH)


def _index_archive(index, evidence_id, parent_ref, content, parent_path,
                   depth):
    """Index the members of an archive, and of archives inside it."""
    if depth <= 0:
        return

    try:
        members = list_members(content)
    except ArchiveError as exc:
        logger.debug("Could not list %s: %s", parent_path, exc)
        return

    for member in members:
        if member['is_dir'] or member['encrypted']:
            # An encrypted member's name is still evidence and is indexed
            # below; its contents cannot be read without the password.
            if member['encrypted']:
                index.add_item(
                    evidence_id, parent_ref, 'archive-member',
                    member['name'], f"{parent_path}!/{member['name']}",
                    '', member['size'])
            continue

        try:
            member_bytes = read_member(content, member['name'])
        except ArchiveError as exc:
            logger.debug("Could not read %s from %s: %s",
                         member['name'], parent_path, exc)
            continue

        member_path = f"{parent_path}!/{member['name']}"
        text = extract_text(member_bytes, member['name'],
                            limit=MAX_TEXT_PER_FILE)
        index.add_item(evidence_id, parent_ref, 'archive-member',
                       member['name'], member_path, text, member['size'])

        if detect_archive(member_bytes):
            _index_archive(index, evidence_id, parent_ref, member_bytes,
                           member_path, depth - 1)
