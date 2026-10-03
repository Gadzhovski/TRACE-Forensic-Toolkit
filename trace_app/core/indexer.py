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
from trace_app.infra.utils import safe_datetime

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

    from trace_app.core.walk import volume_offsets
    offsets = volume_offsets(image_handler)

    total = 0
    done = 0

    try:
        # Count first so the progress bar is honest rather than a spinner
        # pretending to know how far along it is. Volumes that cannot be
        # opened simply count zero -- get_fs_info returns None and the walk
        # handles it, so there is no need to ask a second question first.
        #
        # There used to be a get_fs_type() guard here. It depends on a cached
        # FS_Info, gave a different answer on the worker thread than on the
        # one that loaded the image, and skipped every volume: indexing then
        # reported success having read nothing at all.
        for offset in offsets:
            total += _count_files(image_handler, offset, should_stop)

        logger.info("Indexing evidence %s: %d file(s) across %d volume(s)",
                    evidence_id, total, len(offsets))
        if not total:
            logger.warning(
                "Nothing to index in evidence %s. Volumes examined: %s",
                evidence_id,
                ", ".join(f"{o} ({image_handler.get_fs_type(o)})"
                          for o in offsets))
        index.set_state(evidence_id, INDEX_RUNNING, files_total=total)

        for offset in offsets:
            before = done
            done = _index_partition(
                image_handler, index, evidence_id, offset,
                done, total, progress, should_stop)
            if done == before:
                logger.debug("Volume at %s contributed nothing", offset)

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
        logger.debug("No filesystem to count at offset %s", offset)
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
        logger.warning("Could not count files at %s: %s: %s",
                       offset, type(exc).__name__, exc)
    return count


def _index_partition(image_handler, index, evidence_id, offset, done, total,
                     progress, should_stop):
    fs_info = image_handler.get_fs_info(offset)
    if fs_info is None:
        logger.debug("No filesystem to index at offset %s", offset)
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
                        meta.size, _entry_times(meta))

            # Committing periodically means a cancel or a crash keeps most of
            # the work rather than none of it.
            if done % 200 == 0:
                index.commit()
                index.set_state(evidence_id, INDEX_RUNNING, files_done=done,
                                files_total=total, last_path=child_path)

    walk(fs_info.open_dir(path='/'), '', 0)
    return done


def _entry_times(meta):
    """The four timestamps a listing shows, formatted as it formats them."""
    return {
        'created': safe_datetime(getattr(meta, 'crtime', None)),
        'accessed': safe_datetime(getattr(meta, 'atime', None)),
        'modified': safe_datetime(getattr(meta, 'mtime', None)),
        'changed': safe_datetime(getattr(meta, 'ctime', None)),
        'is_deleted': not bool(int(meta.flags)
                               & pytsk3.TSK_FS_META_FLAG_ALLOC),
    }


def _index_file(image_handler, index, evidence_id, offset, inode, sequence,
                name, path, size, times=None):
    """Index one file, and the members of it if it is an archive."""
    ref = make_artifact_ref(offset, inode, sequence)
    times = times or {}
    facts = dict(inode=inode, start_offset=offset,
                 created_utc=times.get('created', ''),
                 accessed_utc=times.get('accessed', ''),
                 mtime_utc=times.get('modified', ''),
                 changed_utc=times.get('changed', ''),
                 is_deleted=times.get('is_deleted', False))

    if name.lower().endswith(('.pst', '.ost')) and \
            hasattr(image_handler, 'open_file_object'):
        # A mailbox is read lazily -- it is often far larger than any file
        # held in memory -- and indexed message by message.
        stream = image_handler.open_file_object(inode, offset)
        if stream is not None and detect_archive(stream) == 'pst':
            index.add_item(evidence_id, ref, 'file', name, path, '', size,
                           **facts)
            _index_archive(index, evidence_id, ref, stream, path,
                           ARCHIVE_DEPTH)
            return

    if size > MAX_FILE_BYTES:
        # Too large to read; still worth finding by name.
        index.add_item(evidence_id, ref, 'file', name, path, '', size, **facts)
        return

    try:
        content, _meta = image_handler.get_file_content(inode, offset)
    except Exception as exc:
        logger.debug("Could not read %s: %s", path, exc)
        index.add_item(evidence_id, ref, 'file', name, path, '', size, **facts)
        return

    if not content:
        index.add_item(evidence_id, ref, 'file', name, path, '', size, **facts)
        return

    text = extract_text(content, name, limit=MAX_TEXT_PER_FILE)
    index.add_item(evidence_id, ref, 'file', name, path, text, size, **facts)

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
