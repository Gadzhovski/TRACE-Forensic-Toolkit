"""Walking evidence and feeding it to the search index.

The work itself is here rather than in the UI so it can be driven from a script
or a test. The Qt thread that runs it lives in the search panel.

Indexing is resumable by design: a large image takes minutes, an examiner will
cancel one, and starting again from the beginning after a cancel is the kind of
behaviour that stops people using a feature at all.
"""

import logging
import os

import pytsk3

from trace_app.core.archives import (STREAMED_KINDS, ArchiveError,
                                     detect_archive, iter_members)
from trace_app.core import embedded
from trace_app.core import scope as scope_module
from trace_app.core.case import make_artifact_ref
from trace_app.core.search_index import (INDEX_CANCELLED, INDEX_DONE,
                                         INDEX_FAILED, INDEX_RUNNING,
                                         MAX_FILE_BYTES, MAX_TEXT_PER_FILE)
from trace_app.core.text_extract import extract_text, packed_kind
from trace_app.core.text_pool import (MIN_FILES, TextPipeline,
                                      default_workers)

logger = logging.getLogger('TRACE.Indexer')

#: How deep the walk follows directories. Matches the allocation-map walk.
MAX_DEPTH = 64

#: Archives are opened and their members indexed, up to this many levels.
#: One level covers the common case -- a ZIP of documents -- without letting a
#: constructed archive dominate the run.
ARCHIVE_DEPTH = 2


#: Index the files documents embed (core/embedded): pictures in PDFs and
#: Office files, packaged files, attachments. EXIF thumbnails have no
#: text, so photos are not opened for them here.
INDEX_EMBEDDED = True
EMBEDDING_KINDS = ('pdf', 'ole', 'rtf')

#: Index the text in unallocated space (case setting 'index_unallocated').
INDEX_UNALLOCATED = True
#: Index page, swap and hibernation files in pieces (case setting
#: 'index_memory_files'; core/memory_files.py).
INDEX_MEMORY_FILES = True
#: Free space is indexed in pieces this size, each an item of its own with
#: its byte span -- small enough that a hit says where to look.
UNALLOCATED_PIECE = 1024 * 1024


class IndexerCancelled(Exception):
    """The caller asked the run to stop."""


def _scope_signature(scope):
    """The scope a run was made with, as index_state keeps it."""
    import json
    return '' if scope is None else json.dumps(scope.to_dict(),
                                               sort_keys=True)


def index_evidence(image_handler, index, evidence_id, progress=None,
                   should_stop=None, scope=None, resume=False):
    """Index every file in one piece of evidence -- every file in `scope`
    (core/scope.Scope; None: every file). Free space and memory files are
    `index_free_space`'s, a job of their own.

    `progress(done, total, path)` is called as the walk proceeds, and
    `should_stop()` is consulted often enough that Cancel feels immediate.

    `resume`: a run that stopped (cancelled, failed, or cut off by TRACE
    closing) with the same scope continues -- files already indexed are
    skipped (`SearchIndex.resume_point`) -- rather than starting over.

    Returns the number of files indexed.
    """
    signature = _scope_signature(scope)
    state = index.state(evidence_id) or {}
    resuming = bool(resume and state.get('status') in (
        INDEX_RUNNING, INDEX_CANCELLED, INDEX_FAILED)
        and (state.get('scope') or '') == signature
        and state.get('files_done'))
    if resuming:
        indexed = index.resume_point(evidence_id)
        logger.info("Resuming the index of evidence %s: %d file(s) already "
                    "indexed", evidence_id, len(indexed))
    else:
        indexed = set()
        index.clear_evidence(evidence_id, keep_free=True)
    index.set_state(evidence_id, INDEX_RUNNING, files_done=0,
                    scope=signature)

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
        matchers = {offset: scope.matcher(image_handler.get_fs_info(offset))
                    if scope is not None else None for offset in offsets}
        for offset in offsets:
            total += _count_files(image_handler, offset, should_stop,
                                  matchers[offset])

        logger.info("Indexing evidence %s: %d file(s) across %d volume(s)%s",
                    evidence_id, total, len(offsets),
                    '' if scope is None or scope.everything else
                    f"; scope: {scope.describe()}")
        if not total:
            logger.warning(
                "Nothing to index in evidence %s. Volumes examined: %s",
                evidence_id,
                ", ".join(f"{o} ({image_handler.get_fs_type(o)})"
                          for o in offsets))
        index.set_state(evidence_id, INDEX_RUNNING, files_total=total)

        # Text and indicators on worker processes for a run worth it
        # (core/text_pool); rows still written here, in walk order.
        workers = default_workers() if total >= MIN_FILES else 1
        texts = TextPipeline(_writer(index), workers,
                             getattr(index, 'folder', None))
        if texts.parallel:
            logger.info("Extracting text on %d worker processes", workers)
        try:
            for offset in offsets:
                before = done
                done = _index_partition(
                    image_handler, index, evidence_id, offset,
                    done, total, progress, should_stop, matchers[offset],
                    scope is None or scope.covers_free_space, texts,
                    indexed)
                if done == before:
                    logger.debug("Volume at %s contributed nothing", offset)
            texts.close()
        except BaseException:
            texts.close(cancel=True)
            raise
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


def index_carved(read, case, index, evidence_id, should_stop=None):
    """Index one image's carved files, and the members of those that are
    archives (a carved .docx's text, a ZIP's files, a mailbox's messages).

    Each is read back from the image at its offset -- or its fragments, if
    it was rebuilt from them -- never from the copy in the case folder, and
    is referenced by its span, as a carved file is everywhere else. The
    previous carve's items are dropped first: a carve replaces the last.
    Returns the number of carved files indexed.
    """
    from trace_app.core.carving import read_carved
    from trace_app.core.case import make_span_ref
    index.clear_carved(evidence_id)
    count = 0
    for row in case.carved_files(evidence_id, limit=1_000_000):
        if should_stop is not None and should_stop():
            raise IndexerCancelled()
        offset, size = int(row['offset']), int(row['size'])
        ref = make_span_ref(0, offset, offset + size)
        origin = row.get('origin') or {}
        name = os.path.basename(row['path']) or row['name']
        from trace_app.core.carving import carved_path
        path = carved_path(name, origin)
        text = ''
        content = None
        if size <= MAX_FILE_BYTES:
            try:
                content = read_carved(read, offset, size, row.get('fragments'))
                text = extract_text(content, name, limit=MAX_TEXT_PER_FILE)
            except Exception as exc:
                logger.debug("Carved %s unreadable: %s", name, exc)
        index.add_item(evidence_id, ref, 'carved', name, path, text, size,
                       mtime_utc=(row.get('embedded_date') or '')
                       if row.get('embedded_date') != 'N/A' else '')
        if content and detect_archive(content):
            _index_archive(index, evidence_id, ref, content, path,
                           ARCHIVE_DEPTH)
        count += 1
        if count % 200 == 0:
            index.commit()
    index.commit()
    logger.info("Indexed %d carved file(s) for evidence %s", count,
                evidence_id)
    return count


def _count_files(image_handler, offset, should_stop, matcher=None):
    """How many files the walk will visit, for an honest progress bar."""
    count = 0
    fs_info = image_handler.get_fs_info(offset)
    if fs_info is None:
        logger.debug("No filesystem to count at offset %s", offset)
        return 0

    def walk(directory, path, depth):
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
            child_path = f"{path}/{name}"
            if scope_module.entry_skipped(matcher, child_path,
                                          entry.info.meta):
                continue
            if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    walk(entry.as_directory(), child_path, depth + 1)
                except IndexerCancelled:
                    raise
                except Exception:
                    continue
            elif entry.info.meta.size:
                count += 1

    try:
        walk(fs_info.open_dir(path='/'), '', 0)
    except IndexerCancelled:
        raise
    except Exception as exc:
        logger.warning("Could not count files at %s: %s: %s",
                       offset, type(exc).__name__, exc)
    return count


def _index_partition(image_handler, index, evidence_id, offset, done, total,
                     progress, should_stop, matcher=None, slack=True,
                     texts=None, indexed=frozenset()):
    fs_info = image_handler.get_fs_info(offset)
    if fs_info is None:
        logger.debug("No filesystem to index at offset %s", offset)
        return done

    visited = set()
    if texts is None:
        texts = TextPipeline(_writer(index))

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
            # Out of scope (core/scope): a folder is not gone into at all.
            if scope_module.entry_skipped(matcher, child_path, meta):
                continue

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
            sequence = getattr(meta, 'seq', None)
            if indexed and make_artifact_ref(offset, inode,
                                             sequence) in indexed:
                continue            # read by the run this one resumes

            _index_file(image_handler, index, evidence_id, offset, inode,
                        sequence, name, child_path,
                        meta.size, _entry_times(image_handler, offset,
                                                meta), texts)
            if slack and int(meta.flags) & pytsk3.TSK_FS_META_FLAG_ALLOC:
                _index_slack(image_handler, index, evidence_id, fs_info,
                             offset, inode, name, child_path, meta.size,
                             texts)

            # Committing periodically means a cancel or a crash keeps most of
            # the work rather than none of it.
            if done % 200 == 0:
                index.commit()      # the rows written so far
                index.set_state(evidence_id, INDEX_RUNNING, files_done=done,
                                files_total=total, last_path=child_path)

    walk(fs_info.open_dir(path='/'), '', 0)
    return done


#: Free space indexed between checkpoints (bytes): what a resumed run
#: reads again at most.
FREE_CHECKPOINT = 64 * 1024 * 1024


def index_free_space(image_handler, index, evidence_id, progress=None,
                     should_stop=None, scope=None, resume=True):
    """The text in an image's free space and its page, swap and
    hibernation files -- the slow part of indexing, a job of its own so
    the file index is searchable first. Resumable: a stopped run continues
    from its last checkpoint (`FREE_CHECKPOINT`). Returns the items
    written; 0 when the case setting or `scope` leaves free space out."""
    if scope is not None and not scope.covers_free_space:
        logger.info("Free space is outside the scope: not indexed")
        return 0
    from trace_app.core.search_index import INDEX_DONE as DONE
    state = index.state(evidence_id) or {}
    start = (state.get('free_done') or 0) if resume and \
        index.free_unfinished(evidence_id) else 0
    if start:
        logger.info("Resuming free-space indexing of evidence %s at %.1f MB",
                    evidence_id, start / 1048576)
        index.clear_free(evidence_id, ('memory',))   # that step restarts
    else:
        index.clear_free(evidence_id)
    position = [start, 0]           # bytes of free space done, of total

    def checkpoint(read, total):
        position[:] = [read, total]
        index.commit()
        index.set_free_state(evidence_id, INDEX_RUNNING, read, total)

    index.set_free_state(evidence_id, INDEX_RUNNING, start, 0)
    count = 0
    try:
        if INDEX_UNALLOCATED:
            count += _index_unallocated(image_handler, index, evidence_id,
                                        progress, should_stop, skip=start,
                                        checkpoint=checkpoint)
        if INDEX_MEMORY_FILES:
            count += _index_memory_files(image_handler, index, evidence_id,
                                         progress, should_stop)
    except IndexerCancelled:
        # The unallocated step checkpointed where it stopped; a stop in
        # the memory files restarts that step (its rows are cleared).
        index.set_free_state(evidence_id, INDEX_CANCELLED, *position)
        logger.info("Free-space indexing cancelled at %.1f MB",
                    position[0] / 1048576)
        return count
    except Exception as exc:
        # Back to the last checkpoint: rows after it would be read again
        # by the resume, and counted twice.
        index.rollback()
        index.set_free_state(evidence_id, INDEX_FAILED, *position)
        logger.error("Free-space indexing failed: %s", exc)
        raise
    index.commit()
    index.set_free_state(evidence_id, DONE, position[1] or position[0],
                         position[1] or position[0])
    return count


def _index_unallocated(image_handler, index, evidence_id, progress=None,
                       should_stop=None, skip=0, checkpoint=None):
    """The text in free space -- outside every partition and in clusters no
    live file holds -- as items of kind 'unallocated', one per piece with
    text, referenced by byte span so a hit previews from the image. Text in
    no file was invisible to search: NIST's Russian Tea Room hides four of
    its eight menu sections there. Returns the number of items."""
    from trace_app.core import slack
    from trace_app.core.carving import allocation_map, free_ranges
    from trace_app.core.case import make_span_ref
    size = image_handler.get_size()
    if not size:
        return 0                    # logical evidence: no free space
    if progress:
        progress(0, 0, "Finding unallocated space")
    free = free_ranges(0, size, allocation_map(image_handler))
    total = sum(end - begin for begin, end in free)
    sector = image_handler.sector_size or 512
    count = read = 0
    since = 0                       # bytes since the last checkpoint
    if checkpoint:
        checkpoint(min(skip, total), total)
    for begin, end in free:
        for at in range(begin, end, UNALLOCATED_PIECE):
            if should_stop and should_stop():
                if checkpoint:
                    # Exactly here: the rows written so far are kept, and
                    # a resume starts after them, never among them.
                    checkpoint(read, total)
                raise IndexerCancelled()
            length = min(UNALLOCATED_PIECE, end - at)
            if read + length <= skip:
                read += length      # indexed by the run this resumes
                continue
            if checkpoint and since >= FREE_CHECKPOINT:
                checkpoint(read, total)
                since = 0
            try:
                data = image_handler.read(at, length)
                # Most free space is zeros: nothing to extract, and
                # extracting from them was most of this step's time.
                text = slack.text_of(data) if data.strip(b'\0') else ''
            except Exception as exc:
                logger.debug("Free space at %d unreadable: %s", at, exc)
                text = ''
            read += length
            since += length
            if progress:
                progress(read, total, "Unallocated space")
            if not text:
                continue
            first, last = at // sector, (at + length - 1) // sector
            index.add_item(evidence_id, make_span_ref(0, at, at + length),
                           'unallocated',
                           f"Unallocated, sectors {first:,}-{last:,}",
                           f"[unallocated]/sectors {first}-{last}", text,
                           length)
            count += 1
    if checkpoint:
        checkpoint(read, total)
    logger.info("Unallocated space: %d piece(s) with text in %.1f MB",
                count, total / (1024 * 1024))
    return count


def _index_memory_files(image_handler, index, evidence_id, progress=None,
                        should_stop=None):
    """The text in page, swap and hibernation files (core/memory_files),
    as items of kind 'memory', one per piece with text, each referring to
    its bytes on the image. Returns the number of items."""
    from trace_app.core import memory_files, slack
    from trace_app.core.case import make_span_ref
    found = memory_files.find(image_handler, should_stop)
    total = sum(length for item in found for _b, length in item['runs'])
    count = read = 0
    for item in found:
        within = 0                      # offset in the file
        for begin, length in item['runs']:
            for at in range(begin, begin + length, UNALLOCATED_PIECE):
                if should_stop and should_stop():
                    raise IndexerCancelled()
                piece = min(UNALLOCATED_PIECE, begin + length - at)
                start = within + (at - begin)
                try:
                    text = slack.text_of(image_handler.read(at, piece))
                except Exception as exc:
                    logger.debug("%s at %d unreadable: %s", item['name'],
                                 at, exc)
                    continue
                read += piece
                if progress:
                    progress(read, total, item['name'])
                if not text:
                    continue
                index.add_item(
                    evidence_id, make_span_ref(0, at, at + piece), 'memory',
                    f"{item['name']}, bytes {start:,}-{start + piece - 1:,}",
                    f"{item['path']} [memory]/bytes {start}-"
                    f"{start + piece - 1}", text, piece)
                count += 1
            within += length
    if found:
        logger.info("Memory files: %d piece(s) with text in %.1f MB",
                    count, total / (1024 * 1024))
    return count


def _index_slack(image_handler, index, evidence_id, fs_info, offset, inode,
                 name, path, size, texts=None):
    """The text in a live file's slack, as an item of its own: whatever
    was in its last cluster before it (core/slack.py). Referenced by its
    byte span, so it previews from the image."""
    from trace_app.core import slack
    from trace_app.core.case import make_span_ref
    try:
        base = image_handler.partition_bytes(offset)[0]
        handle = fs_info.open_meta(inode=inode)
        region = slack.file_slack(handle, int(size), fs_info.info.block_size,
                                  base)
        if region is None:
            return
        text = slack.text_of(image_handler.read(region[0], region[1]))
    except Exception as exc:
        logger.debug("Slack of %s unreadable: %s", path, exc)
        return
    if not text:
        return
    ref = make_span_ref(0, region[0], region[0] + region[1])
    if texts is not None:
        # In the walk's order, behind its file's row: a resumed run trusts
        # that order (SearchIndex.resume_point).
        from trace_app.core.search_index import entities_of
        texts.put((evidence_id, ref, 'slack', f"{name} (slack)",
                   f"{path} [slack]", region[1], {}),
                  text, entities_of(text))
    else:
        index.add_item(evidence_id, ref, 'slack', f"{name} (slack)",
                       f"{path} [slack]", text, region[1])


def _entry_times(image_handler, offset, meta):
    """The four timestamps a listing shows, formatted as it formats them
    (FAT's local times marked, never called UTC)."""
    return {
        **image_handler.entry_times_text(offset, meta),
        'is_deleted': not bool(int(meta.flags)
                               & pytsk3.TSK_FS_META_FLAG_ALLOC),
    }


def _writer(index):
    """write(text, indicators, payload) for a TextPipeline: one index row."""
    def write(text, entities, payload):
        evidence_id, ref, kind, name, path, size, facts = payload
        index.add_item(evidence_id, ref, kind, name, path, text, size,
                       entities=entities, **facts)
    return write


def _index_file(image_handler, index, evidence_id, offset, inode, sequence,
                name, path, size, times=None, texts=None):
    """Index one file, and the members of it if it is an archive."""
    texts = texts or TextPipeline(_writer(index))
    ref = make_artifact_ref(offset, inode, sequence)
    times = times or {}
    facts = dict(inode=inode, start_offset=offset,
                 created_utc=times.get('created', ''),
                 accessed_utc=times.get('accessed', ''),
                 mtime_utc=times.get('modified', ''),
                 changed_utc=times.get('changed', ''),
                 is_deleted=times.get('is_deleted', False))
    payload = (evidence_id, ref, 'file', name, path, size, facts)

    if (name.lower().endswith(('.pst', '.ost', '.mbox')) or
            size > MAX_FILE_BYTES) and \
            hasattr(image_handler, 'open_file_object'):
        # A mailbox is read lazily -- it is often far larger than any file
        # held in memory -- and indexed message by message.
        stream = image_handler.open_file_object(inode, offset)
        if stream is not None and detect_archive(stream) in STREAMED_KINDS:
            texts.put(payload)
            _index_archive(index, evidence_id, ref, stream, path,
                           ARCHIVE_DEPTH, texts)
            return

    if size > MAX_FILE_BYTES:
        # Too large to read; still worth finding by name.
        texts.put(payload)
        return

    try:
        content, _meta = image_handler.get_file_content(inode, offset)
    except Exception as exc:
        logger.debug("Could not read %s: %s", path, exc)
        texts.put(payload)
        return

    if not content:
        texts.put(payload)
        return
    _index_content(index, evidence_id, ref, content, name, path, payload,
                   ARCHIVE_DEPTH, texts)


def _index_content(index, evidence_id, ref, content, name, path, payload,
                   depth, texts):
    """A file's (or member's) text, and the members of it if it is an
    archive -- an examiner is looking for those; the archive is only the
    container they arrived in. A packed one (zip, tar, xz...) has its
    members read first: when they could be, the strings of its own bytes
    are noise and are not kept (a damaged one keeps them -- they are all
    there is)."""
    if packed_kind(content):
        opened = _index_archive(index, evidence_id, ref, content, path,
                                depth, texts)
        texts.submit(content, name, MAX_TEXT_PER_FILE, payload,
                     skip_packed=opened)
        return
    texts.submit(content, name, MAX_TEXT_PER_FILE, payload)
    if detect_archive(content):
        _index_archive(index, evidence_id, ref, content, path, depth, texts)
    elif INDEX_EMBEDDED and embedded.kind_of(content) in EMBEDDING_KINDS:
        _index_embedded(index, evidence_id, ref, content, path, depth, texts)


def _index_archive(index, evidence_id, parent_ref, content, parent_path,
                   depth, texts=None):
    """Index the members of an archive, and of archives inside it. Returns
    whether it could be opened."""
    if depth <= 0:
        return False
    texts = texts or TextPipeline(_writer(index))

    # The archive opened once, its members read in order (iter_members):
    # opening it again for every member made an archive of n members cost
    # n times its size.
    opened = False
    try:
        for member, member_bytes in iter_members(content):
            opened = True
            _index_member(index, evidence_id, parent_ref, parent_path,
                          member, member_bytes, depth, texts)
    except ArchiveError as exc:
        logger.debug("Could not list %s: %s", parent_path, exc)
    return opened


def _index_embedded(index, evidence_id, parent_ref, content, parent_path,
                    depth, texts):
    """The files a document embeds (core/embedded), as archive members
    under '[embedded]/'."""
    if depth <= 0:
        return
    try:
        for member, member_bytes in embedded.iter_members(
                content, pictures=False):
            _index_member(index, evidence_id, parent_ref, parent_path,
                          member, member_bytes, depth, texts)
    except Exception as exc:
        logger.debug("Embedded files of %s not read: %s", parent_path, exc)


def _index_member(index, evidence_id, parent_ref, parent_path, member,
                  member_bytes, depth, texts):
    """One member of an archive, and the members of it if it is one."""
    if member['is_dir'] or member['encrypted']:
        # An encrypted member's name is still evidence and is indexed
        # below; its contents cannot be read without the password.
        if member['encrypted']:
            texts.put((evidence_id, parent_ref, 'archive-member',
                       member['name'], f"{parent_path}!/{member['name']}",
                       member['size'], {}))
        return
    if member_bytes is None or isinstance(member_bytes, ArchiveError):
        logger.debug("Could not read %s from %s: %s",
                     member['name'], parent_path, member_bytes)
        return
    member_path = f"{parent_path}!/{member['name']}"
    payload = (evidence_id, parent_ref, 'archive-member', member['name'],
               member_path, member['size'], {})
    _index_content(index, evidence_id, parent_ref, member_bytes,
                   member['name'], member_path, payload, depth - 1, texts)
