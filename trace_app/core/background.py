"""Long jobs run in a process of their own, so the window never waits on them.

Indexing, analysis and carving are CPU-bound Python, and a thread shares the
interpreter lock with the UI. Measured on a 168 MB image, the indexing thread
held it for 78% of samples, much of it inside single C calls -- the indicator
regexes over a file's text, binary string extraction -- that cannot be
preempted, and the window froze for seconds at a time while it ran. A child
process has its own interpreter, so however hard it works the window stays as
responsive as when idle.

The child gets paths and plain values, never open objects, and opens the
image and the case itself -- as the thread workers already did, because a
pytsk3 handle or a SQLite connection belongs to the thread that made it. It
talks back over one queue:

    ('progress', payload)    throttled to a few per second
    ('item', dict)           e.g. each carved file, as it is written
    ('log', LogRecord)       re-emitted by the parent into its own log
    ('done', count, error)   last; error is '' on success or cancel

Cancellation is cooperative, as it was for threads: the parent sets an Event
and the job stops at its next check, so nothing is half-written.

`spawn` everywhere, not fork: forking a process with Qt's threads running is
undefined, and spawn is what Windows and macOS do anyway. A frozen build
needs multiprocessing.freeze_support() before anything else (main.py).

No Qt here; ui/process_worker.py adapts this to signals.
"""

import logging
import logging.handlers
import multiprocessing
import os
import time

logger = logging.getLogger('TRACE.Background')

#: Least time between two progress messages from a job.
PROGRESS_INTERVAL = 0.2


def context():
    return multiprocessing.get_context('spawn')


def start(kind, params):
    """Start job `kind` with `params` in a child process.

    Returns (process, queue, stop_event). The caller reads the queue until
    ('done', ...) arrives, and sets the event to cancel.
    """
    ctx = context()
    queue = ctx.Queue()
    stop = ctx.Event()
    process = ctx.Process(target=child_main, args=(kind, params, queue, stop),
                          name=f'TRACE {kind}', daemon=True)
    process.start()
    return process, queue, stop


# --- in the child ------------------------------------------------------------

def child_main(kind, params, queue, stop):
    """Entry point of the child process."""
    root = logging.getLogger()
    root.handlers[:] = [logging.handlers.QueueHandler(_LogChannel(queue))]
    root.setLevel(logging.INFO)
    # A crash in C here would end the job with only an exit code.
    from trace_app.infra import crash_log
    crash_log.enable()

    last = [0.0]

    def progress(*payload, force=False):
        now = time.monotonic()
        if force or now - last[0] >= PROGRESS_INTERVAL:
            last[0] = now
            queue.put(('progress', payload))

    def item(record):
        queue.put(('item', record))

    count, error = 0, ''
    try:
        _apply_settings(params)
        job = JOBS[kind]
        count = job(params, progress, item, stop.is_set)
    except Exception as exc:      # reported, not raised: the parent decides
        logger.exception("%s job failed", kind)
        error = str(exc) or type(exc).__name__
        count = getattr(exc, 'count', 0)
    queue.put(('done', int(count or 0), error))
    queue.close()
    queue.join_thread()


def _apply_settings(params):
    """The examiner's settings and the case's (core/settings.py), in this
    process -- which starts fresh, with the modules' defaults -- before the
    job reads anything."""
    from trace_app.core import settings
    settings.apply_user()
    if params.get('case_folder'):
        settings.apply_case(settings.StoredCase(params['case_folder']))


class _LogChannel:
    """Lets QueueHandler send ('log', record) onto the job's queue."""

    def __init__(self, queue):
        self.queue = queue

    def put_nowait(self, record):
        self.queue.put(('log', record))


def _open_image(path, unlock=None):
    """The image, with any BitLocker volume the examiner unlocked unlocked
    here too. `unlock` is {start sector: {kind: secret}}; it reaches this
    process in memory, over the job's pipe, and is never written down."""
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(path)
    if not handler.load_image():
        handler.close_resources()
        raise RuntimeError(f"Could not open {path}.")
    handler.apply_unlocks(unlock)
    return handler


def _close(*things):
    for thing in things:
        if thing is None:
            continue
        try:
            (thing.close_resources if hasattr(thing, 'close_resources')
             else thing.close)()
        except Exception:
            pass


def job_index(params, progress, item, should_stop):
    from trace_app.core.indexer import index_evidence
    from trace_app.core.search_index import SearchIndex
    index = handler = None
    try:
        index = SearchIndex(params['case_folder'])
        handler = _open_image(params['image_path'], params.get('unlock'))
        done = index_evidence(
            handler, index, params['evidence_id'],
            progress=lambda done, total, path: progress(done, total, path),
            should_stop=should_stop)
        # The image's carved files too: a re-index cleared them with the
        # rest of the image's items.
        _index_carved(handler, index, params, should_stop)
        return done
    finally:
        _close(index, handler)


def _index_carved(handler, index, params, should_stop):
    from trace_app.core.case import Case
    from trace_app.core.indexer import IndexerCancelled, index_carved
    case = None
    try:
        case = Case.open(params['case_folder'])
        index_carved(handler.read, case, index, params['evidence_id'],
                     should_stop)
    except IndexerCancelled:
        pass
    finally:
        _close(case)


def job_analysis(params, progress, item, should_stop):
    from trace_app.core.analysis import analyse_evidence
    from trace_app.core.case import Case
    case = handler = None
    try:
        case = Case.open(params['case_folder'])
        handler = _open_image(params['image_path'], params.get('unlock'))
        return analyse_evidence(
            handler, case, params['evidence_id'], params['modules'],
            progress=lambda done, total, path: progress(done, total, path),
            should_stop=should_stop)
    finally:
        _close(case, handler)


def job_activity(params, progress, item, should_stop):
    """Windows activity records and browser history (core/activity)."""
    from trace_app.core.activity import run_evidence
    from trace_app.core.case import Case
    case = handler = None
    try:
        case = Case.open(params['case_folder'])
        handler = _open_image(params['image_path'], params.get('unlock'))
        return run_evidence(
            handler, case, params['evidence_id'],
            progress=lambda done, total, path: progress(done, total, path),
            should_stop=should_stop)
    finally:
        _close(case, handler)


def job_ntfs(params, progress, item, should_stop):
    """$MFT times, alternate streams and the change journal (core/ntfs)."""
    from trace_app.core import ntfs
    from trace_app.core.case import Case
    case = handler = None
    try:
        case = Case.open(params['case_folder'])
        handler = _open_image(params['image_path'], params.get('unlock'))
        return ntfs.analyse_evidence(
            handler, case, params['evidence_id'],
            progress=lambda done, total, path: progress(done, total, path),
            should_stop=should_stop)
    finally:
        _close(case, handler)


def job_hashsets(params, progress, item, should_stop):
    """Match the case's digests against the examiner's hash sets
    (core/hashsets). Reads the case and the library, never the image."""
    from trace_app.core import hashsets
    from trace_app.core.case import Case
    case = None
    try:
        case = Case.open(params['case_folder'])
        library = hashsets.Library(params['library'])
        summary = hashsets.match_case(
            case, library, params.get('options'),
            evidence_ids=params.get('evidence_ids'),
            progress=lambda done, total, name: progress(done, total, name),
            should_stop=should_stop)
        return summary['matched']
    except hashsets.ImportCancelled:
        return 0
    finally:
        _close(case)


def job_report(params, progress, item, should_stop):
    """Write the case report (core/report). The images are opened only
    for the pictures in it: bookmarked photos, carved pictures."""
    from trace_app.core import report
    from trace_app.core.case import Case
    case = None
    images = {}
    try:
        case = Case.open(params['case_folder'])
        for evidence_id, path, unlock in params.get('images') or ():
            try:
                images[evidence_id] = _open_image(path, unlock)
            except Exception as exc:
                logger.warning("No pictures from %s: %s", path, exc)
        try:
            written = report.write_report(
                case, params['options'], images,
                progress=lambda done, total, what: progress(done, total,
                                                            what),
                should_stop=should_stop)
        except report.ReportCancelled:
            return 0
        for entry in written:
            item(entry)
        return len(written)
    finally:
        _close(case, *images.values())


def job_yara(params, progress, item, should_stop):
    """YARA rules over every file and carved file of one image."""
    from trace_app.core import yara_rules
    from trace_app.core.case import Case
    case = handler = None
    try:
        case = Case.open(params['case_folder'])
        handler = _open_image(params['image_path'], params.get('unlock'))
        library = yara_rules.Library(params['library'])
        try:
            return yara_rules.scan_evidence(
                handler, case, params['evidence_id'], library,
                params.get('options'),
                progress=lambda done, total, path: progress(done, total,
                                                            path),
                should_stop=should_stop)
        except yara_rules.ScanCancelled:
            return 0
    finally:
        _close(case, handler)


def job_sigma(params, progress, item, should_stop):
    """Sigma rules over every event log of one image (core/sigma)."""
    from trace_app.core import sigma
    from trace_app.core.case import Case
    case = handler = None
    try:
        case = Case.open(params['case_folder'])
        handler = _open_image(params['image_path'], params.get('unlock'))
        library = sigma.Library(params['library'])
        try:
            return sigma.scan_evidence(
                handler, case, params['evidence_id'], library,
                params.get('options'),
                progress=lambda done, total, path: progress(done, total,
                                                            path),
                should_stop=should_stop)
        except sigma.ScanCancelled:
            return 0
    finally:
        _close(case, handler)


def job_keywords(params, progress, item, should_stop):
    """The case's keyword lists over its search index (core/keywords)."""
    from trace_app.core import keywords
    from trace_app.core.case import Case
    case = None
    try:
        case = Case.open(params['case_folder'])
        library = keywords.Library(params['library'])
        try:
            result = keywords.run_case(
                case, library, params.get('options'),
                params.get('evidence_ids'),
                progress=lambda done, total, term: progress(done, total,
                                                            term),
                should_stop=should_stop)
        except keywords.SearchCancelled:
            return 0
        item(result)
        return result['files']
    finally:
        _close(case)


def job_deleted(params, progress, item, should_stop):
    """Deleted files and how much of each is left (core/deleted)."""
    from trace_app.core import deleted
    from trace_app.core.case import Case
    case = handler = None
    try:
        case = Case.open(params['case_folder'])
        handler = _open_image(params['image_path'], params.get('unlock'))
        try:
            return deleted.analyse_evidence(
                handler, case, params['evidence_id'],
                progress=lambda done, total, path: progress(done, total,
                                                            path),
                should_stop=should_stop)
        except deleted.DeletedCancelled:
            return 0
    finally:
        _close(case, handler)


def job_thumbnails(params, progress, item, should_stop):
    """Every thumbnail cache on one image (core/thumbnails)."""
    from trace_app.core import thumbnails, walk
    from trace_app.core.case import Case
    case = handler = None
    try:
        case = Case.open(params['case_folder'])
        handler = _open_image(params['image_path'], params.get('unlock'))
        try:
            return thumbnails.analyse_evidence(
                handler, case, params['evidence_id'],
                progress=lambda done, total, path: progress(done, total,
                                                            path),
                should_stop=should_stop)
        except walk.WalkCancelled:
            return 0
    finally:
        _close(case, handler)


def job_persistence(params, progress, item, should_stop):
    """Autostarts on one image, graded (core/persistence)."""
    from trace_app.core import hashsets, persistence
    from trace_app.core.case import Case
    case = handler = None
    try:
        case = Case.open(params['case_folder'])
        handler = _open_image(params['image_path'], params.get('unlock'))
        library = hashsets.Library(params['hash_library']) \
            if params.get('hash_library') else None
        return persistence.analyse_evidence(
            handler, case, params['evidence_id'], library,
            progress=lambda done, total, path: progress(done, total, path),
            should_stop=should_stop)
    finally:
        _close(case, handler)


def _reindex_carved(handler, case, params, should_stop):
    """After a carve, its files into the search index -- if the image
    has one; an image never indexed gets them when it is."""
    from trace_app.core.indexer import IndexerCancelled, index_carved
    from trace_app.core.search_index import SearchIndex
    if not os.path.exists(os.path.join(params['case_folder'], 'search.db')):
        return
    index = None
    try:
        index = SearchIndex(params['case_folder'])
        if index.is_indexed(params['evidence_id']):
            index_carved(handler.read, case, index, params['evidence_id'],
                         should_stop)
    except IndexerCancelled:
        pass
    except Exception as exc:
        logger.warning("Carved files not indexed: %s", exc)
    finally:
        _close(index)


def job_carve(params, progress, item, should_stop):
    """Into the case when there is one (carve_evidence); otherwise into the
    session folder `params['folder']`, as quick triage does."""
    from trace_app.core.carving import (CarvingCancelled, carve_evidence,
                                        carve_image, describe_carved,
                                        write_carved)
    from trace_app.core.case import Case
    megabyte = 1024 * 1024
    case = handler = None

    def report(position, size, found):
        progress(position // megabyte, max(1, size // megabyte), found)

    try:
        handler = _open_image(params['image_path'], params.get('unlock'))
        if params.get('case_folder'):
            case = Case.open(params['case_folder'])
            found = carve_evidence(
                handler, case, params['evidence_id'], params['file_types'],
                params['unallocated_only'], progress=report,
                should_stop=should_stop, on_file=item,
                source=params.get('source'),
                resume=bool(params.get('resume')))
            _reindex_carved(handler, case, params, should_stop)
            return found
        found = [0]
        source = params.get('source') or (
            'unallocated' if params['unallocated_only'] else 'image')

        def sink(content, file_type, offset, fragments=None):
            # Quick triage keeps references too; copies only when asked.
            if params.get('folder') and params.get('write_copies'):
                item(write_carved(params['folder'], content, file_type,
                                  offset, fragments, source=source))
            else:
                item(describe_carved(content, file_type, offset, fragments,
                                     source=source))
            found[0] += 1
        ranges = None
        if source == 'slack':
            from trace_app.core import slack
            ranges = [(begin, length) for begin, length, _p, _r in
                      slack.slack_ranges(handler, should_stop)]
        try:
            carve_image(handler, params['file_types'], sink,
                        source == 'unallocated', progress=report,
                        should_stop=should_stop, ranges=ranges)
        except CarvingCancelled:
            pass
        return found[0]
    finally:
        _close(case, handler)


def job_ping(params, progress, item, should_stop):
    """Imports what the real jobs import and reports back: the packaged
    self-test's proof that a child process starts in a frozen build."""
    from trace_app.core import (activity, analysis, carving,  # noqa: F401
                                deleted, hashsets, indexer, keywords,
                                mailfiles,
                                ntfs, persistence, report, thumbnails,
                                timeline, yara_rules)
    import pytsk3  # noqa: F401
    progress(1, 1, 'ping', force=True)
    item({'pong': params.get('value')})
    return 1


JOBS = {
    'index': job_index,
    'analysis': job_analysis,
    'activity': job_activity,
    'ntfs': job_ntfs,
    'hashsets': job_hashsets,
    'report': job_report,
    'yara': job_yara,
    'sigma': job_sigma,
    'keywords': job_keywords,
    'thumbnails': job_thumbnails,
    'deleted': job_deleted,
    'persistence': job_persistence,
    'carve': job_carve,
    'ping': job_ping,
}
