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
        job = JOBS[kind]
        count = job(params, progress, item, stop.is_set)
    except Exception as exc:      # reported, not raised: the parent decides
        logger.exception("%s job failed", kind)
        error = str(exc) or type(exc).__name__
        count = getattr(exc, 'count', 0)
    queue.put(('done', int(count or 0), error))
    queue.close()
    queue.join_thread()


class _LogChannel:
    """Lets QueueHandler send ('log', record) onto the job's queue."""

    def __init__(self, queue):
        self.queue = queue

    def put_nowait(self, record):
        self.queue.put(('log', record))


def _open_image(path):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(path)
    if not handler.load_image():
        handler.close_resources()
        raise RuntimeError(f"Could not open {path}.")
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
        handler = _open_image(params['image_path'])
        return index_evidence(
            handler, index, params['evidence_id'],
            progress=lambda done, total, path: progress(done, total, path),
            should_stop=should_stop)
    finally:
        _close(index, handler)


def job_analysis(params, progress, item, should_stop):
    from trace_app.core.analysis import analyse_evidence
    from trace_app.core.case import Case
    case = handler = None
    try:
        case = Case.open(params['case_folder'])
        handler = _open_image(params['image_path'])
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
        handler = _open_image(params['image_path'])
        return run_evidence(
            handler, case, params['evidence_id'],
            progress=lambda done, total, path: progress(done, total, path),
            should_stop=should_stop)
    finally:
        _close(case, handler)


def job_carve(params, progress, item, should_stop):
    """Into the case when there is one (carve_evidence); otherwise into the
    session folder `params['folder']`, as quick triage does."""
    from trace_app.core.carving import (CarvingCancelled, carve_evidence,
                                        carve_image, write_carved)
    from trace_app.core.case import Case
    megabyte = 1024 * 1024
    case = handler = None

    def report(position, size, found):
        progress(position // megabyte, max(1, size // megabyte), found)

    try:
        handler = _open_image(params['image_path'])
        if params.get('case_folder'):
            case = Case.open(params['case_folder'])
            return carve_evidence(
                handler, case, params['evidence_id'], params['file_types'],
                params['unallocated_only'], progress=report,
                should_stop=should_stop, on_file=item)
        found = [0]

        def sink(content, file_type, offset, fragments=None):
            item(write_carved(params['folder'], content, file_type, offset,
                              fragments))
            found[0] += 1
        try:
            carve_image(handler, params['file_types'], sink,
                        params['unallocated_only'], progress=report,
                        should_stop=should_stop)
        except CarvingCancelled:
            pass
        return found[0]
    finally:
        _close(case, handler)


def job_ping(params, progress, item, should_stop):
    """Imports what the real jobs import and reports back: the packaged
    self-test's proof that a child process starts in a frozen build."""
    from trace_app.core import (activity, analysis, carving,  # noqa: F401
                                indexer)
    import pytsk3  # noqa: F401
    progress(1, 1, 'ping', force=True)
    item({'pong': params.get('value')})
    return 1


JOBS = {
    'index': job_index,
    'analysis': job_analysis,
    'activity': job_activity,
    'carve': job_carve,
    'ping': job_ping,
}
