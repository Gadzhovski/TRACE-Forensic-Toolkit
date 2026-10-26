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
from trace_app.infra.sqlite_uri import connect_read_only

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
    # Not a daemon: a daemonic process may not start processes, and
    # indexing starts a pool (core/text_pool). It ends with the window all
    # the same -- the window stops it, and watch_parent() ends it if the
    # window is gone.
    process = ctx.Process(target=child_main, args=(kind, params, queue, stop),
                          name=f'TRACE {kind}')
    process.start()
    return process, queue, stop


# --- in the child ------------------------------------------------------------

def watch_parent():
    """End this process when the one that started it is gone (killed, or
    crashed in C): a job, or a worker of its pool, must not run on alone,
    writing to a case nobody has open."""
    import threading
    parent = multiprocessing.parent_process()
    if parent is None:
        return

    def watch():
        parent.join()               # returns when the parent has exited
        os._exit(1)
    threading.Thread(target=watch, name='parent watch', daemon=True).start()


def child_main(kind, params, queue, stop):
    """Entry point of the child process."""
    watch_parent()
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


def _scope(params):
    """The run's scope (core/scope.Scope) from its params, or None when it
    covers everything."""
    from trace_app.core.scope import from_params
    scope = from_params(params)
    return None if scope.everything else scope


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
            should_stop=should_stop, scope=_scope(params),
            resume=params.get('resume', True))
        # The image's carved files too: a re-index cleared them with the
        # rest of the image's items.
        _index_carved(handler, index, params, should_stop)
        return done
    finally:
        _close(index, handler)


def job_index_free(params, progress, item, should_stop):
    """Free space and memory files into the index (indexer.index_free_
    space): the slow, optional part, after the file index."""
    from trace_app.core.indexer import index_free_space
    from trace_app.core.search_index import SearchIndex
    index = handler = None
    try:
        index = SearchIndex(params['case_folder'])
        handler = _open_image(params['image_path'], params.get('unlock'))
        return index_free_space(
            handler, index, params['evidence_id'],
            progress=lambda done, total, what: progress(done, total, what),
            should_stop=should_stop, scope=_scope(params),
            resume=params.get('resume', True))
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
        from trace_app.core.text_pool import default_workers
        return analyse_evidence(
            handler, case, params['evidence_id'], params['modules'],
            progress=lambda done, total, path: progress(done, total, path),
            should_stop=should_stop, scope=_scope(params),
            workers=default_workers(), image_path=params['image_path'],
            unlock=params.get('unlock'),
            case_folder=params['case_folder'])
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


def job_fstimes(params, progress, item, should_stop):
    """File-system times of every non-NTFS volume (core/fs_times)."""
    from trace_app.core import fs_times
    from trace_app.core.case import Case
    case = handler = None
    try:
        case = Case.open(params['case_folder'])
        handler = _open_image(params['image_path'], params.get('unlock'))
        return fs_times.analyse_evidence(
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
                should_stop=should_stop, scope=_scope(params))
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
                should_stop=should_stop, scope=_scope(params))
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
        elif source == 'memory':
            from trace_app.core import memory_files
            ranges = [(begin, length) for begin, length, _p, _r in
                      memory_files.ranges(handler, should_stop)]
        try:
            carve_image(handler, params['file_types'], sink,
                        source == 'unallocated', progress=report,
                        should_stop=should_stop, ranges=ranges,
                        alignment=1 if source == 'memory' else 512)
        except CarvingCancelled:
            pass
        return found[0]
    finally:
        _close(case, handler)


def job_vics(params, progress, item, should_stop):
    """A Project VICS JSON export (core/vics.py) of the pictures and videos
    on `params['sources']`: [(source id, image path, unlock, carved rows,
    marks)] -- marks: the case's categories and comments by artifact_ref
    (optional). The summary goes back as the one item."""
    from trace_app.core import vics
    handlers = []
    try:
        sources = []
        for source in params['sources']:
            source_id, path, unlock, carved = source[:4]
            marks = source[4] if len(source) > 4 else None
            handler = _open_image(path, unlock)
            handlers.append(handler)
            sources.append((source_id, handler, carved or (), marks or {}))
        summary = vics.export(
            sources, params['folder'], params.get('case_number', ''),
            params.get('contact'), params.get('model', vics.DEFAULT_MODEL),
            params.get('version', ''), _scope(params),
            params.get('include_deleted', True),
            params.get('include_carved', True),
            int(params.get('min_size') or 0), should_stop,
            lambda examined, copied, what: progress(examined, copied, what),
            params.get('inside', True), params.get('carve_inside', False))
        item(summary)
        return summary['media_files']
    finally:
        _close(*handlers)


def job_leapp(params, progress, item, should_stop):
    """An external tool (core/modules: iLEAPP, aLEAPP) on one image: each
    of its inputs (core/modules/inputs -- the loose files it reads, every
    packed extraction, every zipped backup) is a run of its own: staged or
    handed over, run, read, and -- in a case -- recorded with its
    artifacts, events, search rows and the tool's coverage. params: tool,
    image_path, unlock, folder (the first run's; others beside it), and
    case_folder + evidence_id, or evidence_name for quick triage. Each
    run's summary is an item.

    An encrypted zipped backup needs `backup_passwords` ({its path on the
    evidence: password}, memory only, never stored or logged): without one
    its run is 'skipped' with needs_password; a wrong one 'failed' with
    needs_password, before the tool runs. `only_inputs` ([paths]) runs just
    those packed inputs -- a backup again, once its password is known."""
    from trace_app.core.case import Case
    from trace_app.core.evidence_export import safe_component
    from trace_app.core import settings as case_settings
    from trace_app.core.ios_backup import BackupError
    from trace_app.core.modules import (install, inputs as module_inputs,
                                        job, lava, run, stage)
    from trace_app.core.modules.spec import TOOLS
    spec = TOOLS[params['tool']]
    record = install.installed(spec)
    if record is None:
        raise RuntimeError(f"{spec.name} is not installed (Tools \u25b8 "
                           f"External Modules).")
    case = handler = None
    base = params['folder']
    name = params.get('evidence_name') or os.path.basename(
        params['image_path'])
    rows_total = 0
    relink = set()
    try:
        handler = _open_image(params['image_path'], params.get('unlock'))
        if params.get('case_folder'):
            case = Case.open(params['case_folder'])
        program_sha256 = install.executable_sha256(record)
        try:
            plans = job.plan(spec, record, handler, params['image_path'],
                             should_stop, progress, _scope(params))
        except (stage.StageCancelled,):
            item({'tool': spec.name, 'version': record['version'],
                  'folder': base, 'status': 'cancelled', 'evidence': name})
            return 0
        except job.NothingToRead as exc:
            # Recorded all the same: that the tool was tried, and why it
            # had nothing to read, is part of the examination.
            summary = {'tool': spec.name, 'version': record['version'],
                       'folder': base, 'status': 'failed',
                       'message': str(exc), 'evidence': name,
                       'input': 'nothing it reads'}
            if case is not None:
                run_id = case.add_module_run(
                    params['evidence_id'], spec.name, record['version'],
                    program_sha256, {'tool': spec.id, 'input': {
                        'kind': 'none', 'label': 'nothing it reads'}},
                    base)
                case.finish_module_run(run_id, 'failed', message=str(exc))
                summary['run_id'] = run_id
            item(summary)
            return 0
        only = params.get('only_inputs')
        if only is not None:
            plans = [p for p in plans if p.get('path') in only]
        passwords = params.get('backup_passwords') or {}
        for number, plan in enumerate(plans, start=1):
            folder = base if len(plans) == 1 else \
                f"{base} ({number}) {safe_component(plan['label'], 'input')}"
            summary = {'tool': spec.name, 'version': record['version'],
                       'folder': folder, 'evidence': name,
                       'evidence_id': params.get('evidence_id'),
                       'input': plan['label']}
            run_params = {'tool': spec.id,
                          'input': {'kind': plan['kind'],
                                    'label': plan['label']}}
            run_id = None
            if case is not None:
                run_id = case.add_module_run(
                    params['evidence_id'], spec.name, record['version'],
                    program_sha256, run_params, folder)
                summary['run_id'] = run_id
            password = None
            if plan.get('encrypted'):
                password = passwords.get(plan['path'])
                summary['backup'] = plan['path']
                why = None
                if not password:
                    # Recorded, not run: the tool reads nothing of an
                    # encrypted backup without its password.
                    why = (f"{plan['name']} is an encrypted backup: "
                           f"{spec.name} needs its password to read it")
                    status = 'skipped'
                else:
                    progress(0, 0, f"Checking the password of {plan['name']}")
                    try:
                        module_inputs.check_password(handler, plan, password)
                    except BackupError as exc:
                        why = f"{plan['name']}: {exc}"
                        status = 'failed'
                if why is not None:
                    summary.update(status=status, message=why,
                                   needs_password=True)
                    if case is not None:
                        run_params['input']['needs_password'] = True
                        case.finish_module_run(run_id, status, message=why,
                                               params=run_params)
                    item(summary)
                    continue
            try:
                done = job.execute(spec, record, handler, folder,
                                   params.get('evidence_id'), name, plan,
                                   should_stop, progress, password=password,
                                   keys=params.get('tool_keys'))
            except (stage.StageCancelled, run.ToolCancelled):
                summary['status'] = 'cancelled'
                if case is not None:
                    case.finish_module_run(
                        run_id, 'cancelled',
                        message='cancelled by the examiner')
                item(summary)
                return rows_total
            except (stage.StageError, run.ToolError, lava.LavaError) as exc:
                summary.update(status='failed', message=str(exc))
                if case is not None:
                    case.finish_module_run(run_id, 'failed',
                                           message=str(exc))
                item(summary)
                continue
            info = done['info']
            covered = job.coverage(info)
            run_params['input'] = done['input']
            run_params['coverage'] = covered
            rows = sum(a['record_count'] for a in info['artifacts'])
            rows_total += rows
            summary['secrets_wanted'] = done['input'].get(
                'secrets_wanted') or []
            summary.update(status='complete', staged=done['staged'],
                           artifacts=len(info['artifacts']), rows=rows,
                           problems=done['problems'], report=done['report'],
                           coverage=covered)
            added, kept = job.split_by_size(
                info['artifacts'],
                int(case_settings.current('module_import_rows') or 0))
            if kept:
                run_params['not_imported'] = [list(k) for k in kept]
                summary['not_imported'] = kept
            # By table too: names can repeat; a later limit change
            # (job_module_import) needs to know exactly what is in.
            run_params['not_imported_tables'] = sorted(
                {a['tablename'] for a in info['artifacts']} -
                {a['tablename'] for a in added})
            run_params['import_limit'] = int(
                case_settings.current('module_import_rows') or 0)
            # Nothing in either yet: apply_destinations adds what the
            # case's choice wants once the run is sorted.
            run_params['timeline_tables'] = []
            run_params['search_tables'] = []
            if case is not None:
                case.add_module_artifacts(run_id, info['artifacts'])
                case.finish_module_run(
                    run_id, 'complete', done['staged'],
                    done['manifest_sha256'], done['lava_sha256'],
                    f"{plan['label']}: {covered['with_data']} of "
                    f"{covered['artifacts']} artifacts found data, "
                    f"{rows:,} row(s)"
                    + (f"; {len(done['problems'])} file(s) not staged"
                       if done['problems'] else '')
                    + (f"; {len(kept)} artifact(s) too large for the "
                       f"Timeline and Search, browsed in the Modules tab "
                       f"({', '.join(f'{n}: {c:,} rows' for n, c in kept)})"
                       if kept else ''),
                    params=run_params)
                if password:
                    # Read with its password: the runs that could not
                    # read it say nothing the case needs kept.
                    summary['superseded'] = case.supersede_password_runs(
                        params['evidence_id'], spec.name, plan['label'],
                        keep=run_id)
                if params.get('tool_keys'):
                    summary['superseded'] = case.supersede_keyless_runs(
                        params['evidence_id'], spec.name, plan['label'],
                        keep=run_id)
                # Sorted first (core/modules/bridge: its evidence into
                # Activity and Triage), so that only what the case sends
                # to the Timeline and Search is copied there
                # (core/modules/destinations) -- telemetry by default
                # never is: on a large phone or Mac it is most rows.
                try:
                    summary['sorted'] = _bridge(case, run_id, progress,
                                                should_stop, relink=False)
                except Exception as exc:
                    logger.warning("%s run %s not sorted into Activity: %s",
                                   spec.name, run_id, exc)
                relink.add(params['evidence_id'])
                try:
                    placed = job.apply_destinations(
                        case, params['case_folder'], run_id,
                        int(case_settings.current('module_import_rows')
                            or 0), progress, should_stop)
                    summary['indexed'] = placed['indexed']
                    summary['placed'] = placed.get('wanted')
                except Exception as exc:
                    logger.warning("%s rows not added to the Timeline and "
                                   "Search: %s", spec.name, exc)
            item(summary)
        return rows_total
    finally:
        if case is not None:
            # Readings linked once for the job, not once per run.
            for evidence_id in relink:
                try:
                    case.relink_matches(evidence_id)
                except Exception as exc:
                    logger.warning("Readings of evidence %s not linked: %s",
                                   evidence_id, exc)
        _close(case, handler)


def _bridge(case, run_id, progress, should_stop, only=None, force=False,
            relink=True):
    from trace_app.core import settings as case_settings
    from trace_app.core.modules import bridge
    limit = int(case_settings.current('module_import_rows') or 0)
    done = bridge.bridge_run(
        case, run_id, only=only, force=force, limit=limit,
        should_stop=should_stop, relink=relink,
        progress=lambda d, t, text: progress(d, t, text))
    if done['artifacts']:
        run = case.module_run(run_id)
        case._record_activity(
            'external module results sorted',
            f"{run['tool']} run id={run_id}: {done['rows']:,} row(s) into "
            f"Activity from {done['evidence']} evidence artifact(s); "
            f"{done['telemetry']} telemetry and {done['other']} other "
            f"artifact(s) on the Timeline only; {done['superseded']} older "
            f"cop(ies) superseded")
    return done


def job_module_import(params, progress, item, should_stop):
    """The case's import limit (module_import_rows) or the places chosen
    per role (module_destinations) changed (params: case_folder, limit,
    old_limit, rebridge): every completed run's Timeline events and Search
    rows follow them (core/modules/job.apply_destinations), from the
    tools' databases already in the case. Evidence artifacts are sorted
    into Activity again where the change touches them: those over the
    smaller of the two limits (their rows were cut at the old one), every
    one when `rebridge` (evidence into Activity turned on or off). The
    readings are linked once at the end. Audited per run."""
    from trace_app.core.case import Case
    from trace_app.core.modules import destinations, job
    case = None
    total = {'runs': 0, 'added_rows': 0, 'dropped_rows': 0}
    evidence = set()
    try:
        case = Case.open(params['case_folder'])
        limit = int(params.get('limit') or 0)
        old = int(params.get('old_limit') or 0)
        runs = [r for r in case.module_runs() if r['status'] == 'complete']
        for run in runs:
            if should_stop():
                break
            stored = case.module_artifacts(run['id'])
            low = min(x for x in (limit, old) if x) if (limit or old) else 0
            touched = [a['id'] for a in stored
                       if params.get('rebridge') and
                       destinations.role_of(a) == destinations.EVIDENCE
                       or (low and (a.get('row_count') or 0) > low)]
            if touched:
                _bridge(case, run['id'], progress, should_stop,
                        only=set(touched), force=True, relink=False)
                evidence.add(run['evidence_id'])
            done = job.apply_destinations(
                case, params['case_folder'], run['id'], limit,
                lambda d, t, text, r=run: progress(
                    d, t, f"{r['tool']}: {text}"), should_stop)
            total['runs'] += 1
            total['added_rows'] += done['added_rows']
            total['dropped_rows'] += done['dropped_rows']
            if done['added'] or done['dropped']:
                case._record_activity(
                    'external module rows imported again',
                    f"{run['tool']} run id={run['id']}: limit "
                    f"{old or 'none'} -> {limit or 'none'}; "
                    f"{'; '.join(destinations.describe(None))}; added to "
                    f"the Timeline and Search: "
                    f"{', '.join(f'{n} ({c:,})' for n, c in done['added']) or 'nothing'}"
                    f"; taken out: "
                    f"{', '.join(f'{n} ({c:,})' for n, c in done['dropped']) or 'nothing'}"
                    + ("; stopped by the examiner" if done['cancelled']
                       else ''))
            if should_stop():
                break
        for evidence_id in evidence:
            case.relink_matches(evidence_id)
        item(total)
    finally:
        if case is not None:
            case.close()
    return total['added_rows']


def job_module_bridge(params, progress, item, should_stop):
    """Sort external modules' runs into Activity, Triage and the Timeline
    (core/modules/bridge) -- the runs a case imported before this was done,
    or after core/modules/routes.ROUTES_VERSION changed, or the artifacts
    an override changed (params: case_folder, run_id?, artifact_ids?).
    Works from the tools' databases already in the case: no tool runs."""
    from trace_app.core import settings as case_settings
    from trace_app.core.case import Case
    from trace_app.core.modules import job
    from trace_app.core.modules.bridge import BridgeCancelled
    case = None
    try:
        case = Case.open(params['case_folder'])
        if params.get('run_id'):
            runs = [params['run_id']]
        else:
            runs = case.unbridged_module_runs()
        only = set(params['artifact_ids']) if params.get('artifact_ids') \
            else None
        total = {'rows': 0, 'runs': 0}
        limit = int(case_settings.current('module_import_rows') or 0)
        evidence = set()
        for run_id in runs:
            if should_stop():
                break
            done = _bridge(case, run_id, progress, should_stop, only=only,
                           force=bool(only), relink=False)
            # A role changed: what goes to the Timeline and Search
            # follows it.
            job.apply_destinations(case, params['case_folder'], run_id,
                                   limit, progress, should_stop)
            run = case.module_run(run_id)
            if run is not None:
                evidence.add(run['evidence_id'])
            total['rows'] += done['rows']
            total['runs'] += 1
        for evidence_id in evidence:
            case.relink_matches(evidence_id)
        item(total)
        return total['rows']
    except BridgeCancelled:
        return 0
    finally:
        if case is not None:
            case.close()


def job_archive_index(params, progress, item, should_stop):
    """Index an archive too big to read whole (core/archive_index): a
    16 GB phone extraction's tar, header by header. params: image_path,
    unlock, start_offset, inode, kind, target. One item: {count, target};
    a cancel leaves no index."""
    from trace_app.core import archive_index
    handler = stream = None
    try:
        handler = _open_image(params['image_path'], params.get('unlock'))
        stream = handler.open_file_object(params['inode'],
                                          params['start_offset'])
        if stream is None:
            raise RuntimeError("The archive could not be opened")
        # Folder evidence: the file itself, opened once. Through the folder
        # reader every header read opened the file again (16 GB tar: 44 s
        # against 13 s).
        fs = handler.logical_fs
        if fs is not None and os.path.isdir(params['image_path']):
            try:
                own = os.path.join(params['image_path'], *fs.path_of(
                    params['inode']).strip('/').split('/'))
                stream.seek(0, os.SEEK_END)
                if os.path.isfile(own) and \
                        os.path.getsize(own) == stream.tell():
                    stream = open(own, 'rb')
            except Exception as exc:
                logger.debug("Read through the folder reader: %s", exc)
        try:
            count = archive_index.build(stream, params['kind'],
                                        params['target'], should_stop,
                                        progress)
        except archive_index.IndexCancelled:
            return 0
        item({'count': count, 'target': params['target']})
        return count
    finally:
        _close(stream, handler)


def job_folder_check(params, progress, item, should_stop):
    """Walk folder evidence again and compare it with the listing kept
    from an earlier opening (core/folder_listing): the opening used the
    kept one, so a change made since is only found here. params:
    image_path. One item: folder_listing.check()'s result; a cancel
    reports nothing."""
    from trace_app.core import folder_listing
    try:
        found = folder_listing.check(
            params['image_path'],
            lambda entries: progress(entries, 0,
                                     f"{entries:,} items listed again"),
            should_stop)
    except InterruptedError:
        return 0
    if found is not None:
        item(found)
    return found['checked'] if found else 0


def job_module_fit(params, progress, item, should_stop):
    """Which installed pattern-fitted tools (RLEAPP, VLEAPP: a warrant
    return or a car has no system for TRACE to find) have files to read on
    each image: their own `-p` patterns over the image's listing
    (core/modules/fit; the listing is the Scope editor's, kept per image).
    params: images [{path, unlock}], tools [ids]. One item per image:
    {path, fit: {tool: files}, examples: {tool: [paths]}}."""
    from trace_app.core.modules import fit, install, stage
    from trace_app.core.modules.spec import TOOLS
    patterns = {}
    for tool in params['tools']:
        spec = TOOLS.get(tool)
        record = install.installed(spec) if spec else None
        if record is None:
            continue
        try:
            patterns[tool] = stage.path_patterns(spec, record)
        except stage.StageError as exc:
            logger.warning("No patterns from %s: %s", tool, exc)
    done = 0
    for image in params['images']:
        if should_stop():
            return done
        volumes = _scope_listing(image, progress, should_stop)
        if volumes is None:
            continue
        handler = None

        def open_file(offset, path):
            # Archives are looked inside (a return arrives as zips): the
            # image opened once, only when the listing holds one.
            nonlocal handler
            try:
                if handler is None:
                    handler = _open_image(image['path'], image.get('unlock'))
                fs = handler.get_fs_info(offset)
                from trace_app.core.tsk_names import open_path
                entry = open_path(fs, path)
                size = int(entry.info.meta.size)
            except Exception:
                return None
            from trace_app.core import containers
            return containers.ByteWindow(
                lambda at, length: entry.read_random(at, length), 0, size)

        counts, examples = {}, {}
        try:
            for tool, globs in patterns.items():
                counts[tool], examples[tool] = fit.count(
                    volumes, globs, should_stop, open_file)
        except fit.Cancelled:
            return done
        finally:
            _close(handler)
        item({'path': image['path'], 'fit': counts, 'examples': examples})
        done += 1
    return done


def job_vss_compare(params, progress, item, should_stop):
    """What changed between two states of a volume -- a shadow copy and a
    later one, or the live volume (core/vss_compare.py). Read-only: each
    difference is an item; nothing is stored."""
    from trace_app.core import vss_compare
    handler = None
    try:
        handler = _open_image(params['image_path'], params.get('unlock'))
        handler.shadow_copies(params['volume'])     # opens the snapshots
        progress(0, 2, 'Reading both states of the volume', force=True)
        try:
            rows = vss_compare.compare_volumes(
                handler, params['before'], params['after'],
                system=params.get('system', False), should_stop=should_stop)
        except vss_compare.Cancelled:
            return 0
        progress(2, 2, 'Compared', force=True)
        for row in rows:
            item(row)
        return len(rows)
    finally:
        _close(handler)


def job_record_view(params, progress, item, should_stop):
    """Activity's Charts or Items (core/record_views) over the rows the
    tab lists -- read again here with the tab's own filters. Tens of
    thousands of rows grouped in Python held the window for half a second
    and more; the result is the one item."""
    from trace_app.core import record_views
    from trace_app.core.case import query_user_activity
    path = os.path.join(params['case_folder'], 'case.db')
    connection = connect_read_only(path)
    try:
        rows = query_user_activity(
            connection, params.get('evidence_id'), params.get('category'),
            params.get('text') or '', limit=params.get('limit'),
            reader=params.get('reader'),
            only_reader=bool(params.get('only')))
    finally:
        connection.close()
    if should_stop():
        return 0
    category = params.get('category')
    if params.get('view') == record_views.ITEMS:
        result = {'items': record_views.inventory(rows, category),
                  'unnamed': record_views.unnamed(rows, category),
                  'rows': len(rows)}
    else:
        result = {'overview': record_views.overview(rows, category,
                                                    params.get('zone'))}
    item(result)
    return len(rows)


def job_pictures(params, progress, item, should_stop):
    """Similar pictures (core/phash.py): 'groups' of the case's pictures,
    'match' them with reference pictures, or 'hash_folder' the references.
    CPU-bound Python: on a thread in the window it held the interpreter
    lock, and every query the window ran waited on it -- a Fedora case took
    minutes to open. The result is the one item."""
    from trace_app.core import phash
    operation = params['operation']
    threshold = params.get('threshold', phash.DEFAULT_THRESHOLD)
    items = params.get('items')
    if items is None and params.get('case_folder'):
        # The case's pictures are read here, not in the window: on a big
        # case that read alone held the window for seconds.
        from trace_app.core.case import query_picture_hashes
        path = os.path.join(params['case_folder'], 'case.db')
        connection = connect_read_only(path)
        try:
            items = query_picture_hashes(connection,
                                         params.get('evidence_id'))
        finally:
            connection.close()
    if operation == 'groups':
        result = phash.groups(items, threshold, should_stop)
    elif operation == 'match':
        result = phash.match(params['references'], items, threshold,
                             should_stop)
    elif operation == 'hash_folder':
        result = phash.hash_folder(params['folder'], should_stop)
    else:
        raise ValueError(f"unknown pictures operation {operation!r}")
    if should_stop():
        return 0
    item({'result': result, 'total': len(items or ())})
    return 1


def job_scope_count(params, progress, item, should_stop):
    """How many files a scope keeps, per image (core/scope.count): the
    Scope editor's estimate. An image's folders and files are listed once
    (the walk takes a while on a big one) and kept in the user data folder
    by path, size and time -- after that each edit of the rules is counted
    in a second or two. One item per image: {path, in_scope, total}."""
    from trace_app.core import scope as scope_module
    done = 0
    for image in params['images']:
        if should_stop():
            return done
        volumes = _scope_listing(image, progress, should_stop)
        if volumes is None:
            continue
        try:
            kept, total = scope_module.count(volumes, params['scope'],
                                             should_stop)
        except scope_module.Cancelled:
            return done
        item({'path': image['path'], 'in_scope': kept, 'total': total})
        done += 1
    return done


def _scope_listing(image, progress, should_stop):
    """listing() of one image, from the kept copy when the image has not
    changed. None when cancelled or unreadable."""
    import hashlib
    import pickle
    from trace_app.core import scope as scope_module
    from trace_app.infra.paths import user_data_dir
    path = image['path']
    try:
        stat = os.stat(path)
        stamp = f"{os.path.normcase(os.path.abspath(path))}|{stat.st_size}|" \
                f"{stat.st_mtime_ns}"
    except OSError:
        stamp = path                    # a live disk or a folder
    folder = os.path.join(user_data_dir(), 'scope_listings')
    kept = os.path.join(folder, hashlib.sha256(stamp.encode(
        'utf-8', 'surrogatepass')).hexdigest()[:32] + '.pickle')
    if os.path.exists(kept):
        try:
            with open(kept, 'rb') as handle:
                return pickle.load(handle)
        except Exception as exc:        # damaged or from another version
            logger.debug("Listing %s not reused: %s", kept, exc)
    handler = None
    try:
        handler = _open_image(path, image.get('unlock'))
        name = os.path.basename(path)
        volumes = scope_module.listing(
            handler, should_stop,
            lambda folders, where: progress(
                folders, 0, f"Listing {name}: {folders:,} folders"))
    except scope_module.Cancelled:
        return None
    except Exception as exc:
        logger.warning("Could not list %s for the scope: %s", path, exc)
        return None
    finally:
        _close(handler)
    try:
        os.makedirs(folder, exist_ok=True)
        with open(kept + '.part', 'wb') as handle:
            pickle.dump(volumes, handle, protocol=pickle.HIGHEST_PROTOCOL)
        os.replace(kept + '.part', kept)
    except OSError as exc:
        logger.debug("Listing not kept: %s", exc)
    return volumes


def job_verify(params, progress, item, should_stop):
    """Hash one piece of evidence in full (core/case.hash_evidence) and
    send the results back as one item: {'results'} or {'cancelled'}. The
    window judges and records them; nothing is written here."""
    from trace_app.core.case import hash_evidence
    from trace_app.core.image_handler import HashingCancelled
    row = params['row']

    def report(done, total):
        if should_stop():
            raise HashingCancelled()
        progress(done, total)
    try:
        results = hash_evidence(row, report)
    except HashingCancelled:
        item({'cancelled': True})
        return 0
    item({'results': results})
    return 1


def job_probe(params, progress, item, should_stop):
    """Open one item as the case would and describe it (core/
    evidence_probe.probe), for the wizard's Evidence page. A process, not
    a thread: listing a big folder and matching a million paths against
    the tools' patterns is Python, and on a thread it froze the window."""
    from trace_app.core import evidence_probe
    item({'result': evidence_probe.probe(params['path'])})
    return 1


def job_ping(params, progress, item, should_stop):
    """Imports what the real jobs import and reports back: the packaged
    self-test's proof that a child process starts in a frozen build."""
    from trace_app.core import (activity, analysis, carving,  # noqa: F401
                                deleted, hashsets, indexer, keywords,
                                mailfiles,
                                ntfs, persistence, report, thumbnails,
                                timeline, yara_rules)
    import pytsk3  # noqa: F401
    # Indexing's text pool starts processes of its own from this one: in a
    # frozen build that is the app started again, twice over.
    from trace_app.core.text_pool import TextPipeline
    found = []
    pool = TextPipeline(lambda text, entities, payload: found.append(
        entities), workers=2)
    pool.submit(b'write to ping@example.org', 'ping.txt', 1 << 16, 0)
    pool.close()
    progress(1, 1, 'ping', force=True)
    item({'pong': params.get('value'), 'pool': found})
    return 1


JOBS = {
    'index': job_index,
    'index_free': job_index_free,
    'analysis': job_analysis,
    'activity': job_activity,
    'ntfs': job_ntfs,
    'fstimes': job_fstimes,
    'hashsets': job_hashsets,
    'report': job_report,
    'yara': job_yara,
    'sigma': job_sigma,
    'keywords': job_keywords,
    'thumbnails': job_thumbnails,
    'deleted': job_deleted,
    'persistence': job_persistence,
    'carve': job_carve,
    'vss_compare': job_vss_compare,
    'vics': job_vics,
    'leapp': job_leapp,
    'archive_index': job_archive_index,
    'folder_check': job_folder_check,
    'module_fit': job_module_fit,
    'module_bridge': job_module_bridge,
    'module_import': job_module_import,
    'pictures': job_pictures,
    'record_view': job_record_view,
    'scope_count': job_scope_count,
    'verify': job_verify,
    'probe': job_probe,
    'ping': job_ping,
}
