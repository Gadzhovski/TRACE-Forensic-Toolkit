"""One run of an external tool on one image, start to finish (no Qt).

stage (the files it reads, copied and hashed) -> run its command line ->
read its LAVA output -> the events for the Timeline. The case is written
by the caller (core/background.job_leapp); this module only reads the
evidence and writes the run's folder:

    <run folder>/input/               staged files (or the archive copied
                                      out of an image, or an unpacked
                                      iTunes backup)
    <run folder>/staging-manifest.csv
    <run folder>/report/              the tool's output (LAVA, HTML, ...)
    <run folder>/run.log
"""

import logging
import os

from trace_app.core.evidence_hash import sha256_file as sha256
from trace_app.core.modules import destinations, inputs, lava, run, stage

logger = logging.getLogger('TRACE.Modules')

REPORT = 'report'
LOG = 'run.log'
#: Characters of a row kept as an event's summary.
SUMMARY_LENGTH = 240


class NothingToRead(Exception):
    """The image holds none of the files the tool reads."""


def plan(spec, record, handler, evidence_path, should_stop=None,
         progress=None, scope=None):
    """An image's inputs for the tool (core/modules/inputs): the loose
    files its patterns name, and every packed extraction or zipped backup,
    found in one walk. Raises NothingToRead when there are none."""
    from trace_app.core.modules import inputs
    from trace_app.core import evidence_profile
    from trace_app.core.modules import fit
    patterns = stage.path_patterns(spec, record)
    matcher = stage.Matcher(patterns)
    # A tool whose evidence has no system (RLEAPP's returns, VLEAPP's cars)
    # takes an archive its own specific patterns name inside -- of any
    # size: a return's zips are kilobytes.
    by_patterns = bool(spec.suits) and \
        set(spec.suits) <= set(evidence_profile.PATTERN_KINDS)
    inside = stage.Matcher(fit.specific(patterns)) if by_patterns else None
    candidates = []
    found = stage.find(handler, matcher, should_stop, progress, scope,
                       archives=candidates,
                       min_archive=0 if by_patterns else None)
    if progress is not None and candidates:
        progress(0, 0, f"Looking inside {len(candidates):,} archive(s)")
    # An archive the tool's own patterns name (a sysdiagnose .tar.gz) is a
    # file it parses, given as one -- never unpacked as an extraction. Only
    # a specific pattern says so: RLEAPP's `*/*.*` names every file, and
    # took its return zips for files it parses whole (it read nothing).
    named = stage.Matcher(fit.specific(patterns))
    wanted = {entry.ref for _volume, entry in found if named(entry.path)}
    candidates = [entry for entry in candidates if entry.ref not in wanted]
    archives = inputs.find_archives(handler, spec.suits, candidates,
                                    evidence_path, should_stop, inside)
    packed = {item['entry'].ref for item in archives}
    found = [(volume, entry) for volume, entry in found
             if entry.ref not in packed]
    plans = [dict(item, label=inputs.label(item)) for item in archives
             if item['kind'] in spec.inputs]
    if found:
        plans.insert(0, {'kind': 'staged', 'found': found,
                         'count': len(found),
                         'label': inputs.label({'kind': 'staged',
                                                'count': len(found)})})
    raw = inputs.raw_input(spec, handler, evidence_path, bool(plans))
    if raw is not None:
        plans.append(dict(raw, label=inputs.label(raw)))
    if not plans:
        raise NothingToRead(
            f"The image holds none of the files {spec.name} reads "
            f"({matcher.count:,} patterns), and no extraction or backup "
            f"packed in a tar or zip: nothing to run it on.")
    return plans


def _copy_out(handler, entry, target, should_stop, progress):
    """A file of the image, copied (hashed, read back) to `target`."""
    from trace_app.core import evidence_export
    handle = entry.fs.open_meta(inode=entry.inode)
    import shutil
    free = shutil.disk_usage(os.path.dirname(target)).free
    if free < entry.size * 1.1 + stage.SPACE_MARGIN:
        raise stage.StageError(
            f"Not enough free space to copy {entry.name} "
            f"({entry.size / 1e9:.1f} GB) out of the image.")
    done = [0]

    def copied(length):
        done[0] += length
        if progress is not None:
            progress(done[0], entry.size, f"Copying {entry.name}")
    try:
        return evidence_export.write_verified(
            target, lambda at, length: handle.read_random(at, length),
            entry.size, should_stop, copied)
    except evidence_export.ExportCancelled:
        raise stage.StageCancelled() from None


def _hash(path, should_stop, progress, name):
    from trace_app.core import evidence_hash
    hashers = evidence_hash.new_hashers()
    size = os.path.getsize(path)
    done = 0
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(4 << 20), b''):
            if should_stop is not None and should_stop():
                raise stage.StageCancelled()
            for hasher in hashers.values():
                hasher.update(block)
            done += len(block)
            if progress is not None:
                progress(done, size, f"Hashing {name}")
    return evidence_hash.digests(hashers, done)


def _unzip_backup(source, root, target, should_stop):
    """The backup folder `root` of a zip (a path or a file object) into
    `target`; returns the backup's own folder there."""
    import zipfile
    prefix = (root + '/') if root else ''
    with zipfile.ZipFile(source) as zipped:
        for member in zipped.infolist():
            if should_stop is not None and should_stop():
                raise stage.StageCancelled()
            name = member.filename.replace('\\', '/')
            if not name.startswith(prefix) or name.endswith('/'):
                continue
            path = os.path.realpath(os.path.join(target, *name.split('/')))
            if not path.startswith(os.path.realpath(target) + os.sep):
                raise stage.StageError(f"The backup holds a file outside "
                                       f"its folder ({member.filename}).")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with zipped.open(member) as reader, open(path, 'wb') as writer:
                for block in iter(lambda: reader.read(1 << 20), b''):
                    writer.write(block)
    return os.path.join(target, *root.split('/')) if root else target


def wanted_secrets(spec, rows):
    """The tool's keys (spec.secrets) the staged files call for: a Signal
    Desktop database staged for DLEAPP."""
    import fnmatch
    paths = [(row.get('source_path') or '').lower() for row in rows]
    return [secret for secret in spec.secrets
            if any(fnmatch.fnmatch(path, pattern.lower())
                   for pattern in secret.patterns for path in paths)]


def execute(spec, record, handler, folder, evidence_id, evidence_name,
            item, should_stop=None, progress=None, password=None,
            keys=None):
    """One input (from plan()) through the tool. Returns {'staged',
    'problems', 'manifest_sha256', 'lava_sha256', 'report', 'info',
    'exit_code', 'input'}. Raises stage.StageError/StageCancelled,
    run.ToolError/ToolCancelled, lava.LavaError."""
    os.makedirs(folder, exist_ok=True)
    log_path = os.path.join(folder, LOG)
    with open(log_path, 'a', encoding='utf-8') as log:
        log.write(f"{spec.name} {record['version']} -- "
                  f"{record['executable']}\nInput: {item['label']}\n")
    input_dir = os.path.join(folder, 'input')
    manifest = os.path.join(folder, stage.MANIFEST)
    described = {'kind': item['kind'], 'label': item['label']}
    if item['kind'] == 'staged':
        rows = stage.stage(handler, item['found'], input_dir, evidence_id,
                           evidence_name, should_stop, progress)
        kind, source = 'fs', input_dir
    elif item['kind'] == inputs.RAW:
        # The evidence itself, read in place by the tool: nothing copied,
        # its custody is the evidence's own recorded hashes.
        rows = [{'staged_path': '', 'evidence_id': evidence_id,
                 'evidence': evidence_name, 'volume': '',
                 'source_path': item['os_path'], 'artifact_ref': '',
                 'size': item['size'],
                 'written_copy_check': 'the evidence, read in place'}]
        stage.write_manifest(manifest, rows)
        described.update(path=item['os_path'],
                         unreadable=item.get('unreadable', ''))
        kind, source = inputs.RAW, item['os_path']
    else:
        entry = item['entry']
        os.makedirs(input_dir, exist_ok=True)
        if item.get('os_path'):
            digests = _hash(item['os_path'], should_stop, progress,
                            entry.name)
            digests['written_copy_check'] = 'read where it is'
            container = item['os_path']
        else:
            container = os.path.join(input_dir, stage.staged_name(
                '', entry.name))
            digests = _copy_out(handler, entry, container, should_stop,
                                progress)
        rows = [{'staged_path': os.path.basename(container)
                 if not item.get('os_path') else '',
                 'evidence_id': evidence_id, 'evidence': evidence_name,
                 'volume': '', 'source_path': entry.path,
                 'artifact_ref': entry.ref, 'size': entry.size,
                 **{key: digests.get(key, '') for key in
                    ('md5', 'sha1', 'sha256', 'written_copy_check')}}]
        stage.write_manifest(manifest, rows)
        described.update(path=entry.path, ref=entry.ref,
                         sha256=digests.get('sha256'))
        if item['kind'] == 'itunes':
            if progress is not None:
                progress(0, 0, f"Unpacking the backup in {entry.name}")
            kind = 'itunes'
            source = _unzip_backup(container, item['root'],
                                   os.path.join(input_dir, 'backup'),
                                   should_stop)
            if not item.get('os_path'):
                os.remove(container)        # unpacked: the copy is done
        else:
            kind, source = item['kind'], container
    staged = [row for row in rows if not row.get('problem')]
    arguments = [record['executable'], '-t', kind, '-i', source,
                 '-o', folder, '--custom_output_folder', REPORT]
    secrets = ()
    if kind == 'itunes' and password:
        # The LEAPPs take a backup's password on the command line only.
        arguments += ['--itunes_password', password]
        secrets = (password,)
        described['password'] = ('given by the examiner, checked against '
                                 'the backup keybag')
    # Keys (DLEAPP's Signal key): written to a file of the run's own, its
    # path given (`--signal-key FILE`) -- never the key on the command
    # line -- and removed when the run ends.
    key_files = []
    for secret in spec.secrets:
        value = (keys or {}).get(secret.id)
        if not value:
            continue
        path = os.path.join(folder, f".{secret.id}-key")
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(value)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        key_files.append(path)
        arguments += [secret.option, path]
        secrets += (value,)
        described[f"{secret.id}_key"] = 'given by the examiner'
    wanted = [secret.id for secret in wanted_secrets(spec, rows)
              if not (keys or {}).get(secret.id)]
    if wanted:
        described['secrets_wanted'] = wanted
    with open(log_path, 'a', encoding='utf-8') as log:
        log.write(f"{len(staged):,} file(s) given; running: "
                  f"{run.mask(' '.join(arguments), secrets)}\n")
    try:
        code = run.run(arguments, os.path.dirname(record['executable']),
                       log_path, should_stop,
                       lambda done, total, line: progress(
                           done, total, line[:160]) if progress else None,
                       secrets=secrets,
                       follow=os.path.join(folder, REPORT,
                                           *spec.screen_output))
    finally:
        for path in key_files:
            try:
                os.remove(path)
            except OSError:
                logger.warning("A key file could not be removed: %s", path)
    report = os.path.join(folder, REPORT)
    if secrets:
        _redact(report, secrets, log_path)
    try:
        info = lava.load(report)
    except lava.LavaError as exc:
        raise run.ToolError(f"{spec.name} ended (exit {code}) without its "
                            f"results: {exc} -- see {log_path}") from exc
    if info['status'] != 'Complete':
        raise run.ToolError(f"{spec.name} ended (exit {code}) with its run "
                            f"'{info['status'] or 'unfinished'}' -- see "
                            f"{log_path}")
    return {'staged': len(staged),
            'problems': [f"{row['source_path']}: {row['problem']}"
                         for row in rows if row.get('problem')],
            'manifest_sha256': sha256(manifest),
            'lava_sha256': sha256(os.path.join(report, lava.DATABASE)),
            'report': report, 'info': info, 'exit_code': code,
            'input': described}


#: The tool's own output TRACE may rewrite to star a password in.
_TEXT_OUTPUT = ('.html', '.htm', '.txt', '.tsv', '.csv', '.json', '.lava',
                '.kml', '.log', '.js', '.xml')


def _redact(report, secrets, log_path):
    """Star `secrets` in the tool's text output: iLEAPP writes "Manifest.db
    was successfully decrypted with passcode <password>" into its report's
    index.html and Screen_Output.html, and the case folder is archived and
    handed on. Databases are never rewritten -- a password found in one is
    said in run.log instead."""
    needles = [secret.encode('utf-8') for secret in secrets if secret]
    changed, binary = [], []
    for base, _dirs, names in os.walk(report):
        for name in names:
            path = os.path.join(base, name)
            try:
                with open(path, 'rb') as handle:
                    data = handle.read()
            except OSError:
                continue
            if not any(needle in data for needle in needles):
                continue
            if not name.lower().endswith(_TEXT_OUTPUT):
                binary.append(os.path.relpath(path, report))
                continue
            for needle in needles:
                data = data.replace(needle, b'********')
            with open(path, 'wb') as handle:
                handle.write(data)
            changed.append(os.path.relpath(path, report))
    with open(log_path, 'a', encoding='utf-8') as log:
        if changed:
            log.write(f"TRACE starred the backup password the tool wrote "
                      f"into {len(changed)} of its own file(s): "
                      f"{', '.join(changed)}\n")
        if binary:
            log.write(f"WARNING: the backup password is in {len(binary)} "
                      f"file(s) TRACE does not rewrite: "
                      f"{', '.join(binary)}\n")
    return changed, binary


def coverage(info):
    """What a run covered, from the tool's own account (_lava_data.lava's
    modules): {'artifacts', 'with_data', 'no_files', 'other': [(name,
    status)]} -- 'other' are artifacts that ran but did not finish."""
    modules = info.get('modules') or []
    statuses = [((m.get('artifact_name') or m.get('module_name') or ''),
                 m.get('module_status') or '') for m in modules]
    return {'artifacts': len(statuses),
            'with_data': sum(1 for _n, s in statuses if s == 'Complete'),
            'no_files': sum(1 for _n, s in statuses
                            if s == 'No files found'),
            'other': [(n, s) for n, s in statuses
                      if s not in ('Complete', 'No files found')]}


def split_by_size(artifacts, limit):
    """(artifacts added to the Timeline and Search, [(name, rows)] kept
    in the tool's database only): an artifact over `limit` rows (0 = no
    limit) is not copied -- iLEAPP's unified log of one sysdiagnose is 21
    million rows, hours to copy and a Timeline nobody can read."""
    if not limit:
        return list(artifacts), []
    added, kept = [], []
    for artifact in artifacts:
        if (artifact.get('record_count') or 0) > limit:
            kept.append((artifact['name'], artifact['record_count']))
        else:
            added.append(artifact)
    return added, kept


class _Counter:
    """Rows done over the artifacts being added, for progress."""

    def __init__(self, artifacts, progress, what):
        self.total = sum(a.get('record_count') or 0 for a in artifacts)
        self.done = 0
        self.progress, self.what = progress, what

    def step(self, rows, name):
        self.done += rows
        if self.progress is not None:
            self.progress(min(self.done, self.total), self.total,
                          f"{self.what}: {name}")


def events(report, artifacts, artifact_ids, progress=None,
           should_stop=None):
    """(artifact id, rowid, time_utc, label, summary) for every timestamp
    in every row: a message's sent, read and delivered times are three
    events, each saying which it is."""
    counter = _Counter(artifacts, progress, "Adding to the Timeline")
    connection = lava.connect(report)
    try:
        media = lava.media(connection)
        for artifact in artifacts:
            times = [column for column in artifact['columns']
                     if column['type'] == 'datetime']
            artifact_id = artifact_ids.get(artifact['tablename'])
            if not times or artifact_id is None:
                counter.step(artifact.get('record_count') or 0,
                             artifact['name'])
                continue
            others = [column for column in artifact['columns']
                      if column['type'] != 'datetime']
            for number, (rowid, values) in enumerate(
                    lava.iter_rows(connection, artifact), start=1):
                if number % 2000 == 0:
                    if should_stop is not None and should_stop():
                        return
                    counter.step(2000, artifact['name'])
                summary = summarise(others, values, media)
                for column in times:
                    when = lava.utc_text(values.get(column['name']))
                    if when[:4].isdigit() and when[:4] > '1970':
                        yield (artifact_id, rowid, when,
                               f"{artifact['name']}: {column['label']}",
                               summary)
            counter.step((artifact.get('record_count') or 0) % 2000,
                         artifact['name'])
    finally:
        connection.close()


def index_rows(case_folder, run_id, evidence_id, tool, report, artifacts,
               should_stop=None, progress=None, clear=True):
    """Every row into the case's search index (kind 'module', its module
    ref): its column labels and values as text, so Search finds a message
    or an account by its words, and the index's indicators (phones,
    e-mails, URLs...) are pulled out of it too. A run's rows replace any
    it had. Returns how many rows."""
    from trace_app.core.case import make_module_ref
    from trace_app.core.search_index import SearchIndex
    index = SearchIndex(case_folder)
    count = 0
    counter = _Counter(artifacts, progress, "Adding to Search")
    try:
        if clear:
            index.clear_module_run(run_id)
        connection = lava.connect(report)
        try:
            media = lava.media(connection)
            for artifact in artifacts:
                columns = artifact['columns']
                path = f"[{tool}]/{artifact['category']}/{artifact['name']}"
                after = -2 ** 63
                while True:
                    if should_stop is not None and should_stop():
                        return count
                    page = lava.rows(connection, artifact, limit=2000,
                                     after=after)
                    if not page:
                        break
                    after = page[-1][0]
                    counter.step(len(page), artifact['name'])
                    for rowid, values in page:
                        body = '\n'.join(
                            f"{column['label']}: {text}" for column in columns
                            for text in [lava.display(
                                column, values.get(column['name']), media)]
                            if text)
                        when = next((lava.utc_text(values.get(c['name']))
                                     for c in columns
                                     if c['type'] == 'datetime'
                                     and values.get(c['name'])), '')
                        index.add_item(
                            evidence_id,
                            make_module_ref(run_id, artifact['tablename'],
                                            rowid),
                            'module', f"{artifact['name']} #{rowid}", path,
                            body, mtime_utc=when)
                        count += 1
                    index.commit()
        finally:
            connection.close()
        index.commit()
    finally:
        index.close()
    return count


def imported_tables(run, artifacts):
    """The tablenames of a run's artifacts within the import limit when
    it was imported -- in the Timeline and Search, for runs imported
    before the places were chosen per role (`placed_tables` is what is
    in each). Newer runs record what was left out by table
    (params.not_imported_tables); older ones by (name, rows)."""
    params = run.get('params') or {}
    if 'not_imported_tables' in params:
        kept = set(params['not_imported_tables'])
        return {a['tablename'] for a in artifacts} - kept
    kept = {(name, rows) for name, rows in params.get('not_imported') or ()}
    return {a['tablename'] for a in artifacts
            if (a['name'], a.get('row_count') or 0) not in kept}


def placed_tables(run, artifacts):
    """{'timeline': tablenames, 'search': tablenames} of a run's
    artifacts whose rows are in the case's Timeline / search index now
    (params.timeline_tables / search_tables; a run imported before those
    were recorded had every artifact within the limit in both)."""
    params = run.get('params') or {}
    names = {a['tablename'] for a in artifacts}
    base = None
    out = {}
    for place in destinations.COPIED:
        key = f'{place}_tables'
        if key in params:
            out[place] = set(params[key]) & names
        else:
            if base is None:
                base = imported_tables(run, artifacts)
            out[place] = set(base)
    return out


def _rows(artifact):
    return artifact.get('row_count', artifact.get('record_count')) or 0


def wanted_tables(artifacts, limit, value=None):
    """{'timeline': ..., 'search': ...}: the tablenames whose rows should
    be in each, by the artifact's role (core/modules/destinations, case
    setting module_destinations) and the import limit (0 = none)."""
    out = {place: set() for place in destinations.COPIED}
    for artifact in artifacts:
        if limit and _rows(artifact) > limit:
            continue
        chosen = destinations.places(destinations.role_of(artifact), value)
        for place in out:
            if place in chosen:
                out[place].add(artifact['tablename'])
    return out


def pending(run, artifacts, limit, value=None):
    """What applying the limit and the places would change in one run:
    {'timeline': (add, drop), 'search': (add, drop)} as artifact lists."""
    have = placed_tables(run, artifacts)
    want = wanted_tables(artifacts, limit, value)
    return {place: ([a for a in artifacts
                     if a['tablename'] in want[place] - have[place]],
                    [a for a in artifacts
                     if a['tablename'] in have[place] - want[place]])
            for place in destinations.COPIED}


def pending_rows(run, artifacts, limit, value=None):
    """(rows that applying the limit and places would add to the Timeline
    or Search, rows it would take out) -- each artifact counted once."""
    changes = pending(run, artifacts, limit, value)
    add = {a['tablename']: _rows(a) for place in changes
           for a in changes[place][0]}
    drop = {a['tablename']: _rows(a) for place in changes
            for a in changes[place][1]}
    return sum(add.values()), sum(drop.values())


def apply_destinations(case, case_folder, run_id, limit, progress=None,
                       should_stop=None, value=None):
    """Make a completed run's Timeline events and Search rows follow the
    import limit (case setting module_import_rows) and the places chosen
    per role (module_destinations) as they are now: what they now let in
    is added, what they keep out is dropped -- nothing is read again from
    the evidence, only from the tool's database. Run after the bridge has
    sorted the run (roles are its). A cancel takes back what it had added,
    so the run's params always say what is in.

    Returns {'added', 'dropped', 'added_rows', 'dropped_rows', 'indexed',
    'events'} (artifact names and row counts) and records the run's new
    params."""
    run = case.module_run(run_id)
    out = {'added': [], 'dropped': [], 'added_rows': 0, 'dropped_rows': 0,
           'indexed': 0, 'cancelled': False}
    if run is None or run['status'] != 'complete':
        return out
    report = os.path.join(run['path'], 'report')
    stored = case.module_artifacts(run_id)
    by_table = {a['tablename']: a for a in stored}
    ids = {a['tablename']: a['id'] for a in stored}
    have = placed_tables(run, stored)
    want = wanted_tables(stored, limit, value)
    changes = pending(run, stored, limit, value)
    loaded = {}
    if any(add for add, _drop in changes.values()):
        loaded = {a['tablename']: a for a in lava.load(report)['artifacts']}
    stopped = lambda: should_stop is not None and should_stop()  # noqa: E731
    from trace_app.core.search_index import SearchIndex

    def drop_search(tables):
        if not tables:
            return
        index = SearchIndex(case_folder)
        try:
            for table in tables:
                index.clear_module_artifact(run_id, table)
            index.commit()
        finally:
            index.close()

    now = {place: set(have[place]) for place in have}
    timeline_add, timeline_drop = changes['timeline']
    search_add, search_drop = changes['search']
    if timeline_drop:
        case.drop_module_events(a['id'] for a in timeline_drop)
        now['timeline'] -= {a['tablename'] for a in timeline_drop}
    if search_drop:
        drop_search([a['tablename'] for a in search_drop])
        now['search'] -= {a['tablename'] for a in search_drop}
    adding = [loaded[a['tablename']] for a in timeline_add
              if a['tablename'] in loaded]
    if adding and not stopped():
        case.add_module_events(run_id, events(report, adding, ids, progress,
                                              should_stop))
        if stopped():
            case.drop_module_events(ids[a['tablename']] for a in adding)
        else:
            from trace_app.core.modules import bridge
            for artifact in adding:
                bridge.tag_events(case, run, artifact,
                                  by_table[artifact['tablename']])
            case.commit()
            now['timeline'] |= {a['tablename'] for a in adding}
    adding = [loaded[a['tablename']] for a in search_add
              if a['tablename'] in loaded]
    if adding and not stopped():
        try:
            out['indexed'] = index_rows(
                case_folder, run_id, run['evidence_id'], run['tool'],
                report, adding, should_stop, progress, clear=False)
        except Exception:
            drop_search([a['tablename'] for a in adding])
            raise
        if stopped():
            drop_search([a['tablename'] for a in adding])
        else:
            now['search'] |= {a['tablename'] for a in adding}
    params = dict(run['params'])
    over = sorted(a['tablename'] for a in stored
                  if limit and _rows(a) > limit)
    params['not_imported'] = [[by_table[t]['name'], _rows(by_table[t])]
                              for t in over]
    params['not_imported_tables'] = over
    params['import_limit'] = limit
    params['timeline_tables'] = sorted(now['timeline'])
    params['search_tables'] = sorted(now['search'])
    case.set_module_run_params(run_id, params)
    out['cancelled'] = stopped()
    added = {t for place in now for t in now[place] - have[place]}
    dropped = {t for place in have for t in have[place] - now[place]}
    out.update(added=[(by_table[t]['name'], _rows(by_table[t]))
                      for t in sorted(added)],
               dropped=[(by_table[t]['name'], _rows(by_table[t]))
                        for t in sorted(dropped)])
    out['added_rows'] = sum(rows for _n, rows in out['added'])
    out['dropped_rows'] = sum(rows for _n, rows in out['dropped'])
    out['wanted'] = {place: sorted(want[place]) for place in want}
    return out


def apply_limit(case, case_folder, run_id, limit, progress=None,
                should_stop=None):
    """`apply_destinations` with the case's current places."""
    return apply_destinations(case, case_folder, run_id, limit, progress,
                              should_stop)


def summarise(columns, values, media=None):
    parts = []
    for column in columns:
        text = lava.display(column, values.get(column['name']), media)
        text = ' '.join(text.split())
        if text and text.lower() not in ('none', 'null'):
            parts.append(f"{column['label']}: {text}")
        if sum(len(p) for p in parts) > SUMMARY_LENGTH:
            break
    summary = ' | '.join(parts)
    return summary[:SUMMARY_LENGTH] + ('…' if len(summary) > SUMMARY_LENGTH
                                       else '')
