"""What the case knows about one piece of evidence, as rows for the Image
Information window (no Qt).

Integrity first -- hashes and the last verification -- then what each
analysis found: file analysis, deleted files, carving, user activity, NTFS
internals, the rule-based jobs (YARA, Sigma, keyword lists, hash sets,
persistence) and thumbnail caches. Only what the case recorded: a module
that has not run says so ("not run") rather than showing zeros, because
"not looked" and "looked and found nothing" are different answers.

Rows are (label, value), (label, value, state) where state is a property
table style ('warning'), or (None, heading).
"""

from trace_app.core.carve_verify import STATUSES, STATUS_LABELS

NOT_RUN = "not run"

_CATEGORY_LABELS = None


def _n(value):
    return f"{int(value or 0):,}"


def when(text):
    """'2026-10-04 23:07:58 UTC' from a stored ISO time ('...T...+00:00')."""
    if not text:
        return ''
    text = str(text).replace('T', ' ')
    for suffix in ('+00:00', 'Z'):
        if text.endswith(suffix):
            text = text[:-len(suffix)]
    return f"{text.split('.')[0]} UTC"


def _category_labels():
    global _CATEGORY_LABELS
    if _CATEGORY_LABELS is None:
        try:
            from trace_app.core.activity import CATEGORIES
            _CATEGORY_LABELS = dict(CATEGORIES)
        except Exception:
            _CATEGORY_LABELS = {}
    return _CATEGORY_LABELS


def rows_for(case, evidence_id):
    """Every summary row for one evidence id."""
    out = []
    for section in (_integrity, _file_analysis, _deleted, _carving,
                    _activity, _ntfs, _rules):
        try:
            out += section(case, evidence_id)
        except Exception as exc:          # one section never hides the rest
            out.append((section.__name__.strip('_').replace('_', ' ')
                        .capitalize(), f"could not be read: {exc}",
                        'warning'))
    return out


def _integrity(case, evidence_id):
    row = next((r for r in case.evidence() if r['id'] == evidence_id), {})
    out = [(None, "Integrity")]
    if row.get('added_utc'):
        out.append(("Added to the case", when(row['added_utc'])))
    for key, label in (('md5', 'MD5'), ('sha1', 'SHA-1'),
                       ('sha256', 'SHA-256')):
        if row.get(key):
            out.append((label, row[key]))
    for key, label in (('stored_md5', 'Stored MD5 (in the image)'),
                       ('stored_sha1', 'Stored SHA-1 (in the image)')):
        if row.get(key):
            out.append((label, row[key]))
    history = case.verifications(evidence_id, limit=50)
    if history:
        last = history[0]
        status = (last.get('status') or '').lower()
        out.append(("Last verification",
                    f"{last.get('status')} on {when(last.get('utc'))}",
                    None if status in ('verified', 'ok', 'match', 'matched')
                    else 'warning'))
        out.append(("Verifications recorded", _n(len(history))))
    else:
        out.append(("Last verification", "never verified", 'warning'))
    return out


def _file_analysis(case, evidence_id):
    out = [(None, "File analysis")]
    state = case.analysis_state(evidence_id)
    if not state:
        return out + [("Status", NOT_RUN)]
    summary = case.analysis_summary(evidence_id)
    out.append(("Status", f"{state['status']}, {when(state['updated_utc'])}"
                if state.get('updated_utc') else state['status'],
                None if state['status'] == 'done' else 'warning'))
    out.append(("Files analysed", _n(summary.get('analysed'))))
    for key, label, warn in (
            ('mismatches', "Type mismatches", True),
            ('high_entropy', "High entropy (encrypted or packed?)", True),
            ('hidden', "Hidden data", True),
            ('duplicate_groups', "Groups of identical files", False),
            ('photos', "Photos with metadata", False),
            ('photos_located', "Photos with a location", False),
            ('authors', "Documents naming an author", False),
            ('executables', "Executables", False),
            ('executables_flagged', "Executables flagged", True)):
        value = summary.get(key) or 0
        out.append((label, _n(value), 'warning' if warn and value else None))
    return out


def _deleted(case, evidence_id):
    from trace_app.core import deleted
    out = [(None, "Deleted files")]
    counts = case.deleted_counts(evidence_id)
    if not counts:
        listed = case.last_audited('deleted files listed', evidence_id)
        return out + [("Listed", f"none found ({when(listed)})" if listed
                       else NOT_RUN)]
    out.append(("Listed", _n(sum(counts.values()))))
    for state in deleted.STATES:
        if counts.get(state):
            out.append((state.capitalize(), _n(counts[state])))
    return out


def _carving(case, evidence_id):
    out = [(None, "Carving")]
    state = case.carving_state(evidence_id)
    if not state:
        return out + [("Status", NOT_RUN)]
    out.append(("Status", f"{state['status']}, "
                          f"{when(state.get('updated_utc'))}",
                None if state['status'] == 'done' else 'warning'))
    out.append(("Files recovered", _n(state.get('found'))))
    runs = case.carving_runs(evidence_id, limit=1)
    stats = (runs[0].get('stats') or {}) if runs else {}
    for status in STATUSES:
        count = (stats.get('status') or {}).get(status)
        if count:
            out.append((f"  {STATUS_LABELS.get(status, status)}", _n(count)))
    for key, label in (('named', "Named from deleted entries"),
                       ('duplicates', "Identical copies"),
                       ('wal_pairs', "WAL files paired with a database")):
        if stats.get(key):
            out.append((label, _n(stats[key])))
    return out


def _activity(case, evidence_id):
    out = [(None, "User activity")]
    state = case.user_activity_state(evidence_id)
    if not state:
        return out + [("Status", NOT_RUN)]
    summary = case.user_activity_summary(evidence_id)
    out.append(("Records", _n(sum(summary.values()))))
    first, last = case.activity_span(evidence_id)
    if first:
        out.append(("Earliest", when(first)))
        out.append(("Latest", when(last)))
    labels = _category_labels()
    for category, count in sorted(summary.items(), key=lambda kv: -kv[1]):
        out.append((f"  {labels.get(category, category)}", _n(count)))
    users = case.activity_users(evidence_id)
    if users:
        out.append(("Accounts named", ', '.join(
            f"{user} ({count:,})" for user, count in users)))
    return out


def _ntfs(case, evidence_id):
    counts = case.ntfs_counts(evidence_id)
    if not any(counts.values()):
        return []                       # not NTFS, or not read: no section
    return [(None, "NTFS internals"),
            ("Timestamps altered (timestomp)", _n(counts.get('timestomp')),
             'warning' if counts.get('timestomp') else None),
            ("Alternate streams and downloads", _n(counts.get('streams'))),
            ("Names in $I30 slack", _n(counts.get('slack'))),
            ("$LogFile operations", _n(counts.get('logfile'))),
            ("Change journal records", _n(counts.get('journal')))]


def _rules(case, evidence_id):
    out = [(None, "Rules, hash sets and persistence")]
    modules = case.finding_module_counts(evidence_id)
    for module, label in (('yara', "YARA rule matches"),
                          ('sigma', "Sigma detections"),
                          ('keywords', "Keyword hits")):
        out.append((label, _n(modules[module]) if module in modules
                    else "none or not run",
                    'warning' if modules.get(module) else None))
    matches = case.hash_match_counts(evidence_id)
    if matches:
        for category, count in sorted(matches.items()):
            out.append((f"Hash set: {category.replace('_', ' ')}",
                        _n(count), 'warning' if 'bad' in category
                        or 'notable' in category else None))
    persistence = case.persistence_counts(evidence_id)
    if persistence:
        out.append(("Autostart entries", _n(sum(persistence.values()))))
        for grade in ('suspicious', 'notable'):
            if persistence.get(grade):
                out.append((f"  {grade.capitalize()}",
                            _n(persistence[grade]), 'warning'))
    thumbs = case.thumbnail_counts(evidence_id)
    if thumbs.get('pictures'):
        out.append(("Pictures in thumbnail caches",
                    _n(thumbs['pictures'])))
        if thumbs.get('gone'):
            out.append(("  Their original is gone", _n(thumbs['gone']),
                        'warning'))
    return out
