"""Every kind of artifact a case can hold, in one list: what the Artifacts
navigator and the Case Overview show, with counts and whether the scan
that finds each has run (no Qt).

TRACE's results grew up in several places -- Triage's 22 sub-tabs in six
groups, Activity's categories in six more, the Search, Registry, Timeline
and Modules panels, and nodes of the evidence tree -- each grouped its own
way, so an examiner could not see in one place what the case holds. The
tools examiners know (AXIOM's Artifacts explorer, Cellebrite's Analyzed
Data, Autopsy's Data Artifacts / Analysis Results) list every artifact
type once, by what it is about. `SECTIONS` is that list; each entry says
which existing view opens it, so the panels stay as they are.

The counts are the tabs' own (the rule: the tree, the tabs and now the
navigator count alike): `counts` reads them with the Case methods the
tabs and the tree's Findings node use.
"""

from trace_app.core import export_readiness as readiness
from trace_app.core.analysis import (MODULE_AUTHORS, MODULE_ENTROPY,
                                     MODULE_EXECUTABLES, MODULE_HASH,
                                     MODULE_HIDDEN, MODULE_MAGIC,
                                     MODULE_PHOTO)

# Entry states (`states`).
FOUND, NONE_FOUND, NOT_RUN, STOPPED, RUNNING, NOT_APPLICABLE = (
    'found', 'none found', 'not run', 'stopped', 'running', 'not applicable')


class Entry:
    """One artifact type. `opens` is ('triage', group), ('activity',
    category), ('panel', name) or ('overview',); `icon` the icon's name
    in ui/icons ('activity:<category>' for an Activity category's);
    `modules` the scans that produce it (export_readiness keys) -- none
    for what is always there (the Listing, the Timeline)."""

    __slots__ = ('key', 'label', 'icon', 'opens', 'modules', 'flag')

    def __init__(self, key, label, icon, opens, modules=(), flag=None):
        self.key, self.label, self.icon = key, label, icon
        self.opens, self.modules = opens, tuple(modules)
        #: 'bad' / 'warn' when a count of it is worth a look (Overview).
        self.flag = flag


def _activity(category, modules=(readiness.ACTIVITY,)):
    from trace_app.core.activity import CATEGORIES
    label = dict(CATEGORIES)[category]
    return Entry(f'activity:{category}', label, f'activity:{category}',
                 ('activity', category), modules)


def _sections():
    A = readiness
    return [
        ('communication', "Communication", [
            Entry('conversations', "Conversations", 'CONVERSATIONS',
                  ('triage', 'conversations'), (A.ACTIVITY,)),
            _activity('communication'),
            _activity('accounts'),
            _activity('calendar'),
        ]),
        ('web', "Web", [
            _activity('browser'), _activity('downloads'),
            _activity('searches'), _activity('cloud'),
        ]),
        ('media', "Media & places", [
            Entry('photos', "Photos", 'FINDING_PHOTO', ('triage', 'photos'),
                  (MODULE_PHOTO,)),
            Entry('map', "Located on the map", 'FINDING_LOCATION',
                  ('triage', 'map'), (MODULE_PHOTO, A.ACTIVITY)),
            _activity('locations'),
            Entry('similar', "Similar pictures", 'FINDING_DUPLICATES',
                  ('triage', 'similar')),
            Entry('thumbnails', "Thumbnail caches", 'THUMBNAILS',
                  ('triage', 'thumbnails'), (A.THUMBNAILS,)),
        ]),
        ('files', "Files", [
            Entry('deleted', "Deleted files", 'DELETED_FILES',
                  ('triage', 'deleted'), (A.DELETED,)),
            Entry('carved', "Carved files", 'FINDING_CARVED',
                  ('triage', 'carved'), (A.CARVE,)),
            Entry('duplicates', "Duplicates", 'FINDING_DUPLICATES',
                  ('triage', 'duplicates'), (MODULE_HASH,)),
            Entry('authors', "Document authors", 'FINDING_AUTHOR',
                  ('triage', 'authors'), (MODULE_AUTHORS,)),
            _activity('files'), _activity('recycle'), _activity('usb'),
            _activity('notes'),
        ]),
        ('system', "Programs & system", [
            _activity('programs'), _activity('usage'), _activity('system'),
            _activity('logons'), _activity('network'),
            _activity('antivirus'),
            Entry('persistence', "Persistence", 'PERSISTENCE',
                  ('triage', 'persistence'), (A.PERSISTENCE,), 'warn'),
            Entry('executables', "Executables", 'EXECUTABLE',
                  ('triage', 'executables'), (MODULE_EXECUTABLES,)),
            Entry('ntfs', "NTFS records", 'NTFS', ('triage', 'ntfs'),
                  (A.NTFS,)),
            Entry('registry', "Registry", 'REGISTRY', ('panel', 'registry')),
            _activity('records'),
        ]),
        ('flags', "Analysis results (flags)", [
            Entry('hash:known-bad', "Known bad (hash sets)", 'HASH_SETS',
                  ('triage', 'hash:known-bad'), (A.HASHSETS,), 'bad'),
            Entry('hash:notable', "Notable (hash sets)", 'HASH_SETS',
                  ('triage', 'hash:notable'), (A.HASHSETS,), 'warn'),
            Entry('yara', "YARA matches", 'FINDING_YARA', ('triage', 'yara'),
                  (A.YARA,), 'bad'),
            Entry('sigma', "Sigma detections", 'SIGMA', ('triage', 'sigma'),
                  (A.SIGMA,), 'bad'),
            Entry('keywords', "Keyword hits", 'KEYWORDS',
                  ('triage', 'keywords'), (A.KEYWORDS,), 'warn'),
            Entry('indicators', "Indicators", 'FINDING_INDICATORS',
                  ('triage', 'indicators'), (A.INDEX,)),
            Entry('mismatch', "Type mismatches", 'FINDING_MISMATCH',
                  ('triage', 'mismatch'), (MODULE_MAGIC,), 'warn'),
            Entry('entropy', "High entropy", 'FINDING_ENTROPY',
                  ('triage', 'entropy'), (MODULE_ENTROPY,)),
            Entry('hidden', "Hidden data", 'FINDING_HIDDEN',
                  ('triage', 'hidden'), (MODULE_HIDDEN,), 'warn'),
            Entry('ntfs:timestomp', "Timestomping", 'FINDING_TIMESTOMP',
                  ('triage', 'ntfs:timestomp'), (A.NTFS,), 'warn'),
        ]),
        ('work', "My work", [
            Entry('bookmarks', "Bookmarks", 'BOOKMARK',
                  ('triage', 'bookmarks')),
            Entry('tags', "Tags", 'TAG', ('triage', 'tags')),
            Entry('notes', "Notes", 'TAB_NOTES', ('panel', 'notes')),
        ]),
        ('everything', "Everything", [
            Entry('listing', "All files (Listing)", 'TAB_TREE',
                  ('panel', 'listing')),
            Entry('timeline', "Timeline", 'TIMELINE', ('panel', 'timeline')),
            Entry('search', "Search", 'SEARCH_CONTENT', ('panel', 'search'),
                  (A.INDEX,)),
        ]),
    ]


SECTIONS = _sections()
#: Entries that are always offered, with no count (whole views).
UNCOUNTED = frozenset({'registry', 'listing', 'timeline', 'search'})


def entries():
    return [entry for _key, _title, members in SECTIONS for entry in members]


def entry(key):
    return next((e for e in entries() if e.key == key), None)


# --- counts ---------------------------------------------------------------------

def counts(case, evidence_id=None, index=None, similar=None):
    """{entry key: count} for the case (or one evidence item), as the tabs
    and the tree count them. `index`: the case's SearchIndex (indicators);
    `similar`: the Similar pictures groups the window counted (a job of
    its own), when known."""
    from trace_app.core import geo, hashsets
    from trace_app.core.keywords import term_summary
    summary = case.analysis_summary(evidence_id)
    activity = case.user_activity_summary(evidence_id)
    ntfs = case.ntfs_counts(evidence_id)
    hashed = case.hash_match_counts(evidence_id)
    out = {
        'photos': summary['photos'],
        'similar': similar or 0,
        'thumbnails': case.thumbnail_counts(evidence_id).get('pictures', 0),
        'deleted': sum(case.deleted_counts(evidence_id,
                                           files_only=True).values()),
        'carved': summary['carved'],
        'duplicates': summary['duplicate_groups'],
        'authors': summary['authors'],
        'executables': summary['executables'],
        # Flagged entries, as the Persistence tab counts them (routine
        # ones are listed there on request).
        'persistence': sum(count for grade, count in
                           case.persistence_counts(evidence_id).items()
                           if grade in ('suspicious', 'notable')),
        'ntfs': sum(ntfs.values()),
        'hash:known-bad': hashed.get(hashsets.KNOWN_BAD, 0),
        'hash:notable': hashed.get(hashsets.NOTABLE, 0),
        'yara': len({(f['evidence_id'], f['artifact_ref']) for f in
                     case.findings(evidence_id, 'yara', limit=500000)}),
        'sigma': summary['sigma'],
        'keywords': len(term_summary(case.findings(evidence_id, 'keywords',
                                                   limit=500000))),
        'mismatch': summary['mismatches'],
        'entropy': summary['high_entropy'],
        'hidden': summary['hidden'],
        'ntfs:timestomp': ntfs.get('timestomp', 0),
        'bookmarks': len(case.bookmarks(evidence_id)),
        'tags': len(case.tagged(evidence_id=evidence_id)),
        'notes': len(case.notes(evidence_id)),
    }
    try:
        out['map'] = len(geo.located(case, evidence_id))
    except Exception:
        out['map'] = 0
    try:
        out['conversations'] = len(case.conversations(evidence_id))
    except Exception:
        out['conversations'] = 0
    out['indicators'] = 0
    if index is not None:
        try:
            out['indicators'] = sum(
                index.indicator_summary(evidence_id).values())
        except Exception:
            pass
    from trace_app.core.activity import CATEGORIES
    for category, _label in CATEGORIES:
        out[f'activity:{category}'] = activity.get(category, 0)
    for key in UNCOUNTED:
        out[key] = None
    return out


def states(case, evidence_ids, found, index=None, not_applicable=None):
    """{entry key: state} over the evidence: FOUND when `found` (counts)
    has some; else from the scans that produce it on each item
    (export_readiness.module_states) -- NOT_APPLICABLE where none can run
    (`not_applicable`: {evidence id: {module: why}}), RUNNING, STOPPED
    (cancelled or failed), NOT_RUN, or NONE_FOUND when one finished."""
    module_states = {eid: readiness.module_states(case, eid, index)
                     for eid in evidence_ids}
    ruled = not_applicable or {}
    out = {}
    for item in entries():
        if found.get(item.key):
            out[item.key] = FOUND
            continue
        if item.key in UNCOUNTED:
            out[item.key] = FOUND           # a whole view: always offered
            continue
        if not item.modules:                # the examiner's own, or similar
            out[item.key] = NONE_FOUND
            continue
        seen = []
        for eid in evidence_ids:
            usable = [m for m in item.modules
                      if m not in (ruled.get(eid) or {})]
            if not usable:
                continue
            recorded = [(module_states[eid].get(m) or {}).get('state')
                        for m in usable]
            if readiness.DONE in recorded:
                seen.append(NONE_FOUND)
            elif readiness.RUNNING in recorded:
                seen.append(RUNNING)
            elif any(r in (readiness.CANCELLED, readiness.FAILED)
                     for r in recorded):
                seen.append(STOPPED)
            else:
                seen.append(NOT_RUN)
        out[item.key] = NOT_APPLICABLE if not seen else next(
            state for state in (NONE_FOUND, RUNNING, STOPPED, NOT_RUN)
            if state in seen)
    return out


def missing_modules(found_states, evidence_ids, case, index=None,
                    not_applicable=None):
    """{evidence id: [module]} that would produce the entries not run or
    stopped -- what Run Missing Scans queues."""
    module_states = {eid: readiness.module_states(case, eid, index)
                     for eid in evidence_ids}
    ruled = not_applicable or {}
    out = {}
    for item in entries():
        if found_states.get(item.key) not in (NOT_RUN, STOPPED):
            continue
        for eid in evidence_ids:
            for module in item.modules:
                if module in (ruled.get(eid) or {}):
                    continue
                state = (module_states[eid].get(module) or {}).get('state')
                if state != readiness.DONE and state != readiness.RUNNING:
                    modules = out.setdefault(eid, [])
                    if module not in modules:
                        modules.append(module)
    return out


# --- the overview ---------------------------------------------------------------

def stopped_analyses(case):
    """[(evidence name, files done, files total)] of file analyses that
    stopped before the end -- the line an examiner most needs: a case
    that looks analysed and is 2% analysed."""
    import os
    out = []
    for row in case.evidence():
        state = case.analysis_state(row['id']) or {}
        if state.get('status') in ('cancelled', 'failed') and \
                state.get('files_total'):
            out.append((row.get('display_name') or
                        os.path.basename(row['path']),
                        int(state.get('files_done') or 0),
                        int(state['files_total'])))
    return out


def time_span(case, evidence_id=None):
    """(first, last) UTC time of the users' activity (dates TRACE trusts:
    1980-2100, zoned), or None."""
    where, params = '', []
    if evidence_id is not None:
        where, params = ' AND evidence_id = ?', [evidence_id]
    row = case._db.execute(
        "SELECT min(time_utc), max(time_utc) FROM user_activity WHERE "
        "time_utc >= '1980' AND time_utc < '2100' AND "
        f"COALESCE(time_local, 0) = 0{where}", params).fetchone()
    return (row[0], row[1]) if row and row[0] else None
