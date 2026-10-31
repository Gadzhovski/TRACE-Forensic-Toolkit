"""Which scans an export depends on, and which of them have not run on the
evidence being exported (no Qt).

An export reads what the case holds, so one made before the scans it
draws on have finished is incomplete without saying so. A tester's first
comparison of TRACE's Project VICS export with AXIOM's and X-Ways' was
made with no carving run: 2,488 carved pictures were missing from it for
that reason alone. Each export dialog asks `gaps()` and shows what it
finds (ui/widgets/readiness_banner), with a way to run what is missing
before the export.

What a module did is read from the record its job leaves:
`Case.module_completions` (every module job, written by
core/background.child_main), and for cases older than that table the
state each module kept of its own (analysis_state, carving_state,
user_activity_state, ntfs_state, the index's index_state) or, for the
rest, whether it left any rows.
"""

from trace_app.core.analysis import (MODULE_AUTHORS, MODULE_ENTROPY,
                                     MODULE_EXECUTABLES, MODULE_HASH,
                                     MODULE_HIDDEN, MODULE_MAGIC,
                                     MODULE_PHOTO)

# The module keys of ui/dialogs/analysis_modules.py (core may not import
# ui; tests/test_export_readiness.py holds the two equal).
CARVE = 'carve'
INDEX = 'index'
INDEX_FREE = 'index_free'
ACTIVITY = 'activity'
NTFS = 'ntfs'
FSTIMES = 'fstimes'
HASHSETS = 'hashsets'
YARA = 'yara'
SIGMA = 'sigma'
PERSISTENCE = 'persistence'
KEYWORDS = 'keywords'
THUMBNAILS = 'thumbnails'
DELETED = 'deleted'

#: The background jobs (core/background.JOBS kinds) whose completion is
#: recorded per evidence. 'analysis' stands for the file modules it was
#: given (analysis.MODULES).
RECORDED_JOBS = ('analysis', CARVE, INDEX, INDEX_FREE, ACTIVITY, NTFS,
                 FSTIMES, HASHSETS, YARA, SIGMA, PERSISTENCE, KEYWORDS,
                 THUMBNAILS, DELETED)

#: The Analysis Modules dialog's Full profile: every module that reads
#: the evidence itself.
FULL = frozenset({MODULE_MAGIC, MODULE_HIDDEN, MODULE_PHOTO,
                  MODULE_AUTHORS, ACTIVITY, NTFS, FSTIMES, PERSISTENCE,
                  THUMBNAILS, DELETED, SIGMA, MODULE_HASH,
                  MODULE_EXECUTABLES, INDEX, HASHSETS, YARA, KEYWORDS,
                  MODULE_ENTROPY, INDEX_FREE, CARVE})

DONE, RUNNING, CANCELLED, FAILED, NOT_RUN, LESS = (
    'done', 'running', 'cancelled', 'failed', 'not run', 'ran with less')

def media_carve_types():
    """The carved types a media export wants: every picture and video."""
    from trace_app.core.carving import CARVE_CATEGORIES
    return frozenset(t.lower() for category in ('Pictures', 'Video')
                     for t in CARVE_CATEGORIES[category])


class Need:
    """One module an export draws on. `why` says what the export lacks
    without it; `wants` (optional) checks the settings the module ran
    with and returns what it left out, or ''."""

    def __init__(self, module, why, wants=None, one_of=None):
        self.module, self.why, self.wants = module, why, wants
        #: Modules any one of which serves (NTFS's own times or the other
        #: file systems'): the need is met when one has run.
        self.one_of = tuple(one_of or (module,))


def _carve_wants(settings):
    types = {t.lower() for t in settings.get('types') or ()}
    missing = sorted(media_carve_types() - types)
    if missing:
        return ("not carved for " + ', '.join(t.upper() for t in missing[:6])
                + (f" and {len(missing) - 6} more" if len(missing) > 6
                   else ''))
    return ''


_TIMES = ("file-system times (created, modified, accessed) are missing")

NEEDS = {
    'vics': [
        Need(CARVE, "pictures and videos carved from unallocated space "
                    "will be missing", _carve_wants)],
    'dfxml': [
        Need(MODULE_MAGIC, "files will have no type found by content"),
        Need(MODULE_HASH, "files will have no hashes"),
        Need(NTFS, _TIMES, one_of=(NTFS, FSTIMES))],
    'case': [
        Need(MODULE_MAGIC, "files will have no type found by content"),
        Need(MODULE_HASH, "files will have no hashes"),
        Need(NTFS, _TIMES, one_of=(NTFS, FSTIMES)),
        Need(MODULE_HIDDEN, "hidden-data findings will be missing"),
        Need(MODULE_PHOTO, "photo findings (EXIF, GPS) will be missing")],
    'timeline': [
        Need(NTFS, _TIMES, one_of=(NTFS, FSTIMES)),
        Need(ACTIVITY, "user activity (programs, browsing, logons) will be "
                       "missing"),
        Need(MODULE_PHOTO, "photo and video times will be missing"),
        Need(MODULE_AUTHORS, "document times will be missing"),
        Need(SIGMA, "Sigma detections will be missing"),
        Need(CARVE, "carved files will be missing")],
}
NEEDS['report'] = [Need(module, "its findings will be missing")
                   for module in sorted(FULL)]

#: What each export is called in the notice.
EXPORT_NAMES = {'vics': "Project VICS", 'dfxml': "DFXML",
                'case': "CASE/UCO", 'timeline': "timeline export",
                'report': "report"}


class Gap:
    __slots__ = ('evidence', 'evidence_id', 'module', 'state', 'why')

    def __init__(self, evidence, evidence_id, module, state, why):
        self.evidence, self.evidence_id = evidence, evidence_id
        self.module, self.state, self.why = module, state, why

    def __repr__(self):
        return (f"Gap({self.evidence!r}, {self.module!r}, {self.state!r}, "
                f"{self.why!r})")


def gaps(kind, evidence, states, not_applicable=None):
    """[Gap] for export `kind` over `evidence` ([(id or key, name)]):
    `states` is {id: module_states(...)}, `not_applicable` {id: {module:
    why}} (evidence_profile.not_applicable) -- a module that cannot find
    anything in an image is never asked for."""
    out = []
    for key, name in evidence:
        mine = states.get(key) or {}
        ruled_out = (not_applicable or {}).get(key) or {}
        for need in NEEDS[kind]:
            choices = [m for m in need.one_of if m not in ruled_out]
            if not choices:
                continue
            found = [mine.get(m) for m in choices]
            done = [s for s in found if s and s['state'] == DONE]
            if done:
                left_out = need.wants(done[0].get('settings') or {}) \
                    if need.wants else ''
                if left_out:
                    out.append(Gap(name, key, choices[0], LESS,
                                   f"{left_out}: {need.why}"))
                continue
            state = next((s['state'] for s in found if s), NOT_RUN)
            out.append(Gap(name, key, choices[0], state, need.why))
    return out


def missing_modules(found):
    """{evidence id: [module]} to run so the gaps close (running and
    'ran with less' carving included: it is run again with every type)."""
    out = {}
    for gap in found:
        if gap.state == RUNNING:
            continue
        modules = out.setdefault(gap.evidence_id, [])
        if gap.module not in modules:
            modules.append(gap.module)
    return out


# --- what has run --------------------------------------------------------------

def _state(status):
    return {'done': DONE, 'running': RUNNING, 'cancelled': CANCELLED,
            'failed': FAILED}.get((status or '').lower(), NOT_RUN)


def module_states(case, evidence_id, index=None):
    """{module: {'state', 'settings'}} for one evidence item of `case`
    (`index`: its SearchIndex, for the index's own state)."""
    out = {}
    recorded = case.module_completions(evidence_id)
    for module, row in recorded.items():
        if module == 'analysis':
            continue
        out[module] = {'state': _state(row['status']),
                       'settings': row.get('settings') or {}}
    analysis = recorded.get('analysis')
    if analysis is not None:
        status = analysis['status']
        modules = (analysis.get('settings') or {}).get('modules') or []
    else:
        legacy = case.analysis_state(evidence_id) or {}
        status = legacy.get('status')
        modules = [m for m in (legacy.get('modules') or '').split(',') if m]
    for module in modules:
        out[module] = {'state': _state(status), 'settings': {}}
    _legacy(case, evidence_id, index, out)
    return out


def _legacy(case, evidence_id, index, out):
    """What older cases recorded before module_completions existed."""
    if CARVE not in out:
        state = case.carving_state(evidence_id)
        if state:
            out[CARVE] = {'state': _state(state['status']), 'settings': {
                'types': [t for t in (state.get('types') or '').split(',')
                          if t],
                'source': 'unallocated' if state.get('unallocated_only')
                else 'image'}}
    for module, reader in ((ACTIVITY, case.user_activity_state),
                           (NTFS, case.ntfs_state)):
        if module not in out:
            state = reader(evidence_id)
            if state:
                out[module] = {'state': _state(state.get('status')),
                               'settings': {}}
    if index is not None:
        state = index.state(evidence_id) or {}
        if INDEX not in out and state.get('status'):
            out[INDEX] = {'state': _state(state['status']), 'settings': {}}
        if INDEX_FREE not in out and state.get('free_status'):
            out[INDEX_FREE] = {'state': _state(state['free_status']),
                               'settings': {}}
    for module in (DELETED, THUMBNAILS, PERSISTENCE, FSTIMES, YARA, SIGMA,
                   KEYWORDS, HASHSETS):
        if module not in out and case.module_left_rows(evidence_id, module):
            out[module] = {'state': DONE, 'settings': {}}
