"""Where an external tool's results go, by how TRACE sorted them (no Qt).

core/modules/routes.py gives every artifact a role -- evidence (calls,
messages, browsing, places...), other records (what a tool read that is
neither), telemetry (log lines, power and health samples). The case
setting 'module_destinations' says, per role, which of TRACE's views take
its rows:

* activity -- evidence: an Activity row per record (Triage's
  Conversations and Map read those too), linked with TRACE's own reading
  of the same record; other / telemetry: the Activity ▸ Others tabs,
  which read the tool's database live (nothing copied);
* timeline -- a Timeline event per timestamp of each row (case.db
  module_events); an evidence row's own time is its Activity row's event;
* search -- each row's text in the case's search index (search.db), so
  Search and the Indicators find its words, phones, addresses;
* report -- evidence: the tool's records in the report's Activity and
  Conversations sections; other / telemetry: listed among the run's
  artifacts in the report's External modules section.

Timeline and Search copy rows into the case, which is what makes a large
extraction slow (a sysdiagnose's unified log is millions of rows); the
tool's own database always keeps every row, browsed in the Modules tab
whatever is chosen here. Activity rows of evidence are copied too, Others
are not.
"""

EVIDENCE, OTHER, TELEMETRY = 'evidence', 'other', 'telemetry'

#: (role, label, what it holds) in the order the settings show them.
ROLES = (
    (EVIDENCE, "Evidence",
     "Calls, messages, web history, places, accounts, installed apps -- "
     "what TRACE's own readers also find."),
    (OTHER, "Other records",
     "Everything else a tool read that is not device telemetry: app "
     "settings, caches, databases TRACE has no reader for."),
    (TELEMETRY, "Device telemetry",
     "Log lines, battery, power and health samples, network usage "
     "counters -- usually most of a phone's or Mac's rows."),
)
ROLE_KEYS = tuple(key for key, _l, _h in ROLES)

#: (place, label) in the order the settings show them.
PLACES = (
    ('activity', "Activity & Triage"),
    ('timeline', "Timeline"),
    ('search', "Search"),
    ('report', "Report"),
)
PLACE_KEYS = tuple(key for key, _l in PLACES)
#: Places that copy rows into the case when on.
COPIED = ('timeline', 'search')

DEFAULT = {
    EVIDENCE: ['activity', 'timeline', 'search', 'report'],
    OTHER: ['activity', 'timeline', 'search', 'report'],
    TELEMETRY: ['activity'],
}

#: What the settings had before telemetry stayed out of the Timeline and
#: Search -- the state of a case imported before then.
EVERYWHERE = {role: list(PLACE_KEYS) for role in ROLE_KEYS}


def normalise(value):
    """{role: [places]} with every role, known places only, in order; a
    missing or broken value is the default."""
    if not isinstance(value, dict):
        value = DEFAULT
    out = {}
    for role in ROLE_KEYS:
        given = value.get(role, DEFAULT[role])
        if not isinstance(given, (list, tuple, set)):
            given = DEFAULT[role]
        out[role] = [place for place in PLACE_KEYS if place in given]
    return out


def current():
    """The case's choice, as last applied in this process."""
    from trace_app.core import settings
    return normalise(settings.current('module_destinations'))


def places(role, value=None):
    """The places a role's rows go to."""
    value = normalise(value) if value is not None else current()
    return set(value.get(role_key(role), ()))


def role_key(role):
    """A stored artifact's role as one of ROLES: one not sorted yet (an
    older case, or the moment before the bridge ran) counts as other."""
    return role if role in ROLE_KEYS else OTHER


def role_of(artifact):
    return role_key(artifact.get('role'))


def goes_to(artifact, place, value=None):
    return place in places(role_of(artifact), value)


def describe(value):
    """One line per role, for the audit trail and the report's methods."""
    value = normalise(value)
    labels = dict(PLACES)
    return [f"{label}: " + (', '.join(labels[p] for p in value[role])
                            or 'the Modules tab only')
            for role, label, _h in ROLES]


def changed_places(old, new):
    """{place: set of roles whose choice of it changed}."""
    old, new = normalise(old), normalise(new)
    out = {}
    for role in ROLE_KEYS:
        for place in set(old[role]) ^ set(new[role]):
            out.setdefault(place, set()).add(role)
    return out
