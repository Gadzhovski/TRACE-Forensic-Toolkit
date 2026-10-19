"""Where a LEAPP artifact's rows belong in TRACE (no Qt).

A LEAPP reports hundreds of artifacts; LAVA says what each is called and
which columns hold dates or media, and -- for 18 or so -- that it is a
conversation. Nothing says which are evidence an examiner reads (calls,
messages, browser history, places, accounts...) and which are device
telemetry (unified log lines, power and health samples, cache entries) --
on a real iPhone the second is millions of rows to the first's thousands.
`route()` decides, in this order:

1. the examiner's override for the case (`overrides`, from the Modules
   tab: evidence / telemetry / default);
2. the tool's map (resources/leapp_maps/<tool>.json, core/modules/maps),
   by the tool's stable `artifact_key`: a record type with typed fields,
   or telemetry, or other -- checked against the tool's real output;
3. a conversation view (the tool says so);
4. for what no map names (RLEAPP, VLEAPP, DLEAPP; artifacts a later
   release adds): telemetry by LAVA category, rules on the artifact's
   name (calls, contacts, messages, browser history, searches, Wi-Fi,
   accounts, installed apps), latitude/longitude columns;
5. 'other': shown in the Modules tab and on the Timeline, not in Activity.

An evidence route names the Activity category, the `what` of its rows and,
where the columns' names do not say it, which columns are the time, the
subject or the other party (core/modules/bridge.py reads them). Bump
`ROUTES_VERSION` when this table changes: old runs are sorted again when a
case opens.
"""

import re
from dataclasses import dataclass, field

#: 4: the tools' maps (resources/leapp_maps, core/modules/maps) -- typed
#: fields under TRACE's own keys. 5: how each was sorted is kept
#: (module_artifacts.sorted_by, the run's accounting). 6: iLEAPP's map
#: replaces the table that was here.
ROUTES_VERSION = 6
EVIDENCE, TELEMETRY, OTHER = 'evidence', 'telemetry', 'other'
ROLES = (EVIDENCE, TELEMETRY, OTHER)


@dataclass(frozen=True)
class Route:
    role: str
    category: str = ''          # the Activity category (evidence only)
    what: str = ''              # the rows' 'what'; '{direction}' filled in
    time: str = ''              # column of the row's time ('' = the first
    #                             date column)
    subject: tuple = ()         # columns tried for the subject, in order
    party: str = ''             # column of the other party (calls)
    direction: str = ''         # column saying in / out
    conversation: bool = False  # read through core/modules/chats
    why: str = ''               # how it was decided, for the Modules tab
    #: The tool's map entry (core/modules/maps) when its map names the
    #: artifact: the record type and its typed columns.
    mapping: dict = field(default=None, compare=False, hash=False)
    #: How it was sorted, for the accounting: 'map', 'conversation',
    #: 'name', 'columns', 'list'
    #: (telemetry/other lists), 'override', 'none'.
    sorted_by: str = ''


def _e(category, what, time='', subject=(), party='', direction=''):
    return Route(EVIDENCE, category, what, time, tuple(subject), party,
                 direction)


#: LAVA categories whose rows are telemetry -- samples taken by the device,
#: not things a person did that an examiner reads one by one -- for an
#: artifact no map names (a tool without a map, a newer release's).
_TELEMETRY_CATEGORIES = {'unified logs', 'powerlog', 'health',
                         'database metadata', 'cache data', 'images',
                         'network usage', 'ios diagnostic reports',
                         'sysdiagnose', 'cloudkit', 'knowledgec'}

#: Name rules for any tool: (regex on the artifact's name, route).
_NAMES = (
    (r'\bcall (log|history)|\bcalls?\b', _e('communication',
                                             'Call {direction}')),
    (r'\bcontacts?\b|address book|phone ?book', _e('communication',
                                                    'Contact')),
    # Messages -- not their attachments, users, settings or a database's
    # leftovers (names from iLEAPP 2026.4: 'IMO HD Chat - Key Values',
    # 'Twitter X - Direct Message Users', 'iOS Message Retention').
    (r'^(?!.*\b(attachments?|media|missing|strings|rowids?|wal|users?|'
     r'key ?values?|retention|settings|preferences|config\w*)\b).*'
     r'\b(messages?|chats?|sms|mms|imessages?)\b',
     _e('communication', 'Message {direction}', '',
        ('message', 'body', 'text', 'content', 'message_body',
         'message_text'))),
    (r'\b(browser|chrome|firefox|edge|safari|brave|opera)\b.*\bhistory\b|'
     r'\bweb history\b', _e('browser', 'Visited')),
    (r'\bdownloads?\b', _e('downloads', 'Downloaded')),
    (r'\bsearch(es| terms| history)\b|\bsearched\b', _e('searches',
                                                         'Searched')),
    (r'\bbookmarks?\b', _e('browser', 'Bookmark')),
    (r'\bwi-?fi\b.*\b(networks?|profiles?|connections?)\b',
     _e('network', 'Wi-Fi network')),
    (r'\bbluetooth\b', _e('network', 'Bluetooth device')),
    (r'\baccounts?\b', _e('accounts', 'Account')),
    (r'\binstalled (apps|applications|packages)\b|\bapp installs?\b',
     _e('programs', 'Installed')),
    (r'\bnotes?\b', _e('notes', 'Note')),
    (r'\bcalendar\b', _e('calendar', 'Calendar event')),
)
_LATITUDE = re.compile(r'(^|_)lat(itude)?\d*($|_)', re.I)
_LONGITUDE = re.compile(r'(^|_)(lon|lng|long|longitude)\d*($|_)', re.I)


def has_location(columns):
    names = [c['name'] for c in columns]
    return any(_LATITUDE.search(n) for n in names) and \
        any(_LONGITUDE.search(n) for n in names)


def default(tool, artifact):
    """TRACE's route, before any override."""
    key = artifact.get('artifact_key') or artifact.get('tablename') or ''
    name = artifact.get('name') or ''
    category = (artifact.get('category') or '').strip().lower()
    columns = artifact.get('columns') or []
    # The tool's map first (resources/leapp_maps): typed fields.
    from trace_app.core.modules import maps, record_types
    role, mapped = maps.entry(tool, key)
    if role == EVIDENCE:
        kind = mapped['type']
        category, what, _fields = record_types.TYPES[kind]
        if kind == 'event':
            category, what = mapped.get('category'), mapped.get('what')
        elif mapped.get('what') and kind not in ('call', 'message', 'email'):
            what = mapped['what']
        if kind in ('message', 'email') and artifact.get('conversation'):
            # The tool's own conversation view threads it best.
            return Route(EVIDENCE, 'communication', '', conversation=True,
                         why=f"{tool}'s map ({kind}), read through its "
                             f"conversation view", mapping=mapped,
                         sorted_by='map')
        return Route(EVIDENCE, category, what, mapped.get('time') or '',
                     why=f"{tool}'s map: {kind}", mapping=mapped,
                     sorted_by='map')
    if role == TELEMETRY:
        return Route(TELEMETRY, why=f"device telemetry ({tool}'s map)",
                     sorted_by='list')
    if role == OTHER:
        return Route(OTHER, why=f"not an event ({tool}'s map): browse it "
                                f"in the Modules tab", sorted_by='list')
    if artifact.get('conversation'):
        return Route(EVIDENCE, 'communication', '', conversation=True,
                     why='a conversation view (the tool says so)',
                     sorted_by='conversation')
    if category in _TELEMETRY_CATEGORIES:
        return Route(TELEMETRY, why=f"device telemetry "
                                    f"({artifact.get('category')})",
                     sorted_by='list')
    for pattern, route in _NAMES:
        if re.search(pattern, name, re.I):
            return _with(route, f'its name ({name})', 'name')
    if has_location(columns):
        return Route(EVIDENCE, 'locations', 'Location',
                     why='latitude and longitude columns',
                     sorted_by='columns')
    return Route(OTHER, why='not sorted: browse it in the Modules tab',
                 sorted_by='none')


#: How an artifact was sorted (Route.sorted_by), in words, in the order
#: the accounting lists them.
SORTED_WORDS = (
    ('map', "the tool's map: typed fields, as TRACE's own records"),
    ('conversation', "the tool's conversation view"),
    ('list', "listed as telemetry or other (the tool's map or TRACE's)"),
    ('name', "its name only (not in the tool's map: check it)"),
    ('columns', "its latitude/longitude columns only (not in the map)"),
    ('override', "the examiner's choice"),
    ('none', "nothing: no map entry, no rule (other)"),
    ('', "not sorted yet"),
)


def accounting(artifacts):
    """A run's artifacts by how they were sorted: [{'sorted_by', 'words',
    'role', 'artifacts', 'rows', 'names'}] in SORTED_WORDS order, one per
    (sorted_by, role) present. Superseded copies are counted apart
    ('superseded'), as their rows show under the newer run."""
    groups = {}
    for artifact in artifacts:
        how = artifact.get('sorted_by') or ''
        role = 'superseded' if artifact.get('superseded_by') else \
            (artifact.get('role') or '')
        group = groups.setdefault((how, role), {
            'sorted_by': how, 'role': role, 'artifacts': 0, 'rows': 0,
            'names': []})
        group['artifacts'] += 1
        rows = artifact.get('row_count')
        if rows is None:
            rows = artifact.get('record_count')
        group['rows'] += rows or 0
        group['names'].append(artifact.get('name') or '')
    order = [key for key, _words in SORTED_WORDS]
    words = dict(SORTED_WORDS)
    out = []
    for (how, role), group in sorted(
            groups.items(), key=lambda kv: (
                order.index(kv[0][0]) if kv[0][0] in order else len(order),
                ROLES.index(kv[0][1]) if kv[0][1] in ROLES else len(ROLES))):
        group['words'] = words.get(how, how)
        group['names'].sort(key=str.lower)
        out.append(group)
    return out


def _with(route, why, sorted_by=''):
    return Route(route.role, route.category, route.what, route.time,
                 route.subject, route.party, route.direction,
                 route.conversation, why, sorted_by=sorted_by)


def route(tool, artifact, overrides=None):
    """The artifact's Route: the examiner's override, else TRACE's."""
    found = default(tool, artifact)
    wanted = (overrides or {}).get(override_key(tool, artifact))
    if wanted == TELEMETRY:
        return Route(TELEMETRY, why='the examiner: telemetry',
                     sorted_by='override')
    if wanted == OTHER:
        return Route(OTHER, why='the examiner: not evidence',
                     sorted_by='override')
    if wanted == EVIDENCE and found.role != EVIDENCE:
        # No table entry: a generic one, its rows under 'Other records'.
        return Route(EVIDENCE, 'records', artifact.get('name') or 'Record',
                     why='the examiner: evidence', sorted_by='override')
    return found


def override_key(tool, artifact):
    return f"{(tool or '').lower()}:" + (artifact.get('artifact_key') or
                                         artifact.get('tablename') or '')
