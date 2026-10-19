"""A LEAPP run's evidence, as TRACE's own activity (no Qt).

`bridge_run(case, run_id)` reads a completed run's LAVA database (read
only) and, artifact by artifact as core/modules/routes.py routes it:

* evidence -> `user_activity` rows in `activity.record`'s shape, each
  naming its reader (the tool) and pointing at its LAVA row
  (`make_module_ref`): the Activity tab, Triage (Conversations, Map), the
  Timeline, the report and the search all take them like TRACE's own;
* every artifact's Timeline events tagged with its role; an evidence row's
  own time is its Activity row, so that event is tagged 'bridged' (the
  Timeline never shows it twice);
* the same artifact read by an older run of the same tool on the same
  evidence -- the same rows, by `content_sha256` -- leaves the older run's
  rows and events out ('superseded'); both stay in the Modules tab;
* then the evidence's readings are linked across readers
  (`Case.relink_matches`: one record read by TRACE and by iLEAPP shows
  once, naming both).

Idempotent: an artifact is bridged again only when ROUTES_VERSION or the
examiner's override for it changes. Nothing in the tool's output is
written.
"""

import hashlib
import json
import logging
import os
import re
import sqlite3

from trace_app.core.case import make_module_ref
from trace_app.core.modules import chats, lava, routes

logger = logging.getLogger('TRACE.Modules')

#: Columns never copied into a row's details (secrets a tool reads):
#: aLEAPP's Wi-Fi hotspot 'passphrase', a Bluetooth pairing 'link_key',
#: Snapchat's My Eyes Only 'master_key' among them.
_SECRET = re.compile(r'password|passcode|passphrase|psk|secret|token|'
                     r'wrapped_key|key_material|private_key|master_key|'
                     r'link_key|cookie_value', re.I)
#: Markup some tools put in values (aLEAPP's call type: 'Missed <i
#: data-feather=...></i>').
_TAGS = re.compile(r'<[^>]+>')
_PREFERRED_SUBJECT = ('title', 'name', 'display_name', 'subject', 'url',
                      'phone_number', 'number', 'ssid', 'search_term',
                      'application', 'bundle_id', 'app_name', 'message',
                      'address', 'username', 'filename', 'path')
_DATE_TEXT = re.compile(r'^\d{4}-\d\d-\d\d[ T]\d\d:\d\d(:\d\d)?')
_OUT = re.compile(r'out|sent|made|orig|dial', re.I)
_IN = re.compile(r'in|rec|answer', re.I)
_MISSED = re.compile(r'miss|reject|declin', re.I)
MAX_DETAIL = 40
MAX_VALUE = 400


class BridgeCancelled(Exception):
    pass


def _text(value):
    if value is None:
        return ''
    if isinstance(value, bytes):
        return f'<{len(value)} bytes>'
    return str(value)


def _direction(value):
    """'made' / 'received' / 'missed' / '' from a tool's direction value."""
    text = _text(value).strip()
    if not text:
        return ''
    if _MISSED.search(text):
        return 'missed'
    if text in ('1', 'true', 'True') or _OUT.search(text):
        return 'made'
    if text in ('0', 'false', 'False') or _IN.search(text):
        return 'received'
    return ''


#: Columns naming the other party of a message or call, when the route
#: does not say (a name rule matched): the first such column.
_PARTY = re.compile(r'(^|_)(phone(_number)?|number|address|recipients?|'
                    r'sender|from|to|contact|remote(_party)?|other_party|'
                    r'participants?|handle)($|_)', re.I)


#: Artifact names whose rows are files (media, photos, downloads): an
#: unplaced row of one is a file record, not a location.
_FILE_LIKE = re.compile(r'\b(files?|media|photos?|pictures?|images?|'
                        r'gallery|videos?|downloads?|storage)\b', re.I)


def _mapped(mapping, columns, types, values, media, detail):
    """(category, what, subject, detail) of a row its tool's map names
    (core/modules/maps): the typed fields under TRACE's own keys
    (core/modules/record_types), over the tool's other columns, which
    stay in the detail as the tool labels them."""
    from trace_app.core.modules import record_types
    by_name = {c['name']: c for c in columns}
    fields = {}
    for field, wanted in (mapping.get('fields') or {}).items():
        for column in (wanted if isinstance(wanted, list) else [wanted]):
            if _SECRET.search(column):
                continue                    # never, even when mapped
            value = values.get(column)
            if value in (None, ''):
                continue
            if types.get(column) == 'datetime':
                text = lava.utc_text(value)
            elif types.get(column) == 'media':
                text = lava.display(by_name.get(column, {'name': column,
                                                         'type': 'media'}),
                                    value, media)
            else:
                text = _TAGS.sub('', _text(value)).strip()
            if text:
                fields[field] = text
                break
    if mapping.get('app') and 'app' not in fields and \
            'app' in record_types.TYPES[mapping['type']][2]:
        fields['app'] = mapping['app']
    category, what, subject, typed = record_types.build(
        mapping['type'], fields, mapping.get('directions'), mapping)
    detail = dict(detail)
    # The guesses the generic reading made (a party column, a direction)
    # give way to the map's: never a 'to' from one and a 'from' from the
    # other on one message.
    for key in ('to', 'from', 'direction', 'phone', 'email'):
        detail.pop(key, None)
    detail.update(typed)
    if mapping.get('app') and not detail.get('app'):
        detail['app'] = mapping['app']
    return category, what, subject, detail


def _party_column(columns):
    return next((c['name'] for c in columns
                 if _PARTY.search(c['name']) and
                 c.get('type') not in ('datetime', 'media')), '')


def _location(columns, values):
    """(latitude, longitude) from the first pair of lat/long columns."""
    names = [c['name'] for c in columns]
    lats = [n for n in names if routes._LATITUDE.search(n)]
    lons = [n for n in names if routes._LONGITUDE.search(n)]
    for lat_name, lon_name in zip(lats, lons):
        try:
            latitude = float(values.get(lat_name))
            longitude = float(values.get(lon_name))
        except (TypeError, ValueError):
            continue
        if (latitude, longitude) != (0.0, 0.0) and \
                -90 <= latitude <= 90 and -180 <= longitude <= 180:
            return latitude, longitude
    return None


def _time(route, columns, values):
    """(time text, local?) of a row: the route's column, else the first
    date column. A date the tool stored as text (no zone said) is kept as
    local wall-clock time, never shifted."""
    types = {c['name']: c.get('type') for c in columns}
    name = route.time or next((c['name'] for c in columns
                               if c.get('type') == 'datetime'), '')
    if not name:
        return None, False, ''
    value = values.get(name)
    if value in (None, ''):
        return None, False, name
    if types.get(name) == 'datetime':
        text = lava.utc_text(value)
        return (text if text[:4].isdigit() and text[:4] > '1970'
                else None), False, name
    text = _text(value).strip()
    if _DATE_TEXT.match(text):
        return text.replace('T', ' ')[:26], True, name
    return None, False, name


def artifact_rows(connection, media, artifact, route, run_id, tool,
                  report, limit):
    """`activity.record`-shaped dicts for an evidence artifact's rows."""
    if route.conversation:
        view = artifact.get('conversation') or {}
        for row in chats._artifact_rows(
                connection, media, artifact, view, report, run_id, None,
                tool, artifact.get('name') or ''):
            yield {'category': 'communication', 'source': row['source'],
                   'time': (row['time_utc'] or '').replace('T', ' ') or None,
                   'local': False, 'what': row['what'],
                   'subject': row['subject'], 'user': '',
                   'detail': row['detail'], 'path': row['source_path'],
                   'ref': row['source_ref']}
        return
    columns = artifact['columns']
    labels = {c['name']: c.get('label') or c['name'] for c in columns}
    types = {c['name']: c.get('type') for c in columns}
    source = artifact.get('category') or artifact.get('name') or tool
    for count, (rowid, values) in enumerate(lava.iter_rows(connection,
                                                           artifact)):
        if limit and count >= limit:
            break
        when, local, time_column = _time(route, columns, values)
        detail = {}
        for column in columns:
            name = column['name']
            if name == time_column or _SECRET.search(name):
                continue
            value = values.get(name)
            if value in (None, ''):
                continue
            if types.get(name) == 'media':
                value = lava.display(column, value, media)
            elif types.get(name) == 'datetime':
                value = lava.utc_text(value)
            text = _text(value)
            if len(text) > MAX_VALUE:
                text = text[:MAX_VALUE] + '…'
            detail[labels[name]] = text
            if len(detail) >= MAX_DETAIL:
                break
        detail['module'] = f"{tool} · {artifact.get('name') or ''}"
        url = next((values.get(n) for n in ('url', 'page_url', 'request_url',
                                            'content_url') if values.get(n)),
                   None)
        if url:
            detail['url'] = _text(url)
        place = _location(columns, values)
        if place is not None:
            detail['latitude'], detail['longitude'] = place
        subject = ' · '.join(_text(values.get(n)).strip()
                             for n in route.subject
                             if _text(values.get(n)).strip())
        if not subject:
            subject = next((_text(values.get(n)).strip()
                            for n in _PREFERRED_SUBJECT
                            if _text(values.get(n)).strip()), '')
        what = route.what or artifact.get('name') or 'Record'
        direction = ''
        if '{direction}' in what or route.direction:
            column = route.direction or next(
                (c['name'] for c in columns if 'direction' in c['name']), '')
            direction = _direction(values.get(column)) if column else ''
            # A call is made, a message sent.
            word = 'sent' if direction == 'made' and \
                what.startswith('Message') else direction
            what = what.replace('{direction}', word).strip()
        for placeholder in re.findall(r'\{(\w+)\}', what):
            what = what.replace('{' + placeholder + '}',
                                _text(values.get(placeholder)) or '').strip()
        if route.category == 'communication':
            if direction:
                detail['direction'] = 'sent' if direction == 'made' \
                    else 'received'
            party_column = route.party or _party_column(columns)
            if party_column and values.get(party_column):
                party = _text(values.get(party_column))
                detail['to' if direction == 'made' else 'from'] = party
            if what == 'Contact':
                phones = [_text(v) for n, v in values.items()
                          if v and 'phone' in n]
                mails = [_text(v) for n, v in values.items()
                         if v and 'email' in n]
                if phones:
                    detail['phone'] = ', '.join(phones)
                if mails:
                    detail['email'] = ', '.join(mails)
        category = route.category
        source_name = source
        if route.mapping is not None:
            category, what, subject, detail = _mapped(
                route.mapping, columns, types, values, media, detail)
            source_name = route.mapping.get('app') or source
        if category == 'locations' and place is None:
            # A row of a location artifact with no position is not a
            # place: aLEAPP's 'Emulated Storage Metadata - Files' has
            # latitude/longitude columns and 260 rows, none placed; Google
            # Photos 240, 32 placed. Activity said 627 locations beside
            # the Map's 63.
            category = 'files' if _FILE_LIKE.search(
                artifact.get('name') or '') else 'records'
            what = artifact.get('name') or what
        yield {'category': category, 'source': source_name,
               'time': when, 'local': bool(local and when), 'what': what,
               'subject': subject, 'user': '', 'detail': detail,
               'path': lava.source_path(artifact, values, media),
               'ref': make_module_ref(run_id, artifact['tablename'], rowid)}


def content_hash(connection, artifact, limit):
    """SHA-256 of an artifact's rows (values in rowid order), or None for
    one past `limit` (not imported: nothing to de-duplicate)."""
    if limit and (artifact.get('record_count') or 0) > limit:
        return None
    digest = hashlib.sha256()
    digest.update(json.dumps([c['name'] for c in artifact['columns']])
                  .encode())
    for _rowid, values in lava.iter_rows(connection, artifact):
        digest.update(json.dumps(values, sort_keys=True,
                                 default=_text).encode('utf-8', 'replace'))
    return digest.hexdigest()


def _primary_label(route, artifact):
    """The label of the event that is an evidence row's own time -- its
    Activity row's event, so the Timeline shows it once."""
    if not route.conversation:
        _when, _local, column = _time(route, artifact['columns'], {})
        name = column
    else:
        name = (artifact.get('conversation') or {}).get('timeColumn')
    return next((c.get('label') or c['name'] for c in artifact['columns']
                 if c['name'] == name), '')


def tag_events(case, run, artifact, stored, overrides=None):
    """Tag an artifact's Timeline events as its stored sorting says
    (role; 'superseded'; 'bridged' for an evidence row's own time while
    its Activity rows exist) -- for events added after the bridge ran."""
    from trace_app.core.modules import destinations
    if overrides is None:
        overrides = case.setting('module_routes') or {}
    role = stored.get('role') or routes.route(run['tool'], artifact,
                                              overrides).role
    if stored.get('superseded_by'):
        case.set_module_event_kind(stored['id'], 'superseded',
                                   artifact['name'], '')
        return
    label = ''
    if role == routes.EVIDENCE and destinations.goes_to(stored, 'activity'):
        label = _primary_label(routes.route(run['tool'], artifact,
                                            overrides), artifact)
    case.set_module_event_kind(stored['id'], role, artifact['name'], label)


def bridge_run(case, run_id, overrides=None, only=None, force=False,
               progress=None, should_stop=None, limit=250_000, relink=True):
    """Sort a completed run's artifacts (see the module docstring).
    `only`: artifact ids to do (an override changed); `force`: redo all.
    Evidence becomes Activity rows only while the case sends evidence
    there (core/modules/destinations). `relink=False` leaves linking the
    readings to the caller (once, after several runs).
    Returns {'rows', 'evidence', 'telemetry', 'other', 'superseded'}."""
    from trace_app.core.modules import destinations
    run = case.module_run(run_id)
    summary = {'rows': 0, 'evidence': 0, 'telemetry': 0, 'other': 0,
               'superseded': 0, 'artifacts': 0}
    if run is None or run['status'] != 'complete':
        return summary
    report = os.path.join(run['path'], 'report')
    try:
        info = {a['tablename']: a for a in lava.load(report)['artifacts']}
        connection = lava.connect(report)
    except (lava.LavaError, OSError, ValueError, sqlite3.Error) as exc:
        logger.warning("Run %s not sorted into Activity: %s", run_id, exc)
        return summary
    if overrides is None:
        overrides = case.setting('module_routes') or {}
    to_activity = 'activity' in destinations.places(routes.EVIDENCE)
    try:
        media = lava.media(connection)
        stored = case.module_artifacts(run_id)
        wanted = [a for a in stored
                  if force or (only is not None and a['id'] in only) or
                  (only is None and (a.get('bridged_version') or 0) <
                   routes.ROUTES_VERSION)]
        for number, stored_artifact in enumerate(wanted):
            if should_stop is not None and should_stop():
                raise BridgeCancelled()
            artifact = dict(info.get(stored_artifact['tablename']) or {})
            if not artifact:
                continue
            if progress is not None:
                progress(number, len(wanted),
                         f"Sorting {run['tool']}: {artifact['name']}")
            route = routes.route(run['tool'], artifact, overrides)
            summary[route.role] += 1
            summary['artifacts'] += 1
            artifact_id = stored_artifact['id']
            case.drop_module_activity(artifact_id)
            try:
                digest = content_hash(connection, artifact, limit)
            except sqlite3.Error:
                digest = None
            newer = case.newer_same_artifact(
                run_id, run['evidence_id'], run['tool'],
                artifact.get('artifact_key') or artifact['tablename'],
                digest) if digest else None
            primary_label = ''
            if route.role == routes.EVIDENCE and newer is None and \
                    to_activity:
                rows = list(artifact_rows(connection, media, artifact,
                                          route, run_id, run['tool'],
                                          report, limit))
                for start in range(0, len(rows), 2000):
                    case.add_user_activity(
                        run['evidence_id'], rows[start:start + 2000],
                        module_run_id=run_id, module_artifact_id=artifact_id,
                        reader=run['tool'])
                case.commit()
                summary['rows'] += len(rows)
                primary_label = _primary_label(route, artifact)
            kind = 'superseded' if newer is not None else route.role
            case.set_module_event_kind(artifact_id, kind,
                                       artifact['name'], primary_label)
            case.set_module_artifact_route(
                artifact_id, artifact.get('artifact_key') or '',
                route.role, route.why, digest, routes.ROUTES_VERSION,
                newer, route.sorted_by)
            if newer is None and digest:
                # This one is the newest: older runs' copies step aside.
                summary['superseded'] += case.supersede_older_artifacts(
                    run_id, run['evidence_id'], run['tool'],
                    artifact.get('artifact_key') or artifact['tablename'],
                    digest, artifact_id)
        case.commit()
    finally:
        connection.close()
    if relink:
        case.relink_matches(run['evidence_id'])
    return summary
