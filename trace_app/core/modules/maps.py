"""LEAPP maps: which of a tool's artifacts are which TRACE records, column
by column (no Qt).

One JSON file per tool, resources/leapp_maps/<tool id>.json -- reviewable,
like Autopsy's <tool>-artifact-attribute-reference.xml, but keyed by the
LAVA `artifact_key` (stable across releases, where Autopsy keys TSV file
names) and with nothing dropped: an artifact a map does not name is still
sorted (core/modules/routes: name rules, else Others) and browsable.

    {"tool": "aLEAPP", "checked_with": "<release>",
     "artifacts": {"<artifact_key>": {
         "type": "<record_types.TYPES key>",
         "time": "<column>" | ["<column>", ...],   (optional; a list:
                                                   the first the artifact
                                                   has -- a column a newer
                                                   release renamed)
         "fields": {"<typed field>": "<column>" | ["<column>", ...]},
         "directions": {"<tool value>": "out|in|missed"},  (optional)
         "app": "<name>",                         (optional)
         "what": "<the rows' wording>"}},         (optional; an 'event'
                                                   also names "category")
     "telemetry": ["<artifact_key>", ...],
     "other": ["<artifact_key>", ...]}

`problems(map_)` says what is wrong with a map (an unknown type, a field
its type does not have); tests/test_module_maps.py also checks every
column against the tool's real output.
"""

import functools
import json
import logging
import os

from trace_app.core.modules import record_types

logger = logging.getLogger('TRACE.ModuleMaps')


def _folder():
    from trace_app.infra.paths import resource_path
    return resource_path('resources', 'leapp_maps')


@functools.lru_cache(maxsize=None)
def load(tool):
    """The map of `tool` ('iLEAPP' / 'ileapp'...), or an empty one."""
    path = os.path.join(_folder(), f"{(tool or '').lower()}.json")
    try:
        with open(path, encoding='utf-8') as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {'artifacts': {}, 'telemetry': [], 'other': []}
    except (OSError, ValueError) as exc:
        logger.warning("LEAPP map %s not read: %s", path, exc)
        return {'artifacts': {}, 'telemetry': [], 'other': []}
    for problem in problems(data):
        logger.warning("LEAPP map %s: %s", path, problem)
    return data


def entry(tool, artifact_key):
    """(role, map entry or None) for one artifact: ('evidence', entry),
    ('telemetry', None), ('other', None) or (None, None) when the map does
    not name it."""
    data = load(tool)
    found = (data.get('artifacts') or {}).get(artifact_key)
    if found is not None and found.get('type') in record_types.TYPES:
        return 'evidence', found
    if artifact_key in (data.get('telemetry') or ()):
        return 'telemetry', None
    if artifact_key in (data.get('other') or ()):
        return 'other', None
    return None, None


def time_column(found, columns):
    """The entry's time column among `columns` (the artifact's own, LAVA
    column dicts): a list names a column under each release's name, the
    first the artifact has wins; '' when it has none."""
    wanted = found.get('time') or ''
    if not isinstance(wanted, list):
        return wanted
    names = {column['name'] for column in columns}
    return next((name for name in wanted if name in names), '')


def columns_of(found):
    """Every column a map entry reads (time and fields)."""
    wanted = found.get('time')
    out = (wanted if isinstance(wanted, list) else [wanted]) if wanted \
        else []
    for value in (found.get('fields') or {}).values():
        out += value if isinstance(value, list) else [value]
    return out


def problems(data):
    """What is wrong with a map's shape: [text]."""
    out = []
    artifacts = data.get('artifacts') or {}
    for key, found in artifacts.items():
        kind = found.get('type')
        if kind not in record_types.TYPES:
            out.append(f"{key}: unknown type {kind!r}")
            continue
        if kind == 'event' and (
                found.get('category') not in record_types.EVENT_CATEGORIES
                or not found.get('what')):
            out.append(f"{key}: an event needs a category of "
                       f"{record_types.EVENT_CATEGORIES} and a what")
        allowed = set(record_types.TYPES[kind][2])
        for field in found.get('fields') or {}:
            if field not in allowed:
                out.append(f"{key}: {kind} has no field {field!r}")
        for meaning in (found.get('directions') or {}).values():
            if meaning not in ('out', 'in', 'missed', ''):
                out.append(f"{key}: direction {meaning!r}")
    listed = list(artifacts) + list(data.get('telemetry') or ()) + \
        list(data.get('other') or ())
    twice = {key for key in listed if listed.count(key) > 1}
    if twice:
        out.append(f"named more than once: {sorted(twice)}")
    return out
