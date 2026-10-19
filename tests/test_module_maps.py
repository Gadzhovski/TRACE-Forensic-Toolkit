"""The LEAPPs' maps (resources/leapp_maps, core/modules/maps): their shape,
their columns against the tools' real output, and that a record a LEAPP
read looks -- and matches -- like the one TRACE read.

The column lists in tests/expected/leapp_columns/ were recorded from the
real tools' LAVA databases (aLEAPP 2026.4.3 on a Pixel 3 extraction; the
iLEAPP list from 2026.4.4 on an iOS 13.3.1 file-system tar), so a map
naming a column the tool does not write fails here, not in a case.
"""

import datetime
import glob
import json
import os

import pytest
from PySide6.QtCore import Qt

from trace_app.core import activity_match, conversations
from trace_app.core.activity import record
from trace_app.core.modules import bridge, maps, record_types, routes

HERE = os.path.dirname(os.path.abspath(__file__))
MAPS = os.path.join(os.path.dirname(HERE), 'resources', 'leapp_maps')
COLUMNS = os.path.join(HERE, 'expected', 'leapp_columns')
WHEN = datetime.datetime(2020, 1, 2, 3, 4, 5,
                         tzinfo=datetime.timezone.utc)


def _tools():
    return sorted(os.path.splitext(os.path.basename(p))[0]
                  for p in glob.glob(os.path.join(MAPS, '*.json')))


def _recorded(tool):
    """{artifact_key: [column]} from the tool's recorded run, or None."""
    found = sorted(glob.glob(os.path.join(COLUMNS, f'{tool}-*.json')))
    if not found:
        return None
    with open(found[-1], encoding='utf-8') as handle:
        return json.load(handle)['columns']


def test_there_are_maps():
    assert {'aleapp', 'ileapp'} <= set(_tools())


@pytest.mark.parametrize('tool', _tools())
def test_each_map_is_well_formed(tool):
    data = maps.load(tool)
    assert data['artifacts'], f"{tool}: no artifacts mapped"
    assert maps.problems(data) == []
    assert data.get('checked_with'), "say which release it was checked on"


@pytest.mark.parametrize('tool', _tools())
def test_every_mapped_column_is_one_the_tool_writes(tool):
    columns = _recorded(tool)
    if columns is None:
        pytest.skip(f"no recorded columns for {tool}")
    wrong = []
    for key, entry in maps.load(tool)['artifacts'].items():
        if key not in columns:
            # Only an entry saying why it could not be checked (an
            # artifact the recorded run's evidence has no source for).
            if not entry.get('unchecked'):
                wrong.append(f"{key}: not an artifact of the recorded run")
            continue
        for column in maps.columns_of(entry):
            if column not in columns[key]:
                wrong.append(f"{key}: no column {column!r}")
    for key in maps.load(tool)['telemetry'] + maps.load(tool)['other']:
        if key not in columns:
            wrong.append(f"{key}: listed, but not an artifact of the run")
    assert wrong == []


def test_the_map_decides_before_any_name_rule():
    # 'Telegram - VoIP Call Logs' reads like calls by its name; the map
    # knows it is a settings table.
    artifact = {'artifact_key': 'get_telegramVoipLogs',
                'name': 'Telegram - VoIP Call Logs', 'columns': []}
    found = routes.default('aLEAPP', artifact)
    assert (found.role, found.sorted_by) == (routes.OTHER, 'list')
    artifact = {'artifact_key': 'get_calllog', 'name': 'Call Logs',
                'columns': []}
    found = routes.default('aLEAPP', artifact)
    assert (found.role, found.category, found.sorted_by) == (
        routes.EVIDENCE, 'communication', 'map')
    assert found.mapping['type'] == 'call'
    # A tool with no map still sorts by name.
    found = routes.default('RLEAPP', {'artifact_key': 'x',
                                      'name': 'Call Logs', 'columns': []})
    assert (found.role, found.sorted_by) == (routes.EVIDENCE, 'name')


def _aleapp_row(key, columns, values, source='Call Logs'):
    role, entry = maps.entry('aleapp', key)
    assert role == 'evidence'
    cols = [{'name': name, 'type': kind} for name, kind in columns]
    types = dict(columns)
    category, what, subject, detail = bridge._mapped(
        entry, cols, types, values, {}, {'partner': 'generic guess'})
    return {'category': category, 'what': what, 'subject': subject,
            'detail': detail, 'time': '2020-01-02 03:04:05',
            'local': False, 'source': entry.get('app') or source}


def test_a_call_trace_and_aleapp_read_has_the_same_fields_and_is_one():
    trace = record('communication', 'Android call log', WHEN, 'Call made',
                   '+15551234567', {'to': '+15551234567', 'name': 'Bob',
                                    'duration': '1:05'},
                   path='calllog.db', ref='p0:i1:s1')
    leapp = _aleapp_row(
        'get_calllog', [('call_date', 'datetime'), ('partner', 'text'),
                        ('type', 'text'), ('duration_in_secs', 'integer')],
        {'partner': '(555) 123-4567', 'type': 'Outgoing',
         'duration_in_secs': 65})
    assert leapp['what'] == trace['what'] == 'Call made'
    assert leapp['detail']['to'] == '(555) 123-4567'
    assert leapp['detail']['duration'] == trace['detail']['duration']
    assert 'from' not in leapp['detail']
    assert conversations.app_of(leapp) == conversations.app_of(trace) == \
        'Phone'
    key = activity_match.match_key(trace)
    assert key is not None and key == activity_match.match_key(leapp)


def test_a_map_reads_the_tools_own_direction_words():
    # aLEAPP writes the call type as HTML with an icon.
    leapp = _aleapp_row(
        'get_calllog', [('call_date', 'datetime'), ('partner', 'text'),
                        ('type', 'text')],
        {'partner': '+15551234567',
         'type': 'Missed <i data-feather="phone-missed"></i>'})
    assert leapp['what'] == 'Call missed'
    assert leapp['detail']['from'] == '+15551234567'
    assert record_types.direction('Voicemail',
                                  {'Voicemail': 'in'}) == 'in'
    assert record_types.direction('2') == ''        # numbers need a table


def test_a_secret_column_is_never_copied_even_when_mapped():
    entry = {'type': 'account', 'fields': {'account': ['password',
                                                       'username']}}
    cols = [{'name': 'password', 'type': 'text'},
            {'name': 'username', 'type': 'text'}]
    _c, _w, subject, detail = bridge._mapped(
        entry, cols, {}, {'password': 'hunter2', 'username': 'bob'}, {}, {})
    assert subject == 'bob'
    assert 'hunter2' not in json.dumps(detail)


def test_an_event_takes_its_category_and_what_from_the_map():
    role, entry = maps.entry('aleapp', 'magisk_superuser_log')
    assert role == 'evidence' and entry['type'] == 'event'
    found = routes.default('aLEAPP', {'artifact_key': 'magisk_superuser_log',
                                      'name': 'Magisk', 'columns': []})
    assert (found.category, found.what) == ('programs',
                                            'Root (superuser) request')


def test_activity_shows_both_readers_calls_in_the_same_columns(qapp):
    from trace_app.ui.viewers.activity_panel import ActivityModel
    trace = record('communication', 'Android call log', WHEN, 'Call made',
                   '+15551234567', {'to': '+15551234567', 'name': 'Bob',
                                    'duration': '1:05'},
                   path='data/com.android.providers.contacts/calllog.db',
                   ref='p0:i1:s1')
    leapp = _aleapp_row(
        'get_calllog', [('call_date', 'datetime'), ('partner', 'text'),
                        ('type', 'text'), ('duration_in_secs', 'integer')],
        {'partner': '+15559876543', 'type': 'Incoming',
         'duration_in_secs': 3725})
    rows = []
    for row, reader in ((trace, None), (leapp, 'aLEAPP')):
        rows.append(dict(row, time_utc=row['time'], reader=reader,
                         source_path=row.get('path') or ''))
    model = ActivityModel()
    model.set_layout('communication')
    model.set_rows(rows, {})
    header = [model.headerData(c, Qt.Horizontal)
              for c in range(model.columnCount())]
    assert header[:7] == ['Time', 'What', 'Party', 'Name', 'Text',
                          'Duration', 'App']
    assert 'Source file' in header and header[-1] == 'Details'

    def cell(r, title):
        return model.index(r, header.index(title)).data()

    assert [cell(0, 'Party'), cell(1, 'Party')] == ['→ +15551234567',
                                                    '← +15559876543']
    assert [cell(0, 'Duration'), cell(1, 'Duration')] == ['1:05', '1:02:05']
    assert [cell(0, 'App'), cell(1, 'App')] == ['Android call log', 'Phone']
    assert cell(0, 'Source file').endswith('calllog.db')
    # A value with its own column is not repeated in Details.
    assert 'duration' not in cell(0, 'Details')
    # Durations sort as times, not text ('1:05' before '1:02:05').
    from trace_app.ui.viewers.activity_panel import SORT_ROLE
    column = header.index('Duration')
    assert model.index(0, column).data(SORT_ROLE) < \
        model.index(1, column).data(SORT_ROLE)
    model.set_layout(None)
    assert model.headerData(model.column_of('read_by'), Qt.Horizontal) == \
        'Read by'
