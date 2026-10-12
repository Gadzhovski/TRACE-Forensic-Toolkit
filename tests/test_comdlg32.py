"""The Open / Save As dialog's memory (registry.comdlg32), checked against
plaso's own tests on the same hive (tests/parsers/winreg_plugins/
mrulistex.py at the plaso commit samples.py pins, on NTUSER-WIN7.DAT)."""

import datetime

from tests.conftest import data_path
from trace_app.core.activity import registry


def _items():
    with open(data_path('samples', 'NTUSER-WIN7.DAT'), 'rb') as handle:
        return registry.comdlg32(registry.open_hive(handle.read()))


def test_open_save_pidl_mru_as_plaso_reads_it():
    exe = [i for i in _items() if i['key'] == 'exe']
    # plaso: "Index: 1 [MRU Value 1]: ... P:\Application Tools\Firefox
    # 6.0\Firefox Setup 6.0.exe", "Index: 2 [MRU Value 0]: ...
    # \\controller\WebDavShare\Firefox Setup 3.6.12.exe", last written
    # 2011-08-28T22:48:28.1593086.
    assert [i['path'] for i in exe] == [
        r'P:\Application Tools\Firefox 6.0\Firefox Setup 6.0.exe',
        r'\\controller\WebDavShare\Firefox Setup 3.6.12.exe']
    assert exe[0]['time'] == datetime.datetime(
        2011, 8, 28, 22, 48, 28, 159309, tzinfo=datetime.timezone.utc)
    assert exe[1]['time'] is None
    assert all(i['extension'] == 'exe' for i in exe)


def test_last_visited_pidl_mru_as_plaso_reads_it():
    visited = [i for i in _items() if i['key'] == 'LastVisitedPidlMRU']
    # plaso's eight entries in MRU order: the program, then its folder.
    assert [i['program'] for i in visited] == [
        'chrome.exe', '{48E1ED6B-CF49-4609-B1C1-C082BFC3D0B4}',
        '{427865A0-03AF-4F25-82EE-10B6CB1DED3E}',
        '{24B5C9BB-48B5-47FF-8343-40481DBA1E2B}',
        '{0B8CFE96-DB69-4D33-8E3C-36EAB4F709E0}',
        '{D4F85F66-003D-4127-BCE9-CAD7A57B2857}', 'iexplore.exe',
        'Skype.exe']
    paths = {i['program']: i['path'] for i in visited}
    assert paths['{24B5C9BB-48B5-47FF-8343-40481DBA1E2B}'] == \
        r'C:\Users\nfury\Documents'
    assert paths['{0B8CFE96-DB69-4D33-8E3C-36EAB4F709E0}'] == \
        r'C:\Users\nfury\Documents\Alloy Research'
    assert paths['iexplore.exe'] == r'P:\Application Tools\Firefox 6.0'
    assert paths['{48E1ED6B-CF49-4609-B1C1-C082BFC3D0B4}'].endswith(
        'Alloy Research')
    # plaso: last written 2012-04-01T13:52:38.9662902.
    assert visited[0]['time'] == datetime.datetime(
        2012, 4, 1, 13, 52, 38, 966290, tzinfo=datetime.timezone.utc)


def test_star_lists_only_what_no_extension_list_names():
    items = _items()
    named = {i['path'] for i in items
             if i['extension'] and i['what'] == 'File opened or saved'}
    starred = [i for i in items if i['key'] == '*']
    assert starred
    assert not any(i['path'] in named for i in starred)


def test_programs_from_cidsizemru_and_firstfolder():
    items = _items()
    assert 'Explorer.EXE' in {i['program'] for i in items
                              if i['key'] == 'CIDSizeMRU'}
    assert {i['program'] for i in items if i['key'] == 'FirstFolder'} == {
        r'C:\Users\nfury\AppData\Local\Google\Chrome\Application\chrome.exe',
        r'C:\Program Files (x86)\Internet Explorer\iexplore.exe'}
