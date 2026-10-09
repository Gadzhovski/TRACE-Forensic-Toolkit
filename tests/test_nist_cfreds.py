"""NIST CFReDS data sets (cfreds-archive.nist.gov), against what NIST
publishes about each -- never against TRACE's own output:

* Deleted File Recovery (DFR-01..17 on ext, FAT, exFAT, NTFS, HFS+):
  tests/expected/nist_dfr_ground_truth.json, parsed from NIST's answer key by
  tools/score/nist_dfr_key.py; content checked against the sectors the key lists
  and the test files' own block markers ("DFR / Block 00008 ... file X").
  tools/score/dfr_score.py runs the whole set; these tests hold the cases that
  found something.
* Searching Container Files: the sentence NIST hid in each container type
  (its content_info-2.txt).
* Russian Tea Room: the eight menu sections (UTF-16BE), as NIST's own
  source files (russian-utf-16.zip) spell them.
* cfreds-2017-winreg: deleted keys and values, against the same hive
  before the deletion (NIST's "all-in-one" hive, read by python-registry).

The images live in test_images/nist/ (downloaded by hand for now; the CI
plan is separate) and are skipped when absent. dfr-01-xfat.dd and
dfr-01-recycle-ntfs.dd are in the image catalog, so their tests run in CI.
"""

import glob
import io
import json
import os
import zipfile

import pytest

from tests.conftest import ROOT, image_path
from tools import testdata

NIST = testdata.NIST
KEY = os.path.join(ROOT, 'tests', 'expected', 'nist_dfr_ground_truth.json')


def nist(*parts):
    path = os.path.join(NIST, *parts)
    if not os.path.exists(path):
        pytest.skip(f"{os.path.join(*parts)} is not downloaded")
    return path


def _key(name):
    with open(KEY, encoding='utf-8') as handle:
        return json.load(handle)['images'][name]


def _handler(path):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(path)
    assert handler.loaded, handler.load_error
    return handler


def _deleted(handler):
    from trace_app.core import deleted
    from trace_app.core.carving import allocation_map
    return list(deleted.deleted_files(handler, allocation_map(handler)))


def _by_key_name(records, fat=True):
    """{the key's name: record} -- FAT loses a deleted short name's first
    character ('_APELLA.TXT'), matched as tools/score/dfr_score.py does."""
    from tools.score.dfr_score import same_name

    class Lookup(dict):
        def __missing__(self, name):
            for record in records:
                if same_name(name, record['name'], fat):
                    return record
            raise KeyError(name)
    return Lookup()


# --- DFR: exFAT ---------------------------------------------------------------

def test_exfat_times_are_utc_from_the_offset_each_entry_records():
    """exFAT keeps a UTC offset beside each time; TSK ignores it. The key's
    modified and accessed times (UTC, from the Mac that made the image)
    are the stored digits minus that offset: 2000-02-29 18:12 and
    1999-01-02 08:02, where the raw digits read 22:12 and 12:02."""
    handler = _handler(image_path('dfr-01-xfat.dd'))
    try:
        record = next(r for r in _deleted(handler)
                      if r['name'] == 'Betelgeuse.txt')
    finally:
        handler.close_resources()
    times = _key('xfat-01')['times']['Betelgeuse.txt']
    assert record['modified'] == times['modify']['utc'][:19]
    assert record['accessed'] == times['access']['utc'][:19]
    assert record['times_local'] is False


def test_a_fragmented_deleted_exfat_file_is_read_from_its_own_chain():
    """DFR-05 braid: two deleted files' clusters interleaved. exFAT keeps
    the FAT chain on deletion; TSK reads each as one piece (half itself,
    half the other). Both are recovered byte for byte -- every block of
    each names its file, in order."""
    from tools.score.dfr_score import own_content
    handler = _handler(nist('dfr', 'dfr-05-braid-xfat.dd'))
    try:
        records = {r['name']: r for r in _deleted(handler)}
        for name in ('Betelgeuse.txt', 'Capella.txt'):
            record = records[name]
            assert record['state'] == 'recoverable'
            content, _meta = handler.get_file_content(record['inode'],
                                                      record['volume'])
            assert own_content(content, name, record['size']), name
    finally:
        handler.close_resources()


def test_files_of_a_deleted_exfat_folder_are_read_from_their_chains():
    """DFR-12: a folder deleted with its files; their entries keep the
    in-use bit (exFAT frees the folder's clusters, not its entries)."""
    from tools.score.dfr_score import own_content
    handler = _handler(nist('dfr', 'dfr-12-xfat.dd'))
    try:
        records = [r for r in _deleted(handler)
                   if r['name'] in _key('xfat-12')['sectors']]
        assert len(records) == 9
        for record in records:
            content, _meta = handler.get_file_content(record['inode'],
                                                      record['volume'])
            assert own_content(content, record['name'], record['size'])
    finally:
        handler.close_resources()


# --- DFR: FAT -----------------------------------------------------------------

def test_fat_files_whose_space_a_later_deleted_file_took_are_not_recoverable():
    """DFR-07: files deleted, others written into their clusters and
    deleted too. The key: Capella, Deneb, Denebola 0 of 8 sectors left."""
    handler = _handler(nist('dfr', 'dfr-07-fat.dd'))
    try:
        records = _by_key_name(_deleted(handler))
    finally:
        handler.close_resources()
    key = _key('fat-07')['sectors']
    for name in ('Capella.txt', 'Deneb.txt', 'Denebola.TXT'):
        assert key[name]['intact'] == 0
        assert records[name]['state'] != 'recoverable', name


@pytest.mark.parametrize('image, key', [('dfr-05-braid-fat.dd',
                                         'fat-05-braid'),
                                        ('dfr-05-nest-fat.dd',
                                         'fat-05-nest')])
def test_fat_files_in_pieces_say_only_their_start_is_known(image, key):
    """FAT zeroes a deleted file's chain: TSK reads on from its first
    cluster, through the other file's. The key says every sector is
    intact; what can be said is where each began -- not 'recoverable'
    (its bytes would be half another file's), not 'overwritten'."""
    handler = _handler(nist('dfr', image))
    try:
        records = _by_key_name(_deleted(handler))
    finally:
        handler.close_resources()
    for name in _key(key)['sectors']:
        assert records[name]['state'] in ('start only', 'possibly '
                                          'overwritten'), name


def test_large_fat_files_in_pieces_are_not_called_recoverable():
    """DFR-06: 8, 33 and 63 MB files on FAT12/16/32; TSK's one-piece
    reading stops at the first live cluster."""
    handler = _handler(nist('dfr', 'dfr-06-fat.dd'))
    try:
        states = {r['name']: r['state'] for r in _deleted(handler)}
    finally:
        handler.close_resources()
    # 'no data recorded': FAT32's entry points past its own volume.
    assert set(states.values()) <= {'start only', 'no data recorded'}


def test_fat_times_are_the_digits_the_volume_holds():
    """The key's FAT times went through the Mac's msdosfs, which converts
    with one fixed offset; its access times (a date: local midnight) show
    the offset as their UTC time of day. TRACE shows the digits on disk,
    marked as local."""
    from tools.score.dfr_score import _fat_driver_offset, _shifted
    image = _key('fat-01')
    offset = _fat_driver_offset(image)
    assert offset == -240
    handler = _handler(nist('dfr', 'dfr-01-fat.dd'))
    try:
        records = _by_key_name(_deleted(handler))
    finally:
        handler.close_resources()
    for name, stamps in image['times'].items():
        want = _shifted(stamps['modify']['utc'], offset)
        assert records[name]['modified'][:17] == want[:17], name
        assert records[name]['times_local'] is True


# --- DFR: NTFS ----------------------------------------------------------------

def test_ntfs_files_only_logfile_still_names_are_listed():
    """DFR-08: 25 files deleted, MFT entries of 12 reused. $LogFile still
    holds their names; Deleted Files lists every one."""
    handler = _handler(nist('dfr', 'dfr-08-ntfs.dd'))
    try:
        names = {r['name'] for r in _deleted(handler)}
    finally:
        handler.close_resources()
    for item in _key('ntfs-08')['deleted']:
        assert item['name'] in names, item['name']


def test_of_two_deleted_ntfs_files_the_one_freed_later_owns_the_clusters():
    """DFR-13: D067 was created before D099 but appended to after D099 was
    deleted, so its clusters are its own -- $LogFile frees D067's entry
    later. Its bytes, block by block, are D067's."""
    from tools.score.dfr_score import own_content
    handler = _handler(nist('dfr', 'dfr-13-ntfs.dd'))
    try:
        records = {r['name']: r for r in _deleted(handler)}
        for prefix in ('D067', 'D086'):
            record = next(r for n, r in records.items()
                          if n.startswith(prefix))
            assert record['state'] == 'recoverable', prefix
            content, _meta = handler.get_file_content(record['inode'],
                                                      record['volume'])
            assert own_content(content, record['name'], record['size'])
    finally:
        handler.close_resources()


def test_recycle_bin_deletions_keep_the_original_name_and_content():
    from tools.score.dfr_score import score
    result = score('ntfs-01-recycle', _key('ntfs-01-recycle'))
    assert result.get('listed') == 1 and not result.get('false ok')
    assert result.get('content ok') == 1


# --- DFR: the scorer's whole-image verdicts -------------------------------------

@pytest.mark.parametrize('name', [
    'fat-01', 'fat-02', 'fat-05', 'fat-07', 'fat-07-one', 'fat-12', 'fat-14',
    'xfat-01', 'xfat-05', 'xfat-07', 'xfat-08', 'xfat-12', 'xfat-13',
    'ntfs-01', 'ntfs-05', 'ntfs-05-nest', 'ntfs-07', 'ntfs-11-compress',
    'ntfs-11-mft', 'ntfs-12', 'ntfs-13', 'ext-04', 'fat-04', 'xfat-04'])
def test_no_deleted_file_is_called_recoverable_when_it_is_not(name):
    """Whatever TRACE calls recoverable is the file's bytes, or the key
    says so; every time agrees with the key."""
    from tools.score.dfr_score import image_path as dfr_image, score
    if dfr_image(name) is None:
        pytest.skip(f"{name} is not downloaded")
    result = score(name, _key(name))
    assert not result.get('false ok'), result['_notes']
    assert result.get('times ok', 0) == result.get('times', 0), \
        result['_notes']
    assert result.get('listed', 0) == result.get('deleted', 0), \
        result['_notes']


# --- Searching Container Files ------------------------------------------------

#: content_info-2.txt: container -> (country, the sentence's capital, the
#: city it names as not the capital).
CONTAINERS = {
    'archive-zip.zip': ('China', 'Beijing', 'Nanjing'),
    'archive-tar_bzip2.tar.bz2': ('Italy', 'Rome', 'Turin'),
    'archive-tar_gzip.tar.gz': ('Ethiopia', 'Addis Ababa', 'Adama'),
    'archive-tar_xz.tar.xz': ('Colombia', 'Bogota', 'Medellin'),
    'archive-7z.7z': ('England', 'London', 'Liverpool'),
    'archive-rar.rar': ('Spain', 'Madrid', 'Bilbao'),
    'archive-cpio.cpio': ('Japan', 'Tokyo', 'Kyoto'),
    'archive-alz.alz': ('India', 'New Delhi', 'Calcutta'),
    'archive-LZH.lzh': ('France', 'Paris', 'Lyon'),
    'archive-tar.tar': ('Nigeria', 'Abuja', 'Lagos'),
    'archive-cab.CAB': ('Russia', 'Moscow', 'Bor'),
    'archive-tar_uue.uue': ('Angola', 'Luanda', 'Jamba'),
    'archive-lha.lha': ('Brazil', 'Brasilia', 'Curitiba'),
}


def _members_text(data, depth=0):
    """Every member's bytes, archives inside archives opened too. A RAR
    member compressed with RAR's own method is listed but not read: that
    needs the unrar program, and evidence never goes to one."""
    from trace_app.core import archives
    kind = archives.detect_archive(data)
    if kind is None or depth > 3:
        return [data]
    out = []
    for member in archives.list_members(data, kind):
        if member['is_dir']:
            continue
        try:
            body = archives.read_member(data, member['name'] or None, kind)
        except archives.ArchiveError:
            if kind == 'rar':
                continue
            raise
        out += _members_text(body, depth + 1)
    return out


@pytest.mark.parametrize('name', sorted(CONTAINERS))
def test_each_container_gives_up_its_sentence(name):
    country, capital, decoy = CONTAINERS[name]
    handler = _handler(nist('containers', 'files.dd'))
    try:
        fs = handler.get_fs_info(0)
        entry = fs.open('/' + name)
        data = entry.read_random(0, entry.info.meta.size)
    finally:
        handler.close_resources()
    texts = b'\n'.join(_members_text(data))
    # NIST's tar.gz spells the country 'Ehtiopia': the sentence is pinned
    # by its capital and the city it names as not the capital.
    assert f"is {capital}, not {decoy}".encode() in texts, (name, country)


def test_legacy_container_members_check_their_own_checksums():
    """LHA members carry a CRC-16, ALZ members a CRC-32: a decoder bug
    would raise, not return wrong bytes. The 466 KB Word file in each is
    decoded and checked."""
    from trace_app.core import legacy_archives
    handler = _handler(nist('containers', 'files.dd'))
    try:
        fs = handler.get_fs_info(0)
        for name, kind in (('archive-LZH.lzh', 'lzh'),
                           ('archive-lha.lha', 'lzh'),
                           ('archive-alz.alz', 'alz'),
                           ('archive-cab.CAB', 'cab')):
            entry = fs.open('/' + name)
            data = entry.read_random(0, entry.info.meta.size)
            assert legacy_archives.kind_of(data) == kind
            for member in legacy_archives.members(data, kind):
                if not member['is_dir']:
                    body = legacy_archives.read(data, kind, member['name'])
                    assert len(body) == member['size'], member['name']
    finally:
        handler.close_resources()


# --- Russian Tea Room ---------------------------------------------------------

def test_every_menu_section_is_found_by_search(tmp_path):
    """Eight sections in UTF-16BE: in files, a deleted file, the FAT of an
    older volume, slack and unallocated space -- four of them in no file
    at all. The headings as NIST's source files spell them."""
    from trace_app.core.indexer import index_evidence
    from trace_app.core.search_index import SearchIndex
    with zipfile.ZipFile(nist('russian', 'russian-utf-16.zip')) as source:
        headings = sorted(
            source.read(n).decode('utf-16').lstrip('﻿')
            .split(' (')[0].strip()
            for n in source.namelist()
            if n.endswith('.txt') and 'english names' in n
            and not n.endswith('snack.txt'))
    assert len(headings) == 8
    handler = _handler(nist('russian', 'CFReDS001.E01'))
    index = SearchIndex(str(tmp_path))
    try:
        index_evidence(handler, index, 1)
        for heading in headings:
            assert index.search(f'"{heading}"'), heading
    finally:
        index.close()
        handler.close_resources()


# --- cfreds-2017-winreg -------------------------------------------------------

def _winreg(*parts):
    return nist('winreg', 'x', *parts)


def _stored(value):
    """A value's data as stored. python-registry misreads an inline
    REG_DWORD_BIG_ENDIAN (see the DWORD-BE test); its four bytes are the
    record's data-offset field."""
    if value.value_type() == 5:
        record = value._vkrecord
        at = record.absolute_offset(0x8)
        return bytes(record._buf[at:at + 4])
    return value.raw_data()


def _tree(path):
    from Registry import Registry
    root = Registry.Registry(open(path, 'rb')).root()
    out, stack = {}, [(root, '')]
    while stack:
        key, path_ = stack.pop()
        out[path_] = {value.name(): _stored(value) for value in key.values()}
        stack += [(sub, path_ + '/' + sub.name()) for sub in key.subkeys()]
    return out


@pytest.mark.parametrize('version', ['v13', 'v15'])
@pytest.mark.parametrize('tool', ['1', '2'])     # RegEdit, hivex
def test_deleted_registry_keys_and_values_are_recovered(version, tool):
    """[nrd]-01..06: keys (with and without values and subkeys) and values
    deleted from the "all-in-one" hive. Each deleted key is recovered at
    its path; each deleted value with its data, and with its key when the
    hive still says which -- never a wrong one."""
    from trace_app.core import regf_deleted
    before = glob.glob(_winreg('ugrd-nr') + f'/[[]nr[]]-##-{tool}_all-in-one_'
                       f'{version}/*.hive')
    if not before:
        pytest.skip("no all-in-one hive for this tool")
    base = _tree(before[0])
    cases = sorted(glob.glob(_winreg('ugrd-nrd') +
                             f'/*-0[1-6]-{tool}_*_{version}/*.hive'))
    assert cases
    for hive in cases:
        now = _tree(hive)
        with open(hive, 'rb') as handle:
            found = regf_deleted.recover(handle.read())
        keys = {k['path'] for k in found['keys']}
        for path in base:
            if path not in now:
                assert path in keys, (hive, path)
        for path, values in base.items():
            for name, data in values.items():
                if path in now and name in now[path]:
                    continue
                default = name.lower() in ('', '(default)')
                matches = [v for v in found['values']
                           if (v['name'] == name or
                               (default and v['name'] == '(Default)'))
                           and v['data'][:len(data)] == data]
                assert matches, (hive, path, name)
                assert any(v['key'] in (path, '') for v in matches), \
                    (hive, path, name)
        # Never a wrong key: a value said to be a key's was that key's,
        # with that data, before the deletion.
        for value in found['values']:
            if not value['key']:
                continue
            had = base.get(value['key'], {})
            names = [n for n in had if n == value['name'] or (
                value['name'] == '(Default)' and n.lower() in
                ('', '(default)'))]
            assert any(value['data'][:len(had[n])] == had[n]
                       for n in names), (hive, value['key'],
                                         value['name'])


def test_a_big_endian_dword_reads_as_stored():
    """python-registry reads an inline REG_DWORD_BIG_ENDIAN from the four
    bytes after its data field (the type, 5): 83,886,080. The record holds
    00 00 00 04 -- 4, like the DWORD and QWORD values beside it."""
    from Registry import Registry
    from trace_app.core import regf_deleted
    hive = glob.glob(_winreg('ugrd-nr') +
                     '/[[]nr[]]-##-1_all-in-one_v13/*.hive')[0]
    key = Registry.Registry(open(hive, 'rb')).open('0x01_TYPE1_DATA-TYPES')
    value = next(v for v in key.values() if 'DWORD-BE' in v.name())
    assert value.value() == 83886080             # the library's reading
    assert regf_deleted.live_value_text(value) == '4'


def test_every_test_hive_is_read_without_crashing_or_stalling():
    """144 hives, 14 deliberately corrupted and 64 manipulated (sizes
    forged to hide keys). Recovery never raises on one and never takes
    long: forged cell sizes are cut to their hive bin."""
    import time
    from trace_app.core import regf_deleted
    hives = glob.glob(_winreg() + '/*/*/*.hive')
    assert len(hives) == 144
    for hive in hives:
        with open(hive, 'rb') as handle:
            data = handle.read()
        started = time.time()
        try:
            regf_deleted.recover(data)
        except ValueError:
            assert data[:4] != b'regf'           # no header: refused
        assert time.time() - started < 5, hive


def test_the_registry_tab_shows_deleted_keys_and_their_values(qapp):
    """The Registry tab's "Deleted keys and values" node: each deleted key
    by its path, a click listing its values with their data and key."""
    from trace_app.core import regf_deleted
    from trace_app.ui.viewers.registry_hive import RegistryExtractor
    hive = glob.glob(_winreg('ugrd-nrd') +
                     '/*-01-1_*_v13/*.hive')[0]
    with open(hive, 'rb') as handle:
        found = regf_deleted.recover(handle.read())
    browser = RegistryExtractor()
    browser._source_rows = []
    browser._add_deleted(found)
    top = browser.treeWidget.topLevelItem(0)
    assert top.text(0).startswith('Deleted keys and values (2 keys')
    keys = {top.child(i).text(0): top.child(i) for i in range(top.childCount())}
    item = keys['/0x01_TYPE1_DATA-TYPES']
    browser.on_item_clicked(item, 0)
    table = browser.tableWidget
    rows = {table.item(r, 0).text(): (table.item(r, 1).text(),
                                      table.item(r, 2).text(),
                                      table.item(r, 3).text())
            for r in range(table.rowCount())}
    assert rows['VALUE 0x04 (DWORD-LE)'] == ('REG_DWORD', '4',
                                             '/0x01_TYPE1_DATA-TYPES')
    assert rows['VALUE 0x05 (DWORD-BE)'][1] == '4'
    assert rows['VALUE 0x01 (SZ)'][1] == 'UTF-16LE NULL-terminated string'


def _journal_recoveries(image):
    """(inode, recovered bytes, reused bytes) for each deleted inode of the
    image's ext3/ext4 volumes the journal gives back (core/ext_journal) --
    read without listing directories (NIST's filler file makes that slow)."""
    import struct
    from trace_app.core import ext_journal
    handler = _handler(nist('dfr', image))
    out = []
    try:
        for start in handler.volume_offsets():
            if handler.get_fs_type(start) not in ('Ext3', 'Ext4'):
                continue
            journal = ext_journal.Journal(handler, start,
                                          handler.get_fs_info(start))
            for inode in journal.logged_inodes():
                now = journal.inode_now(inode)
                if len(now) < 28 or struct.unpack_from('<H', now, 26)[0]:
                    continue                          # live or unread
                found = journal.deleted_runs(inode)
                if not found:
                    continue
                runs, size = found
                data = b''.join(handler.read(o, n) for o, n in runs)[:size]
                out.append((inode, data,
                            journal.reused(inode, runs, journal.last_place)))
    finally:
        handler.close_resources()
    return out


def test_ext_files_emptied_on_deletion_come_back_from_the_journal():
    """DFR-10: ext3/ext4 empty a deleted inode (no size, no blocks); the
    journal's copy from before holds them. Every file recovered is its own
    bytes, block by block, by NIST's markers -- 279 of them."""
    import re
    from tools.score.dfr_score import own_content
    found = _journal_recoveries('dfr-10-ext.dd')
    assert len(found) >= 279
    for inode, data, reused in found:
        names = set(re.findall(rb'\nDFR\nFile (.+?) path ', data))
        assert len(names) == 1, inode
        name = names.pop().decode()
        assert own_content(data, name, len(data)), (inode, name)
        assert reused == 0


def test_the_journal_says_when_a_deleted_files_blocks_went_to_another():
    """DFR-07: Duhr.TXT's blocks were written over by Furud.txt (the key's
    overlap list). The journal logs Furud's inode after Duhr's: the reuse
    is caught, and the blocks hold Furud's data, not Duhr's."""
    found = _journal_recoveries('dfr-07-ext.dd')
    for inode, data, reused in found:
        if b'file Furud.txt' in data and b'File Furud.txt' not in data:
            assert reused == len(data), inode       # another's bytes
            break
    else:
        pytest.fail("no overwritten file among the recoveries")


def test_an_attribute_block_a_later_file_named_counts_as_reuse():
    """DFR-07: Diadem.TXT's first block became the extended-attribute block
    of two later files (i_file_acl, kept after they were freed). The key
    lists 6 of its 8 sectors intact; the journal's copy of those inodes is
    what says so."""
    found = _journal_recoveries('dfr-07-ext.dd')
    for inode, data, reused in found:
        if b'file Diadem.TXT path' in data:      # its later blocks
            assert 0 < reused < len(data), inode
            break
    else:
        pytest.fail("Diadem.TXT not recovered from the journal")


def test_a_file_made_and_deleted_later_leaves_the_state_open():
    """DFR-07-one: Chort.txt was written over (the key: 0 of 8 sectors
    intact) by a file made after Chort's deletion and itself deleted -- ext
    emptied its inode, and no logged copy records its blocks. TRACE cannot
    prove the reuse, so it must not call Chort recoverable."""
    from trace_app.core import deleted
    handler = _handler(nist('dfr', 'dfr-07-one-ext.dd'))
    try:
        states = {r['path']: r for r in deleted.deleted_files(handler)}
    finally:
        handler.close_resources()
    chort = states['/Chort.txt']
    assert chort['state'] == deleted.POSSIBLY
    assert 'inode 13' in chort['claimed_by']
    assert states['/Eltanin.txt']['state'] == deleted.RECOVERABLE
