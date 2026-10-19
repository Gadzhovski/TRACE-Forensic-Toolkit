"""Folder evidence opened from a kept listing (core/folder_listing): the
same nodes and bytes as a fresh walk, refused when it cannot be trusted,
and a change since found by the background check."""

import os
import sys
import time

import pytest

from trace_app.core import folder_listing
from trace_app.core.logical import ROOT
from trace_app.core.logical_sources import open_folder


def _tree(root):
    for top in ('Alpha', 'beta', 'Gamma'):
        for middle in range(3):
            folder = root / top / f"m{middle}"
            folder.mkdir(parents=True)
            for leaf in range(4):
                (folder / f"f{leaf}.bin").write_bytes(
                    bytes([leaf]) * (leaf * 100 + middle))
    (root / 'empty').mkdir()
    (root / 'top.txt').write_text('top level')
    return root


def _nodes(fs):
    return [(n.inode, n.parent, n.name, n.is_dir, n.size,
             {k: v for k, v in n.times.items() if k != 'atime'},
             sorted((n.children or {}).items()))
            for _, n in sorted(fs.nodes.items())]


@pytest.fixture
def evidence(tmp_path):
    return str(_tree(tmp_path / 'evidence'))


def test_a_kept_listing_gives_the_walk_s_nodes_and_bytes(evidence):
    first = open_folder(evidence)
    assert not first.listing_kept
    assert os.path.exists(folder_listing.listing_file(evidence))
    again = open_folder(evidence)
    assert again.listing_kept
    assert _nodes(again) == _nodes(first)
    assert len(again.nodes) == len(first.nodes) > 40
    for inode, node in again.nodes.items():
        if not node.is_dir:
            full = os.path.join(evidence, *again.path_of(inode)
                                .strip('/').split('/'))
            with open(full, 'rb') as handle:
                assert node.reader(0, node.size) == handle.read()
    assert sorted(again.file_names()) == sorted(
        n.name for n in first.nodes.values() if not n.is_dir)
    assert again.total_size() == first.total_size()
    assert 'kept' in again.facts['Listing']


def test_a_change_at_the_top_is_walked_again(evidence):
    open_folder(evidence)
    with open(os.path.join(evidence, 'new.txt'), 'w') as handle:
        handle.write('added')
    fs = open_folder(evidence)
    assert not fs.listing_kept
    assert 'new.txt' in set(fs.file_names())


def test_a_damaged_listing_is_refused(evidence):
    open_folder(evidence)
    path = folder_listing.listing_file(evidence)
    raw = bytearray(open(path, 'rb').read())
    raw[-10] ^= 0xFF
    open(path, 'wb').write(bytes(raw))
    with pytest.raises(folder_listing.ListingError):
        folder_listing.read(path, evidence)
    fs = open_folder(evidence)
    assert not fs.listing_kept and len(fs.nodes) > 40


def test_a_listing_of_another_folder_is_refused(evidence, tmp_path):
    open_folder(evidence)
    other = str(_tree(tmp_path / 'other'))
    with pytest.raises(folder_listing.ListingError):
        folder_listing.read(folder_listing.listing_file(evidence), other)


def test_the_check_finds_a_change_below_and_promote_takes_it_up(evidence):
    open_folder(evidence)
    assert folder_listing.check(evidence)['added'] == 0
    # Below the top: the opening's cheap guard does not see it.
    deep = os.path.join(evidence, 'beta', 'm1')
    with open(os.path.join(deep, 'planted.bin'), 'wb') as handle:
        handle.write(b'x' * 10)
    os.remove(os.path.join(deep, 'f0.bin'))
    later = time.time() + 100
    os.utime(os.path.join(deep, 'f2.bin'), (later, later))
    assert open_folder(evidence).listing_kept
    found = folder_listing.check(evidence)
    # Folders are compared by being there (their times follow their
    # contents, and Windows reports them lazily).
    assert (found['added'], found['removed'], found['changed']) == (1, 1, 1)
    assert sorted(found['examples']) == [
        'added: /beta/m1/planted.bin', 'changed: /beta/m1/f2.bin',
        'removed: /beta/m1/f0.bin']
    pending = folder_listing.pending_file(evidence)
    assert os.path.exists(pending)
    # Until promoted, an opening (a job of this session) keeps the old one.
    assert 'planted.bin' not in set(open_folder(evidence).file_names())
    folder_listing.promote(evidence)
    assert not os.path.exists(pending)
    fs = open_folder(evidence)
    assert fs.listing_kept and 'planted.bin' in set(fs.file_names())


@pytest.mark.skipif(sys.platform != 'win32', reason=(
    "os.utime moves the inode's ctime there (a read moving atime does "
    "not), so the check rightly reports a change"))
def test_access_times_are_not_a_change(evidence):
    open_folder(evidence)
    target = os.path.join(evidence, 'Alpha', 'm0', 'f1.bin')
    info = os.stat(target)
    os.utime(target, ns=(info.st_atime_ns + 10 ** 12, info.st_mtime_ns))
    found = folder_listing.check(evidence)
    assert (found['added'], found['removed'], found['changed']) == (0, 0, 0)


def test_the_background_job_reports_the_check(evidence):
    from trace_app.core import background
    open_folder(evidence)
    with open(os.path.join(evidence, 'Gamma', 'm2', 'new.bin'), 'wb') as h:
        h.write(b'new')
    items = []
    count = background.job_folder_check(
        {'image_path': evidence}, lambda *a, **k: None, items.append,
        lambda: False)
    assert count > 40 and items[0]['added'] == 1


def test_evidence_information_totals_from_the_columns(evidence):
    from trace_app.core import evidence_overview

    class Handler:
        pass
    open_folder(evidence)
    handler = Handler()
    handler.logical_fs = open_folder(evidence)
    fast = evidence_overview.summary(handler)
    handler.logical_fs.listing = None
    assert fast == evidence_overview.summary(handler)
    assert fast['files'] == 37 and fast['folders'] == 13
    assert [row[0] for row in fast['top']] == ['Alpha', 'beta', 'empty',
                                               'Gamma', 'top.txt']


def test_nodes_are_made_only_when_asked(evidence):
    open_folder(evidence)
    fs = open_folder(evidence)
    assert fs.listing_kept and not fs.nodes._made
    fs.nodes[ROOT]
    assert len(fs.nodes._made) == 1


def test_verification_walks_the_folder_as_it_is_now(evidence):
    """The opening may use a kept listing; verification never does -- a
    file planted below the top level must change the hash."""
    from trace_app.core.image_handler import ImageHandler
    open_folder(evidence)
    handler = ImageHandler(evidence)
    try:
        assert handler.logical_fs.listing_kept
        before = handler.calculate_hashes()['computed_sha256']
        with open(os.path.join(evidence, 'Alpha', 'm2', 'later.bin'),
                  'wb') as handle:
            handle.write(b'planted after the listing')
        assert handler.calculate_hashes()['computed_sha256'] != before
    finally:
        handler.close_resources()


def test_the_window_warns_and_audits_a_changed_folder(tmp_path,
                                                      monkeypatch):
    from types import SimpleNamespace
    from trace_app.core.case import Case
    from trace_app.ui import main_window
    warnings, statuses = [], []
    monkeypatch.setattr(main_window.message, 'warning',
                        lambda *args: warnings.append(args))
    case = Case.create(str(tmp_path / 'case'), 'Listing')
    window = SimpleNamespace(
        case=case, set_status=lambda text, ms=0: statuses.append(text),
        job_bar=SimpleNamespace(job_finished=lambda job, error=None: None))
    checked = main_window.MainWindow._folder_checked
    try:
        checked(window, 'job', '/x/phone', 'phone',
                [{'added': 0, 'removed': 0, 'changed': 0, 'checked': 9}],
                '')
        assert 'unchanged' in statuses[-1] and not warnings
        checked(window, 'job', '/x/phone', 'phone',
                [{'added': 2, 'removed': 0, 'changed': 1, 'checked': 9,
                  'saved': '2026-10-01 10:00:00',
                  'examples': ['added: /a', 'added: /b', 'changed: /c']}],
                '')
        assert len(warnings) == 1
        assert '2 added, 1 changed' in warnings[0][2]
        assert 'added: /a' in warnings[0][3]
        lines = [row for row in case.activity()
                 if row['action'] == 'folder evidence changed since listed']
        assert len(lines) == 1 and '2 added, 1 changed' in lines[0]['detail']
    finally:
        case.close()


def test_evidence_information_is_worked_out_once(tmp_path):
    """overview() is kept on the handler, and the shallow walks behind it
    give what the whole walk gave (they only look near the top)."""
    from trace_app.core import evidence_overview, walk
    from trace_app.core.image_handler import ImageHandler
    root = _tree(tmp_path / 'phone')
    (root / 'Logs').mkdir()
    (root / 'Logs' / 'extraction report.txt').write_text('hashes')
    deep = root / 'a' / 'b' / 'c' / 'd' / 'e'
    deep.mkdir(parents=True)
    (deep / 'build.prop').write_text('ro.product.model=Deep\n')
    handler = ImageHandler(str(root))
    try:
        assert not evidence_overview.overview_ready(handler)
        first = evidence_overview.overview(handler)
        assert evidence_overview.overview_ready(handler)
        assert evidence_overview.overview(handler) is first
        assert [row[1] for row in first['contents']] == [
            '/Logs/extraction report.txt']
        # Too deep for device facts, as before (path depth <= 4).
        assert first['device'] == {}
        everything = [e.path for e in walk.iter_files(handler)]
        shallow = [e.path for e in walk.iter_files(handler, max_depth=2)]
        assert shallow == [p for p in everything if p.count('/') <= 3]
    finally:
        handler.close_resources()


def test_file_rows_name_every_file_as_its_path_does(evidence):
    """The probe's fit and the module_fit job read (folder, name, size)
    rows; over the columns no node is made, and the rows are what
    path_of gives for each file node."""
    fs = open_folder(evidence)
    expected = []
    for inode, node in sorted(fs.nodes.items()):
        if not node.is_dir:
            folder = fs.path_of(node.parent)
            expected.append(('' if folder == '/' else folder, node.name,
                             node.size))
    again = open_folder(evidence)
    assert again.listing_kept
    assert list(again.file_rows()) == expected
    assert not again.nodes._made              # no node made for them
    assert ('', 'top.txt', 9) in expected
    # Nodes kept as a plain mapping (archives, backups) give the same.
    fs.nodes = dict(fs.nodes.items())
    assert list(fs.file_rows()) == expected
