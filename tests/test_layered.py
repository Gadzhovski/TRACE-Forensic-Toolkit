"""File systems layered in one partition (ImageHandler.fs_layers): DFTT
#10, "NTFS Autodetect", whose every partition was formatted NTFS, then
formatted again as Ext2, UFS2 or UFS1 without being wiped -- both file
systems intact and mountable.

The test's question is whether a tool warns that there are two, or shows
one and hides the other. The Sleuth Kit's detection refuses such a
partition outright, so TRACE showed each as empty -- worse than either.
Now each file system is opened on its own, named, and read by every
module; the file each one's root holds says which side is which (the
authors' own answer: ntfs.txt, ext2.txt, ufs1.txt).
"""

import pytest

from tests.conftest import image_path

DISK = '10-ntfs-disk.dd'
PART3 = '10-ntfs-part3.dd'


def handler_for(name):
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path(name))
    assert handler.loaded
    return handler


def root_files(handler, key):
    return {e['name'].lower(): e for e in
            handler.get_directory_contents(key, None)
            if not e['name'].startswith('$') and not e.get('is_directory')}


@pytest.mark.parametrize('name, start, layers, texts', [
    (DISK, 63, ['NTFS', 'Ext2'],
     {'ntfs.txt': b'"This is the NTFS side of the partition."',
      'ext2.txt': b'This is the EXT2 side of the partition.'}),
    (DISK, 96390, ['NTFS', 'UFS2'],
     {'ntfs.txt': b'"This is the NTFS side of the partition."',
      'ufs1.txt': b'This is the UFS1 side of the partition.'}),
    (PART3, 0, ['NTFS', 'UFS1'], {'ntfs.txt': None, 'ufs1.txt': None}),
])
def test_both_file_systems_are_opened_and_named(name, start, layers, texts):
    handler = handler_for(name)
    try:
        assert handler.get_fs_info(start) is None    # TSK alone: neither
        found = handler.fs_layers(start)
        assert [layer['name'] for layer in found] == layers
        files = {}
        for layer in found:
            files.update({n: (layer['key'], e) for n, e in
                          root_files(handler, layer['key']).items()})
        assert set(files) == set(texts)
        for file_name, text in texts.items():
            if text is None:
                continue
            key, entry = files[file_name]
            data, _meta = handler.get_file_content(entry['inode_number'],
                                                   key)
            assert data.startswith(text)
        # Every reader takes the layers in the partition's place.
        offsets = handler.volume_offsets()
        assert start not in offsets
        assert all(layer['key'] in offsets for layer in found)
    finally:
        handler.close_resources()


def test_an_ordinary_partition_has_no_layers():
    handler = handler_for(DISK)
    try:
        assert handler.fs_layers(0) == []          # the table, not a volume
    finally:
        handler.close_resources()


def test_carving_skips_live_data_of_both(tmp_path):
    from trace_app.core import carving
    handler = handler_for(DISK)
    try:
        ranges = carving.allocation_map(handler)
        texts = [handler.read(b, e - b) for b, e in ranges]
        joined = b''.join(texts)
        assert b'This is the EXT2 side' in joined
        assert b'This is the NTFS side' in joined
        assert b'This is the UFS1 side' in joined
    finally:
        handler.close_resources()


def test_analysis_and_profile_read_both(tmp_path):
    from trace_app.core import evidence_profile
    from trace_app.core.walk import iter_files
    handler = handler_for(PART3)
    try:
        names = {entry.name.lower() for entry in iter_files(handler)}
        summary = evidence_profile.profile(handler)['summary']
        assert 'NTFS' in summary and 'UFS1' in summary
    finally:
        handler.close_resources()
    assert {'ntfs.txt', 'ufs1.txt'} <= names


def test_the_tree_shows_both_layers(qapp):
    from PySide6.QtCore import Qt
    from trace_app.ui.main_window import MainWindow
    window = MainWindow()
    try:
        assert window.open_evidence_image(image_path(DISK))
        tree = window.tree_viewer
        root = tree.topLevelItem(tree.topLevelItemCount() - 1)
        groups = [root.child(i) for i in range(root.childCount())
                  if (root.child(i).data(0, Qt.UserRole) or {})
                  .get('is_volume_group')]
        assert len(groups) == 2
        assert all('2 file systems layered' in g.text(0) for g in groups)
        labels = [[g.child(i).text(0) for i in range(g.childCount())]
                  for g in groups]
        assert labels == [['NTFS / exFAT (0x07) @ 63 — NTFS (layered)',
                           'NTFS / exFAT (0x07) @ 63 — Ext2 (layered)'],
                          ['NTFS / exFAT (0x07) @ 96390 — NTFS (layered)',
                           'NTFS / exFAT (0x07) @ 96390 — UFS2 (layered)']]
        assert 'formatted again' in groups[0].toolTip(0)
    finally:
        window.cleanup_resources()
