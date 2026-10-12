"""ext block maps read by TRACE (core/ext_blockmap.py) and the files of
deleted ext folders (core/ext_folders.py).

The Sleuth Kit is the reference for the block maps: with the threshold
forced to 0, every block-mapped regular file read through TRACE's own
block map must have TSK's metadata, TSK's runs and TSK's bytes. The
deleted folders are checked against NIST's DFR-11 key -- every file name
NIST deleted inside a folder.
"""

import hashlib
import json
import os
import time

import pytest
import pytsk3

from tests.conftest import ROOT, data_path, image_path

FIELDS = ('addr', 'size', 'type', 'mode', 'nlink', 'uid', 'gid', 'flags',
          'seq', 'atime', 'mtime', 'ctime', 'crtime', 'atime_nano',
          'mtime_nano', 'ctime_nano', 'crtime_nano')


def _runs(handle):
    """Merged, non-sparse runs of the default data attribute."""
    merged = []
    for attribute in handle:
        if int(attribute.info.type) != pytsk3.TSK_FS_ATTR_TYPE_DEFAULT:
            continue
        for run in attribute:
            if not run.len or int(run.flags) & \
                    pytsk3.TSK_FS_ATTR_RUN_FLAG_SPARSE:
                continue
            offset, addr, length = int(run.offset), int(run.addr), \
                int(run.len)
            if merged and merged[-1][0] + merged[-1][2] == offset and \
                    merged[-1][1] + merged[-1][2] == addr:
                merged[-1] = (merged[-1][0], merged[-1][1],
                              merged[-1][2] + length)
            else:
                merged.append((offset, addr, length))
    return merged


def _compare_with_tsk(path, monkeypatch):
    """(files compared, [differences]) for every block-mapped regular file."""
    from trace_app.core import ext_blockmap
    from trace_app.core.image_handler import ImageHandler
    monkeypatch.setattr(ext_blockmap, 'MANY_BLOCKS', 0)
    handler = ImageHandler(path)
    compared, problems = 0, []
    try:
        starts = [p[2] for p in handler.get_partitions()] or [0]
        for start in starts:
            fs = handler.get_fs_info(start)
            if not isinstance(fs, ext_blockmap.ExtFileSystem):
                continue
            for number in range(1, fs.geometry.inodes_count + 1):
                ours = fs.mapped(number)
                if ours is None:
                    continue
                try:
                    theirs = fs._fs.open_meta(inode=number)
                except (IOError, OSError):
                    continue
                meta = theirs.info.meta
                if meta is None or \
                        int(meta.type) != pytsk3.TSK_FS_META_TYPE_REG:
                    continue
                compared += 1
                for field in FIELDS:
                    if getattr(meta, field, None) is not None and \
                            int(getattr(meta, field)) != \
                            int(getattr(ours.info.meta, field)):
                        problems.append((start, number, field))
                if _runs(theirs) != _runs(ours):
                    problems.append((start, number, 'runs'))
                size = int(meta.size)
                try:
                    expected = theirs.read_random(0, size) if size else b''
                except (IOError, OSError):
                    continue                # TSK cannot read it either
                if hashlib.sha256(expected).digest() != \
                        hashlib.sha256(ours.read_random(0, size)).digest():
                    problems.append((start, number, 'content'))
    finally:
        handler.close_resources()
    return compared, problems


def test_block_maps_read_as_the_sleuth_kit_reads_them(monkeypatch):
    """DFTT #4's ext3 volume: every block-mapped file, TRACE against TSK --
    metadata, runs (TSK lists blocks a file holds past its size too) and
    every byte."""
    compared, problems = _compare_with_tsk(image_path('ext3-img-kw-1.dd'),
                                           monkeypatch)
    assert compared >= 4
    assert problems == []


@pytest.mark.parametrize('image', ['dfr-07-ext.dd', 'dfr-10-ext.dd'])
def test_nist_ext_files_read_as_the_sleuth_kit_reads_them(image,
                                                          monkeypatch):
    """NIST's ext2/3/4 images (local): hundreds of files, deleted ones,
    and the 300 MB filler of 132,000 TSK runs -- all equal to TSK."""
    compared, problems = _compare_with_tsk(data_path('nist', 'dfr', image),
                                           monkeypatch)
    assert compared >= 10
    assert problems == []


def test_a_file_of_132000_runs_opens_at_once():
    """TSK takes 40 s to open NIST's FILL.TXT on ext2 and ext3, on every
    open. Through TRACE it opens in well under a second, and reads whole."""
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(data_path('nist', 'dfr', 'dfr-07-ext.dd'))
    try:
        for start in (61, 651236):                  # ext2, ext3
            fs = handler.get_fs_info(start)
            inode = next(e.info.meta.addr for e in fs.open_dir('/')
                         if e.info.name.name == b'FILL.TXT')
            began = time.time()
            handle = fs.open_meta(inode=inode)
            assert time.time() - began < 5
            data = handle.read_random(0, int(handle.info.meta.size))
            assert len(data) == int(handle.info.meta.size) > 300_000_000
            # NIST's filler is self-describing too: its first block says so.
            assert data[:9] == b'\nDFR\nFile' or data[:4] == b'\nDFR'
    finally:
        handler.close_resources()


def test_files_of_deleted_folders_are_named_on_every_ext():
    """NIST's DFR-11: one folder deleted with three files on each of ext2,
    ext3 and ext4. ext2 left the folder's entry pointing nowhere, ext3
    emptied its inode, ext4 zeroed its extents -- the files were nameless
    orphans or missing. Every name NIST deleted is listed, in its folder."""
    from trace_app.core import deleted
    from trace_app.core.image_handler import ImageHandler
    with open(os.path.join(ROOT, 'tests', 'expected',
                           'nist_dfr_ground_truth.json'),
              encoding='utf-8') as handle:
        key = json.load(handle)
    key = key.get('images', key)['ext-11']
    handler = ImageHandler(data_path('nist', 'dfr', 'dfr-11-ext.dd'))
    try:
        paths = {r['path'] for r in deleted.deleted_files(handler)}
    finally:
        handler.close_resources()
    for item in key['deleted']:
        assert any(path.endswith('/' + item['name']) and
                   not path.startswith('/$OrphanFiles')
                   for path in paths), item['name']
    for folder, names in (('/Orion', ('Rigel.txt', 'Mintaka.txt',
                                      'Betelguese.txt')),
                          ('/Andromeda', ('Alpheratz.txt', 'Mirach.txt',
                                          'Adhil.txt')),
                          ('/Lyra', ('Sheliak.txt', 'Vega.txt',
                                     'Sulafat.txt'))):
        for name in names:
            assert f"{folder}/{name}" in paths
