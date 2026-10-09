"""Image handling: what TRACE reads out of evidence must not change.

Each public test image has a manifest in tests/expected/manifests -- every partition,
volume, file and directory with its inode, size, deleted flag, timestamps and
content hash -- recorded when the result was last checked against the old
engine and the raw on-disk bytes. A fresh walk must match it exactly, on every
platform and Python version, which is what proves an engine upgrade or a
platform difference has not changed what an examiner is told.
"""

import glob
import hashlib
import json
import os
import subprocess
import sys

import pytest

from tests.conftest import ROOT, image_path

MANIFESTS = sorted(glob.glob(os.path.join(ROOT, 'tests', 'expected', 'manifests',
                                          '*.manifest.json')))
pytestmark = pytest.mark.images


def _load(path):
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)


def _describe(expected, actual):
    """A readable account of the first differences, for the failure."""
    lines = []
    for key in ('partitions', 'stored_hashes'):
        if expected[key] != actual[key]:
            lines.append(f"{key}: {expected[key]} != {actual[key]}")
    if len(expected['volumes']) != len(actual['volumes']):
        lines.append(f"volumes: {len(expected['volumes'])} != "
                     f"{len(actual['volumes'])}")
    for ev, av in zip(expected['volumes'], actual['volumes']):
        want = {(e['path'], e.get('inode')): e for e in ev['entries']}
        got = {(e['path'], e.get('inode')): e for e in av['entries']}
        for key in sorted(set(want) | set(got), key=str):
            if want.get(key) != got.get(key):
                lines.append(f"{key}: expected {want.get(key)} got "
                             f"{got.get(key)}")
            if len(lines) > 12:
                return '\n'.join(lines + ['...'])
    return '\n'.join(lines)


@pytest.mark.parametrize('manifest', MANIFESTS,
                         ids=[os.path.basename(m).replace('.manifest.json', '')
                              for m in MANIFESTS])
def test_walk_matches_manifest(manifest):
    from trace_app.core.manifest import build_manifest
    expected = _load(manifest)
    actual = build_manifest(image_path(expected['image']))
    assert actual == expected, _describe(expected, actual)


@pytest.mark.parametrize('name', ['7-ntfs-undel.dd', 'ntfs1-gen2.E01',
                                  'image.gen1.dmg', 'dfr-01-xfat.dd',
                                  '6-fat-undel.dd', 'ext3-img-kw-1.dd'])
def test_trace_reads_every_file_byte_for_byte(name):
    """Through ImageHandler.get_file_content -- the path the viewers use --
    every file's bytes hash to what the manifest recorded."""
    from trace_app.core.image_handler import ImageHandler
    manifest = _load(os.path.join(ROOT, 'tests', 'expected', 'manifests',
                                  f'{name}.manifest.json'))
    handler = ImageHandler(image_path(name))
    try:
        checked = 0
        for volume in manifest['volumes']:
            for entry in volume['entries']:
                digest = entry.get('sha256')
                if not digest or ':' in digest:
                    continue
                content, _ = handler.get_file_content(entry['inode'],
                                                      volume['offset'])
                assert hashlib.sha256(content or b'').hexdigest() == digest, \
                    entry['path']
                checked += 1
        assert checked, f"{name}: no files were checked"
    finally:
        handler.close_resources()


def test_deleted_ntfs_files_are_listed_and_recoverable():
    """DFTT #7 plants six deleted files; the listing must flag them as
    deleted and still reach their content."""
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path('7-ntfs-undel.dd'))
    try:
        offset = 0 if not handler.get_partitions() else \
            handler.get_partitions()[0][2]
        entries = handler.get_directory_contents(
            offset, handler.get_root_inode(offset))
        deleted = [e for e in entries if e.get('is_deleted')
                   and not e.get('is_directory')]
        assert len(deleted) >= 4, [e['name'] for e in entries]
        readable = [e for e in deleted if e.get('is_recoverable')
                    and handler.get_file_content(e['inode_number'],
                                                 offset)[0]]
        assert readable, "no deleted file could be read back"
    finally:
        handler.close_resources()


def test_e01_verifies_against_its_stored_hash():
    from trace_app.core.image_handler import ImageHandler
    handler = ImageHandler(image_path('ntfs1-gen2.E01'))
    try:
        result = handler.calculate_hashes()
    finally:
        handler.close_resources()
    assert result['stored_md5'], "the E01's acquisition MD5 was not read"
    assert result['computed_md5'] == result['stored_md5']


def test_fat_times_are_the_stored_digits_whatever_the_machine_zone():
    """FAT stores wall-clock time with no zone. TRACE must show the digits on
    disk -- 15:00:04 for DFTT #5's summer.txt -- whatever time zone the
    examiner's machine is in. Run in a child process with a non-UTC zone set
    before TRACE loads, which is what made the new engine shift them."""
    zone = 'EST5EDT' if sys.platform == 'win32' else 'America/New_York'
    script = (
        "import sys; sys.path.insert(0, %r)\n"
        "from trace_app.core.image_handler import ImageHandler\n"
        "h = ImageHandler(%r)\n"
        "e = [x for x in h.get_directory_contents(0, h.get_root_inode(0))"
        " if x['name'] == 'summer.txt'][0]\n"
        "print(e['modified'])\n" % (ROOT, image_path('daylight.dd')))
    env = dict(os.environ, TZ=zone)
    shown = subprocess.run([sys.executable, '-c', script], env=env,
                           capture_output=True, text=True, timeout=120)
    assert shown.returncode == 0, shown.stderr
    assert shown.stdout.strip() == '2004-06-01 15:00:04 (local, no zone)', \
        shown.stdout


def test_unmountable_carving_images_report_no_volume():
    """DFTT #11/#12 are deliberately unmountable: their files are reachable
    only by carving. TRACE must not invent a file system for them."""
    from trace_app.core.image_handler import ImageHandler
    for name in ('11-carve-fat.dd', '12-carve-ext2.dd'):
        handler = ImageHandler(image_path(name))
        try:
            assert handler.loaded
            assert not handler.has_filesystem(0)
        finally:
            handler.close_resources()
