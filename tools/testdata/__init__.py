"""Where TRACE's test data lives, in one place.

Everything is under test_images/ (gitignored but for its READMEs), one
folder per group -- the group says where a file comes from and whether CI
has it:

    ci/        public images CI downloads (catalog group 'ci')
    local/     public images too big or slow for CI ('local')
    samples/   artifact files: hives, logs, databases, small images
               (tools/testdata/samples.py), CI downloads them
    corpus/    the carving corpus: its source files (samples/) and the
               image tools/testdata/build/carve_corpus.py builds from them
    built/     images the Linux kernel's own tools make in CI
               (btrfs-deleted, md RAID, LUKS + LVM)
    nist/      NIST CFReDS sets: dfr/ carving/ containers/ russian/ winreg/
    private/   evidence with no public source: never in CI
    sources/   whole copies of upstream test-data repositories (dfvfs,
               sleuthkit_test_data), kept for reference

Tests ask for a file by name (`locate`); nothing builds these paths by hand.

TRACE_TEST_TIER (set by tools/run_tests.py for the test run, never needed
otherwise) limits which folders exist for a run: 'quick' -- none, so every
test that reads data skips; 'ci' -- only what CI has (ci, samples, corpus,
built on Linux), so a local 'ci' run reads exactly what CI reads; 'full' (default)
-- everything. A folder outside the tier points at a path that does not
exist, so a test cannot read it by any route.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
DATA = os.path.join(ROOT, 'test_images')

TIER = os.environ.get('TRACE_TEST_TIER', 'full')
#: The groups CI has: the images the kernel's tools build only on Linux.
CI_GROUPS = ('ci', 'samples', 'corpus') + (
    ('built',) if sys.platform.startswith('linux') else ())


def _folder(group, *parts):
    if TIER == 'quick' or (TIER == 'ci' and group not in CI_GROUPS):
        return os.path.join(DATA, '.not-in-tier-' + TIER, group, *parts)
    return os.path.join(DATA, group, *parts)


CI = _folder('ci')
LOCAL = _folder('local')
SAMPLES = _folder('samples')
CORPUS = _folder('corpus')
CORPUS_SAMPLES = _folder('corpus', 'samples')
BUILT = _folder('built')
NIST = _folder('nist')
PRIVATE = _folder('private')
SOURCES = _folder('sources')

#: Where an image is looked for by name, in order.
IMAGE_FOLDERS = (CI, LOCAL, BUILT, CORPUS, PRIVATE,
                 os.path.join(NIST, 'dfr'))

#: How to get each group, for messages.
HOW = {
    'ci': "python -m tools.testdata.fetch --group ci",
    'local': "python -m tools.testdata.fetch --group local",
    'samples': "python -m tools.testdata.fetch --group samples",
    'corpus': "python -m tools.testdata.fetch --group corpus",
    'built': "sudo python3 tools/testdata/build/make_<name>.py (Linux)",
    'nist': "python -m tools.testdata.fetch --group nist",
    'private': "no public source: copy it into test_images/private/",
}


def locate(name):
    """The path of the image `name`, or None when it is not here."""
    for folder in IMAGE_FOLDERS:
        path = os.path.join(folder, name)
        if os.path.exists(path):
            return path
    return None


def group_of(name):
    """The catalog group of an image (`catalog.group_of`)."""
    from tools.testdata.catalog import group_of as find
    return find(name)


def how_to_get(name):
    """One line saying how to get `name`."""
    group = group_of(name)
    if group is None:
        return f"{name} is not in the catalog (tools/testdata/catalog.py)"
    return f"{name} ({group}): {HOW.get(group, HOW['local'])}"
