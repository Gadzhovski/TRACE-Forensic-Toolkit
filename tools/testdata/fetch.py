"""Get TRACE's test data, check it, and say what is missing.

Everything lands in test_images/ (gitignored), one folder per group
(tools/testdata/__init__.py). Each file comes from its publisher and is kept
only if its SHA-256 matches the one recorded here; a file already present
is never overwritten -- one that differs is reported, not replaced.

    python -m tools.testdata.fetch                  # tier ci: what CI uses
    python -m tools.testdata.fetch --tier full      # everything public
    python -m tools.testdata.fetch --group nist     # one group
    python -m tools.testdata.fetch daylight.dd      # named images
    python -m tools.testdata.fetch --verify --tier full   # hash what is here
    python -m tools.testdata.fetch --list           # the catalog
    python -m tools.testdata.fetch --migrate        # old flat layout -> groups

Groups: ci (public, small: CI downloads it), samples (artifact files),
corpus (carving corpus, built from pinned files), local (public, big or
slow: maintainers' machines only), nist (NIST CFReDS sets), private (no
public source: verified when present, never fetched), built (made by the
Linux kernel's tools: tools/testdata/build/, Linux CI).
"""

import argparse
import bz2
import gzip
import hashlib
import os
import shutil
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tools import testdata  # noqa: E402
from tools.testdata import catalog, nist  # noqa: E402

TIERS = {'ci': ('ci', 'samples', 'corpus'),
         'full': ('ci', 'samples', 'corpus', 'local', 'nist')}
GROUPS = ('ci', 'samples', 'corpus', 'local', 'nist', 'private', 'built')
FOLDER = {'ci': testdata.CI, 'local': testdata.LOCAL,
          'private': testdata.PRIVATE, 'built': testdata.BUILT}


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def _download(url, target):
    """Fetch with retries and mirrors (tools/testdata/download.py)."""
    from tools.testdata.download import download
    download(url, target)


def _extract(archive, kind, name, target):
    """Write the file `name` from a downloaded `archive` to `target`."""
    if kind == 'raw':
        shutil.move(archive, target)
    elif kind == 'bz2':
        with bz2.open(archive, 'rb') as src, open(target, 'wb') as out:
            shutil.copyfileobj(src, out, 1 << 20)
    elif kind == 'gz':
        with gzip.open(archive, 'rb') as src, open(target, 'wb') as out:
            shutil.copyfileobj(src, out, 1 << 20)
    elif kind == 'zip':
        with zipfile.ZipFile(archive) as package:
            # macOS adds __MACOSX/._name resource forks; they share the
            # image's name and are not the image.
            members = [m for m in package.namelist()
                       if m.rsplit('/', 1)[-1] == name
                       and not m.startswith('__MACOSX/')]
            if len(members) != 1:
                raise RuntimeError(f"{name} not found once in the archive "
                                   f"(found {members})")
            with package.open(members[0]) as src, open(target, 'wb') as out:
                shutil.copyfileobj(src, out, 1 << 20)
    else:
        raise ValueError(kind)


def fetch_file(target, url, kind, expected, cache=None):
    """Make sure `target` exists with SHA-256 `expected`. Returns a status."""
    if os.path.exists(target):
        actual = sha256_of(target)
        return 'present' if actual == expected else \
            f'PRESENT BUT CHECKSUM DIFFERS ({actual}) -- left untouched'
    os.makedirs(os.path.dirname(target), exist_ok=True)
    cache = cache if cache is not None else {}
    name = os.path.basename(target)
    twin = testdata.locate(name)
    if twin and sha256_of(twin) == expected:
        # The same file in another group's folder (a NIST DFR image is both
        # in the CI set and in nist/dfr): a hard link, not a second copy.
        try:
            os.link(twin, target)
        except OSError:
            shutil.copyfile(twin, target)
        return f'linked to {os.path.relpath(twin, testdata.DATA)}'
    with tempfile.TemporaryDirectory() as work:
        archive = cache.get(url)
        if archive is None or not os.path.exists(archive):
            archive = os.path.join(work, 'download')
            _download(url, archive)
            if kind == 'zip':
                # Several images share one archive (the three ISOs): keep it
                # for this run rather than downloading it three times.
                kept = os.path.join(tempfile.gettempdir(),
                                    'trace-fetch-' + hashlib.sha256(
                                        url.encode()).hexdigest()[:16])
                shutil.copyfile(archive, kept)
                cache[url] = kept
        staged = os.path.join(work, name)
        _extract(archive, kind, name, staged)
        actual = sha256_of(staged)
        if actual != expected:
            raise RuntimeError(f"{name}: SHA-256 {actual} does not match the "
                               f"recorded {expected}; discarded")
        shutil.move(staged, target)
    return 'downloaded'


def _image_jobs(group, names=None):
    """(label, target, url, kind, sha256) for a catalog group of images."""
    entries = catalog.GROUPS[group]
    for name in (names or entries):
        url, kind, digest = entries[name]
        yield name, os.path.join(FOLDER[group], name), url, kind, digest


def _nist_jobs():
    for rel, (url, kind, digest, _size) in nist.FILES.items():
        yield ('nist/' + rel, os.path.join(testdata.NIST, *rel.split('/')),
               url, kind, digest)


def _extract_nist():
    """Unpack the archives the tests read unpacked (nist.EXTRACT)."""
    import py7zr
    for rel, folder in nist.EXTRACT.items():
        archive = os.path.join(testdata.NIST, *rel.split('/'))
        target = os.path.join(testdata.NIST, *folder.split('/'))
        top = os.path.basename(rel)[len('cfreds-2017-winreg_'):-len('.7z')]
        if not os.path.exists(archive) or \
                os.path.isdir(os.path.join(target, top)):
            continue
        print(f"  unpacking {rel} -> nist/{folder}/{top}", flush=True)
        with py7zr.SevenZipFile(archive) as package:
            package.extractall(target)


def run_jobs(jobs):
    cache, failed = {}, 0
    for label, target, url, kind, digest in jobs:
        try:
            status = fetch_file(target, url, kind, digest, cache)
        except Exception as exc:          # noqa: BLE001 -- reported, counted
            status, failed = f"FAILED: {exc}", failed + 1
        if status != 'present':
            print(f"{label:40} {status}", flush=True)
        if 'DIFFERS' in status:
            failed += 1
    for kept in cache.values():
        try:
            os.remove(kept)
        except OSError:
            pass
    return failed


def fetch_group(group):
    print(f"== {group}", flush=True)
    if group in ('ci', 'local'):
        return run_jobs(_image_jobs(group))
    if group == 'nist':
        failed = run_jobs(_nist_jobs())
        _extract_nist()
        return failed
    if group == 'samples':
        from tools.testdata import samples
        return samples.main()
    if group == 'corpus':
        from tools.testdata.build import carve_corpus
        return carve_corpus.main([])
    if group == 'private':
        missing = [n for n in catalog.PRIVATE
                   if not os.path.exists(os.path.join(testdata.PRIVATE, n))]
        for name in missing:
            print(f"{name:40} missing (no public source: copy it into "
                  f"test_images/private/)")
        return 0
    if group == 'built':
        print("built on Linux by tools/testdata/build/make_*.py (root)")
        return 0
    raise SystemExit(f"unknown group {group}")


def verify(groups):
    """Hash every file of `groups` that is here; list what is missing."""
    bad = 0
    for group in groups:
        rows = []
        if group in ('ci', 'local'):
            rows = [(label, target, digest)
                    for label, target, _u, _k, digest in _image_jobs(group)]
        elif group == 'private':
            rows = [(name, os.path.join(testdata.PRIVATE, name), digest)
                    for name, digest in catalog.PRIVATE.items()]
        elif group == 'nist':
            rows = [(label, target, digest)
                    for label, target, _u, _k, digest in _nist_jobs()]
        elif group == 'samples':
            from tools.testdata import samples
            rows = [(name, os.path.join(testdata.SAMPLES, name), digest)
                    for name, (_url, digest) in samples.SAMPLES.items()]
        elif group == 'corpus':
            # The image is deterministic; its answer key records its hash.
            import json
            truth = os.path.join(ROOT, 'tests', 'expected',
                                 'carve_ground_truth.json')
            with open(truth, encoding='utf-8') as handle:
                digest = json.load(handle)['carve-corpus.dd']['sha256']
            rows = [('carve-corpus.dd',
                     os.path.join(testdata.CORPUS, 'carve-corpus.dd'), digest)]
        present = missing = 0
        for label, target, digest in rows:
            if not os.path.exists(target):
                missing += 1
                continue
            present += 1
            if sha256_of(target) != digest:
                bad += 1
                print(f"  CHECKSUM DIFFERS: {label}")
        print(f"{group:8} {present} present and checked, {missing} missing",
              flush=True)
    return bad


# --- one-off: the old flat layout -> one folder per group ----------------------

_OLD_FOLDERS = {
    'artifact_samples': testdata.SAMPLES,
    'carve_samples': testdata.CORPUS_SAMPLES,
    'X-WaysTrainingImages': os.path.join(testdata.PRIVATE,
                                         'X-WaysTrainingImages'),
    # The Sleuth Kit's images, saved by hand before samples.py pinned them.
    'sleuthkit': os.path.join(testdata.SOURCES, 'sleuthkit-loose'),
}
_KEEP = {'README.md', 'TEST_RESULTS.md', '.gitignore', 'ci', 'local',
         'samples', 'corpus', 'built', 'nist', 'private', 'sources'}


def _destination(name):
    for group in ('ci', 'local', 'private', 'built'):
        if name in catalog.GROUPS[group]:
            return FOLDER[group]
    if name == 'carve-corpus.dd':
        return testdata.CORPUS
    if name.startswith(('md-', 'luks')) or name.startswith('btrfs-deleted'):
        return testdata.BUILT
    return None


def migrate():
    """Move files from the old flat test_images/ into their group folders.
    Renames only: nothing is copied over or deleted, except a second hard
    link to a file already in nist/dfr (the same file, not a copy)."""
    moved, left = 0, []
    for name in sorted(os.listdir(testdata.DATA)):
        if name in _KEEP:
            continue
        source = os.path.join(testdata.DATA, name)
        if name in _OLD_FOLDERS:
            target = _OLD_FOLDERS[name]
        elif name.startswith('dfr-') and os.path.exists(
                os.path.join(testdata.NIST, 'dfr', name)):
            twin = os.path.join(testdata.NIST, 'dfr', name)
            if os.path.samefile(source, twin):
                os.remove(source)              # a hard link: the file stays
                print(f"  {name}: second link to nist/dfr/{name} removed")
                continue
            left.append(f"{name} (differs from nist/dfr/{name})")
            continue
        else:
            folder = _destination(name)
            if folder is None:
                left.append(name)
                continue
            target = os.path.join(folder, name)
        if os.path.exists(target):
            left.append(f"{name} (already at {os.path.relpath(target, ROOT)})")
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        os.rename(source, target)
        moved += 1
        print(f"  {name} -> {os.path.relpath(target, testdata.DATA)}")
    print(f"{moved} moved")
    for name in left:
        print(f"  NOT MOVED: {name}")
    return 1 if left else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('names', nargs='*', help='images (ci or local)')
    parser.add_argument('--tier', choices=sorted(TIERS))
    parser.add_argument('--group', action='append', choices=GROUPS)
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--migrate', action='store_true')
    args = parser.parse_args(argv)

    if args.migrate:
        return migrate()
    groups = args.group or list(TIERS[args.tier or 'ci'])
    if args.verify:
        return 1 if verify(groups + (['private'] if args.tier == 'full'
                                     else [])) else 0
    if args.list:
        for group in ('ci', 'local'):
            for name, (url, kind, _d) in catalog.GROUPS[group].items():
                print(f"{group:6} {name:46} {kind:4} {url}")
        for name in catalog.PRIVATE:
            print(f"{'private':6} {name}")
        print(f"nist   {len(nist.FILES)} files (tools/testdata/nist.py)")
        return 0
    if args.names:
        jobs = []
        for name in args.names:
            group = catalog.group_of(name)
            if group not in ('ci', 'local'):
                print(f"{name}: not a downloadable image ({group})",
                      file=sys.stderr)
                return 2
            jobs += list(_image_jobs(group, [name]))
        return 1 if run_jobs(jobs) else 0
    failed = sum(fetch_group(group) or 0 for group in groups)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
