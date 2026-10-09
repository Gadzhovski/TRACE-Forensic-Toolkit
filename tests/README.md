# How TRACE is tested

Three things, each in one place:

| What | Where | Committed? |
|---|---|---|
| The tests | `tests/test_*.py` (pytest) | yes |
| What the answers must be, from outside TRACE | `tests/expected/` | yes |
| The evidence the tests read | `test_images/` | **no** (gitignored, ~95 GB here) |
| Getting the evidence, scoring, running | `tools/` | yes |

Expected values never come from TRACE's own output. They are the answer
keys and documentation the publishers wrote: DFTT, DFRWS, NIST CFReDS, The
Sleuth Kit's DFXML, plaso's test values. The one exception is the manifests
(`tests/expected/manifests/`). They record how each image reads, and were
checked by hand against the raw bytes before they were committed.

## The test data: `test_images/`

One folder, never committed, one sub-folder per **group**. The group says
where the data comes from and whether CI has it.

```
test_images/
  ci/        public images CI uses: DFTT, NPS, AFF4, Btrfs, media,
             two NIST DFR images (38 files, tools/testdata/catalog.py: CI)
  samples/   artifact files: registry hives, event logs, browser databases,
             phone backups, small images (tools/testdata/samples.py)    -- CI too
  corpus/    the carving corpus: 60+ real published files (samples/) and the
             image built from them, carve-corpus.dd                       -- CI too
  built/     images the Linux kernel's tools make: Btrfs with deleted files,
             md RAID, LUKS + LVM (tools/testdata/build/)            -- Linux CI
  local/     public but too big or slow for CI: DFRWS 2006/2007, NPS
             domexusers (4.4 GB), ubnist1, Fedora 44 (catalog.py: LOCAL)
  nist/      NIST CFReDS: dfr/ carving/ containers/ russian/ winreg/
             (81 GB, tools/testdata/nist.py)
  private/   no public source: never fetched, never in CI (catalog.py: PRIVATE)
  sources/   whole copies of upstream test-data repositories (dfvfs,
             sleuthkit_test_data), for reference
```

Every file is pinned by SHA-256 in the catalogs. A file whose hash does
not match is never kept, and a file already here is never overwritten.

```bash
python -m tools.testdata.fetch                   # the CI set (what CI has)
python -m tools.testdata.fetch --tier full       # everything public (~85 GB)
python -m tools.testdata.fetch --group nist      # one group
python -m tools.testdata.fetch --verify --tier full   # hash-check what is here
python -m tools.testdata.fetch --list
```

Tests never build a path into `test_images/` by hand. They call:

- `image_path(name)`, which finds an image in whichever group folder holds it;
- `data_path(group, ...)`, for samples, corpus, nist, local or private files;
- the folder constants in `tools.testdata` (`SAMPLES`, `NIST`, ...).

When the data is not here, the test skips and says how to get it. In CI
(`TRACE_REQUIRE_IMAGES=1`), a missing file of the CI set fails instead, so
CI cannot pass by quietly testing nothing.

## Three tiers

```bash
python tools/run_tests.py quick   # no data at all: ~1 minute. Before a commit.
python tools/run_tests.py ci      # exactly what CI reads (needs the CI set)
python tools/run_tests.py full    # everything here + both scores. On the
                                  # Windows PC, the Mac and the Linux VM.
python tools/run_tests.py full -- -k nist -x      # extra pytest arguments
```

The tier reaches the tests as `TRACE_TEST_TIER`. Folders outside the tier
do not exist for that run, so no test can read them by any route. A local
`ci` run therefore reads exactly what CI reads, and its skip list is the
set of tests that run only on your machines.

`full` also runs the two scores:

- `tools/score/carve_score.py` scores the carver against every published
  carving key present (DFTT #11/#12, DFRWS 2006/2007, NIST L0–L5, the
  corpus). It fails if any score drops below the baseline recorded in it.
- `tools/score/dfr_score.py` scores Deleted Files against NIST's DFR answer
  key (`tests/expected/nist_dfr_ground_truth.json`). It fails if any
  deleted file is called recoverable when it is not.

## CI (`.github/workflows/tests.yml`)

CI uses **only the CI set**. That is `ci/` plus `samples/`, `corpus/` and,
on Linux, `built/`: 4.1 GB on disk, but about 500 MB compressed as GitHub
stores it, because most of the images are zeros. Nothing from `local/`, `nist/` or `private/` ever
runs in CI.

- **What runs** is chosen by `tools/testdata/ci_select.py` from what the
  push changed: the test files that import the changed code, and only the
  data groups those files read. A change it cannot place runs every test:
  the installers, requirements, the shared setup, image access, or a module
  no test imports directly. Run `python tools/testdata/ci_select.py` to
  see what your branch would run.
- **Where it runs:**
  - a branch push: Ubuntu, Python 3.12;
  - master and pull requests: Windows, macOS (Apple Silicon and Intel) and
    Linux, on Python 3.10 and 3.14;
  - the weekly and manual runs: everything, adding Python 3.12.
- **Downloads happen once.** Each data group is one GitHub cache, keyed
  only by its catalog file, and shared by all four operating systems. The
  first run downloads from the publishers and saves the cache. Every later
  run restores it from GitHub in seconds. Only master, weekly and manual
  runs save caches, so branches never fill the repository's 10 GB with
  copies. A cache unused for 7 days is dropped; the weekly run keeps the
  caches alive.

## Answer keys and how they were made

| Key | Made by | From |
|---|---|---|
| `tests/expected/carve_ground_truth.json` | hand-transcribed, plus `tools/score/nist_carving_truth.py` | DFTT/DFRWS published keys; NIST's layouts, confirmed by the bytes |
| `tests/expected/nist_dfr_ground_truth.json` | `tools/score/nist_dfr_key.py` | NIST's 290-page DFR answer key PDF |
| `tests/expected/manifests/` | `python -m tests.manifest` | each image, checked by hand against its raw bytes |

## Tools at a glance

```
tools/
  run_tests.py            the three tiers
  fetch_test_images.py    old name, kept: = python -m tools.testdata.fetch
  testdata/               the data: layout (__init__), catalog, nist, samples,
                          fetch, download, ci_select, build/ (corpus, Linux images)
  score/                  carve_score, dfr_score and the key parsers
```
