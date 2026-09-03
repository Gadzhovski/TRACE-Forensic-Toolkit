# Test images

Disk images used to verify TRACE. **Nothing in this directory except this file
is committed** — `.gitignore` excludes every image extension at any depth. The
images are recorded here rather than stored in git so a checkout can be
reconstructed without carrying a gigabyte of evidence in history.

Verify a download before trusting a result from it: a truncated image produces
carving failures that look like tool defects.

## Carving corpora (published ground truth)

Each of these ships an answer key naming every planted file, its MD5, its size
and its sector runs. Those keys are transcribed into
`tools/carve_ground_truth.json` and scored by `tools/carve_score.py`.

| File | Size | Filesystem | Source |
|---|---|---|---|
| `11-carve-fat.dd` | 62 MB | FAT32 | [DFTT #11](https://dftt.sourceforge.net/test11/index.html) |
| `12-carve-ext2.dd` | 124 MB | Ext2 | [DFTT #12](https://dftt.sourceforge.net/test12/index.html) |
| `9-fat-label.dd` | 9.9 MB | FAT | [DFTT #9](https://dftt.sourceforge.net/test9/index.html) |
| `dfrws-2006-challenge.raw` | 48 MB | none (raw) | [DFRWS 2006](https://github.com/dfrws/dfrws2006-challenge) |
| `dfrws-2007-challenge.img` | 331 MB | none (raw) | [DFRWS 2007](https://github.com/dfrws/dfrws2007-challenge) |

### What each corpus is for

**DFTT #11 and #12** are ordinary filesystems holding ordinary files, and they
test the basics honestly. `11-carve-fat.dd` deliberately includes `haxor2.jpg`
with one byte corrupted at offset 19, which **must be rejected** — the test
exists, in the authors' words, "to show the importance of ignoring corrupted
files". `pumpkin.jpg` is an EXIF photo whose embedded thumbnail terminates with
`FFD9` before the image does, so a carver taking the first footer truncates it.
`surf.mov` begins at a `moov` atom with no `ftyp`. The boot sector is corrupted
on purpose, so the volume will not mount. `12-carve-ext2.dd` fragments almost
everything across indirect blocks; only `main_dive.jpg` is contiguous.

**DFRWS 2006 and 2007** are raw images with no filesystem, built specifically
to break carvers. 2006 lays out 32 files in 22 named scenarios, several of
which target carving heuristics directly:

- **3c** plants a lone sector beginning `0xFFD8` immediately before a real JPEG
- **3j** plants a sector beginning `0xFFD9` *inside* a JPEG
- **3g** places one complete JPEG inside another's fragmentation gap
- **3i** is a 24 MB JPEG, larger than many tools' default maximum
- **1d**, **3h** intertwine two files of the same type

2007 deepened this: 54 files of types TRACE carves, of which **only 5 are
contiguous**. It also contains MP3, MPG, EXE, FLV, AVI and mbox data that TRACE
does not carve and the harness does not score.

## Other images

| File | Size | Notes |
|---|---|---|
| `2020JimmyWilson.E01` | 296 MB | NTFS, E01. General browsing and verification. |
| `BXS-1.E01` | 152 MB | NTFS, E01. The image the I/O constants work was measured against. |
| `Op Archway AXA-1.E01` | 123 MB | NTFS, E01. |

## Checksums

The two DFRWS images were verified against the MD5s their organisers published,
and both matched on download:

```
bd09d612fc8b3f92662b98f9456f2ada  dfrws-2006-challenge.raw   (published)
8a501f3f525c85a50a3aa0bf698bffe7  dfrws-2007-challenge.img   (published)
```

SHA-256 of everything here as downloaded:

```
83585232e908529286f1ff04c43b4d858604875c733183a9e3b44a07ff818d26  11-carve-fat.dd
ffeb78b6cf8eed64c241212fb5cd1f3d226dcd58e16b67192f465e4a3ec46342  12-carve-ext2.dd
ca312b0582c78e1b379eca318aa7a9d7fc4a809bfcfd25be093f5298e72a81ab  9-fat-label.dd
9d24547c9d8a17602ee5a8ecf960ff8cc2ee48575ffc127cd084b3b0a484d1dd  dfrws-2006-challenge.raw
ace31ac34503bf3f56acd7cfe729a1f701f17e6fc2c202de7ccbb7ea58bc3a2c  dfrws-2007-challenge.img
6c18f662744d55e2769d9510f6173f04dab668c42b67ef27b675d22e628b4ed5  2020JimmyWilson.E01
1196221c27515e4f9a5c855da529e006bd9bebfbc5703d37bb419476ea0db55d  BXS-1.E01
a621e46b88a6366c90cc5bc7d412b46f3f012a08b1fd7d3fcbea2d78b761af1d  Op Archway AXA-1.E01
```

## Re-downloading

```bash
curl -L -o dfrws-2006-challenge.zip \
  "https://www.dropbox.com/s/genp058scvl8hbp/dfrws-2006-challenge.zip?dl=1"
curl -L -o dfrws-2007-challenge.zip \
  "https://www.dropbox.com/s/5ze0r2o1vjxf811/dfrws-2007-challenge.zip?dl=1"
unzip dfrws-2006-challenge.zip && unzip dfrws-2007-challenge.zip
```

The DFTT images come from <https://dftt.sourceforge.net/>, one page per test.

## Scoring the carvers

```bash
python tools/carve_score.py                  # every image with a known key
python tools/carve_score.py 11-carve-fat.dd  # one image
```

Exits non-zero if a score falls below the baseline recorded in that script.
The score counts files **located**; byte-exactness is reported separately,
because a fragmented file cannot be reproduced by a contiguous carver and
counting that as a failure would measure the wrong thing.
