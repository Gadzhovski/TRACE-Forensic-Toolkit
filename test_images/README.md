# Test images

Disk images used to verify TRACE. **Nothing in this directory except this file
is committed** — `.gitignore` excludes every image extension at any depth. The
images are recorded here rather than stored in git so a checkout can be
reconstructed without carrying hundreds of megabytes of evidence in history.

Verify a download before trusting a result from it: a truncated image produces
carving failures that look like tool defects.

```bash
sha256sum -c test_images/SHA256SUMS   # if you keep one
```

## Carving test images (published ground truth)

These come from the **Digital Forensics Tool Testing** project (DFTT), created
by Brian Carrier and Nick Mikus. Each has a documented answer key naming every
planted file, its MD5, its size and its sector runs. That key is transcribed
into `tools/carve_ground_truth.json` and scored by `tools/carve_score.py`.

| File | Size | FS | Source |
|---|---|---|---|
| `11-carve-fat.dd` | 62 MB | FAT32 | <https://dftt.sourceforge.net/test11/index.html> |
| `12-carve-ext2.dd` | 124 MB | Ext2 | <https://dftt.sourceforge.net/test12/index.html> |
| `9-fat-label.dd` | 9.9 MB | FAT | <https://dftt.sourceforge.net/test9/index.html> |

Both carving images deliberately include cases a naive carver gets wrong:

- **`11-carve-fat.dd`** — 15 files. `haxor2.jpg` has one byte corrupted at
  offset 19 and **must be rejected**; the test exists, in the authors' words,
  "to show the importance of ignoring corrupted files". `pumpkin.jpg` is an EXIF
  JPEG whose embedded thumbnail terminates with `FFD9` *before* the image does,
  so a carver taking the first footer truncates it. `surf.mov` begins with a
  `free` atom rather than `ftyp`. The boot sector is corrupted on purpose, so
  the volume will not mount.
- **`12-carve-ext2.dd`** — 10 files, several fragmented across indirect blocks.
  `n_lin_ss.pdf` spans a double-indirect chain.

## Other images

| File | Size | Notes |
|---|---|---|
| `2020JimmyWilson.E01` | 296 MB | NTFS, E01. General browsing/verification. |
| `BXS-1.E01` | 152 MB | NTFS, E01. The image the I/O constants work was measured against. |
| `Op Archway AXA-1.E01` | 123 MB | NTFS, E01. |

## SHA-256

```
83585232e908529286f1ff04c43b4d858604875c733183a9e3b44a07ff818d26  11-carve-fat.dd
ffeb78b6cf8eed64c241212fb5cd1f3d226dcd58e16b67192f465e4a3ec46342  12-carve-ext2.dd
ca312b0582c78e1b379eca318aa7a9d7fc4a809bfcfd25be093f5298e72a81ab  9-fat-label.dd
6c18f662744d55e2769d9510f6173f04dab668c42b67ef27b675d22e628b4ed5  2020JimmyWilson.E01
1196221c27515e4f9a5c855da529e006bd9bebfbc5703d37bb419476ea0db55d  BXS-1.E01
a621e46b88a6366c90cc5bc7d412b46f3f012a08b1fd7d3fcbea2d78b761af1d  Op Archway AXA-1.E01
```

## Scoring the carvers

```bash
python tools/carve_score.py                  # every image with a known key
python tools/carve_score.py 11-carve-fat.dd  # one image
```

Exits non-zero if a score falls below the baseline recorded in that script.
