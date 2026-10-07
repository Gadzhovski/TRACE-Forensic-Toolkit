# Test results

What TRACE was run against, and what happened. Every figure here was measured
by running the images through TRACE's own code paths — `ImageHandler`,
`get_directory_contents`, `get_file_content` and the carvers — not by reading
the code and reasoning about it.

Last run: 2026-09-04, on Windows 11, against branch `refactor/cleanup-crossplatform`.

> **This directory is not committed.** 32 images, 7.8 GB. `.gitignore` excludes
> every image extension at any depth (`*.dd`, `*.E01`, `*.dmg`, `*.raw`,
> `*.img`, `*.iso`, `*.bz2` …), so nothing here can be staged by accident.
> `README.md` and this file are the only tracked things in it — they exist so
> the corpus can be rebuilt from scratch. See README.md for download commands
> and checksums.

---

## Summary

| Area | Result |
|---|---|
| Filesystems read | NTFS, FAT12/16/32, exFAT, Ext2/3/4, HFS+, ISO9660 |
| Image formats read | E01, DD/RAW, DMG, IMG |
| File reads | **0 failures** across every image — 300+ files read back at their exact size |
| Deleted-file recovery | Works on NTFS, FAT, exFAT, ext3. Correctly reports when it *cannot* work |
| Carving vs. published answer keys | 15/15, 10/10, 25/27, 30/54 (see below) |
| Known gaps | No fragment reassembly; no UFS/APFS/XFS coverage; carving is slow on large images |

---

## Carving, scored against published answer keys

`python tools/carve_score.py` re-runs this. Score counts files **located**;
byte-exactness is separate, because a fragmented file cannot be reproduced by a
contiguous carver and counting that as failure would measure the wrong thing.

| Image | Corpus | Located | Byte-exact | False positives |
|---|---|---|---|---|
| `11-carve-fat.dd` | DFTT #11 | **15/15** | — | 1 |
| `12-carve-ext2.dd` | DFTT #12 | **10/10** | 1/1 | 0 |
| `dfrws-2006-challenge.raw` | DFRWS 2006 | **25/27** | **10/10** | 2 |
| `dfrws-2007-challenge.img` | DFRWS 2007 | **30/54** | **5/5** | 25 |

**Reading these numbers.** 30/54 on DFRWS 2007 is near the ceiling, not a
shortfall: only 5 of those 54 files are stored contiguously, and the rest need
fragment reassembly, which TRACE does not do. Where a file *can* be carved
contiguously, it is recovered byte-for-byte — 5/5 and 10/10 on the two DFRWS
images, matched against the organisers' own MD5s.

The two DFRWS 2006 misses are ZIP archives written in streaming mode (bit 3
set, sizes in a trailing data descriptor) whose members fail CRC because the
archives are fragmented. `testzip()` is right to reject them.

Formats carved: PDF, JPG, PNG, GIF, BMP, TIFF, WAV, MOV, MP4, WMV, ZIP, GZ,
RAR, 7Z, OLE (doc/xls/ppt), HTML.

---

## Filesystem and feature tests

### DFTT — Digital Forensics Tool Testing

| Image | Tests | Result |
|---|---|---|
| `ext-part-test-2.dd` | Extended/nested partitions | **Pass** — all 6 FAT16 volumes found and readable, including those inside extended tables. Files are zero-byte markers; the test is about layout |
| `fat-img-kw.dd` | Keyword search, FAT16 | **Pass** — 8 files listed, all read |
| `ntfs-img-kw-1.dd` | Keyword search, NTFS | **Pass** — 10 files listed, all read |
| `ext3-img-kw-1.dd` | Keyword search, ext3 | **Pass** |
| `daylight.dd` | FAT timestamps across a DST boundary | **Pass, after a fix** — see below |
| `6-fat-undel.dd` | FAT deleted-file recovery | **Pass** — 6/6 deleted files recovered at full size |
| `7-ntfs-undel.dd` | NTFS deleted-file recovery | **Pass, after a fix** — 6/6 recovered |
| `8-jpeg-search.dd` | Identifying JPEGs by content, not extension | **Pass** — `file2.dat` correctly read as JPEG, `file9.boo` as ZIP, fake `file3.jpg` correctly rejected as text. 14 files read |
| `9-fat-label.dd` | FAT volume labels | **Pass** |
| `10-ntfs-disk.dd`, `-part1`, `-part2` | Two filesystems layered in one partition | **Pass, after a fix** — see below |
| `11-carve-fat.dd` | Carving, FAT32 | **15/15** |
| `12-carve-ext2.dd` | Carving, ext2 | **10/10** |
| `iso-dirtree1/2.iso`, `iso-endian.iso` | ISO9660 structure and byte order | **Pass** |

### NPS (Digital Corpora) and NIST deleted-file recovery

| Image | Filesystem | Result |
|---|---|---|
| `ntfs1-gen2.E01` | NTFS + compression + EFS | **Pass** — 19 files read. Compressed files read back at full length with correct magic bytes, identical to the raw copies. EFS files return ciphertext at the right size, which is the honest answer |
| `image.gen1.dmg` | HFS+ journaled | **Pass** — first HFS+ image ever run through TRACE |
| `ubnist1.casper-rw.gen3.E01` | ext3 | **Pass** — 15 files, 1 deleted and recovered |
| `dfr-01-xfat.dd` | exFAT | **Pass** — 2/2 deleted files recovered |
| `dfr-01-osx.dd` | HFS+ ×4 volumes | **Pass** — 36 files read. No deleted entries shown, correctly: HFS+ removes the catalog record on delete |
| `dfr-01-ext.dd` | Ext2, Ext3, Ext4 | **Pass** — all three volumes read. 0/3 deleted recovered, correctly: the test wipes the contents, leaving only names |
| `dfr-01-ntfs.dd` | NTFS | **Pass** — 1/2 deleted recovered; the other is a stale entry whose MFT record was reused |
| `dfr-05-braid-ntfs.dd` | NTFS, interleaved fragments | **Pass** — 2/3 recovered |
| `dfr-05-nest-ntfs.dd` | NTFS, nested fragments | **Pass** — 2/3 recovered |
| `dfr-01-recycle-ntfs.dd` | NTFS Recycle Bin | **Pass** |

### Real evidence images

`BXS-1.E01` (16 GB NTFS), `2020JimmyWilson.E01` (133 files read), and
`Op Archway AXA-1.E01` (78 files read) all list and read with no failures.

---

## Defects these tests found, and what changed

Each of these was a real fault in TRACE, caught by an image built to expose it.

**Deleted NTFS files were listed but could not be opened.** NTFS keeps the name
and drops the metadata link on delete, so TSK returns `info.meta` as `None`.
TRACE read the inode only from there and recorded `None` — six file names an
examiner could see and none they could open. The MFT record number survives as
`name.meta_addr`. *(DFTT #7 — all six now recover at their documented sizes.)*

**pytsk3 metadata was being read off a temporary.** `fs.open_meta(inode=n).info.meta`
returns `None` once the intermediate `File` is collected — silently, so it read
as "no metadata" rather than raising. Fields are now copied into `_OrphanMeta`.
*(Found while fixing the above; it made the first attempt appear to work and
then report size 0.)*

**FAT timestamps were labelled UTC.** FAT stores wall-clock time with no zone.
The values TRACE showed were already right — `winter.txt` reads 14:00:01
against a documented 2:00 PM, with no DST shift — but the label claimed
knowledge the evidence does not carry and invited a reader to "correct" a
correct time. FAT/exFAT now read `(local, no zone)`; NTFS/ext/HFS keep UTC.
*(DFTT #5.)*

**A partition holding two filesystems was reported as empty.** DFTT #10 formats
each partition as NTFS then overwrites it with Ext2 or UFS, leaving both
signature sets intact. TSK refuses to guess and raises; TRACE turned that into
nothing at all — the worse of the two failures the test describes, since an
examiner has no reason to look further at a volume the tool calls empty. TRACE
now reads the signatures directly and reports *"NTFS + Ext2/3/4 — two file
systems present. The volume was reformatted without being wiped, so the earlier
one's data may still be recoverable by carving."*

**"Deleted" hid two different situations.** Some deleted files have surviving
metadata and open; others are a name pointing at nothing — which is what ext2
does on every delete, and NTFS does once the MFT record is reused. Both looked
identical, so an examiner learned the difference by clicking and getting
nothing. The listing now records `is_recoverable` and the status line reads
*"deleted, recoverable"* or *"deleted, name only"*.

**Carving lost files it could see.** `pumpkin.jpg` sat intact in DFTT #11 and
was written out as a 5 KB fragment, because the carver stopped at the first
`FFD9` — which in an EXIF photo terminates the thumbnail, not the image. MOV
had `ftyp` commented out of its signature list and could emit only one file per
chunk. ZIP's entry stride omitted the filename-length field, so every archive
came out 11 bytes short. OLE documents were not carved at all. *(DFTT #11/#12,
15/15 and 10/10 now.)*

**Carving invented files it could not see.** DFRWS 2007 produced 800 carves
against 30 real files. A file allocated by a filesystem begins on a sector
boundary — every file in every answer key does — so a signature found
mid-sector is a thumbnail or a video frame, not a deleted file. **800 → 25**,
with nothing real lost.

---

## What does not work, and why

**Fragment reassembly is not implemented.** A file split across
non-adjacent blocks is recovered only as far as its first fragment. This is the
single largest gap: it is what separates 30/54 from 54/54 on DFRWS 2007, and it
is a substantial algorithm (bifragment gap carving) rather than a fix.

**Carving is slow on large images.** Chunks advance 4 MB but read 36 MB, so
every byte is scanned about nine times, by each of sixteen carvers — roughly
50 billion byte-scans for a 331 MB image, about 13 minutes. The overlap is
deliberate: it is what stops a file being lost at a chunk boundary. But the
cost is real and grows linearly.

**These filesystems are untested:** UFS1/UFS2, APFS, XFS, YAFFS2, and NTFS
volumes using `$UsnJrnl` or Volume Shadow Copies. UFS is *detected* (DFTT #10)
but never mounted or read.

**EFS-encrypted files are not decrypted.** TRACE returns the ciphertext at the
correct size. Decryption would need the key material, which is a separate
capability rather than a defect.

**These are correct results that look like failures:**

- `11-carve-fat.dd` and `12-carve-ext2.dd` report no filesystem. Both are meant
  to: #11 has a deliberately zeroed boot sector, #12 is raw carving data.
- `dfr-01-osx.dd` shows no deleted files. HFS+ removes the catalog record on
  delete; there is nothing to list.
- `dfr-01-ext.dd` recovers 0 of 3 deleted files. The image's own construction
  wipes their contents — only the directory names survive, which was verified
  by searching the raw bytes.

---

## Reproducing this

```bash
# Carving, scored against the published keys
python tools/carve_score.py

# One image
python tools/carve_score.py 11-carve-fat.dd
```

`carve_score.py` exits non-zero if a score falls below the baseline recorded in
it, so a change that loses a file is caught. The filesystem and deleted-file
checks above were run as one-off scripts rather than a committed harness; the
carving score is the part worth keeping green.
