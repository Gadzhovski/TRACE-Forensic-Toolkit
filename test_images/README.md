# Test images

Disk images used to verify TRACE. **Nothing in this directory except this file
is committed** — `.gitignore` excludes every image extension at any depth. The
images are recorded here rather than stored in git so a checkout can be
reconstructed without carrying a gigabyte of evidence in history.

How the tests use them, the tiers and CI: `tests/README.md`. Every file
is pinned by SHA-256 in `tools/testdata/` (`catalog.py`, `samples.py`,
`nist.py`), and it lives in the folder of its group:

| Folder | Group | In CI | Get it |
|---|---|---|---|
| `ci/` | public, small: DFTT, NPS, AFF4, Btrfs, media, two NIST DFR | yes | `python -m tools.testdata.fetch` |
| `samples/` | artifact files (hives, logs, databases, small images) | yes | `... --group samples` |
| `corpus/` | carving corpus sources + `carve-corpus.dd` | yes | `... --group corpus` |
| `built/` | made by the Linux kernel's tools | Linux | `tools/testdata/build/make_*.py` |
| `local/` | public, big or slow (DFRWS, NPS domexusers, ubnist1, Fedora) | no | `... --group local` |
| `nist/` | NIST CFReDS sets | no | `... --group nist` |
| `private/` | no public source | never | copied by hand |
| `sources/` | whole upstream test-data repositories (dfvfs, sleuthkit_test_data) | no | reference only |

`python -m tools.testdata.fetch --tier full` gets every public group;
`--verify --tier full` hash-checks everything here. Names below are files;
the table above says which folder each is in.

Verify a download before trusting a result from it: a truncated image produces
carving failures that look like tool defects.

## Carving corpora (published ground truth)

Each of these ships an answer key naming every planted file, its MD5, its size
and its sector runs. Those keys are transcribed into
`tests/expected/carve_ground_truth.json` and scored by `tools/score/carve_score.py`.

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
`lin_test.pdf` is in exactly two pieces -- its first twelve blocks, then the
rest after the indirect block -- the case reassembly rebuilds.

**DFRWS 2006 and 2007** are raw images with no filesystem, built specifically
to break carvers. 2006 lays out 32 files in 22 named scenarios, several of
which target carving heuristics directly:

- **3c** plants a lone sector beginning `0xFFD8` immediately before a real JPEG
- **3j** plants a sector beginning `0xFFD9` *inside* a JPEG
- **3g** places one complete JPEG inside another's fragmentation gap
- **3i** is a 24 MB JPEG, larger than many tools' default maximum
- **1d**, **3h** intertwine two files of the same type

2007 deepened this: of the 54 originally scored files **only 5 are
contiguous**, and its full key (114 files once MP3, MPG, EXE, ELF, AVI, FLV
and mail are counted) is what the harness scores. The fragmented ZIPs of 2006
and the in-order, two-fragment PDFs of 2007 are what reassembly is measured
against; 4.pdf is two in-order fragments too, but encrypted, so its split
cannot be proved and it is (correctly) not rebuilt.

## The rest of the DFTT suite

These test everything except carving: partition tables, keyword search,
undelete, timestamps, volume labels, filesystem detection and ISO9660. Each
page at <https://dftt.sourceforge.net/> documents what its image contains and
what a tool is expected to do with it.

| File | Size | Tests | DFTT |
|---|---|---|---|
| `ext-part-test-2.dd` | 153 MB | Extended/nested partitions -- 6 FAT16 volumes, some inside extended tables | [#1](https://dftt.sourceforge.net/test1/index.html) |
| `fat-img-kw.dd` | 15 MB | Keyword search on FAT16 | [#2](https://dftt.sourceforge.net/test2/index.html) |
| `ntfs-img-kw-1.dd` | 7.8 MB | Keyword search on NTFS | [#3](https://dftt.sourceforge.net/test3/index.html) |
| `ext3-img-kw-1.dd` | 5 MB | Keyword search on ext3 | [#4](https://dftt.sourceforge.net/test4/index.html) |
| `daylight.dd` | 1.4 MB | FAT timestamps across a daylight-saving boundary | [#5](https://dftt.sourceforge.net/test5/index.html) |
| `6-fat-undel.dd` | 5.9 MB | Recovering deleted files from FAT | [#6](https://dftt.sourceforge.net/test6/index.html) |
| `7-ntfs-undel.dd` | 5.9 MB | Recovering deleted files from NTFS, and a leap day | [#7](https://dftt.sourceforge.net/test7/index.html) |
| `8-jpeg-search.dd` | 9.8 MB | Identifying JPEGs by content, not extension | [#8](https://dftt.sourceforge.net/test8/index.html) |
| `10-ntfs-disk.dd` | 94 MB | Two file systems layered in one partition | [#10](https://dftt.sourceforge.net/test10/index.html) |
| `10-ntfs-part1.dd` | 47 MB | Partition 1 of the above: NTFS under Ext2 | [#10](https://dftt.sourceforge.net/test10/index.html) |
| `10-ntfs-part2.dd` | 47 MB | Partition 2 of the above: NTFS under UFS2 | [#10](https://dftt.sourceforge.net/test10/index.html) |
| `10-ntfs-part3.dd` | 78 MB | A third partition (10b's archive): NTFS under UFS1 | [#10](https://dftt.sourceforge.net/test10/index.html) |
| `iso-dirtree1.iso` | 366 KB | ISO9660 directory structure | [#14](https://dftt.sourceforge.net/test14/index.html) |
| `iso-dirtree2.iso` | 366 KB | ISO9660 directory structure, variant | [#14](https://dftt.sourceforge.net/test14/index.html) |
| `iso-endian.iso` | 366 KB | ISO9660 byte-order handling | [#14](https://dftt.sourceforge.net/test14/index.html) |

Three of these earn particular attention:

- **#5 (`daylight.dd`)** holds one file written in January and one in June, both
  at a round hour. FAT stores wall-clock time with no timezone, so a tool that
  converts them as though they were UTC shifts one by an hour and not the
  other. `winter.txt` must read 2:00 PM and `summer.txt` 3:00 PM.
- **#7 (`7-ntfs-undel.dd`)** deletes six files. Their directory entries survive
  but no longer link to their metadata, so a tool that reads the inode only
  from that link lists six names it cannot open. The MFT record number is still
  in the entry.
- **#10** formats each partition as NTFS and then overwrites it with Ext2 or
  UFS, leaving both signature sets intact. In the authors' words: "The test is
  whether your tool will warn you that there are two valid file systems or if
  it will show you only one and hide the other." Showing an empty partition is
  worse than either -- and was what TRACE did, since The Sleuth Kit's
  detection refuses such a partition. Each file system is now opened on its
  own (`ImageHandler.fs_layers`, `tests/test_layered.py`).

## Filesystems beyond FAT and NTFS

TRACE had only ever been exercised on FAT, NTFS, ext2/3 and ISO9660. These add
HFS+, exFAT and ext4, plus NTFS features -- compression, EFS encryption,
journaling -- that none of the DFTT images cover.

| File | Size | Filesystem | Tests | Source |
|---|---|---|---|---|
| `ntfs1-gen2.E01` | 34 MB | NTFS | The same files stored raw, NTFS-compressed and EFS-encrypted, plus interleaved logfile writes that fragment them | [NPS](https://digitalcorpora.org/corpora/drives/) |
| `image.gen1.dmg` | 10 MB | HFS+ | A journaled HFS+ volume where an earlier version of a file survives only in the journal | [NPS](https://digitalcorpora.org/corpora/drives/) |
| `ubnist1.casper-rw.gen3.E01` | 160 MB | ext3 | The persistence file from a bootable Ubuntu 8.10 USB | [NPS](https://digitalcorpora.org/corpora/drives/) |
| `dfr-01-xfat.dd` | 63 MB | exFAT | Deleted-file recovery | [NIST DFR](https://cfreds-archive.nist.gov/dfr-test-images.html) |
| `dfr-01-osx.dd` | 1.0 GB | HFS+ | Deleted-file recovery across four HFS+ volumes | [NIST DFR](https://cfreds-archive.nist.gov/dfr-test-images.html) |
| `dfr-01-ext.dd` | 1.0 GB | ext2, ext3, ext4 | Deleted-file recovery, one volume per generation | [NIST DFR](https://cfreds-archive.nist.gov/dfr-test-images.html) |
| `dfr-01-ntfs.dd` | 1.0 GB | NTFS | Deleted-file recovery, non-fragmented | [NIST DFR](https://cfreds-archive.nist.gov/dfr-test-images.html) |
| `dfr-05-braid-ntfs.dd` | 1.0 GB | NTFS | Several deleted files interleaved fragment by fragment | [NIST DFR](https://cfreds-archive.nist.gov/dfr-test-images.html) |
| `dfr-05-nest-ntfs.dd` | 1.0 GB | NTFS | Several deleted files nested inside one another's gaps | [NIST DFR](https://cfreds-archive.nist.gov/dfr-test-images.html) |
| `dfr-01-recycle-ntfs.dd` | 1.0 GB | NTFS | Files deleted through the Recycle Bin rather than unlinked | [NIST DFR](https://cfreds-archive.nist.gov/dfr-test-images.html) |

What these established, all measured rather than assumed:

- **HFS+, exFAT and ext4 list and read correctly.** exFAT recovers both its
  deleted files; ext3 recovers its one.
- **NTFS compression is transparent.** Files in the `Compressed` directory read
  back at full length with correct magic bytes, identical to `RAW`.
- **EFS-encrypted files return ciphertext**, at the right size but with no valid
  header -- which is the honest result. TRACE reports what is on the disk
  rather than implying it decrypted anything.
- **HFS+ shows no deleted entries at all**, because HFS+ removes the catalog
  record on delete rather than flagging it. That is the filesystem's behaviour,
  not a gap in the tool; those files are reachable only by carving.
- **ext2 zeroes the inode pointer on delete**, so a deleted name there has no
  metadata to follow. ext3 and ext4 keep the record but clear its size and
  block pointers. The listing now says which deleted files can actually be
  opened and which are a name and nothing more.

## NIST CFReDS (local, in `nist/`)

Downloaded by hand from https://cfreds-archive.nist.gov/ (each file's
SHA-256 is in the `.json` beside it); not yet in the fetch catalog -- how
these reach CI is planned separately. `tests/test_nist_cfreds.py` skips
what is absent.

| Folder | Set | What it checks | Ground truth |
|---|---|---|---|
| `nist/dfr/` | Deleted File Recovery, 91 images (ext, FAT, exFAT, NTFS, HFS+; DFR-01..17) | deleted names, states, content, MAC times | `setup-july-10-2012.pdf`, parsed by `tools/score/nist_dfr_key.py`; `tools/score/dfr_score.py` |
| `nist/carving/` | File Carving L0-L5 x Graphic/Archive/Audio/Video/Documents, 30 images + `TestFiles/` originals | carving | pieces identified by bytes against the originals (`tools/score/nist_carving_truth.py`); `tools/score/carve_score.py` |
| `nist/containers/` | Searching Container Files (`files.dd`, `nested.dd`) | text inside 17 container types, nested | `content_info-2.txt` |
| `nist/russian/` | Russian Tea Room (`CFReDS001.E01`) | UTF-16BE Cyrillic search, in files and free space | `russian-utf-16.zip` (the planted files) |
| `nist/winreg/` | cfreds-2017-winreg (10 archives; extract to `nist/winreg/x/`) | deleted keys/values, corrupted and manipulated hives | the same hives before deletion; NIST's `.txt` per corrupted hive |

What they found and fixed (details in CLAUDE.md):

- exFAT times are UTC (each entry records its offset; TSK ignores it) and
  deleted exFAT files are read from their own cluster chain (braided
  files recovered byte-exact)
- deleted files whose space a later, also-deleted file took were called
  recoverable (FAT, NTFS); FAT files in pieces now say only their start
  is known; NTFS files only `$LogFile` still names are listed (50 on
  DFR-08/10/13); ext3/ext4 files emptied on deletion are recovered from
  the journal's copy of their inode (279 on DFR-10, byte-exact)
- file-system structures counted as free space (carving, deleted states,
  free-space search); ext backup superblocks taken for lost partitions
- free space was never searched (4 of the Russian menu's 8 sections are
  in no file); UTF-16 in non-Latin alphabets was never extracted
- CAB, LHA/LZH, ALZip, uuencode, Unix .Z were unreadable (16 of 17
  container types now searchable; StuffIt X is proprietary)
- BMP over 5,000,000 bytes not carved, GIFs cut at the first `00 3B`, MP3
  carves running past a cut last frame, a nested ZIP's end record taken
  for the outer one's
- deleted registry keys and values were not recovered (81/81 keys,
  163/168 values with their data, none attributed to a wrong key);
  python-registry misreads inline REG_DWORD_BIG_ENDIAN

## Btrfs

The Sleuth Kit in the pytsk3 wheels does not read Btrfs; TRACE does, in
Python (`trace_app/core/btrfs.py`). Thirteen of fox-it/dissect.btrfs's test
volumes (128 MB each, gzip-packed, pinned to a commit) are in the CI set;
the values `tests/test_btrfs.py` asserts are the ones dissect's own tests
publish.

| File | Tests | Source |
|---|---|---|
| `btrfs-subvolume-snapshot.raw` | The same small tree in the top-level subvolume, a subvolume, and a snapshot of it written to afterwards | [dissect.btrfs](https://github.com/fox-it/dissect.btrfs/tree/main/tests/_data) |
| `btrfs-subvolume-nested.raw` | Subvolumes inside a directory and inside another subvolume | dissect.btrfs |
| `btrfs-compression.raw` | zlib, LZO and zstd files, as extents and inline | dissect.btrfs |
| `btrfs-sparse.raw` | Holes at the start, middle and end; a snapshot's partly rewritten copies | dissect.btrfs |
| `btrfs-raid1-1.raw` | One disk of a two-disk RAID1, read alone | dissect.btrfs |
| `btrfs-raid1-2.raw`, `btrfs-raid0-1/2.raw`, `btrfs-raid5-1/2.raw`, `btrfs-raid6-1/2/3.raw` | Multi-disk pools, one image per device: assembled (`core/assembly.py`) whole, RAID6 with a device missing, RAID0's devices alone (`tests/test_assembly.py`) | dissect.btrfs |
| `btrfs-deleted.raw` (+ `.json` answer key) | **Built, not downloaded**: `tools/testdata/build/make_btrfs_deleted.py` has the Linux kernel write and delete known files (plain, inline, zstd, no-checksum, a folder, a subvolume; one overwritten for certain). CI builds it on Ubuntu; elsewhere run the script in a privileged Linux container (its docstring) | Deleted-file recovery: every file back byte for byte, the overwritten one never called recoverable |
| `md-<array>-<n>.raw` (+ `md-raid.json` answer key) | **Built, not downloaded**: `tools/testdata/build/make_md_raid.py` has mdadm make Linux software RAID arrays -- RAID0/1/5/6/10, superblocks 0.90, 1.0 and 1.2, left-symmetric and right-asymmetric RAID5, a member inside a GPT partition -- each with ext4 and known files. Linux CI builds them; elsewhere a privileged container (its docstring) | md arrays read across their members' images, and with a member missing where the level allows (`core/mdraid.py`) |
| `luks1-lvm.raw`, `luks2-lvm.raw` (+ `luks-lvm.json` answer key) | **Built, not downloaded**: `tools/testdata/build/make_luks_lvm.py` has cryptsetup and lvm2 lay out a disk as Linux installers do -- GPT -> LUKS -> LVM (root, home) -> ext4 -- with LUKS1 (PBKDF2) and LUKS2 (argon2id, 4 KiB sectors), password `PASSWORD`, known files, and a PNG deleted in home. Linux CI builds them; elsewhere a privileged container (its docstring) | LUKS2 unlocked in Python (`core/luks2.py`), LVM found inside an unlocked volume, carving inside it (`tests/test_luks.py`) |
| `Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2` | **Local only** (583 MB). A real Fedora 44 install: GPT, EFI FAT16, a Btrfs root with root/boot/home/var subvolumes, zstd throughout, in a compressed QCOW2 | [Fedora](https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/) (SHA-256 as Fedora's CHECKSUM file publishes it) |

What the Fedora image established:

- **libqcow misreads compressed QCOW2.** It takes bit 0 of a compressed
  cluster's L2 entry for the "reads as zeros" flag, but there it is the
  lowest bit of the host offset: every compressed cluster at an odd offset
  read as zeros (273 of the first 559 in the Btrfs partition). TRACE now
  reads QCOW2 itself (`trace_app/core/qcow2.py`), libqcow only for what
  that does not (QCOW 1, encryption).
- **Every byte checks out.** All 1,988 tree nodes and all 151,522 data
  sectors (592 MB) match their stored CRC32C, and 22,831 installed files
  match the SHA-256 in the RPM database. The ten that differ are files the
  image build regenerates after install (SELinux policy, the gconv cache),
  and four are edited config files.

## Other images

| File | Size | Notes |
|---|---|---|
| `2020JimmyWilson.E01` | 296 MB | NTFS, E01. General browsing and verification. |
| `BXS-1.E01` | 152 MB | NTFS, E01. The image the I/O constants work was measured against. |
| `Op Archway AXA-1.E01` | 123 MB | NTFS, E01. |

## Video

For the media player's tests (first frame, frame stepping, Save Frame): small
clips from Wikimedia Commons, each released under **CC0**.

| File | Size | Video | Source |
|---|---|---|---|
| `VP9test.webm` | 175 KB | VP9, 512×288, 25 fps, 9 s | [Commons](https://commons.wikimedia.org/wiki/File:VP9test.webm) |
| `ContainerShip.webm` | 289 KB | 1084×738, 30 fps, 22 s | [Commons](https://commons.wikimedia.org/wiki/File:ContainerShip.webm) |
| `Wiki.OrientateEdges.ogg` | 770 KB | Theora, 480×480, 30 fps, 9 s -- an `.ogg` that holds video | [Commons](https://commons.wikimedia.org/wiki/File:Wiki.OrientateEdges.ogg) |

## AFF4

The AFF4 Standard v1.0 canonical reference images, made by Evimetry
([aff4/ReferenceImages](https://github.com/aff4/ReferenceImages), pinned to a
commit): `Base-Linear.aff4` (the whole disk), `Base-Allocated.aff4`
(allocated blocks only; the rest is `aff4:UnknownData`) and
`Base-Linear-ReadError.aff4` (a read error, `aff4:UnreadableData`). The disk
SHA-1s TRACE must produce are the ones pyaff4's own tests assert.

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
b075ed83211765dd14f24390389b77b20ef688d70aaf69385e026b5513bdd8d2  ext-part-test-2.dd
b173fd82a052e2637cfeb89cf21a603817f072799a63decffbfc948fc19a06e6  fat-img-kw.dd
cad097e8fcf4538a928c980a01bc64dcf36ca062432b0f6d5c3962e3bc0c4060  ntfs-img-kw-1.dd
2065c9b3fa3f1f59fd5ee2ec0ad83a987d988e9ae898497a0b48e4986010f686  ext3-img-kw-1.dd
a81dc8aeefb28b75e0625c1c8b54db9f46ec1c6c28e16595539d1cb00bbd45b5  daylight.dd
e6f1f3bc53d426ae6f81b2d7b75598bc95f7447853e38b8f9ca1d1b65f7b3512  6-fat-undel.dd
4138cc42148e3381e3c66eb50090f4a30416ae8c20247c2b9bad27cf8c764d88  7-ntfs-undel.dd
9c43d6a2dd5132cf6afc29e5c644cde0cb747c64998a68e73f2efb787887b126  8-jpeg-search.dd
4d2edfe4a8ee0079720a4b9e258ecf59ffa17783465a5a013101614b4ac64049  10-ntfs-disk.dd
d6739c45d652c0eb67e59536e7b9c02b25ca99aaabf500fe9c374bb7f2ae8bc3  10-ntfs-part1.dd
529c607152f8ca25a6f2645e6894a80b303b4f2b352b89bdfef0fde549e3c6e2  10-ntfs-part2.dd
8e6c7b7709d52e6a41080002c0589ac3204f0e77d834f75b58d8f249d391d7bb  10-ntfs-part3.dd
0418d266405e1baf1334a014b9fba984962e81ec65003f34b67a7f5c7b28e6ad  iso-dirtree1.iso
5f4fe2707eb4227b2d8e35482f492c888a44937abca05b67a0b63f2a2e34e074  iso-dirtree2.iso
70231746c40640efc6ea5a926ef9184910c44b43b0716d72026db41b40966b9c  iso-endian.iso
2badead91bef56c80155d7731671ad1d93c08f32cd4ce17566fdf02d5769feea  ntfs1-gen2.E01
beb7795dd6d1a5319f9c20101855ffff9665fcc11c6b23de822d50c0d1e388ee  image.gen1.dmg
f2ad970ab2c8ed41e2d26d0c7e821aaee0bb6fe71063ae17bea894306a8e55ff  ubnist1.casper-rw.gen3.E01
bb3755982959e189d7cfc7a4819553406e5c64e67a11d6b875ea1d4f23fa745b  dfr-01-xfat.dd
06e997b4a341854495ced8e201fa3b63fdfe0ba042c62fb8fa4e98283d430b6d  dfr-01-osx.dd
855e7dfdc3a807beae3dadd519243f1c047d9a7bd2c08a4e70e7a8eda8f75901  dfr-01-ext.dd
c863ccad01804b840a6dfa623a94996ca876e15ded41c6c0d8ae148620eb6493  dfr-01-ntfs.dd
43f239c3b141a02c20ee2e6adc94e553215a3b35371fa291f7e3d4aa9b562cb7  dfr-05-braid-ntfs.dd
7da808c9d3da75eb437fd175567dc781f6291547fab37bb704773cb31562669c  dfr-05-nest-ntfs.dd
6a44af0530812edf1a289c539a3c6c7d6b42e1c93e8f60e53287bddb5fdf7efa  dfr-01-recycle-ntfs.dd
2efbc8cbc302ce5ae498fa3f019eeb36447f15372fa92d6a62165f92449c1236  VP9test.webm
dc6f9ed8ea395c91df33f1b7aae0a50e1e4d54434514efffcb32258a1e2f4a3c  ContainerShip.webm
4e583efb3a59d577f5f2a32cd8a6743785fe8f315a2f95c72778eb81635a1375  Wiki.OrientateEdges.ogg
bcde3297ae95cd9df214bfb79821334628dad08f21ef38374a2c091481e391c0  Base-Linear.aff4
df6c705c15339a53cf86b221858f2cd6b85c56f7078287ae99273145efe567c1  Base-Allocated.aff4
0b1c2edd6bdf37f2efe9c6fa274dd3c100de3fc5152d8a1fd82fb61f41c68e12  Base-Linear-ReadError.aff4
ce5b3950c4b6b7200b8b76f795d09340652952bd6bec2b1803af6ecfe219f1f2  btrfs-subvolume-snapshot.raw
bdc211d245a6bc1adec4540ae9b9041fe88f3583c9663f0aa1fa3ba8f0f1c1c7  btrfs-subvolume-nested.raw
2088190ca033e2a20c3fb93d2b5d2ca65313fbf32d193cb242d333ca5e0a538f  btrfs-compression.raw
5d15ae65c1c45cdeb599294d9efacdbdb1d9133dff936200f6265521e089d258  btrfs-sparse.raw
63a60b87e9c17313610885db8ddd6b54146e88e910bf0bab8d7091605c20add7  btrfs-raid1-1.raw
236e3d135601e0d12d2268943a08b772ab3d0443111280e0c74634072f3da2f6  btrfs-raid1-2.raw
50df8801d6e5ba9d2eff6d5eae77f5d20289b56de1954abd418c5f648e4abb7f  btrfs-raid0-1.raw
e8e8a50e7f92c112cea0750eb857e2091dfafe207b96ee2266986176fee0ae79  btrfs-raid0-2.raw
a70fe168247374bf8fa49f61d7dba18f776a780a4f9cf5fb6c4cc8f74fa2fd4c  btrfs-raid5-1.raw
4017c940e5c6ebab590ee74f5efb9239d94a367155b91632352204b4542e97aa  btrfs-raid5-2.raw
8362b35dee600402e8bb2707609d9d6911752890339bc02550cd3bdb79cae7a6  btrfs-raid6-1.raw
2ee5262ef2e22dea37abbdce6489c1448de40e8fa3932753de88afa348739fa7  btrfs-raid6-2.raw
25f51d61b044b96c221a46850a61928a8eb351aa505001c1b1e77aaedba76461  btrfs-raid6-3.raw
28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f  Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2
6c18f662744d55e2769d9510f6173f04dab668c42b67ef27b675d22e628b4ed5  2020JimmyWilson.E01
1196221c27515e4f9a5c855da529e006bd9bebfbc5703d37bb419476ea0db55d  BXS-1.E01
a621e46b88a6366c90cc5bc7d412b46f3f012a08b1fd7d3fcbea2d78b761af1d  Op Archway AXA-1.E01
```

## The carving corpus

`carve-corpus.dd` is built, not downloaded:

```bash
python -m tools.testdata.fetch --group corpus   # = tools/testdata/build/carve_corpus.py
```

It fetches 51 real published files of the formats the DFTT/DFRWS images do
not hold (SQLite, PST, EVTX, registry hives, LNK, Office Open XML, HEIC,
Opus, Matroska, Mach-O, RAR3/RAR5, 7z, a pre-POSIX V7 tar and more) into `corpus/samples/`, checks each against
its pinned SHA-256, and lays them out with a fixed seed -- so the image, and
its answer key in `tests/expected/carve_ground_truth.json`, are the same every time.

## The artifact samples

`test_images/samples/` holds real Windows and browser artifacts for
the activity tests -- Prefetch from XP to Windows 11 (five compressed),
NTUSER / UsrClass / SYSTEM / Amcache hives, Jump Lists, a shortcut, Recycle
Bin records, event logs (including a damaged one) and Chrome, Firefox and
Safari databases:

```bash
python -m tools.testdata.fetch --group samples   # tools/testdata/samples.py
```

They come from log2timeline/plaso's test_data (Apache 2.0) and
omerbenamram/evtx's samples (MIT / Apache 2.0), pinned to a commit and checked
by SHA-256. The same tool fetches dfvfs's container images (Apache 2.0): a
dynamic VHD, a differencing VHDX with its parent, a VMDK, a BitLocker To Go
volume (password `bde-TEST`, as in dfvfs's own tests) and an NTFS volume with
two Volume Shadow Copies; the APFS images (plain, and encrypted with
`apfs-TEST`), a FileVault 2 disk (`fvde-TEST`), a LUKS 1 volume
(`luksde-TEST`) and an LVM volume group -- the passwords dfvfs's own tests
use; plaso's ESE databases (SRUDB.dat, WebCacheV01.dat), IE index.dat
files, a Windows Timeline database and a Windows 7 SOFTWARE hive; and
plaso's NTFS samples -- a raw Windows XP
`$MFT`, a `$UsnJrnl:$J` excerpt and `usnjrnl.qcow2`, a QCOW2 disk holding an
NTFS volume and its change journal (the NTFS, timeline and QCOW tests).
`nps-2009-domexusers.E01` (Digital Corpora, 4.4 GB, a multi-user
Windows XP machine) is used by a local end-to-end test when present.

## Re-downloading

Every public file here is fetched and checksum-verified by one command,
from the source recorded in `tools/testdata/` -- DFTT and DFRWS archives,
Digital Corpora, NIST's CFReDS archive, GitHub-pinned commits:

```bash
python -m tools.testdata.fetch                 # the CI set
python -m tools.testdata.fetch --tier full     # every public group
python -m tools.testdata.fetch --list          # sources
```

It never overwrites a file already here; one whose checksum differs is
reported, not replaced. The NIST winreg archives are unpacked into
`nist/winreg/x/`, which is what the tests read.

## Scoring the carvers

```bash
python tools/score/carve_score.py                  # every image with a known key
python tools/score/carve_score.py 11-carve-fat.dd  # one image
```

Exits non-zero if a score falls below the baseline recorded in that script.
The score counts files **located**; byte-exactness is reported separately,
because a fragmented file cannot be reproduced by a contiguous carver and
counting that as a failure would measure the wrong thing.

**Expect the 2007 image to take a while.** Chunks advance 4 MB but read 36 MB,
so every byte is scanned about nine times, by each of sixteen carvers -- around
50 billion byte-scans for a 331 MB image. That overlap is what stops a file
being lost at a chunk boundary, so it is deliberate, but it makes a large image
slow to score.
