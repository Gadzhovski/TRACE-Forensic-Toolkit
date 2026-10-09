"""Score TRACE's deleted-file listing against NIST's DFR answer key.

    python tools/dfr_score.py                 # every image present
    python tools/dfr_score.py ext-07 fat-02   # some
    python tools/dfr_score.py -v ext-07       # and every disagreement
    python tools/dfr_score.py -j 6            # six images at a time

ext2/ext3 images take a minute or more each: NIST filled their volumes
with one file of ~130,000 runs, and The Sleuth Kit's run list is
quadratic to build (opening that file's metadata takes ~50 s).

The images (dfr-NN[-variant]-<fs>.dd) are read from test_images/nist/dfr
or test_images; the key is tools/nist_dfr_ground_truth.json, parsed from
NIST's own document by tools/nist_dfr_key.py. Per image:

  listed     deleted files in the key that TRACE lists by name
  state      of the key's files with an intact count, those whose TRACE
             state agrees with it: all sectors intact -> recoverable /
             resident (or "no data recorded": ext3/4 clear the block list);
             none -> not recoverable; some -> partly overwritten
  false ok   TRACE says recoverable but the key says sectors were lost, or
             the bytes TRACE recovers are not the file's -- the failure
             that matters most: an examiner trusts a "recoverable" file.
             Any makes the run exit non-zero
  unknowable "recoverable" where the key says the file was overwritten,
             but only by files it also says left no entry: nothing on
             the disk records that overwrite (kept apart, not hidden)
  content    recoverable files whose recovered bytes equal the key's
             sectors (read from the image, cut to the file's size)
  times      modified / accessed times equal to the key's
  key check  live files whose bytes TRACE reads equal the key's sectors --
             proves the key's sector numbers are read the right way

Times, as each file system records them:

* NTFS, HFS+, ext: UTC, equal to the key's. ext3/ext4 free a file's
  blocks by truncating it, which sets its modified time: a modified time
  equal to the key's deletion time is what the disk says, and counts.
* FAT made on Windows (fat-14, whose delete log is in Windows' format):
  the local time the key prints.
* FAT made on a Mac: local wall-clock digits with no zone. The key's times
  are what the
  Mac's msdosfs made of those digits: it converts with one fixed offset,
  writing and reading alike, whatever the date (and whether the image was
  made in October or December). The key says which: FAT keeps an access
  *date*, read as local midnight, so every access time in the key shows the
  driver's offset as its UTC time of day (04:00 -> -4 h). The digits on
  disk are the key's UTC time plus that offset. FAT keeps no access time
  of day and modified times in 2-second steps.
* exFAT: digits plus the UTC offset each time records -- UTC, equal to the
  key's.

The key's Sector List leaves out a file's last part-sector, which its
layout table names TAIL/<file>: content is compared over both.
"""

import json
import re
import os
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
KEY = os.path.join(HERE, 'nist_dfr_ground_truth.json')
FOLDERS = [os.path.join(ROOT, 'test_images', 'nist', 'dfr'),
           os.path.join(ROOT, 'test_images')]
SECTOR = 512


def image_file(name):
    """'ext-05-braid' -> 'dfr-05-braid-ext.dd' (as NIST names them)."""
    fs, rest = name.split('-', 1)
    return f"dfr-{rest}-{fs}.dd"


def image_path(name):
    for folder in FOLDERS:
        path = os.path.join(folder, image_file(name))
        if os.path.exists(path):
            return path
    return None


def load_key():
    with open(KEY, encoding='utf-8') as handle:
        return json.load(handle)['images']


def same_name(key_name, trace_name, fat):
    """FAT overwrites a deleted entry's first byte (0xE5); TSK shows the
    long name when its checksum still matches the short entry, else the
    short name with the first character lost."""
    a, b = key_name.lower(), trace_name.lower()
    if a == b:
        return True
    return fat and len(a) == len(b) and a[1:] == b[1:]


def file_ranges(image, file_name, size):
    """The sectors holding a file per the key (Sector List + TAIL), or None
    when the key does not account for all `size` bytes."""
    entry = image['sector_lists'].get(file_name)
    if not entry or not entry['complete']:
        return None
    stem = file_name.rsplit('/', 1)[-1].rsplit('.', 1)[0]
    ranges = entry['ranges'] + [r for r in image['tails'].get(stem, [])
                                if r not in entry['ranges']]
    if sum(b - a + 1 for a, b in ranges) * SECTOR < size:
        return None
    return ranges


#: NIST's test files are made of 512-byte blocks that say what they are:
#: "\nDFR\nFile <name> path ..." is block 0, "\nDFR\nBlock 00008 Segment
#: 002 file <name> path ..." block 8.
_FIRST = re.compile(rb'\nDFR\nFile (.+?) path ')
_BLOCK = re.compile(rb'\nDFR\nBlock (\d+) Segment \d+ file (.+?) path ')
#: ... and the last part-block "\nDFR\nTail <name>\n".
_TAIL = re.compile(rb'\nDFR\nTail (.+?)\n')


def key_bytes(read, ranges, size, name=None):
    """The file's bytes as the key's sectors hold them, in the file's
    order -- or None when they cannot be told.

    Each block names its file and number, so block n is the listed sector
    that says it is block n of this file. The Sector List cannot be taken
    as it stands: it is in ascending sector order, not the file's (ntfs-07's
    Furud.txt: its second fragment lies first on disk), and on NTFS it
    lists sectors that are not the file's data at all (a $LogFile page, an
    older copy of a first block, a zero sector)."""
    sectors = []
    for first, last in ranges:
        data = read(first * SECTOR, (last - first + 1) * SECTOR)
        sectors += [data[i:i + SECTOR] for i in range(0, len(data), SECTOR)]
    wanted = (name or '').rsplit('/', 1)[-1].encode('utf-8', 'replace')
    blocks = {}
    for sector in sectors:
        first = _FIRST.match(sector)
        later = _BLOCK.match(sector)
        if first and (not wanted or first.group(1) == wanted):
            number = 0
        elif later and (not wanted or later.group(2) == wanted):
            number = int(later.group(1))
        else:
            continue
        blocks.setdefault(number, set()).add(sector)
    count = -(-size // SECTOR)
    for sector in sectors:
        tail = _TAIL.match(sector)
        if tail and (not wanted or tail.group(1) == wanted):
            blocks.setdefault(count - 1, set()).add(sector)
    if not blocks:
        # Not NIST's self-describing blocks: the list as it stands.
        return b''.join(sectors)[:size]
    if any(len(blocks.get(n, ())) != 1 for n in range(count)):
        return None                 # a block missing, or two different ones
    return b''.join(next(iter(blocks[n])) for n in range(count))[:size]


def _shifted(text, minutes):
    from datetime import datetime, timedelta
    moment = datetime.strptime(text[:19], '%Y-%m-%d %H:%M:%S')
    return (moment + timedelta(minutes=minutes)).strftime('%Y-%m-%d %H:%M:%S')


def _recycled(handler, records):
    """{original name (lower case): index of its $R record} from the
    deleted $I records among `records`, read by TRACE's own parser. FAT
    loses a deleted name's first character: '_IOONCP6.txt' is $IOONCP6."""
    from trace_app.core.activity import recyclebin
    found = {}
    for record in records:
        name = record['name']
        if len(name) < 3 or name[1:2].upper() != 'I' or \
                'RECYCLE' not in record['path'].upper():
            continue
        try:
            facts = recyclebin.parse_i_file(trace_bytes(handler, record))
        except Exception:
            facts = None
        if not facts:
            continue
        original = facts['path'].replace('\\', '/').rsplit('/', 1)[-1]
        suffix = name[2:].upper()
        for index, other in enumerate(records):
            if other['name'][1:2].upper() == 'R' and \
                    other['name'][2:].upper() == suffix and \
                    other['path'].rsplit('/', 1)[0] == \
                    record['path'].rsplit('/', 1)[0]:
                found[original.lower()] = index
    return found


def trace_bytes(handler, record):
    """A file's bytes as TRACE gives them (preview, export, hashing)."""
    content, _meta = handler.get_file_content(record['inode'],
                                              record['volume'])
    return content or b''


def own_content(content, file_name, size):
    """Is `content` the whole file, by its own block markers -- block 0
    'File <name>', block n 'Block n ... file <name>', the last part-block
    'Tail <name>' -- every block in place?"""
    if not content or not size or len(content) != size:
        return False
    name = file_name.rsplit('/', 1)[-1].encode('utf-8', 'replace')
    count = -(-size // SECTOR)
    for number in range(count):
        block = content[number * SECTOR:(number + 1) * SECTOR]
        first, later, tail = (_FIRST.match(block), _BLOCK.match(block),
                              _TAIL.match(block))
        if number == 0 and first and first.group(1) == name:
            continue
        if later and int(later.group(1)) == number and \
                later.group(2) == name:
            continue
        if number == count - 1 and tail and tail.group(1) == name:
            continue
        return False
    return True


def _unrecorded_overwrite(handler, record, records, file_name, missing):
    """Is `record`'s data now another file's, by a write nothing on the
    disk records? The sectors say whose blocks they hold (NIST's markers);
    the overwrite is unrecorded when each such file left no entry, or its
    entry records no run over those sectors (FAT zeroes a deleted file's
    chain: fat-13's A150 lies, in pieces, over A030)."""
    owners = {}
    for begin, length in record['runs']:
        for at in range(begin, begin + length, SECTOR):
            block = handler.read(at, SECTOR)
            match = _FIRST.match(block) or _BLOCK.match(block)
            if match:
                owner = match.group(match.lastindex).decode('utf-8',
                                                            'replace')
                owners.setdefault(owner, []).append(at)
    base = file_name.rsplit('/', 1)[-1]
    owners.pop(base, None)
    if not owners:
        return False
    for owner, places in owners.items():
        if owner in missing:
            continue
        entry = next((r for r in records if r['name'] == owner), None)
        if entry is None:
            continue
        if any(b <= at < b + n for at in places for b, n in entry['runs']):
            return False                # recorded: TRACE should have seen it
    return True


def _fat_driver_offset(image):
    """Minutes the Mac's msdosfs added to UTC, from the key's FAT access
    times (a date, read as local midnight): every one must agree."""
    seen = set()
    for stamps in image['times'].values():
        access = (stamps.get('access') or {}).get('utc')
        if access:
            minutes = int(access[11:13]) * 60 + int(access[14:16])
            seen.add(-minutes if minutes <= 720 else 1440 - minutes)
    return seen.pop() if len(seen) == 1 else None


def _set_by_deletion(got, when, fs_kind, kind, driver_offset):
    """Is `got` the deletion time the key records for the file?"""
    moment = when['utc']
    if fs_kind == 'fat':
        if driver_offset is None:
            return False
        moment = _shifted(moment, driver_offset)
        if kind == 'access':
            return got[:10] == moment[:10]       # FAT keeps a date only
        return abs(_seconds(got) - _seconds(moment)) <= 2
    return abs(_seconds(got) - _seconds(moment)) <= 1


def _seconds(text):
    from datetime import datetime, timezone
    return datetime.strptime(text[:19], '%Y-%m-%d %H:%M:%S').replace(
        tzinfo=timezone.utc).timestamp()


def _same_time(want, got, fat_access=False, two_seconds=False):
    """Equal as the file system can record them: FAT keeps an access date
    only, and modified times in 2-second steps -- a writer may round
    either way, so one step either side is the same time."""
    if not want or not got:
        return False
    if fat_access:
        return want[:10] == got[:10]
    if two_seconds:
        return abs(_seconds(want) - _seconds(got)) <= 2
    return want[:19] == got[:19]


def score(name, image, verbose=False):
    from trace_app.core import deleted
    from trace_app.core.carving import allocation_map
    from trace_app.core.image_handler import ImageHandler
    path = image_path(name)
    handler = ImageHandler(path)
    if not handler.loaded:
        return {'error': handler.load_error}
    result = Counter()
    notes = []
    try:
        fs_kind = name.split('-', 1)[0]
        fat = fs_kind in ('fat', 'xfat')
        allocated = allocation_map(handler)
        records = [r for r in deleted.deleted_files(handler, allocated)
                   if not r['is_dir']]
        used = set()
        binned = _recycled(handler, records)

        def find(key_name):
            base = key_name.rsplit('/', 1)[-1]
            for index, record in enumerate(records):
                if index not in used and same_name(base, record['name'], fat):
                    used.add(index)
                    return record
            # Deleted through the Recycle Bin: listed as its $R content,
            # named by its $I record -- as the Deleted Files panel shows it
            # ("$R019S2V.txt -- was F:\\Bunda.txt").
            index = binned.get(base.lower())
            if index is not None and index not in used:
                used.add(index)
                return records[index]
            return None

        matched = {}
        missing = set(image['metadata_missing'])
        listed = image['deleted']
        summary = image['summary'] or {}
        if summary.get('deleted') == len(image['sectors']) < len(listed):
            # DFR-07-two's table also names the files that overwrote the
            # deleted ones -- live on the image. Its summary and its
            # per-file counts agree on which were deleted.
            listed = [d for d in listed if d['name'] in image['sectors']]
        for item in listed:
            record = find(item['name'])
            if item['name'] in missing:
                # The key: nothing records this file any more.
                result['no metadata'] += 1
                if record is not None:
                    result['no metadata, listed'] += 1
                    matched[item['name']] = record
                continue
            result['deleted'] += 1
            if record is None:
                notes.append(f"not listed: {item['name']}")
                continue
            result['listed'] += 1
            matched[item['name']] = record

        # State against the key's intact count.
        for file_name, count in image['sectors'].items():
            record = matched.get(file_name) or find(file_name)
            if record is None:
                continue
            matched[file_name] = record
            total, intact = count['total'], min(count['intact'],
                                                count['total'])
            state = record['state']
            result['stated'] += 1
            if intact == total:
                # "start only" claims less than it could: not wrong.
                good = state in (deleted.RECOVERABLE, deleted.RESIDENT,
                                 deleted.NO_DATA, deleted.REUSED,
                                 deleted.START_ONLY, deleted.POSSIBLY)
            elif intact == 0:
                good = state != deleted.RECOVERABLE and \
                    state != deleted.RESIDENT
            else:
                good = state in (deleted.PARTLY, deleted.NO_DATA,
                                 deleted.REUSED, deleted.OVERWRITTEN,
                                 deleted.START_ONLY, deleted.POSSIBLY)
            proved = False
            if not good and state in (deleted.RECOVERABLE, deleted.RESIDENT) \
                    and own_content(trace_bytes(handler, record), file_name,
                                    record['size']):
                # The key counts sectors, which says nothing of data kept
                # in the MFT entry or compressed into fewer clusters; every
                # block of what TRACE recovers names this file, in order.
                good = proved = True
                result['proved by content'] += 1
            unknowable = False
            if not good and state == deleted.RECOVERABLE:
                # Overwritten only by files the key says left no entry: no
                # metadata on the disk records the overwrite, so nothing
                # reading it can know. Counted apart, not hidden.
                by = {o['by'] for o in image['overlaps']
                      if o['deleted'] == file_name}
                unknowable = bool(by) and by <= set(image['metadata_missing'])
                if not unknowable:
                    unknowable = _unrecorded_overwrite(
                        handler, record, records, file_name,
                        set(image['metadata_missing']))
            if good:
                result['state ok'] += 1
            elif unknowable:
                result['unknowable'] += 1
                notes.append(f"unknowable: {file_name} reads 'recoverable'; "
                             f"the files that overwrote it left no entry")
            else:
                notes.append(f"state: {file_name} is '{state}'; key "
                             f"{intact}/{total} sectors intact")
            if state == deleted.RECOVERABLE and intact < total and \
                    not unknowable and not proved:
                result['false ok'] += 1

        # Content of what TRACE calls recoverable.
        lists = image['sector_lists']
        for file_name, record in matched.items():
            if record['state'] not in (deleted.RECOVERABLE,
                                       deleted.RESIDENT):
                continue
            count = image['sectors'].get(file_name)
            ranges = file_ranges(image, file_name, record['size'])
            if not ranges or not count or \
                    count['intact'] < count['total']:
                continue
            want = key_bytes(handler.read, ranges, record['size'],
                             file_name)
            if want is None:
                continue                # the key's sectors do not say
            result['content checked'] += 1
            got = trace_bytes(handler, record)
            if got == want:
                result['content ok'] += 1
            else:
                result['false ok'] += 1
                notes.append(f"content: {file_name} recovered as "
                             f"{len(got):,} bytes that are not the file's")

        # Times.
        deleted_at = image['deleted_at']
        # Made on a Mac (its delete log is `date` output: "Sun Oct  9 ...
        # EDT 2011"), FAT's digits are the msdosfs driver's; made on
        # Windows ("Mon 01/16/2012 08:17 PM"), they are the local time
        # the key prints.
        mac_made = bool(deleted_at)
        driver_offset = _fat_driver_offset(image) \
            if fs_kind == 'fat' and mac_made else None
        for file_name, stamps in image['times'].items():
            base = file_name.rsplit('/', 1)[-1]
            record = matched.get(base) or matched.get(file_name)
            if record is None or record['state'] == deleted.REUSED:
                continue
            when = deleted_at.get(base)
            for kind, field in (('modify', 'modified'),
                                ('access', 'accessed')):
                if kind not in stamps or not stamps[kind]:
                    continue
                want = stamps[kind]['utc'][:19]
                if fs_kind == 'fat' and not mac_made:
                    want = stamps[kind]['local'][:19]
                elif fs_kind == 'fat':
                    if driver_offset is None:
                        continue
                    want = _shifted(want, driver_offset)
                got = record.get(field)
                fat_access = fs_kind == 'fat' and kind == 'access'
                two = fs_kind == 'fat' and kind == 'modify'
                result['times'] += 1
                if _same_time(want, got, fat_access, two):
                    result['times ok'] += 1
                elif when and got and _set_by_deletion(
                        got, when, fs_kind, kind, driver_offset):
                    # The deletion itself wrote it: ext3/4 truncate (modified
                    # time), a move into the Recycle Bin (FAT access date).
                    result['times ok'] += 1
                    result['times at deletion'] += 1
                else:
                    notes.append(f"time: {file_name} {kind} {got} != key "
                                 f"{want[:19]}")

        # The key's sector numbers, checked on live files.
        from trace_app.core.case import parse_artifact_ref
        live = defaultdict(list)
        for offset, fs_path, ref in _live_files(handler):
            live[fs_path.rsplit('/', 1)[-1].lower()].append((offset, ref))
        for file_name in lists:
            hits = live.get(file_name.rsplit('/', 1)[-1].lower())
            if not hits:
                continue
            checked = agreed = False
            for offset, ref in hits:       # the same name on two volumes
                fs = handler.get_fs_info(offset)
                handle = fs.open_meta(inode=parse_artifact_ref(ref)['inode'])
                size = int(handle.info.meta.size)
                ranges = file_ranges(image, file_name, size)
                want = ranges and key_bytes(handler.read, ranges, size,
                                            file_name)
                if want is None or not ranges:
                    continue
                checked = True
                got = handle.read_random(0, size) if size else b''
                if got == want:
                    agreed = True
                    break
            if not checked:
                continue
            result['key checked'] += 1
            if agreed:
                result['key ok'] += 1
            else:
                notes.append(f"key: live {file_name} differs from its "
                             f"listed sectors")
    finally:
        handler.close_resources()
    result = dict(result)
    if verbose:
        result['notes'] = notes
    else:
        result['notes'] = notes[:0]
    result['_notes'] = notes
    return result


def _live_files(handler):
    from trace_app.core import walk
    names = []
    list(walk.iter_files(handler, every_name=lambda offset, path, deleted,
                         ref: names.append((offset, path, ref, deleted))))
    return [(o, p, r) for o, p, r, d in names if not d]


COLUMNS = ('listed', 'state ok', 'false ok', 'content ok', 'times ok',
           'key ok')


def _score_one(args):
    try:
        return score(*args)
    except Exception as exc:                  # one image must not stop all
        return {'error': f"{type(exc).__name__}: {exc}"}


def main(argv):
    verbose = '-v' in argv
    jobs = 1
    args = list(argv[1:])
    if '-j' in args:
        at = args.index('-j')
        jobs = int(args[at + 1])
        del args[at:at + 2]
    wanted = [a for a in args if not a.startswith('-')]
    key = load_key()
    names = [n for n in key if (not wanted or n in wanted)
             and (key[n]['deleted'] or key[n]['sector_lists'])]
    totals = defaultdict(int)
    print(f"{'image':18} {'listed':>9} {'state':>9} {'false ok':>8} "
          f"{'content':>9} {'times':>9} {'key':>9} {'no-meta':>8} "
          f"{'unknowable':>10}")
    present = [n for n in names if image_path(n)]
    for name in names:
        if name not in present:
            print(f"{name:18} (image missing)")
    if jobs > 1:
        from concurrent.futures import ProcessPoolExecutor
        pool = ProcessPoolExecutor(jobs)
        results = pool.map(_score_one, [(n, key[n], verbose)
                                        for n in present])
    else:
        results = (score(n, key[n], verbose) for n in present)
    for name, r in zip(present, results):
        if 'error' in r:
            print(f"{name:18} ERROR {r['error']}")
            continue
        for column in ('no metadata', 'no metadata, listed',
                       'deleted', 'listed', 'stated', 'state ok',
                       'false ok', 'content checked', 'content ok',
                       'times', 'times ok', 'key checked', 'key ok',
                       'unknowable', 'times at deletion'):
            totals[column] += r.get(column, 0)

        def pair(a, b):
            return f"{r.get(a, 0)}/{r.get(b, 0)}"
        print(f"{name:18} {pair('listed', 'deleted'):>9} "
              f"{pair('state ok', 'stated'):>9} {r.get('false ok', 0):>8} "
              f"{pair('content ok', 'content checked'):>9} "
              f"{pair('times ok', 'times'):>9} "
              f"{pair('key ok', 'key checked'):>9} "
              f"{pair('no metadata, listed', 'no metadata'):>8} "
              f"{r.get('unknowable', 0):>10}", flush=True)
        for note in r['_notes'] if verbose else []:
            print('    ' + note)
    print(f"{'TOTAL':18} {totals['listed']}/{totals['deleted']} "
          f"{totals['state ok']}/{totals['stated']} {totals['false ok']} "
          f"{totals['content ok']}/{totals['content checked']} "
          f"{totals['times ok']}/{totals['times']} "
          f"{totals['key ok']}/{totals['key checked']} "
          f"unknowable={totals['unknowable']} "
          f"times-at-deletion={totals['times at deletion']}")
    return 1 if totals['false ok'] else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
