"""Turn NIST CFReDS's Deleted File Recovery answer key into JSON.

The key is `setup-july-10-2012.pdf` ("Test Images layout.docx"), published
with the images at https://cfreds-archive.nist.gov/dfr-test-images.html.
It is parsed here rather than transcribed by hand, so the ground truth is
the publisher's document and nothing else:

    python tools/nist_dfr_key.py test_images/nist/dfr/setup-july-10-2012.pdf

writes tools/nist_dfr_ground_truth.json. Per image ('ext-07', 'fat-04',
...): the partitions' start sectors; every deleted file (name, size); the
MAC times `stat` printed just before deletion (UTC and local); the key's count of
each file's sectors and of those still intact at the end; when each was
deleted (UTC, and the offset the clock was on); a file's last part-sector
(the layout's TAIL rows, which the Sector List leaves out); the files whose
metadata the key says is gone; and every file's sector list. The document
abbreviates long lists ("20 omitted", ". . . + 1254 more"); such a list is
kept with `"complete": false` and only what it states is used.

Times: GNU stat prints a zone ("-0400"); OS X's stat does not, and the
images were made in US Eastern time (every delete time says EDT/EST), so
those are read as America/New_York.
"""

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:                                   # pragma: no cover
    ZoneInfo = None

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(HERE, 'nist_dfr_ground_truth.json')
#: SHA-256 of setup-july-10-2012.pdf as published.
PDF_SHA256 = None

_HEADER = re.compile(r'^(?:Last save .*|Page \d+ of \d+|Test Images layout\.docx'
                     r'|=====PAGE \d+)$')
_SECTION = re.compile(r'^(?:\d+\s+)?Test Image (\S+)$')
_SIZE = re.compile(r'^(\d+) \((\d+)\+(\d+)\)$')
_STAT_NAME = re.compile(r"^File: [`\"](.+)['\"]$")
_STAT_TIME = re.compile(r'^(Access|Modify|Change|Birth): (.+)$')
_INTACT = re.compile(r'^File: (.+?) (\d+) (\d+)(?:\s+(\w.*))?$')
_SUMMARY = re.compile(r'^Summary: (\d+) (\d+) (\d+) (\d+)$')
_METADATA = re.compile(r'Metadata found (\d+) files, not found (\d+), '
                       r'total (\d+)')
_OVERLAP = re.compile(r'^(.+?) x (.+?):\s+overlap -\s+(\d+) - (\d+)$')
_PARTITION = re.compile(r'^/dev/\w+?(\d+)\s+(?:\*\s+)?(\d+)\s+(\d+)\s+'
                        r'\d+\+?\s+(\w+)\s+(.*)$')
_RANGE = re.compile(r'(\d+)\s*-\s*(\d+)')


def stat_time(text):
    """{'utc': ..., 'local': ...} for a time as GNU or OS X stat prints it
    -- both 'YYYY-MM-DD HH:MM:SS.nnnnnnnnn', 'local' as the clock read
    where the image was made (what FAT and exFAT store) -- or None."""
    text = text.strip()
    match = re.match(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\.(\d{9}) '
                     r'([+-]\d{4})$', text)
    if match:
        moment = datetime.strptime(match.group(1) + ' ' + match.group(3),
                                   '%Y-%m-%d %H:%M:%S %z')
        nanos = match.group(2)
    else:
        try:
            moment = datetime.strptime(' '.join(text.split()),
                                       '%a %b %d %H:%M:%S %Y')
        except ValueError:
            return None
        moment = moment.replace(tzinfo=ZoneInfo('America/New_York'))
        nanos = '000000000'
    return {'local': moment.strftime('%Y-%m-%d %H:%M:%S.') + nanos,
            'utc': moment.astimezone(timezone.utc).strftime(
                '%Y-%m-%d %H:%M:%S.') + nanos}


def delete_time(text):
    """'Sun Oct  9 13:12:59 EDT 2011' -> {'utc', 'offset' (minutes)}."""
    parts = text.split()
    offsets = {'EDT': -240, 'EST': -300}
    if len(parts) != 6 or parts[4] not in offsets:
        return None
    moment = datetime.strptime(' '.join(parts[:4] + parts[5:]),
                               '%a %b %d %H:%M:%S %Y')
    offset = offsets[parts[4]]
    utc = moment - timedelta(minutes=offset)
    return {'utc': utc.strftime('%Y-%m-%d %H:%M:%S'), 'offset': offset}


#: Where the PDF's text layer is not what its page shows. The one case:
#: DFR-04's Arabic "tajine", whose last two letters the text layer stores
#: in visual order (taa alif jeem NOON YEH); the word, and the name on the
#: images, is taa alif jeem YEH NOON.
TEXT_LAYER = {'\u0637\u0627\u062c\u0646\u064a':
              '\u0637\u0627\u062c\u064a\u0646'}


def lines_of(pdf):
    import pymupdf
    with pymupdf.open(pdf) as document:
        for page in list(document)[2:]:               # 1-2: contents
            for line in page.get_text().splitlines():
                if not _HEADER.match(line.strip()):
                    for wrong, right in TEXT_LAYER.items():
                        line = line.replace(wrong, right)
                    yield line.rstrip()


def sections(lines):
    name, body, pending = None, [], None
    for line in lines:
        stripped = line.strip()
        match = _SECTION.match(stripped)
        if match and (pending is not None or stripped[0].isdigit()):
            if name:
                yield name, body
            name, body, pending = match.group(1), [], None
            continue
        # "2 \nTest Image ext-01-recycle": a section number on its own.
        if pending is not None:
            body.append(pending)
        pending = line if re.fullmatch(r'\d+', stripped) else None
        if pending is None:
            body.append(line)
    if name:
        yield name, body


def parse(body):
    image = {'partitions': [], 'deleted': [], 'times': {},
             'times_complete': True, 'sectors': {}, 'overlaps': [],
             'summary': None, 'metadata_found': None,
             'metadata_missing': [], 'sector_lists': {}, 'tails': {},
             'deleted_at': {}, 'delete_log': []}
    state, current, last_name, row, deleting = None, None, None, None, 0
    stripped = [line.strip() for line in body]
    index = 0
    while index < len(stripped):
        line, raw = stripped[index], body[index]
        index += 1
        if not line:
            continue
        match = _PARTITION.match(line)
        if match:
            image['partitions'].append(
                {'number': int(match.group(1)), 'start': int(match.group(2)),
                 'end': int(match.group(3)), 'id': match.group(4),
                 'system': match.group(5).strip()})
            continue
        if line.startswith('Deleted files (') and line.endswith(')'):
            state = 'deleted'
            continue
        if line.startswith('MAC times just before'):
            state = 'times'
            continue
        if line.startswith('Deleted files without metadata'):
            state = 'missing'
            continue
        if line.startswith('Layout History') or line.startswith('Layout for'):
            state = 'layout'
            continue
        if line == 'Sector List':
            state = 'sectors'
            continue
        if line.startswith('File delete times'):
            state = 'deletes'
            continue
        if line.startswith('Steps to Create'):
            state = None
            continue
        if state == 'deletes':
            log = image['delete_log']
            if line.startswith('ACTION (delete time):'):
                moment = delete_time(line.split(':', 1)[1])
                for item in log[len(log) - deleting:]:
                    image['deleted_at'].setdefault(item, moment)
                deleting = 0
            elif line.startswith('ACTION (delete):'):
                names = line.split(':', 1)[1].split()
                log.extend(names)
                deleting = len(names)
            elif deleting and not line.startswith(('Times:', '=====',
                                                   'CASE ')):
                # A right-to-left name the PDF broke over two lines.
                log[-1] += line
            continue
        if state == 'layout':
            # Rows: a sector range, then what held it at each step. The
            # Sector List leaves out a file's last part-sector; the layout
            # names it TAIL/<name>.
            match = _RANGE.fullmatch(line)
            if match:
                row = [int(match.group(1)), int(match.group(2))]
            elif row and 'TAIL/' in line:
                stem = line.replace('TAIL/', '').rsplit('/', 1)[-1]
                tails = image['tails'].setdefault(stem, [])
                if row not in tails:
                    tails.append(row)
            continue
        if state == 'deleted':
            if line in ('Name', 'Size', 'F-Hd', 'F-Bks'):
                continue
            if index < len(stripped) and _SIZE.match(stripped[index]):
                size = _SIZE.match(stripped[index])
                image['deleted'].append({'name': line,
                                         'size': int(size.group(1))})
                index += 3                     # size, F-Hd, F-Bks
            continue
        if state == 'times':
            match = _STAT_NAME.match(line)
            if match:
                current = match.group(1)
                image['times'][current] = {}
                continue
            match = _STAT_TIME.match(line)
            if match and current:
                image['times'][current][match.group(1).lower()] = \
                    stat_time(match.group(2))
                continue
            if line.endswith('omitted') or line == '. . .':
                image['times_complete'] = False
            continue
        match = _INTACT.match(line)
        if match and not line.startswith('File: `'):
            image['sectors'][match.group(1)] = {
                'total': int(match.group(2)), 'intact': int(match.group(3))}
            if match.group(4):                 # "Growth": a remark
                image['sectors'][match.group(1)]['note'] = match.group(4)
            continue
        match = _SUMMARY.match(line)
        if match:
            image['summary'] = dict(zip(
                ('deleted', 'intact', 'partly', 'overwritten'),
                map(int, match.groups())))
            continue
        match = _METADATA.search(line)
        if match:
            image['metadata_found'] = int(match.group(1))
            continue
        match = _OVERLAP.match(line)
        if match:
            image['overlaps'].append(
                {'deleted': match.group(1), 'by': match.group(2),
                 'sectors': [int(match.group(3)), int(match.group(4))]})
            continue
        if state == 'missing':
            # Names run together on a line; match the deleted list's.
            for item in image['deleted']:
                if re.search(r'(?:^|\s)' + re.escape(item['name']) +
                             r'(?:\s|$)', line) and \
                        item['name'] not in image['metadata_missing']:
                    image['metadata_missing'].append(item['name'])
            continue
        if state == 'sectors':
            if raw[:1].isspace() or _RANGE.fullmatch(line) or \
                    re.fullmatch(r'\d+', line):
                if last_name is None:
                    continue
                entry = image['sector_lists'][last_name]
                if line.startswith('. . .') and 'more' in line:
                    entry['complete'] = False
                    continue
                if line == '. . .':
                    continue
                entry['text'] += ' ' + line
                continue
            if line.endswith('omitted'):
                last_name = None
                image['sector_lists_complete'] = False
                continue
            last_name = line
            image['sector_lists'][line] = {'text': '', 'complete': True}
    for entry in image['sector_lists'].values():
        text = entry.pop('text')
        entry['ranges'] = [[int(a), int(b)] for a, b in _RANGE.findall(text)]
    image.setdefault('sector_lists_complete', True)
    # DFR-04's table lists the ASCII names the files were made under
    # (/tmp/dfr-04-3/BeiJing.txt3); the names on disk -- the point of the
    # test -- are the ones the delete log records (北京.txt3).
    if image['deleted'] and all(d['name'].startswith('/')
                                for d in image['deleted']) and \
            len(image['delete_log']) == len(image['deleted']):
        image['made_as'] = [d['name'] for d in image['deleted']]
        image['deleted'] = [{'name': name, 'size': None}
                            for name in image['delete_log']]
    return image


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    images = {}
    for name, body in sections(lines_of(argv[1])):
        images[name] = parse(body)
    with open(OUTPUT, 'w', encoding='utf-8') as handle:
        json.dump({'source': 'https://cfreds-archive.nist.gov/dfr-images/'
                             'setup-july-10-2012.pdf',
                   'images': images}, handle, indent=1, ensure_ascii=False,
                  sort_keys=True)
        handle.write('\n')
    print(f"{len(images)} images -> {OUTPUT}")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
