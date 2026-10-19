"""What Spotlight remembers about files and app content (no Qt).

Reads every Spotlight store on a volume (core/spotlight.py parses them):

* the volume's own index -- .Spotlight-V100/Store-V2/<UUID>/store.db (and
  .store.db, read when store.db gives nothing), also under
  /private/var/db/Spotlight-V100 and System/Volumes/Data;
* each user's CoreSpotlight (Library/Metadata/CoreSpotlight/...) and an
  iPhone's (/private/var/mobile/Library/Spotlight/CoreSpotlight/...): what
  apps donated -- messages, mail, notes, web pages.

A file store becomes:

* **Opened** at kMDItemLastUsedDate -- with every day in
  kMDItemUsedDates and the use count;
* **Downloaded** at kMDItemDownloadedDate (else the date added) for a
  file with kMDItemWhereFroms -- the page and the file's URL;
* **Indexed file no longer on disk** for a file under /Users whose path
  does not resolve on the volume now: Spotlight kept its name, dates and
  origin after it went.

A CoreSpotlight store becomes one 'App content indexed' row per item with
a name or text, under the app's bundle id.

Times are Cocoa (seconds since 2001, UTC). Rows are capped per store
(`MAX_ROWS`); the cap is said in the log.
"""

import logging

from trace_app.core import spotlight
from trace_app.core.activity import record, times

logger = logging.getLogger('TRACE.Activity.Spotlight')

#: Records kept from one store at most.
MAX_ROWS = 100_000
#: Items read from one store at most.
MAX_ITEMS = 2_000_000

_STORE_NAMES = ('store.db', '.store.db')

#: Where a volume's own Spotlight index is kept.
_VOLUME_ROOTS = (
    ('.Spotlight-V100',),
    ('System', 'Volumes', 'Data', '.Spotlight-V100'),
    ('private', 'var', 'db', 'Spotlight-V100'),
)
_IOS_ROOTS = (
    ('private', 'var', 'mobile', 'Library', 'Spotlight', 'CoreSpotlight'),
)
_USER_ROOT = ('Library', 'Metadata', 'CoreSpotlight')

_FIRST_DATES = ('kMDItemLastUsedDate', 'kMDItemContentModificationDate',
                'kMDItemFSContentChangeDate', 'kMDItemContentCreationDate',
                'kMDItemFSCreationDate', 'kMDItemDateAdded')


def collect(volume, step, homes):
    """Activity records from every Spotlight store on the volume."""
    from trace_app.core.activity import _split
    out = []
    for parts in _VOLUME_ROOTS:
        for folder_stores in _stores_under(volume, parts):
            out += _read_first(volume, step, folder_stores)
    for parts in _IOS_ROOTS:
        for folder_stores in _stores_under(volume, parts, depth=6):
            out += _read_first(volume, step, folder_stores, user='mobile')
    for user, home in homes:
        for folder_stores in _stores_under(volume, (*_split(home.path),
                                                    *_USER_ROOT), depth=5):
            out += _read_first(volume, step, folder_stores, user=user)
    return out


def _stores_under(volume, parts, depth=4):
    """[store entries of one folder] for each folder under `parts` that
    holds store.db and/or .store.db, store.db first."""
    root = volume.find(*parts)
    if root is None or not root.is_dir:
        return
    pending = [(root, 0)]
    while pending:
        folder, level = pending.pop()
        here = {e.name.lower(): e for e in volume.listdir(folder.path)
                if not e.is_dir and e.size}
        found = [here[name] for name in _STORE_NAMES if name in here]
        if found:
            yield found
        if level < depth:
            pending += [(child, level + 1)
                        for child in volume.children(folder, dirs=True)]


def _read_first(volume, step, entries, user=''):
    """Rows of the first store of a folder that reads (store.db, else the
    .store.db beside it). A volume's own store records files; an iOS or
    per-user CoreSpotlight store (definitions in dbStr-*.map files beside
    it) records what apps donated."""
    for entry in entries:
        step(entry.path)
        data = volume.read(entry)
        if not spotlight.is_store(data):
            continue
        try:
            store = spotlight.Store(data, maps=_maps(volume, entry))
        except spotlight.SpotlightError as exc:
            logger.info("Spotlight store %s unreadable: %s", entry.path, exc)
            continue
        reader = app_records if store.external else file_records
        rows = reader(store, entry.path, volume.ref(entry), volume=volume,
                      user=user)
        if rows:
            return rows
    return []


def _maps(volume, entry):
    """{n: (data, offsets, header)} of the dbStr-<n>.map files beside a
    store, or None when there are none."""
    folder = entry.path.rsplit('/', 1)[0]
    here = {e.name.lower(): e for e in volume.listdir(folder)
            if not e.is_dir}
    maps = {}
    for number in spotlight.MAP_FILES:
        parts = [here.get(f'dbstr-{number}.map.{kind}')
                 for kind in ('data', 'offsets', 'header')]
        if parts[0] is not None and parts[1] is not None:
            maps[number] = tuple(volume.read(p) if p is not None else b''
                                 for p in parts)
    return maps or None


def _date(value):
    if isinstance(value, list):
        value = max((v for v in value if isinstance(v, (int, float))),
                    default=None)
    if isinstance(value, (int, float)):
        return times.mac_absolute(value)
    return None


def _dates(value):
    values = value if isinstance(value, list) else [value]
    return [d for d in (times.mac_absolute(v) for v in values
                        if isinstance(v, (int, float))) if d]


def _text(value, limit=400):
    if isinstance(value, list):
        value = ' | '.join(str(v) for v in value if v not in (None, ''))
    if isinstance(value, bytes):
        return None
    return str(value)[:limit] if value not in (None, '') else None


def _common(item, path):
    a = item.attributes
    detail = {
        'name': item.name or None,
        'path': path,
        'content type': _text(a.get('kMDItemContentType')),
        'kind': _text(a.get('kMDItemKind')),
        'size': a.get('kMDItemFSSize') or a.get('kMDItemLogicalSize'),
        'created': times.iso(_date(a.get('kMDItemFSCreationDate'))),
        'modified': times.iso(_date(a.get('kMDItemFSContentChangeDate'))),
        'content created': times.iso(_date(
            a.get('kMDItemContentCreationDate'))),
        'added': times.iso(_date(a.get('kMDItemDateAdded'))),
        'last used': times.iso(_date(a.get('kMDItemLastUsedDate'))),
        'use count': a.get('kMDItemUseCount'),
        'title': _text(a.get('kMDItemTitle')),
        'authors': _text(a.get('kMDItemAuthors')),
        'creator': _text(a.get('kMDItemCreator')),
        'where from': _text(a.get('kMDItemWhereFroms'), 1000),
        'inode': item.item_id if item.item_id > 0 else None,
    }
    used = _dates(a.get('kMDItemUsedDates'))
    if used:
        detail['used on'] = ', '.join(sorted({d.strftime('%Y-%m-%d')
                                              for d in used}))
    return detail


def file_records(store, path, ref, volume=None, user=''):
    """Rows for a volume's own store: opened, downloaded, and files gone."""
    items = [i for i in store.items(limit=MAX_ITEMS)
             if not i.is_store_metadata]
    paths = spotlight.Store.paths(items)
    out = []
    capped = False
    for item in items:
        if len(out) >= MAX_ROWS:
            capped = True
            break
        a = item.attributes
        full = paths.get(item.id) or item.name
        if not full:
            continue
        detail = _common(item, full)
        detail['store'] = store.original_path or None
        last_used = _date(a.get('kMDItemLastUsedDate'))
        if last_used:
            out.append(record(
                'files', 'Spotlight', last_used, 'Opened (Spotlight)', full,
                dict(detail, basis="kMDItemLastUsedDate: when the file was "
                                   "last opened"),
                user=user or _user_of(full), path=path, ref=ref))
        if a.get('kMDItemWhereFroms'):
            when = _date(a.get('kMDItemDownloadedDate')) or \
                _date(a.get('kMDItemDateAdded'))
            out.append(record(
                'downloads', 'Spotlight', when, 'Downloaded (Spotlight)',
                full, dict(detail, basis="kMDItemDownloadedDate (else the "
                                         "date added)"),
                user=user or _user_of(full), path=path, ref=ref))
        if volume is not None and full.startswith('/Users/') and \
                not _on_volume(volume, full):
            when = next((_date(a.get(k)) for k in _FIRST_DATES
                         if _date(a.get(k))), None)
            out.append(record(
                'files', 'Spotlight', when,
                'Indexed file no longer on disk', full,
                dict(detail, **{'still on disk': 'no',
                                'basis': 'the latest date Spotlight kept '
                                         'for the file'}),
                user=user or _user_of(full), path=path, ref=ref))
    if capped:
        logger.info("Spotlight %s: first %d rows kept", path, MAX_ROWS)
    return out


def app_records(store, path, ref, volume=None, user=''):
    """Rows for a CoreSpotlight store: each item an app donated."""
    out = []
    for item in store.items(limit=MAX_ITEMS):
        if len(out) >= MAX_ROWS:
            logger.info("CoreSpotlight %s: first %d rows kept", path,
                        MAX_ROWS)
            break
        if item.is_store_metadata:
            continue
        a = item.attributes
        bundle = _text(a.get('_kMDItemBundleID') or a.get('kMDItemBundleID')
                       or a.get('_kMDItemApplicationBundleID'))
        title = _text(a.get('kMDItemDisplayName') or a.get('kMDItemTitle')
                      or a.get('kMDItemSubject'))
        text = _text(a.get('kMDItemTextContent') or
                     a.get('kMDItemDescription'), 1000)
        if not (title or text):
            continue
        when = _date(a.get('kMDItemContentCreationDate')) or \
            _date(a.get('kMDItemLastUsedDate')) or \
            _date(a.get('kMDItemContentModificationDate')) or \
            _date(a.get('_kMDItemInterestingDate'))
        detail = _common(item, None)
        detail.update({
            'app': bundle, 'text': text,
            'url': _text(a.get('kMDItemURL') or a.get('kMDItemContentURL')),
            'from': _text(a.get('kMDItemAuthorEmailAddresses') or
                          a.get('kMDItemAuthors')),
            'to': _text(a.get('kMDItemRecipientEmailAddresses') or
                        a.get('kMDItemRecipients')),
            'phone numbers': _text(a.get('kMDItemPhoneNumbers')),
            'basis': 'when the content was created, as the app told '
                     'Spotlight'})
        out.append(record(
            'records', f"CoreSpotlight · {bundle}" if bundle else
            'CoreSpotlight', when, 'App content indexed', title or
            (text or '')[:120], detail, user=user, path=path, ref=ref))
    return out


def _on_volume(volume, full):
    parts = [p for p in full.split('/') if p]
    try:
        return volume.find(*parts) is not None
    except Exception:
        return True                 # cannot say: never claim it is gone


def _user_of(full):
    parts = full.split('/')
    return parts[2] if len(parts) > 2 and parts[1] == 'Users' else ''
