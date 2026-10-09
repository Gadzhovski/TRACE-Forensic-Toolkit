"""macOS Background Task Management: what starts at login, as System
Settings' "Login Items & Extensions" lists it (no Qt).

macOS 13 (Ventura) and later record every login item, launch agent and
daemon a program installed -- and whether the user allowed it -- in
/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm
(v4 on Ventura, higher numbers since). It is an NSKeyedArchiver plist: a
Storage whose itemsByUserIdentifier maps each user's UUID (the account's
GeneratedUID) to ItemRecords -- name, identifier, type, disposition,
developer and team, bundle, the app's URL or the program it starts, and
the parent item ("container") that put it there.

`type` and `disposition` are bit fields, named as Objective-See's DumpBTM
names them (the open version of `sfltool dumpbtm`): type 0x2 app, 0x4
login item, 0x8 agent, 0x10 daemon, 0x20 developer, 0x10000 legacy,
0x80000 curated; disposition 0x1 enabled, 0x2 allowed, 0x4 hidden,
0x8 notified.

Before Ventura each user had ~/Library/Application Support/
com.apple.backgroundtaskmanagementagent/backgrounditems.btm: containers
of BackgroundLoginItems, each a bookmark (activity/macbookmark.py) of
the app it opens. Both are read here; expected values are BTMParser's
and macos-loginitems' tests for the same files.
"""

import datetime
import plistlib
import uuid as uuid_module

from trace_app.core.activity import macbookmark, times

TYPES = ((0x80000, 'curated'), (0x10000, 'legacy'), (0x20, 'developer'),
         (0x10, 'daemon'), (0x8, 'agent'), (0x4, 'login item'),
         (0x2, 'app'))


class BtmError(Exception):
    pass


def unarchive(data):
    """An NSKeyedArchiver plist as plain Python. Objects are followed
    through their UIDs (binary plists) or {'CF$UID': n} dicts (XML ones);
    an object met again inside itself is None, so cycles end."""
    try:
        archive = plistlib.loads(data)
    except Exception as exc:
        raise BtmError(f"Not a property list: {exc}") from exc
    if not isinstance(archive, dict) or '$objects' not in archive:
        raise BtmError("Not an NSKeyedArchiver archive")
    objects = archive['$objects']

    def index_of(value):
        if isinstance(value, plistlib.UID):
            return value.data
        if isinstance(value, dict) and set(value) == {'CF$UID'}:
            return value['CF$UID']
        return None

    def walk(value, open_objects):
        index = index_of(value)
        if index is not None:
            if index in open_objects or index >= len(objects):
                return None
            open_objects = open_objects | {index}
            value = objects[index]
        if isinstance(value, dict):
            if 'NS.keys' in value:
                return {walk(k, open_objects): walk(v, open_objects)
                        for k, v in zip(value['NS.keys'],
                                        value['NS.objects'])}
            if 'NS.objects' in value:
                return [walk(v, open_objects) for v in value['NS.objects']]
            if 'NS.string' in value:
                return value['NS.string']
            if 'NS.bytes' in value:
                return value['NS.bytes']
            if 'NS.data' in value:
                return value['NS.data']
            if 'NS.time' in value:
                return times.mac_absolute(value['NS.time'])
            if 'NS.uuidbytes' in value:
                raw = walk(value['NS.uuidbytes'], open_objects)
                return str(uuid_module.UUID(bytes=bytes(raw))).upper() \
                    if raw and len(raw) == 16 else None
            if 'NS.relative' in value:
                # An NSURL. A helper inside an app is stored relative to
                # the app ('Contents/Library/LoginItems/x.app' over
                # file:///): kept as such, resolved against its container.
                base = walk(value.get('NS.base'), open_objects)
                relative = walk(value['NS.relative'], open_objects)
                if base and relative and '://' not in str(relative):
                    return _Relative(relative)
                return relative or base
            return {key: walk(item, open_objects)
                    for key, item in value.items() if key != '$class'}
        if value == '$null':
            return None
        return value

    return {key: walk(value, frozenset())
            for key, value in archive.get('$top', {}).items()}


class _Relative(str):
    """A URL path stored relative to the item that contains it."""


#: Apple's fixed UUIDs for system accounts end in the uid, in hex.
_SYSTEM_UUID = 'FFFFEEEE-DDDD-CCCC-BBBB-AAAA'


def user_label(uuid, names):
    """The account a BTM user UUID is: its name from the local directory
    (`names`: GeneratedUID -> name), a system account's uid, or the UUID."""
    if not uuid:
        return ''
    if uuid in names:
        return names[uuid]
    if uuid.upper().startswith(_SYSTEM_UUID):
        uid = int(uuid[len(_SYSTEM_UUID):], 16)
        return 'nobody (uid -2)' if uid == 0xFFFFFFFE else f"uid {uid}"
    return uuid


def account_uuids(plists):
    """GeneratedUID -> account name, from the local directory's user
    records (/private/var/db/dslocal/nodes/Default/users/*.plist)."""
    names = {}
    for data in plists:
        try:
            record = plistlib.loads(data)
        except Exception:
            continue
        uuid = (record.get('generateduid') or [None])[0]
        name = (record.get('name') or [None])[0]
        if uuid and name:
            names[str(uuid).upper()] = name
    return names


def type_details(value):
    return ' '.join(name for bit, name in TYPES if (value or 0) & bit)


def disposition_details(value):
    value = value or 0
    return ' '.join((
        'enabled' if value & 0x1 else 'disabled',
        'allowed' if value & 0x2 else 'disallowed',
        'hidden' if value & 0x4 else 'visible',
        'notified' if value & 0x8 else 'not notified'))


def _path(url):
    """A file: URL's path ('file:///Applications/X.app/' ->
    '/Applications/X.app'); a relative one unquoted as it is."""
    from urllib.parse import unquote
    if not url:
        return ''
    if isinstance(url, _Relative):
        return unquote(str(url)).rstrip('/')
    if not str(url).startswith('file://'):
        return str(url)
    path = unquote(str(url)[len('file://'):])
    return path.rstrip('/') or '/'


def _bookmark(data):
    if not data:
        return {}
    try:
        return macbookmark.parse(bytes(data))
    except macbookmark.BookmarkError:
        return {}


def items(data):
    """Every item of a BTM file: [{user_uuid, name, identifier, type,
    type_details, disposition, disposition_details, enabled, developer,
    team, bundle, container, url, executable, arguments, generation,
    modified, uuid, legacy}]."""
    top = unarchive(data)
    store = top.get('store')
    if isinstance(store, dict) and 'itemsByUserIdentifier' in store:
        return _current(store)
    root = top.get('root')
    if isinstance(root, dict) and 'backgroundItems' in root:
        return _legacy(root['backgroundItems'])
    raise BtmError("Neither a BackgroundItems store nor a "
                   "backgrounditems.btm")


def _current(store):
    out = []
    for user, records in (store.get('itemsByUserIdentifier') or {}).items():
        for record in records or ():
            if not isinstance(record, dict):
                continue
            mark = _bookmark(record.get('bookmark'))
            kind = record.get('type') or 0
            disposition = record.get('disposition') or 0
            arguments = record.get('programArguments') or []
            modified = record.get('modificationDate')
            if isinstance(modified, (int, float)) and modified:
                modified = times.mac_absolute(modified)
            elif not isinstance(modified, datetime.datetime):
                modified = None
            out.append({
                'user_uuid': user, 'name': record.get('name') or '',
                'identifier': record.get('identifier') or '',
                'type': kind, 'type_details': type_details(kind),
                'disposition': disposition,
                'disposition_details': disposition_details(disposition),
                'enabled': bool(disposition & 0x1),
                'developer': record.get('developerName') or '',
                'team': record.get('teamIdentifier') or '',
                'bundle': record.get('bundleIdentifier') or '',
                'container': record.get('container') or '',
                'url': _path(record.get('url')) or mark.get('path') or '',
                'relative': isinstance(record.get('url'), _Relative),
                'executable': record.get('executablePath') or '',
                'arguments': ' '.join(str(a) for a in arguments
                                      if a is not None),
                'generation': record.get('generation'),
                'modified': modified,
                'uuid': record.get('uuid') or '',
                'added_by': '', 'legacy': False})
    # A helper's URL is inside its container app: made whole from it.
    by_identifier = {item['identifier']: item for item in out}
    for item in out:
        if item.pop('relative'):
            parent = by_identifier.get(item['container'])
            if parent is not None and parent['url'].startswith('/'):
                item['url'] = f"{parent['url']}/{item['url']}"
    return out


def _legacy(background):
    out = []
    seen = set()
    for container in background.get('allContainers') or ():
        if not isinstance(container, dict):
            continue
        # The container's own bookmark is the program that registered its
        # items -- System Events, for one added by AppleScript.
        owner = container.get('bookmark') or {}
        owner = _bookmark(owner.get('data') if isinstance(owner, dict)
                          else owner).get('path') or ''
        for item in container.get('internalItems') or ():
            if not isinstance(item, dict):
                continue
            bookmark = item.get('bookmark') or {}
            raw = bookmark.get('data') if isinstance(bookmark, dict) \
                else bookmark
            mark = _bookmark(raw)
            key = (bookmark.get('identifier') if isinstance(bookmark, dict)
                   else None) or mark.get('path')
            if key in seen:
                continue
            seen.add(key)
            path = mark.get('path') or ''
            out.append({
                'user_uuid': '', 'name': mark.get('name') or
                path.rsplit('/', 1)[-1].removesuffix('.app'),
                'identifier': '', 'type': 0x4,
                'type_details': 'login item', 'disposition': 0x1,
                'disposition_details': '', 'enabled': True,
                'developer': '', 'team': '', 'bundle': '', 'container': '',
                'url': path, 'executable': '', 'arguments': '',
                'generation': None, 'modified': mark.get('created'),
                'uuid': '', 'added_by': owner, 'legacy': True})
    return out
