"""Whether an external tool has anything to read on an image, from its own
path patterns (no Qt).

iLEAPP and aLEAPP fit a phone, DLEAPP a computer: TRACE finds those
systems itself (evidence_profile.tool_systems). A warrant return (RLEAPP)
or a car's infotainment extraction (VLEAPP) has no system to find, so the
tool's own `-p` patterns are matched against the image's file listing
(the Scope editor's, scope.listing, kept per image) and the files they
name are counted.

Only patterns that say something count. RLEAPP lists `**/*.*`-style globs
for five Snapchat artifacts and short segments such as `app`, `log` or
`notes`; matched against a Windows disk they would find thousands of
files. A pattern counts when it holds at least MIN_LITERAL letters and
digits of its own -- `**/*-account-creation-ip.txt` (20), `*/BT/btpbk*`
(7, not counted), `*/*.*` (none) -- a character class such as `[Nn]`
counting as one.
"""

import re

#: Letters and digits a pattern must spell out to count towards a fit.
MIN_LITERAL = 10
#: Files named in a fit's examples.
EXAMPLES = 5

_CLASS = re.compile(r'\[[^\]]*\]')


def literal_length(pattern):
    """How many letters and digits `pattern` spells out itself."""
    text = _CLASS.sub('x', pattern)
    return sum(1 for char in text if char.isalnum())


def specific(patterns, minimum=MIN_LITERAL):
    """The patterns specific enough to show a tool has its evidence."""
    return [p for p in patterns if literal_length(p) >= minimum]


class Cancelled(Exception):
    pass


#: Archives looked inside: a return arrives as zips. A tar is read
#: header by header, so only its first members are looked at.
ARCHIVE_SUFFIXES = ('.zip', '.tar', '.tar.gz', '.tgz')
TAR_MEMBERS = 3000


def members(stream, name):
    """The member names of the zip or tar `stream`, [] when unreadable."""
    import tarfile
    import zipfile
    try:
        if name.lower().endswith('.zip'):
            with zipfile.ZipFile(stream) as zipped:
                return zipped.namelist()
        out = []
        with tarfile.open(fileobj=stream, mode='r:*') as tarred:
            for member in tarred:
                out.append(member.name)
                tarred.members.clear()
                if len(out) >= TAR_MEMBERS:
                    break
        return out
    except Exception:
        return []


def count(volumes, patterns, should_stop=None, open_file=None):
    """(files the specific patterns name, [a few of their paths]) over a
    scope.listing() -- live files only, as staging takes. `open_file(
    volume offset, path)` -> a stream: zips and tars are looked inside, and
    a member the patterns name counts ('<archive>!/<member>')."""
    from trace_app.core.modules.stage import Matcher
    wanted = specific(patterns)
    if not wanted:
        return 0, []
    matcher = Matcher(wanted)
    found, examples = 0, []
    for volume in volumes:
        for number, (folder, name, _size, _mtime, deleted) in \
                enumerate(volume['files']):
            if should_stop is not None and number % 4096 == 0 and \
                    should_stop():
                raise Cancelled()
            if deleted:
                continue
            path = f"{folder}/{name}"
            if matcher(path):
                found += 1
                if len(examples) < EXAMPLES:
                    examples.append(path)
            elif open_file is not None and \
                    name.lower().endswith(ARCHIVE_SUFFIXES):
                stream = open_file(volume['offset'], path)
                if stream is None:
                    continue
                for member in members(stream, name):
                    if matcher('/' + member.replace('\\', '/').lstrip('/')):
                        found += 1
                        if len(examples) < EXAMPLES:
                            examples.append(f"{path}!/{member}")
    return found, examples
