"""The hashes an image was acquired as, from its acquisition log (no Qt).

A raw image (dd, .raw, .img) stores no hash. What it was acquired as is
written by the imaging tool beside it -- FTK Imager's `<image>.txt`,
Guymager's `<image>.info`, dc3dd's or ewfacquire's log -- and that, not
TRACE's first look at the file, is what a verification should compare
with. `logged_hashes(path)` finds such a log and reads its hashes.

Conservative on purpose: a log names a hash only when every line for that
algorithm gives the same value (a source hash and an image hash agreeing,
or the hash written once). A log giving two different MD5s -- a failed
verification, two images in one log -- gives no MD5 at all, and the log
is never guessed at by searching for any 32 hex digits.
"""

import os
import re

#: (algorithm, pattern) -- the label each tool writes before the digest.
_LABELLED = (
    # FTK Imager:  "MD5 checksum:    0b...", "SHA1 checksum: ...",
    #              "SHA256 checksum: ..."; verification lines
    #              "MD5 verified/Computed hash: ..." are the same value.
    # Guymager:    "MD5 hash                   : 0b..." (".info")
    # ewfacquire:  "MD5 hash calculated over data:  0b..."
    ('md5', r'MD5\b[^\n:]{0,40}:\s*([0-9a-fA-F]{32})\b'),
    ('sha1', r'SHA-?1\b[^\n:]{0,40}:\s*([0-9a-fA-F]{40})\b'),
    ('sha256', r'SHA-?256\b[^\n:]{0,40}:\s*([0-9a-fA-F]{64})\b'),
    # dc3dd:       "   0b... (md5)"
    ('md5', r'\b([0-9a-fA-F]{32})\s+\(md5\)'),
    ('sha1', r'\b([0-9a-fA-F]{40})\s+\(sha1\)'),
    ('sha256', r'\b([0-9a-fA-F]{64})\s+\(sha256\)'),
)
MAX_LOG_BYTES = 1 << 20


def candidates(path):
    """Log files an imaging tool writes beside `path`."""
    stem = os.path.splitext(path)[0]
    seen = []
    for candidate in (path + '.txt', path + '.log', path + '.info',
                      stem + '.txt', stem + '.log', stem + '.info'):
        if candidate not in seen and candidate != path:
            seen.append(candidate)
    return seen


def read_hashes(text):
    """{algorithm: hex} a log's text names unambiguously."""
    found = {}
    for name, pattern in _LABELLED:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            found.setdefault(name, set()).add(match.group(1).lower())
    return {name: values.pop() for name, values in found.items()
            if len(values) == 1}


def logged_hashes(path):
    """({algorithm: hex}, log path) from the first log beside `path`
    that names any hash; ({}, None) when there is none."""
    for candidate in candidates(path):
        if not os.path.isfile(candidate):
            continue
        try:
            with open(candidate, 'rb') as handle:
                text = handle.read(MAX_LOG_BYTES).decode('utf-8-sig',
                                                         'replace')
        except OSError:
            continue
        hashes = read_hashes(text)
        if hashes:
            return hashes, candidate
    return {}, None
