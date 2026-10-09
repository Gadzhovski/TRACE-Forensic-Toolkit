"""Downloads for the test-data scripts, patient with third-party hosts.

tools/testdata/fetch.py and build/carve_corpus.py fetch
from some forty sites nobody here runs. A host that is slow or briefly down
must not fail a test run -- and in CI every job of a run asks at once, the
first time a cache is empty. So each URL is tried several times with a
growing pause, then through its mirrors, and the whole round again.

Mirrors are safe because every caller checks the bytes against a pinned
SHA-256; a mirror can only make a download possible, never different.
"""

import time
import urllib.request

USER_AGENT = 'TRACE-tests (https://github.com/Gadzhovski/TRACE-Forensic-Toolkit)'

#: URL prefix -> the same files elsewhere, tried in order after it.
MIRRORS = {
    'https://ftp.gnu.org/gnu/': (
        'https://ftpmirror.gnu.org/',        # redirects to a nearby mirror
        'https://mirrors.kernel.org/gnu/',
        'https://mirror.csclub.uwaterloo.ca/gnu/',
    ),
}

ROUNDS = 2              # passes over the URL and all its mirrors
ATTEMPTS = 3            # tries per URL per pass
TIMEOUT = 60            # seconds without data before a try is given up
PAUSES = (5, 15, 45)    # seconds before each next try


def candidates(url):
    """`url`, then the same file on each mirror of its host."""
    found = [url]
    for prefix, mirrors in MIRRORS.items():
        if url.startswith(prefix):
            found += [mirror + url[len(prefix):] for mirror in mirrors]
    return found


def download(url, target=None, log=print):
    """Return the bytes at `url`, or write them to the path `target`.

    Raises SystemExit naming every URL tried when none answered."""
    urls = candidates(url)
    errors = []
    tries = 0
    for _round in range(ROUNDS):
        for candidate in urls:
            for _attempt in range(ATTEMPTS):
                if tries:
                    time.sleep(PAUSES[min(tries - 1, len(PAUSES) - 1)])
                tries += 1
                try:
                    return _get(candidate, target)
                except OSError as exc:     # URLError, timeouts, resets
                    errors.append(f"{candidate}: {exc}")
                    log(f"  retrying: {candidate}: {exc}")
    raise SystemExit(f"Could not download {url} after {tries} tries:\n  "
                     + "\n  ".join(errors[-len(urls):]))


def _get(url, target):
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        if target is None:
            return response.read()
        with open(target, 'wb') as out:
            while True:
                block = response.read(1 << 20)
                if not block:
                    return None
                out.write(block)
