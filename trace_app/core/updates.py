"""Is there a newer TRACE? Asked of GitHub's releases, only when the
examiner clicks Check for Updates in About (no Qt).

One request, to the public API, carrying nothing but TRACE's version in
its User-Agent: no evidence, no case, no account. It is refused when the
examiner has turned checking off (Settings ▸ Privacy) or the open case is
offline -- the same rule every request TRACE makes follows
(settings.network_refusal). Nothing is downloaded or installed: the answer
names the version and links its release page.
"""

import logging
import re

logger = logging.getLogger('TRACE.Updates')

REPOSITORY = 'Gadzhovski/TRACE-Forensic-Toolkit'
#: The newest release -- GitHub leaves drafts and pre-releases out.
LATEST_URL = f'https://api.github.com/repos/{REPOSITORY}/releases/latest'
RELEASES_PAGE = f'https://github.com/{REPOSITORY}/releases'
TIMEOUT = 10

_VERSION = re.compile(r'^v?(\d+)\.(\d+)(?:\.(\d+))?(?:[-.]?(rc|beta|b|alpha|a)'
                      r'\.?(\d*))?$', re.IGNORECASE)


class UpdateError(Exception):
    """The check could not be made or understood."""


def parse_version(text):
    """'v2.3.0' -> a tuple that sorts as versions do; a pre-release
    ('2.3.0-rc1') sorts before its release. None if not a version."""
    match = _VERSION.match((text or '').strip())
    if not match:
        return None
    major, minor, patch, tag, number = match.groups()
    # A release outranks any of its pre-releases.
    stage = (1, 0) if not tag else (0, int(number or 0))
    return int(major), int(minor), int(patch or 0), stage


def newer(candidate, current):
    """Whether version `candidate` is newer than `current`."""
    a, b = parse_version(candidate), parse_version(current)
    return a is not None and b is not None and a > b


def refusal():
    """Why a check may not be made now, or None."""
    from trace_app.core import settings
    if not settings.user('check_updates'):
        return ("Checking for new versions is turned off (Options ▸ "
                "Settings ▸ Privacy & Network).")
    return settings.network_refusal()


def latest(session=None):
    """{'version', 'url', 'published', 'name'} of the newest release.
    Raises UpdateError when it cannot be found out."""
    import requests
    from trace_app import __version__
    why = refusal()
    if why:
        raise UpdateError(why)
    session = session or requests
    try:
        response = session.get(
            LATEST_URL, timeout=TIMEOUT,
            headers={'Accept': 'application/vnd.github+json',
                     'User-Agent': f'TRACE/{__version__} (update check)'})
    except requests.RequestException as exc:
        raise UpdateError(f"GitHub could not be reached: {exc}") from exc
    if response.status_code == 404:
        raise UpdateError("No release has been published yet.")
    if response.status_code != 200:
        raise UpdateError(f"GitHub answered {response.status_code}.")
    try:
        data = response.json()
    except ValueError as exc:
        raise UpdateError("GitHub's answer could not be read.") from exc
    version = (data.get('tag_name') or '').lstrip('vV')
    if parse_version(version) is None:
        raise UpdateError(f"The newest release is tagged "
                          f"{data.get('tag_name')!r}, not a version.")
    logger.info("Update check: newest release %s (this is %s)", version,
                __version__)
    return {'version': version,
            'url': data.get('html_url') or RELEASES_PAGE,
            'published': (data.get('published_at') or '')[:10],
            'name': data.get('name') or f"TRACE {version}"}


def check():
    """(status, message, release): status 'newer', 'current' or 'error'."""
    from trace_app import __version__
    try:
        release = latest()
    except UpdateError as exc:
        return 'error', str(exc), None
    if newer(release['version'], __version__):
        when = f", published {release['published']}" if release['published'] \
            else ''
        return ('newer', f"TRACE {release['version']} is available{when}. "
                f"This is {__version__}.", release)
    return 'current', f"TRACE {__version__} is the newest release.", release
