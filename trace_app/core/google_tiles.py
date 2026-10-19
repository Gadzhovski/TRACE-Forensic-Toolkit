"""Google's map tiles, through the Map Tiles API (no Qt).

Google's maps may only be drawn outside Google's own apps through Google
Maps Platform: the examiner's own API key, with the Map Tiles API enabled
on it (billed to the key's Google Cloud project after Google's free
monthly allowance). Without a key these styles are not offered.

The API is three calls, made by the Map panel (the network is the
window's, asked before the first use like every tile server):

1. `session_request(style, key)` -> POST createSession with the map type;
   the answer (`parse_session`) is a session token, valid for days;
2. tiles: `tile_url(session, key, z, x, y)`;
3. `viewport_url(...)` for the area on screen -> its copyright line
   (`parse_copyright`), which Google requires shown with the map.

`BASE` is the API's address; tests point it at a local server.
"""

import json
import time
from urllib.parse import urlencode

BASE = 'https://tile.googleapis.com'

#: TRACE's style key -> the session the API needs for it.
SESSIONS = {
    'google_roadmap': {'mapType': 'roadmap'},
    'google_satellite': {'mapType': 'satellite'},
    'google_hybrid': {'mapType': 'satellite', 'layerTypes': ['layerRoadmap']},
    'google_terrain': {'mapType': 'terrain', 'layerTypes': ['layerRoadmap']},
}
LANGUAGE, REGION = 'en-US', 'US'


class GoogleTilesError(Exception):
    """The API refused or answered something unreadable."""


def is_google(style):
    return style in SESSIONS


def session_request(style, key):
    """(url, JSON body bytes) of the createSession call for `style`."""
    body = dict(SESSIONS[style], language=LANGUAGE, region=REGION)
    return (f"{BASE}/v1/createSession?{urlencode({'key': key})}",
            json.dumps(body).encode('utf-8'))


def parse_session(data):
    """{'session', 'expires' (Unix seconds or None)} of createSession's
    answer; raises GoogleTilesError for an error or an unreadable one."""
    try:
        answer = json.loads(bytes(data).decode('utf-8'))
    except (ValueError, UnicodeDecodeError) as exc:
        raise GoogleTilesError(f"unreadable answer: {exc}") from None
    if not isinstance(answer, dict):
        raise GoogleTilesError("unreadable answer")
    if 'error' in answer:
        error = answer['error'] or {}
        raise GoogleTilesError(
            error.get('message') or error.get('status') or str(error))
    session = answer.get('session')
    if not session:
        raise GoogleTilesError("no session in the answer")
    try:
        expires = int(answer.get('expiry'))
    except (TypeError, ValueError):
        expires = None
    return {'session': session, 'expires': expires}


def expired(session, now=None):
    """Whether a parse_session result needs replacing (a minute early)."""
    if not session:
        return True
    expires = session.get('expires')
    return expires is not None and (now or time.time()) > expires - 60


def tile_url(session, key, zoom, x, y):
    count = 2 ** zoom
    query = urlencode({'session': session['session'], 'key': key})
    return f"{BASE}/v1/2dtiles/{zoom}/{x % count}/{y}?{query}"


def viewport_url(session, key, zoom, north, south, east, west):
    query = urlencode({'session': session['session'], 'key': key,
                       'zoom': zoom, 'north': round(north, 6),
                       'south': round(south, 6), 'east': round(east, 6),
                       'west': round(west, 6)})
    return f"{BASE}/tile/v1/viewport?{query}"


def parse_copyright(data):
    """The copyright line of a viewport answer ('' when there is none)."""
    try:
        answer = json.loads(bytes(data).decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        return ''
    return str(answer.get('copyright') or '') if isinstance(answer, dict) \
        else ''
