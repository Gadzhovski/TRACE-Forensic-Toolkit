"""Located evidence: what in a case says where it was, and the arithmetic
of drawing it (no Qt).

What carries a position today:

* photographs' EXIF GPS -- findings of module 'photo' whose detail holds
  latitude and longitude (core/content_checks.py, which already refuses
  0,0 and anything out of range);
* any activity record whose detail holds latitude and longitude.

Wi-Fi records are not placed. A network's name and access point say
nothing about where they are without asking an online database (WiGLE,
Google, Apple), and sending them there tells a third party what was on the
device. That is not done.

The map is Web Mercator, the projection of every online tile service, so
the offline outline and fetched tiles line up. **Tiles are fetched only
when the examiner asks**: a tile request tells the tile server which area
is being looked at, from where, and when -- in an investigation, that is
itself information. Without tiles the points are drawn over Natural
Earth's land outline (public domain, bundled in resources/), which needs
no network at all.
"""

import json
import logging
import math

logger = logging.getLogger('TRACE.Geo')

#: Web Mercator stops here; the poles are at infinity.
MAX_LATITUDE = 85.0511287798
TILE_SIZE = 256
MIN_ZOOM, MAX_ZOOM = 1, 18

_ESRI = 'https://server.arcgisonline.com/ArcGIS/rest/services/'
_ESRI_SOURCES = ('Powered by Esri · Esri, HERE, Garmin, © OpenStreetMap '
                 'contributors, and the GIS user community')

#: The map styles tiles can be drawn in. Each is one or more layers drawn
#: in order (a base, then labels over it), with the host it is fetched from
#: -- what the examiner is asked about -- and the attribution its terms
#: require on the map. OpenStreetMap's own tiles name places in their local
#: language (Белград, 北京); Esri's basemaps label them in English, and
#: their light and dark canvases match TRACE's two themes, so one of those
#: follows the theme unless the examiner picks another. Tiles are fetched
#: for the area on screen only, with an identifying User-Agent, and kept in
#: memory only.
TILE_STYLES = {
    'light': {'label': "Light (English labels)",
              'host': 'server.arcgisonline.com',
              'layers': (_ESRI + 'Canvas/World_Light_Gray_Base/MapServer/'
                         'tile/{z}/{y}/{x}',
                         _ESRI + 'Canvas/World_Light_Gray_Reference/'
                         'MapServer/tile/{z}/{y}/{x}'),
              'max_zoom': 16, 'attribution': _ESRI_SOURCES},
    'dark': {'label': "Dark (English labels)",
             'host': 'server.arcgisonline.com',
             'layers': (_ESRI + 'Canvas/World_Dark_Gray_Base/MapServer/'
                        'tile/{z}/{y}/{x}',
                        _ESRI + 'Canvas/World_Dark_Gray_Reference/'
                        'MapServer/tile/{z}/{y}/{x}'),
             'max_zoom': 16, 'attribution': _ESRI_SOURCES},
    'streets': {'label': "Streets (English labels)",
                'host': 'server.arcgisonline.com',
                'layers': (_ESRI + 'World_Street_Map/MapServer/tile/'
                           '{z}/{y}/{x}',),
                'max_zoom': 18, 'attribution': _ESRI_SOURCES},
    'osm': {'label': "OpenStreetMap (local names)",
            'host': 'tile.openstreetmap.org',
            'layers': ('https://tile.openstreetmap.org/{z}/{x}/{y}.png',),
            'max_zoom': 18,
            'attribution': '© OpenStreetMap contributors'},
}
#: The style that matches each theme.
THEME_STYLES = {'light': 'light', 'dark': 'dark'}
DEFAULT_STYLE = 'light'

# The default style's host and attribution, for callers that name one.
TILE_HOST = TILE_STYLES[DEFAULT_STYLE]['host']
ATTRIBUTION = TILE_STYLES[DEFAULT_STYLE]['attribution']

KIND_LABELS = {'photo': 'Photo GPS', 'activity': 'Activity record'}


def _coordinate(value, limit):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(value) or not -limit <= value <= limit:
        return None
    return value


def position(detail):
    """(latitude, longitude) from a finding's or record's detail, or None
    when it holds no usable position."""
    if not isinstance(detail, dict):
        return None
    lat = _coordinate(detail.get('latitude'), 90)
    lon = _coordinate(detail.get('longitude'), 180)
    if lat is None or lon is None or (lat, lon) == (0.0, 0.0):
        return None
    return lat, lon


def located(case, evidence_id=None):
    """Every placed item in the case, oldest first (undated last):
    {'kind', 'latitude', 'longitude', 'name', 'when', 'what', 'source',
    'evidence_id', 'artifact_ref', 'path', 'row'} -- `row` being the
    finding or activity row it came from, for previewing."""
    points = []
    for row in case.findings(evidence_id, 'photo'):
        detail = row.get('detail') or {}
        where = position(detail)
        if where is None:
            continue
        camera = ' '.join(p for p in (detail.get('make'),
                                      detail.get('model')) if p)
        points.append({
            'kind': 'photo', 'latitude': where[0], 'longitude': where[1],
            'name': row.get('name') or '', 'when': detail.get('taken')
            or detail.get('gps_date') or '',
            'what': f"Photo taken{' with ' + camera if camera else ''}",
            'source': 'EXIF GPS', 'evidence_id': row.get('evidence_id'),
            'artifact_ref': row.get('artifact_ref'),
            'path': row.get('path') or '', 'row': row})
    for row in case.located_activity(evidence_id):
        where = position(row.get('detail'))
        if where is None:
            continue
        points.append({
            'kind': 'activity', 'latitude': where[0], 'longitude': where[1],
            'name': row.get('subject') or '',
            'when': row.get('time_utc') or '',
            'what': row.get('what') or '', 'source': row.get('source') or '',
            'evidence_id': row.get('evidence_id'),
            'artifact_ref': row.get('artifact_ref'),
            'path': row.get('source_path') or '', 'row': row})
    points.sort(key=lambda p: (not p['when'], str(p['when'])))
    return points


# --- Web Mercator -----------------------------------------------------------------------

def project(latitude, longitude, zoom):
    """World pixel (x, y) of a position at `zoom` (fractional allowed)."""
    latitude = max(-MAX_LATITUDE, min(MAX_LATITUDE, latitude))
    scale = TILE_SIZE * 2 ** zoom
    x = (longitude + 180.0) / 360.0 * scale
    sin = math.sin(math.radians(latitude))
    y = (0.5 - math.log((1 + sin) / (1 - sin)) / (4 * math.pi)) * scale
    return x, y


def unproject(x, y, zoom):
    """(latitude, longitude) of a world pixel at `zoom`."""
    scale = TILE_SIZE * 2 ** zoom
    longitude = x / scale * 360.0 - 180.0
    n = math.pi - 2 * math.pi * y / scale
    latitude = math.degrees(math.atan(math.sinh(n)))
    return latitude, longitude


def fit(points, width, height, margin=40):
    """(zoom, centre latitude, centre longitude) showing every point in a
    view of width x height pixels -- the whole world when there are none."""
    if not points:
        return MIN_ZOOM, 20.0, 0.0
    lats = [p[0] for p in points]
    lons = [p[1] for p in points]
    north, south = max(lats), min(lats)
    east, west = max(lons), min(lons)
    zoom = MAX_ZOOM
    while zoom > MIN_ZOOM:
        x1, y1 = project(north, west, zoom)
        x2, y2 = project(south, east, zoom)
        if x2 - x1 <= max(width - 2 * margin, 1) and \
                y2 - y1 <= max(height - 2 * margin, 1):
            break
        zoom -= 1
    # One point (or several in one spot): close in, but not to a doorstep
    # -- GPS from a phone is good to tens of metres.
    zoom = min(zoom, 15)
    x1, y1 = project(north, west, zoom)
    x2, y2 = project(south, east, zoom)
    centre = unproject((x1 + x2) / 2, (y1 + y2) / 2, zoom)
    return zoom, centre[0], centre[1]


def visible_tiles(centre_x, centre_y, width, height, zoom):
    """[(x, y)] of the tiles covering a view centred on world pixel
    (centre_x, centre_y) at integer `zoom` -- only those, never more."""
    count = 2 ** zoom
    left = int(math.floor((centre_x - width / 2) / TILE_SIZE))
    right = int(math.floor((centre_x + width / 2) / TILE_SIZE))
    top = max(0, int(math.floor((centre_y - height / 2) / TILE_SIZE)))
    bottom = min(count - 1, int(math.floor((centre_y + height / 2)
                                           / TILE_SIZE)))
    return [(x, y) for y in range(top, bottom + 1)
            for x in range(left, right + 1)]


def tile_urls(zoom, x, y, style=DEFAULT_STYLE):
    """The URLs of one tile's layers in `style`, base first, its x wrapped
    round the world."""
    count = 2 ** zoom
    return [layer.format(z=zoom, x=x % count, y=y)
            for layer in TILE_STYLES[style]['layers']]


def tile_url(zoom, x, y, style='osm'):
    """The first layer's URL (OpenStreetMap's by default)."""
    return tile_urls(zoom, x, y, style)[0]


def graticule_step(zoom):
    """Degrees between drawn lines of latitude and longitude at `zoom`."""
    for step, below in ((30, 3), (10, 5), (5, 6), (2, 7), (1, 8),
                        (0.5, 9), (0.2, 10), (0.1, 11), (0.05, 12),
                        (0.02, 13), (0.01, 14)):
        if zoom < below:
            return step
    return 0.005


def land_rings(path):
    """Natural Earth's land outline: [[(longitude, latitude), ...], ...];
    [] when the file cannot be read (the map still draws, without it)."""
    try:
        with open(path, encoding='utf-8') as handle:
            return [[(x, y) for x, y in ring] for ring in json.load(handle)]
    except (OSError, ValueError, TypeError) as exc:
        logger.warning("No land outline for the map (%s): %s", path, exc)
        return []


def describe(latitude, longitude):
    """'51.50101° N, 0.14189° W'."""
    return (f"{abs(latitude):.5f}° {'N' if latitude >= 0 else 'S'}, "
            f"{abs(longitude):.5f}° {'E' if longitude >= 0 else 'W'}")
