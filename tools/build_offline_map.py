"""Build resources/offline_map.json.gz, the Map's offline basemap, from
Natural Earth (public domain).

    python tools/build_offline_map.py [--cache DIR]

Downloads the pinned Natural Earth layers (commit and SHA-256 below; kept
in the cache folder), then writes each layer the way the Map draws it, so
TRACE does no geometry work when it loads it:

* coordinates are Web Mercator, normalised to the world and scaled to
  2**24 (`SCALE`: zoom 16's world in pixels), as integers;
* polygons and lines come at three levels of detail (`LODS`), each
  simplified (Douglas-Peucker) to about one pixel at its zoom -- the Map
  picks one by zoom, so the world view does not draw 10m coastlines;
* each feature carries its bounding box, for drawing only what is on
  screen; vertices are delta-encoded (small numbers, small file);
* places and country names are points with the zoom Natural Earth
  suggests showing them from (`min_zoom`).

Run it again only to change what the Map draws; the output is committed.
"""

import argparse
import gzip
import hashlib
import json
import math
import os
import sys
import urllib.request

COMMIT = 'ca96624a56bd078437bca8184e78163e5039ad19'
BASE = ('https://raw.githubusercontent.com/nvkelso/natural-earth-vector/'
        f'{COMMIT}/geojson/')
FILES = {
    'ne_10m_land': '1ac90796408bc6ad6911d69448485d3c4dbf2190370080368a09976e1c9f7416',
    'ne_10m_admin_0_boundary_lines_land': '74d9c16229c095fde65943a9919e337682f044bcebccb120764f38edf3b70f4a',
    'ne_50m_admin_1_states_provinces_lines': '72cca93c850d412628a5da4bc5ebfe21ba4d376eb34611bde6b623ee73f0fdcf',
    'ne_50m_lakes': 'd350b75978b26fe839b797c2c529b2fb8f47fb3983c03f4964e36d5df9378a52',
    'ne_50m_rivers_lake_centerlines': 'f286e0ce978fde999ca2d7a78c764be08542e19b63cded52b05c12d5173ccc51',
    'ne_10m_populated_places_simple': 'fd3fa867a320cbd5c5b6bb5bc550afeec2939fb2cef688e508007282a55ac42f',
    'ne_50m_admin_0_countries': '3e458fc036ad0a66411f2c1e6cac49c5d7bfb81cb1123bc513b22511a2b7fdeb',
}
SCALE = 2 ** 24
MAX_LATITUDE = 85.0511287798
#: (zoom each level is simplified for): the Map uses level 0 below zoom 5,
#: 1 below 8, 2 from there.
LODS = (3, 6, 9)
OUTPUT = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), 'resources', 'offline_map.json.gz')


def fetch(name, cache):
    path = os.path.join(cache, f'{name}.geojson')
    if not os.path.isfile(path):
        os.makedirs(cache, exist_ok=True)
        url = BASE + f'{name}.geojson'
        print(f"downloading {url}", flush=True)
        with urllib.request.urlopen(url, timeout=300) as response, \
                open(path + '.part', 'wb') as handle:
            handle.write(response.read())
        os.replace(path + '.part', path)
    with open(path, 'rb') as handle:
        data = handle.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != FILES[name]:
        sys.exit(f"{name}: SHA-256 {digest} is not the pinned "
                 f"{FILES[name]}")
    return json.loads(data)


def project(lon, lat):
    lat = max(-MAX_LATITUDE, min(MAX_LATITUDE, lat))
    x = (lon + 180.0) / 360.0
    sin = math.sin(math.radians(lat))
    y = 0.5 - math.log((1 + sin) / (1 - sin)) / (4 * math.pi)
    return int(round(x * SCALE)), int(round(y * SCALE))


def simplify(points, tolerance):
    """Douglas-Peucker, iterative; keeps both ends."""
    if len(points) < 3:
        return points
    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]
    limit = tolerance * tolerance
    while stack:
        first, last = stack.pop()
        ax, ay = points[first]
        bx, by = points[last]
        dx, dy = bx - ax, by - ay
        length = dx * dx + dy * dy
        worst, at = -1.0, None
        for index in range(first + 1, last):
            px, py = points[index]
            if length == 0:
                distance = (px - ax) ** 2 + (py - ay) ** 2
            else:
                t = ((px - ax) * dx + (py - ay) * dy) / length
                t = max(0.0, min(1.0, t))
                qx, qy = ax + t * dx, ay + t * dy
                distance = (px - qx) ** 2 + (py - qy) ** 2
            if distance > worst:
                worst, at = distance, index
        if at is not None and worst > limit:
            keep[at] = True
            stack.append((first, at))
            stack.append((at, last))
    return [p for p, kept in zip(points, keep) if kept]


def encode(points):
    """[minx, miny, maxx, maxy, x0, y0, dx1, dy1, ...]."""
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    out = [min(xs), min(ys), max(xs), max(ys), points[0][0], points[0][1]]
    for (px, py), (x, y) in zip(points, points[1:]):
        out += [x - px, y - py]
    return out


def parts(geometry):
    """The coordinate lists of a (Multi)Polygon's rings or a
    (Multi)LineString's lines."""
    kind, coords = geometry['type'], geometry['coordinates']
    if kind == 'Polygon':
        return coords
    if kind == 'MultiPolygon':
        return [ring for polygon in coords for ring in polygon]
    if kind == 'LineString':
        return [coords]
    if kind == 'MultiLineString':
        return coords
    return []


def layer(collection, closed, min_points, zoom_of=None):
    """{lod: [[min_zoom, encoded...], ...]} for every feature's parts."""
    out = {str(i): [] for i in range(len(LODS))}
    for feature in collection['features']:
        if not feature.get('geometry'):
            continue
        properties = feature.get('properties') or {}
        min_zoom = zoom_of(properties) if zoom_of else 0
        for part in parts(feature['geometry']):
            projected = [project(lon, lat) for lon, lat, *_ in part]
            for lod, zoom in enumerate(LODS):
                tolerance = 2 ** (16 - zoom)    # one pixel at that zoom
                points = simplify(projected, tolerance)
                if len(points) < min_points:
                    continue
                if closed and len(points) < 4:
                    continue
                out[str(lod)].append([min_zoom] + encode(points))
    return out


def _min_zoom(properties, default):
    value = properties.get('min_zoom', properties.get('MIN_ZOOM'))
    try:
        return round(float(value), 1)
    except (TypeError, ValueError):
        return default


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--cache', default=os.path.join(
        os.path.dirname(OUTPUT), '..', 'build', 'natural_earth'))
    args = parser.parse_args()
    data = {name: fetch(name, args.cache) for name in FILES}
    result = {
        'version': 1, 'scale': SCALE, 'lods': list(LODS),
        'source': ("Natural Earth (public domain), "
                   f"nvkelso/natural-earth-vector@{COMMIT[:7]}"),
        'land': layer(data['ne_10m_land'], True, 4),
        'borders': layer(data['ne_10m_admin_0_boundary_lines_land'], False,
                         2),
        'states': layer(data['ne_50m_admin_1_states_provinces_lines'],
                        False, 2, lambda p: _min_zoom(p, 4)),
        'lakes': layer(data['ne_50m_lakes'], True, 4,
                       lambda p: _min_zoom(p, 3)),
        'rivers': layer(data['ne_50m_rivers_lake_centerlines'], False, 2,
                        lambda p: _min_zoom(p, 4)),
    }
    places = []
    for feature in data['ne_10m_populated_places_simple']['features']:
        p = feature['properties']
        x, y = project(float(p['longitude']), float(p['latitude']))
        places.append([p.get('name') or '', x, y, _min_zoom(p, 6),
                       int(p.get('pop_max') or 0),
                       1 if p.get('adm0cap') else 0])
    places.sort(key=lambda row: (row[3], -row[4]))
    result['places'] = places
    countries = []
    for feature in data['ne_50m_admin_0_countries']['features']:
        p = feature['properties']
        lon, lat = p.get('LABEL_X'), p.get('LABEL_Y')
        if lon is None or lat is None:
            continue
        x, y = project(float(lon), float(lat))
        countries.append([p.get('NAME_EN') or p.get('NAME') or '', x, y,
                          float(p.get('MIN_LABEL') or 2)])
    countries.sort(key=lambda row: row[3])
    result['countries'] = countries
    text = json.dumps(result, separators=(',', ':'))
    with gzip.open(OUTPUT, 'wt', encoding='utf-8', compresslevel=9) as out:
        out.write(text)
    print(f"{OUTPUT}: {os.path.getsize(OUTPUT) / 1e6:.2f} MB "
          f"({len(text) / 1e6:.1f} MB of JSON)")
    for key in ('land', 'borders', 'states', 'lakes', 'rivers'):
        print(f"  {key}: " + ', '.join(
            f"lod{lod} {sum(len(f) - 5 for f in fs) // 2:,} points"
            for lod, fs in result[key].items()))
    print(f"  places {len(places):,}, countries {len(countries):,}")


if __name__ == '__main__':
    main()
