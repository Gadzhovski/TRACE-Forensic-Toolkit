"""Build resources/geocoder.json.gz, the offline place-name lookup
(core/geocode.py), from Natural Earth (public domain).

    python tools/build_geocoder.py [--cache DIR]

Downloads the pinned Natural Earth layers (the commit build_offline_map.py
pins, each file's SHA-256 below) and writes:

* first-level regions (states, provinces, counties) as polygons, each
  naming its country -- they tile every country, so a region found is a
  country found: coordinates in 1/10,000 of a degree (`UNITS`),
  simplified (Douglas-Peucker) to `TOLERANCE` of them -- about 200 m --
  and delta-encoded, each with its bounding box;
* the 7,342 populated places, with the region and country Natural Earth
  names for each.

Run it again only to change the data; the output is committed.
"""

import argparse
import gzip
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_offline_map as natural_earth  # noqa: E402

FILES = {
    'ne_10m_admin_1_states_provinces':
        '22d0e3ad85eb3e27f17cabf8ba2d50e554fbc27a87796ff891d958185da62fb5',
    'ne_10m_populated_places_simple':
        natural_earth.FILES['ne_10m_populated_places_simple'],
}
UNITS = 10_000
TOLERANCE = 20                  # in UNITS: 0.002 degrees, about 200 m
OUTPUT = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), 'resources', 'geocoder.json.gz')


def _rings(geometry):
    if not geometry:
        return []
    if geometry['type'] == 'Polygon':
        return list(geometry['coordinates'])
    if geometry['type'] == 'MultiPolygon':
        return [ring for polygon in geometry['coordinates']
                for ring in polygon]
    return []


def _encode(ring):
    """A ring as [x0, y0, dx, dy, ...] in UNITS, simplified; a ring
    simplified below a triangle is kept as it was (a small island is
    still land)."""
    points = [(int(round(lon * UNITS)), int(round(lat * UNITS)))
              for lon, lat in ring]
    simple = natural_earth.simplify(points, TOLERANCE)
    if len(simple) < 4:
        simple = points
    out, last = [], (0, 0)
    for x, y in simple:
        out += [x - last[0], y - last[1]]
        last = (x, y)
    return out, simple


def areas(collection, name_of, extra_of):
    out = []
    for feature in collection['features']:
        rings = _rings(feature.get('geometry'))
        if not rings:
            continue
        encoded, xs, ys = [], [], []
        for ring in rings:
            deltas, points = _encode(ring)
            encoded.append(deltas)
            xs += [x for x, _y in points]
            ys += [y for _x, y in points]
        properties = feature['properties']
        out.append([name_of(properties), *extra_of(properties),
                    [min(xs), min(ys), max(xs), max(ys)], encoded])
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--cache', default=os.path.join(
        os.path.dirname(OUTPUT), '..', 'build', 'natural_earth'))
    args = parser.parse_args()
    natural_earth.FILES.update(FILES)
    data = {name: natural_earth.fetch(name, args.cache) for name in FILES}
    regions = areas(
        data['ne_10m_admin_1_states_provinces'],
        lambda p: p.get('name_en') or p.get('name') or '',
        lambda p: [p.get('admin') or '', p.get('type_en') or ''])
    places = []
    for feature in data['ne_10m_populated_places_simple']['features']:
        p = feature['properties']
        places.append([p.get('name') or '', p.get('adm1name') or '',
                       p.get('adm0name') or '',
                       int(round(float(p['longitude']) * UNITS)),
                       int(round(float(p['latitude']) * UNITS)),
                       int(p.get('pop_max') or 0)])
    result = {
        'version': 1, 'units': UNITS, 'tolerance': TOLERANCE,
        'source': ("Natural Earth 1:10m (public domain), "
                   f"nvkelso/natural-earth-vector@"
                   f"{natural_earth.COMMIT[:7]}"),
        'regions': regions, 'places': places}
    text = json.dumps(result, separators=(',', ':'), ensure_ascii=False)
    with gzip.open(OUTPUT, 'wt', encoding='utf-8', compresslevel=9) as out:
        out.write(text)
    points = sum(len(ring) // 2 for area in regions for ring in area[-1])
    print(f"{OUTPUT}: {os.path.getsize(OUTPUT) / 1e6:.2f} MB; "
          f"{len(regions):,} regions "
          f"({points:,} points), {len(places):,} places")


if __name__ == '__main__':
    main()
