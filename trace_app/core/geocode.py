"""Reverse geocoding, offline: the place a GPS position is in or near
(no Qt).

A photo's or a phone record's position is shown as coordinates; this
names it -- "4 km NE of Reading, Wokingham, United Kingdom" -- from
Natural Earth's first-level regions (which name their country) and its
7,342 populated places, shipped as resources/geocoder.json.gz (built by
tools/build_geocoder.py from the pinned public-domain files). Nothing
leaves the machine: a lookup reads only that file.

Approximate by construction, and said so wherever it is shown: region
outlines are simplified to about 200 m (`BORDER_M`), so a point closer
than that to a border can be named on the wrong side; the places are
towns and cities, so "near" can mean tens of kilometres in open country.

`lookup(latitude, longitude)` -> Place or None; `describe(...)` -> the
text ('' when there is nothing to say).
"""

import gzip
import json
import logging
import math
import threading
from array import array

logger = logging.getLogger('TRACE.Geocode')

RESOURCE = 'geocoder.json.gz'
#: How far region outlines may be from the true border (the build's
#: simplification tolerance, in metres at the equator).
BORDER_M = 220
#: Within this, a point is at the nearest town itself.
AT_TOWN_KM = 2.0
#: Beyond this, a town is too far to describe a position by.
NEAR_KM = 100.0
#: A point in no region (the sea, or a gap simplification left between
#: two regions) within this of a region's edge is taken to be in it.
GAP_DEGREES = 0.01
#: Latitude bands an outline's edges are indexed by (degrees).
BAND = 0.1
_CELL = 1.0                     # degrees, for the bounding-box grid
_DIRECTIONS = ('N', 'NE', 'E', 'SE', 'S', 'SW', 'W', 'NW')
_EARTH_KM = 6371.0088

_LOCK = threading.Lock()
_DATA = None


class Place:
    """Where a position is: its region and country (None at sea), and the
    nearest town with the position's distance and direction from it --
    '4 km NE of Reading' lies north-east of Reading."""

    __slots__ = ('region', 'country', 'town', 'town_country',
                 'distance_km', 'direction')

    def __init__(self, region, country, town, town_country, distance_km,
                 direction):
        self.region, self.country = region, country
        self.town, self.town_country = town, town_country
        self.distance_km, self.direction = distance_km, direction

    @property
    def at_sea(self):
        return self.country is None

    def text(self):
        near = ''
        if self.town and self.distance_km is not None:
            if self.distance_km < AT_TOWN_KM:
                near = self.town
            elif self.distance_km <= NEAR_KM:
                near = (f"{self.distance_km:.0f} km {self.direction} of "
                        f"{self.town}")
        if self.at_sea:
            if not near or self.distance_km is None or \
                    self.distance_km < AT_TOWN_KM:
                return "At sea" + (f", near {self.town_country}"
                                   if near and self.town_country else '')
            return f"At sea, {near}" + (f", {self.town_country}"
                                         if self.town_country else '')
        # 'Paris, France', not 'Paris, Paris, France': a region named as
        # the town already said is not said again.
        region = None if near and self.region == self.town else self.region
        area = ', '.join(part for part in dict.fromkeys(
            (region, self.country)) if part)
        return f"{near}, {area}" if near and area else near or area


def lookup(latitude, longitude):
    """The Place of a position, or None when there is no position or the
    data cannot be read."""
    try:
        latitude, longitude = float(latitude), float(longitude)
    except (TypeError, ValueError):
        return None
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        return None
    data = _data()
    if data is None:
        return None
    region = data.region_at(longitude, latitude)
    town = data.nearest_town(latitude, longitude)
    if town is None:
        town_name = town_country = distance = direction = None
    else:
        town_name, town_country, distance, direction = town
    if region is None:
        return Place(None, None, town_name, town_country, distance,
                     direction)
    return Place(region[0], region[1], town_name, town_country, distance,
                 direction)


def describe(latitude, longitude):
    """'4 km NE of Reading, Wokingham, United Kingdom', or ''."""
    place = lookup(latitude, longitude)
    return place.text() if place is not None else ''


def source():
    """What the names come from, for a tooltip or a report."""
    data = _data()
    origin = data.source if data is not None else 'Natural Earth'
    return (f"Approximate, offline: {origin}. Borders to about "
            f"{BORDER_M} m; places are towns and cities.")


# --- the data ---------------------------------------------------------------

def _data():
    global _DATA
    with _LOCK:
        if _DATA is None:
            try:
                _DATA = _Data(_load())
            except (OSError, ValueError, KeyError) as exc:
                logger.warning("Place names not available: %s", exc)
                _DATA = False
        return _DATA or None


def _load():
    from trace_app.infra.paths import resource_path
    with gzip.open(resource_path('resources', RESOURCE), 'rt',
                   encoding='utf-8') as handle:
        return json.load(handle)


class _Region:
    """One region's outline, decoded and indexed the first time a point
    falls in its bounding box."""

    __slots__ = ('name', 'country', 'kind', 'box', 'encoded', 'xs', 'ys',
                 'bands')

    def __init__(self, row):
        self.name, self.country, self.kind, self.box, self.encoded = row
        self.xs = self.ys = self.bands = None

    def _index(self, units):
        xs, ys, edges = array('d'), array('d'), {}
        for ring in self.encoded:
            x = y = 0
            first = len(xs)
            for position in range(0, len(ring), 2):
                x += ring[position]
                y += ring[position + 1]
                xs.append(x / units)
                ys.append(y / units)
            # Close the ring when the data did not repeat its first point.
            if len(xs) - first > 2 and (xs[first], ys[first]) != \
                    (xs[-1], ys[-1]):
                xs.append(xs[first])
                ys.append(ys[first])
            for index in range(first, len(xs) - 1):
                low, high = sorted((ys[index], ys[index + 1]))
                for band in range(math.floor(low / BAND),
                                  math.floor(high / BAND) + 1):
                    edges.setdefault(band, array('i')).append(index)
        self.xs, self.ys, self.bands = xs, ys, edges
        self.encoded = None

    def contains(self, x, y, units):
        if self.xs is None:
            self._index(units)
        inside = False
        xs, ys = self.xs, self.ys
        for index in self.bands.get(math.floor(y / BAND), ()):
            y1, y2 = ys[index], ys[index + 1]
            if (y1 > y) != (y2 > y):
                x1, x2 = xs[index], xs[index + 1]
                if x < x1 + (y - y1) * (x2 - x1) / (y2 - y1):
                    inside = not inside
        return inside

    def distance(self, x, y, units):
        """Degrees to the nearest edge near `y` (a plane approximation,
        for a gap a few hundred metres wide)."""
        if self.xs is None:
            self._index(units)
        best = None
        xs, ys = self.xs, self.ys
        band = math.floor(y / BAND)
        for near in (band - 1, band, band + 1):
            for index in self.bands.get(near, ()):
                ax, ay, bx, by = xs[index], ys[index], xs[index + 1], \
                    ys[index + 1]
                dx, dy = bx - ax, by - ay
                length = dx * dx + dy * dy
                t = 0.0 if length == 0 else max(0.0, min(1.0, (
                    (x - ax) * dx + (y - ay) * dy) / length))
                gap = math.hypot(x - ax - t * dx, y - ay - t * dy)
                if best is None or gap < best:
                    best = gap
        return best


class _Data:
    def __init__(self, raw):
        self.units = int(raw['units'])
        self.source = raw.get('source') or 'Natural Earth'
        self.regions = [_Region(row) for row in raw['regions']]
        self.grid = {}
        for number, region in enumerate(self.regions):
            low_x, low_y, high_x, high_y = (value / self.units
                                            for value in region.box)
            for cx in range(math.floor(low_x / _CELL),
                            math.floor(high_x / _CELL) + 1):
                for cy in range(math.floor(low_y / _CELL),
                                math.floor(high_y / _CELL) + 1):
                    self.grid.setdefault((cx, cy), []).append(number)
        self.places = []
        self.place_grid = {}
        for name, _region, country, x, y, population in raw['places']:
            lon, lat = x / self.units, y / self.units
            self.places.append((name, country, lat, lon, population))
            self.place_grid.setdefault(
                (math.floor(lon / _CELL), math.floor(lat / _CELL)),
                []).append(len(self.places) - 1)

    def _candidates(self, x, y):
        out = []
        for number in self.grid.get((math.floor(x / _CELL),
                                     math.floor(y / _CELL)), ()):
            low_x, low_y, high_x, high_y = self.regions[number].box
            units = self.units
            if low_x / units - GAP_DEGREES <= x <= high_x / units + \
                    GAP_DEGREES and low_y / units - GAP_DEGREES <= y <= \
                    high_y / units + GAP_DEGREES:
                out.append(self.regions[number])
        return out

    def region_at(self, x, y):
        """(region, country) containing the point, else of the nearest
        region within GAP_DEGREES, else None."""
        candidates = self._candidates(x, y)
        for region in candidates:
            if region.contains(x, y, self.units):
                return region.name, region.country
        best = None
        for region in candidates:
            gap = region.distance(x, y, self.units)
            if gap is not None and gap <= GAP_DEGREES and (
                    best is None or gap < best[0]):
                best = (gap, region)
        return (best[1].name, best[1].country) if best else None

    def nearest_town(self, lat, lon):
        """(name, country, km, direction from it) of the nearest place,
        searched outwards cell ring by cell ring; None past ~2,000 km."""
        cx, cy = math.floor(lon / _CELL), math.floor(lat / _CELL)
        best = None
        for radius in range(0, 20):
            cells = [(cx + dx, cy + dy)
                     for dx in range(-radius, radius + 1)
                     for dy in range(-radius, radius + 1)
                     if max(abs(dx), abs(dy)) == radius]
            for cell in cells:
                for number in self.place_grid.get(
                        ((cell[0] + 180) % 360 - 180, cell[1]), ()):
                    name, country, plat, plon, _pop = self.places[number]
                    km = _haversine(lat, lon, plat, plon)
                    if best is None or km < best[0]:
                        best = (km, name, country, plat, plon)
            # Every place in a later ring is at least `radius` cells away.
            if best is not None and best[0] < radius * _CELL * 111.0 * \
                    max(0.2, math.cos(math.radians(lat))):
                break
        if best is None:
            return None
        km, name, country, plat, plon = best
        return name, country, km, _direction(plat, plon, lat, lon)


def _haversine(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * \
        math.sin(dl / 2) ** 2
    return 2 * _EARTH_KM * math.asin(min(1.0, math.sqrt(a)))


def _direction(lat1, lon1, lat2, lon2):
    """Compass point from position 1 towards position 2."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dl = math.radians(lon2 - lon1)
    bearing = math.degrees(math.atan2(
        math.sin(dl) * math.cos(p2),
        math.cos(p1) * math.sin(p2) -
        math.sin(p1) * math.cos(p2) * math.cos(dl))) % 360
    return _DIRECTIONS[int((bearing + 22.5) // 45) % 8]
