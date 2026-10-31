"""Offline reverse geocoding (core/geocode): the place a GPS position is in
or near, from Natural Earth (resources/geocoder.json.gz).

The expectations are places anyone can check on a map: the country and
first-level region each landmark lies in. Nothing here goes online.
"""

import time

import pytest


@pytest.mark.parametrize('latitude, longitude, region, country', [
    (48.8584, 2.2945, 'Paris', 'France'),                      # Eiffel Tower
    (40.7580, -73.9855, 'New York', 'United States of America'),
    (-33.8568, 151.2153, 'New South Wales', 'Australia'),      # Opera House
    (-29.3151, 27.4869, 'Maseru', 'Lesotho'),        # inside South Africa
    (41.9029, 12.4534, 'Vatican City', 'Vatican'),   # inside Rome
    (47.5596, 7.5886, 'Basel-Stadt', 'Switzerland'),  # at two borders
    (35.6762, 139.6503, 'Tokyo', 'Japan'),
    (47.0, -109.0, 'Montana', 'United States of America'),
])
def test_landmarks_are_in_their_region_and_country(latitude, longitude,
                                                   region, country):
    from trace_app.core import geocode
    place = geocode.lookup(latitude, longitude)
    assert (place.region, place.country) == (region, country)
    assert not place.at_sea


def test_the_open_sea_is_at_sea():
    from trace_app.core import geocode
    place = geocode.lookup(30.0, -40.0)              # mid-Atlantic
    assert place.at_sea and place.text() == "At sea"


def test_off_the_coast_names_the_nearest_town():
    from trace_app.core import geocode
    text = geocode.describe(50.75, -0.15)            # off Brighton
    assert text.startswith("At sea, ") and \
        text.endswith(" S of Brighton, United Kingdom")


def test_the_text_says_how_far_and_which_way():
    from trace_app.core.geocode import Place
    at = Place('Bristol', 'United Kingdom', 'Bristol', 'United Kingdom',
               0.4, 'N')
    assert at.text() == "Bristol, United Kingdom"     # region said once
    near = Place('Wokingham', 'United Kingdom', 'Reading',
                 'United Kingdom', 4.2, 'NE')
    assert near.text() == "4 km NE of Reading, Wokingham, United Kingdom"
    far = Place('Montana', 'United States of America', 'Billings',
                'United States of America', 140.0, 'NW')
    assert far.text() == "Montana, United States of America"


def test_the_direction_is_from_the_town_to_the_position():
    from trace_app.core import geocode
    north = geocode.lookup(51.4545 + 0.1, -2.5879)     # north of Bristol
    assert north.town == 'Bristol' and north.direction == 'N'
    east = geocode.lookup(51.4545, -2.5879 + 0.08)     # Bath is further
    assert east.town == 'Bristol' and east.direction == 'E'


@pytest.mark.parametrize('latitude, longitude', [
    (None, 1.0), ('x', 2.0), (91.0, 0.0), (0.0, 181.0)])
def test_no_position_no_place(latitude, longitude):
    from trace_app.core import geocode
    assert geocode.lookup(latitude, longitude) is None
    assert geocode.describe(latitude, longitude) == ''


def test_lookups_are_fast_enough_for_a_whole_case():
    """A case's photos are named when a table fills: thousands at once."""
    from trace_app.core import geocode
    geocode.describe(51.45, -2.59)                     # load the data
    started = time.perf_counter()
    for step in range(2000):
        geocode.describe(40 + step * 0.01, -100 + step * 0.02)
    assert time.perf_counter() - started < 5


def test_the_source_is_named_and_offline():
    from trace_app.core import geocode
    text = geocode.source()
    assert 'Natural Earth' in text and 'Approximate' in text


def test_the_map_lists_the_place_each_point_is_near(qapp):
    from trace_app.ui.viewers.map_panel import MapPanel
    panel = MapPanel()
    try:
        panel._fill([{'kind': 'photo', 'latitude': 48.8584,
                      'longitude': 2.2945, 'name': 'IMG_1.jpg',
                      'when': '', 'what': 'Photo taken',
                      'source': 'EXIF GPS', 'read_by': ['TRACE'],
                      'evidence_id': None, 'artifact_ref': None,
                      'path': '/DCIM/IMG_1.jpg', 'row': {}}])
        table = panel.table
        headers = [table.horizontalHeaderItem(c).text()
                   for c in range(table.columnCount())]
        near = table.item(0, headers.index('Near (approx.)')).text()
        assert near.endswith('Paris, France')
    finally:
        panel.deleteLater()
