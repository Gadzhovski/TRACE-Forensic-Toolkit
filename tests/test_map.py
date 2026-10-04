"""The Map: located evidence (core/geo.py) and the Triage sub-tab that draws
it (ui/viewers/map_panel.py).

The rule that matters is the network one: nothing is fetched until the
examiner says yes, a no fetches nothing, and a yes fetches only the tiles
on screen, identified as TRACE, with a line in the audit trail. A local
server stands in for the tile server and records every request.
"""

import json
import math
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.conftest import pump


# --- arithmetic -----------------------------------------------------------------

def test_web_mercator_round_trips_and_matches_osm_tiles():
    from trace_app.core import geo
    for lat, lon, zoom in ((51.5072, -0.1276, 12), (-33.8688, 151.2093, 7),
                           (0.0, 0.0, 1), (85.0, 179.9, 3)):
        x, y = geo.project(lat, lon, zoom)
        back = geo.unproject(x, y, zoom)
        assert abs(back[0] - lat) < 1e-9 and abs(back[1] - lon) < 1e-9
    # OpenStreetMap's own slippy-map example: Berlin's tile at zoom 10.
    x, y = geo.project(52.5200, 13.4050, 10)
    assert (int(x // 256), int(y // 256)) == (550, 335)
    assert geo.tile_url(2, -1, 1) == \
        'https://tile.openstreetmap.org/2/3/1.png'      # wrapped


def test_fit_shows_every_point():
    from trace_app.core import geo
    points = [(42.6977, 23.3219), (51.5072, -0.1276), (40.4168, -3.7038)]
    zoom, lat, lon = geo.fit(points, 800, 500)
    cx, cy = geo.project(lat, lon, zoom)
    for p in points:
        x, y = geo.project(*p, zoom)
        assert abs(x - cx) <= 400 and abs(y - cy) <= 250
    # One more zoom level would not fit.
    xs = [geo.project(*p, zoom + 1)[0] for p in points]
    assert max(xs) - min(xs) > 800 - 80
    # A single point is shown close, but not to the doorstep.
    assert geo.fit([(42.6977, 23.3219)], 800, 500)[0] == 15
    assert geo.fit([], 800, 500)[0] == geo.MIN_ZOOM


def test_only_the_tiles_on_screen():
    from trace_app.core import geo
    x, y = geo.project(42.6977, 23.3219, 12)
    tiles = geo.visible_tiles(x, y, 800, 500, 12)
    assert len(tiles) <= math.ceil(800 / 256 + 1) * math.ceil(500 / 256 + 1)
    assert (int(x // 256), int(y // 256)) in tiles
    # Never past the poles.
    assert all(0 <= ty < 2 for _tx, ty in
               geo.visible_tiles(256, 256, 2000, 2000, 1))


def test_positions_that_are_not_places_are_refused():
    from trace_app.core import geo
    assert geo.position({'latitude': 42.69, 'longitude': '23.32'}) == \
        (42.69, 23.32)
    for bad in ({'latitude': 0, 'longitude': 0}, {'latitude': 91,
                'longitude': 0}, {'latitude': 'x', 'longitude': 1},
                {'latitude': float('nan'), 'longitude': 1}, {}, None):
        assert geo.position(bad) is None
    assert geo.describe(-33.8688, 151.2093) == \
        '33.86880° S, 151.20930° E'


def test_land_outline_is_bundled():
    from trace_app.core import geo
    from trace_app.infra.paths import resource_path
    rings = geo.land_rings(resource_path('resources', 'world_land.json'))
    assert len(rings) == 128 and sum(map(len, rings)) > 5000
    assert geo.land_rings('missing.json') == []


# --- the case ------------------------------------------------------------------------

def make_case(tmp_path):
    """A case with a photo with GPS, one without, and an activity record
    with a position."""
    from trace_app.core.activity import record
    from trace_app.core.case import Case, make_artifact_ref
    case = Case.create(str(tmp_path / 'case'), 'Map')
    first = case.add_evidence(str(tmp_path / 'phone.dd'))
    second = case.add_evidence(str(tmp_path / 'laptop.dd'))
    case.add_module_findings(first, 'photo', [
        (make_artifact_ref(0, 40, 1), 'IMG_0001.jpg', '/DCIM/IMG_0001.jpg',
         1000, 'exif', 'notable', 'Taken at 42.69770, 23.32190',
         json.dumps({'latitude': 42.6977, 'longitude': 23.3219,
                     'make': 'Apple', 'model': 'iPhone 13',
                     'taken': '2024-05-01 10:00:00'})),
        (make_artifact_ref(0, 41, 1), 'IMG_0002.jpg', '/DCIM/IMG_0002.jpg',
         1000, 'exif', 'info', 'Apple iPhone 13',
         json.dumps({'make': 'Apple', 'taken': '2024-05-02 10:00:00'}))])
    case.add_module_findings(second, 'photo', [
        (make_artifact_ref(0, 7, 1), 'london.jpg', '/Pictures/london.jpg',
         1000, 'exif', 'notable', 'Taken at 51.50720, -0.12760',
         json.dumps({'latitude': 51.5072, 'longitude': -0.1276}))])
    import datetime
    case.add_user_activity(second, [record(
        'network', 'Test source',
        datetime.datetime(2024, 5, 3, 9, 0, tzinfo=datetime.timezone.utc),
        'Location recorded', 'Madrid',
        {'latitude': 40.4168, 'longitude': -3.7038},
        path='/Users/a/locations.db', ref=make_artifact_ref(0, 99, 1))])
    case.commit()
    return case, first, second


def test_located_gathers_photos_and_records(tmp_path):
    from trace_app.core import geo
    case, first, second = make_case(tmp_path)
    try:
        points = geo.located(case)
        assert [(p['kind'], p['name']) for p in points] == [
            ('photo', 'IMG_0001.jpg'), ('activity', 'Madrid'),
            ('photo', 'london.jpg')]                # undated last
        assert points[0]['what'] == 'Photo taken with Apple iPhone 13'
        assert points[1]['path'] == '/Users/a/locations.db'
        assert [p['name'] for p in geo.located(case, first)] == \
            ['IMG_0001.jpg']
        assert len(geo.located(case, second)) == 2
    finally:
        case.close()


# --- the panel ----------------------------------------------------------------------

@pytest.fixture
def tile_server():
    """A stand-in tile server: every request it sees, and the User-Agent."""
    from io import BytesIO
    from PIL import Image
    png = BytesIO()
    Image.new('RGB', (256, 256), (200, 220, 240)).save(png, 'PNG')
    hits = []

    class Tiles(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append((self.path, self.headers.get('User-Agent')))
            self.send_response(200)
            self.send_header('Content-Type', 'image/png')
            self.end_headers()
            self.wfile.write(png.getvalue())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Tiles)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    yield hits, (lambda z, x, y:
                 f'http://127.0.0.1:{port}/{z}/{x % 2 ** z}/{y}.png')
    server.shutdown()


def _panel(qapp, case, tile_url):
    from trace_app.ui.viewers.map_panel import MapPanel
    panel = MapPanel()
    panel.resize(900, 700)
    panel.canvas.resize(900, 400)
    panel.canvas.tile_urls = lambda z, x, y: [tile_url(z, x, y)]
    panel.set_case(case)
    return panel


def test_nothing_is_fetched_without_a_yes(qapp, tmp_path, tile_server):
    hits, url = tile_server
    case, _first, _second = make_case(tmp_path)
    panel = _panel(qapp, case, url)
    try:
        panel.canvas.grab()                       # paint, offline
        asked = []
        panel.ask = lambda style: asked.append(style) or False
        panel.tiles_button.setChecked(True)
        panel.canvas.grab()
        pump(qapp, 0.5)
        assert asked == [panel.canvas.style]
        assert not panel.tiles_button.isChecked()
        assert not panel.canvas.tiles_enabled and hits == []
        assert 'offline' in panel.status_label.text()
        assert not any('Map tiles' in a['action']
                       for a in case.activity())
    finally:
        panel.shutdown()
        case.close()


def test_a_yes_fetches_the_tiles_on_screen_only(qapp, tmp_path, tile_server):
    from trace_app.core import geo
    from trace_app.ui.viewers.map_panel import USER_AGENT
    hits, url = tile_server
    case, _first, _second = make_case(tmp_path)
    panel = _panel(qapp, case, url)
    try:
        panel.ask = lambda style: True
        panel.tiles_button.setChecked(True)
        canvas = panel.canvas
        expected = {(canvas.zoom, x % 2 ** canvas.zoom, y)
                    for x, y in geo.visible_tiles(
                        canvas.cx, canvas.cy, canvas.width(),
                        canvas.height(), canvas.zoom)}
        canvas.grab()
        pump(qapp, 5, lambda: len(hits) >= len(expected)
             and not canvas._pending)
        fetched = {tuple(int(v) for v in path.strip('/')[:-4].split('/'))
                   for path, _agent in hits}
        assert fetched == expected
        assert {agent for _path, agent in hits} == {USER_AGENT}
        canvas.grab()                              # cached: no new request
        pump(qapp, 0.3)
        assert len(hits) == len(expected)
        assert 'tile(s) from' in panel.status_label.text()
        audit = [a for a in case.activity() if a['action'] ==
                 'Map tiles fetched']
        assert len(audit) == 1 and \
            geo.TILE_STYLES[canvas.style]['host'] in audit[0]['detail']
        # Asked once a session per server: off and on again does not ask.
        panel.ask = lambda style: pytest.fail("asked twice")
        panel.tiles_button.setChecked(False)
        panel.tiles_button.setChecked(True)
        # Another style from the same server does not ask either; one from
        # another server does, and a no keeps what was shown.
        same = next(k for k, s in geo.TILE_STYLES.items()
                    if s['host'] == geo.TILE_STYLES[canvas.style]['host']
                    and k != canvas.style)
        panel.style_combo.setCurrentIndex(panel.style_combo.findData(same))
        panel.style_combo.activated.emit(panel.style_combo.currentIndex())
        assert canvas.style == same
        asked = []
        panel.ask = lambda style: asked.append(style) or False
        panel.style_combo.setCurrentIndex(panel.style_combo.findData('osm'))
        panel.style_combo.activated.emit(panel.style_combo.currentIndex())
        assert asked == ['osm'] and canvas.style == same
        assert panel.style_combo.currentData() == same
    finally:
        panel.shutdown()
        case.close()


def test_landing_on_a_point_previews_it(qapp, tmp_path):
    from PySide6.QtCore import QPointF, Qt
    from PySide6.QtTest import QTest
    from trace_app.core import geo
    case, _first, _second = make_case(tmp_path)
    panel = _panel(qapp, case, lambda *a: pytest.fail("fetched"))
    try:
        assert panel.table.rowCount() == 3
        landed = []
        panel.point_selected.connect(landed.append)
        panel.table.selectRow(1)
        assert landed[-1]['name'] == 'Madrid'
        assert panel.canvas.selected == 1
        # A click on a dot selects its row, which previews it.
        canvas = panel.canvas
        point = panel.points[2]
        x, y = geo.project(point['latitude'], point['longitude'],
                           canvas.zoom)
        sx, sy = canvas._screen(x, y)
        QTest.mouseClick(canvas, Qt.LeftButton, pos=QPointF(sx, sy)
                         .toPoint())
        assert landed[-1]['name'] == 'london.jpg'
        assert panel.table.currentRow() == 2
        # The evidence filter narrows the map too.
        panel.set_evidence_filter(_first)
        assert panel.table.rowCount() == 1
    finally:
        panel.shutdown()
        case.close()
