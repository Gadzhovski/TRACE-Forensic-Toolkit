# Bundled data

- `world_land.json` -- the land outline the Map tab draws when no map tiles
  are fetched: Natural Earth 1:110m land (public domain,
  naturalearthdata.com), from nvkelso/natural-earth-vector commit
  ca96624a56bd078437bca8184e78163e5039ad19, `geojson/ne_110m_land.geojson`
  (SHA-256 9e0729ee253ca7d7a5c4ae9395fb1902264c5377c52e224d13dd85010e2835d9),
  reduced to a list of rings of [longitude, latitude] rounded to 0.01
  degree.

- `offline_map.json.gz` -- the Map tab's offline map (shown until the
  examiner turns Online Map on): Natural Earth (public domain), the same
  commit -- 1:10m land and land borders, 1:50m states/provinces lines,
  lakes and rivers, 1:10m populated places (7,342) and 1:50m country
  label points. Built by `tools/build_offline_map.py`, which pins each
  file's SHA-256: Web Mercator coordinates at three levels of detail,
  simplified to about a pixel at zoom 3, 6 and 9, delta-encoded with
  bounding boxes (drawn by `trace_app/ui/viewers/map_offline.py`).

- `leapp_maps/<tool>.json` -- TRACE's own: which of an external LEAPP's
  artifacts are which TRACE records, column by column (read by
  `trace_app/core/modules/maps.py`). Written from the tools' real output
  (aLEAPP 2026.4.3 on a Pixel 3 extraction, iLEAPP 2026.4.4 on an iOS
  13.3.1 file-system tar); `tests/test_module_maps.py` checks every
  column against the lists recorded in `tests/expected/leapp_columns/`.
