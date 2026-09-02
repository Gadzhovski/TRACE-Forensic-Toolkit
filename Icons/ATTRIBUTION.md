# Icon attribution

TRACE bundles icons from several sources. This file records where each set came
from and under what terms, which was previously undocumented.

## Tabler Icons — `Icons/tabler/`

Toolbar and control icons (navigation, media transport, zoom, rotate, print,
save, and the domain icons for evidence, carving and registry).

- Source: <https://github.com/tabler/tabler-icons> (v3.46.0)
- Licence: **MIT** — see `Icons/tabler/LICENSE`
- Copyright © Paweł Kuna

Monochrome SVG on a 24×24 grid with a 2px stroke. They are authored with
`stroke="currentColor"`, which Qt's SVG renderer resolves to black, so
`trace_app/ui/icons.py` tints them to the active theme's foreground colour at
runtime. That is why one set works on both the light and dark themes.

## File-type and folder icons — `Icons/mimetypes/`, `places/`, `devices/`, `apps/`, `status/`, `animations/`

Used for the file-type icons in the tree and listing views, resolved through
the mapping table in `trace_app/infra/file_icons.py`.

These are SVGs from a Linux desktop icon theme. The original upstream project
and its licence have not been positively identified — the files carry only
Inkscape editing metadata, with no author, project or licence fields. Most such
themes are distributed under the GPL or CC BY-SA, both of which require
attribution and, for GPL, that the icon sources remain available.

`apps/` (161 files), `status/` (16) and `animations/` (12) are no longer
referenced by any code path — the mapping table used to carry entries for them
that nothing ever queried. They are kept for now in case more file types are
mapped later; excluding them would save roughly 1.3 MB in a packaged build.

**If you redistribute TRACE, identify this set and record its licence here.**
The likely candidates are Papirus, Breeze or a derivative.

## icons8 — `Icons/icons8-*.png`

No longer referenced by the application; retained so the previous look can be
restored by editing `trace_app/ui/icons.py`.

- Source: <https://icons8.com>
- The free tier requires a visible link back to icons8. TRACE never carried
  that attribution, which is one reason these were replaced.

**If you revert to these icons, add the required icons8 link** to the
application's About dialog and to the README.

## Logos — `Icons/logo.png`, `Icons/logo_prev_ui.png`

TRACE's own branding.

## VirusTotal — `Icons/VirusTotal_logo.svg`

The VirusTotal wordmark, shown in the VirusTotal tab to identify the service
being queried. Trademark of Google LLC; used to identify the integration only.
