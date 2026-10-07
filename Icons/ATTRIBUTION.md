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

Every icon in this directory is an unmodified upstream file, downloaded from
the tag above. The exceptions are `virustotal-wordmark.svg` (see the VirusTotal
section below) and the files in `Icons/tabler/themed/`, which are upstream
glyphs with their `currentColor` stroke replaced by a fixed per-theme colour,
because Qt's SVG renderer does not resolve `currentColor` in a stylesheet.

`Icons/tabler/trace/` holds glyphs drawn for TRACE where the set has no fitting
icon -- the Findings groups (type mismatch, high entropy, duplicates) and the
Search and Triage panel logos (`search-content.svg`, `triage.svg`). They
follow Tabler's conventions (24×24 grid, 2px round stroke, `currentColor`) so
they are tinted with the rest, and `duplicates.svg` reuses Tabler's `files`
geometry. They are TRACE's own work, not upstream files.

The directory holds more icons than the interface currently uses. They are kept
so that adding a control does not mean going back to the upstream repository
and risking a mixed set of versions.

## File-type and folder icons — `Icons/mimetypes/`, `places/`, `devices/`, `apps/`, `status/`, `animations/`

Used for the file-type icons in the tree and listing views, resolved through
the mapping table in `trace_app/infra/file_icons.py`.

These are SVGs from a Linux desktop icon theme. The original upstream project
and its licence have not been positively identified — the files carry only
Inkscape editing metadata, with no author, project or licence fields. Most such
themes are distributed under the GPL or CC BY-SA, both of which require
attribution and, for GPL, that the icon sources remain available.

Only the icons the application actually references are committed. `status/` and
`animations/` are gone entirely, and `apps/` is down to the one icon still in
use. A complete copy of the original set is kept locally in `Icons_archive/`
(gitignored), so an icon can be recovered without going through git history.

**If you redistribute TRACE, identify this set and record its licence here.**
The likely candidates are Papirus, Breeze or a derivative.

## icons8 — removed

The toolbar icons were originally icons8 PNGs. They are no longer referenced or
committed; the originals are in `Icons_archive/` if the previous look is ever
wanted back.

- Source: <https://icons8.com>
- The free tier requires a visible link back to icons8. TRACE never carried
  that attribution, which is one reason these were replaced.

**If you restore these icons, add the required icons8 link** to the
application's About dialog and to the README.

## Logos — `Icons/logo.png`, `Icons/logo_prev_ui.png`

TRACE's own branding.

## VirusTotal — `Icons/VirusTotal_logo.svg`, `Icons/tabler/virustotal-wordmark.svg`

The VirusTotal wordmark, shown in the VirusTotal tab to identify the service
being queried. Trademark of Google LLC; used to identify the integration only.

`virustotal-wordmark.svg` is the same artwork with its `#394eff` fill replaced
by `currentColor`, so it takes the interface foreground colour instead of a
blue that matched nothing else on the toolbar. The letterforms are unchanged.
