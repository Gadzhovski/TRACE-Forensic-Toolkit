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

`Icons/tabler/trace/` names upstream glyphs by what they mean in TRACE
(`triage.svg` is Tabler's `first-aid-kit`, `sigma.svg` its `sum`,
`type-mismatch.svg` its `file-unknown`...). Each is an unmodified upstream
file from the same tag: the hand-drawn glyphs that used to live here were
replaced in October 2026, when every file in `Icons/tabler/` was compared with the
upstream drawings. The `*-filled.svg` dialog glyphs are Tabler's filled set.

External modules' artifacts (iLEAPP, aLEAPP) name Feather or Tabler
icons; every name the installed releases use (263) resolves to a file here
(`icons._LEAPP_RENAMED` lists the Feather names Tabler draws under another
name). The 185 added for them in October 2026 are unmodified upstream files
from the same tag, each checked to be a plain SVG (no script, no external
reference) before it was copied in.

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

## External modules' logos — `Icons/modules/`

`ileapp.png`, `aleapp.png`, `rleapp.png`, `vleapp.png`, `dleapp.png`: each
LEAPP's own program icon, read from its released build (the Windows
executable's icon group, scaled to 128 px by `core/modules/logo.py`), so the
tools show their logos in External Modules and the Modules tab before they
are installed.

- Source: <https://github.com/abrignoni/iLEAPP>, `ALEAPP`, `RLEAPP`,
  `VLEAPP`, `DLEAPP` (Alexis Brignoni and contributors), release 2026.4.x
- Licence: **MIT** (each repository's `LICENSE`)

## Messaging apps' marks — `Icons/tabler/brand-*.svg`

Triage ▸ Conversations names each app by Tabler's brand glyph (WhatsApp,
Telegram, Signal, Discord, Instagram, Messenger, Snapchat, Skype, WeChat,
Line, TikTok, X, Zoom, Teams, Slack, Threads, Tinder, Reddit, LinkedIn,
Gmail, Google) from the same Tabler release and licence as above, tinted in
code with the app's colour. Tabler has no Viber mark: Viber is a phone.

## Logos — `Icons/logo.png`, `Icons/logo_prev_ui.png`

TRACE's own branding.

## Operating system marks — `Icons/os/`

Shown beside a volume that holds an operating system (the tree, Image
Information; `core/os_identity.py`).

- `windows.svg`: Tabler Icons' filled `brand-windows` (v3.46.0, MIT, as
  above), unmodified -- Simple Icons no longer carries Microsoft's marks.
- Every other file: Simple Icons v15.0.0 (<https://simpleicons.org>),
  unmodified, **CC0 1.0** (public domain). Colours are each brand's own hex
  from Simple Icons' data, set in `trace_app/ui/icons.py` (`OS_LOGOS`).
  `chromeos.svg` is Simple Icons' `googlechrome`, renamed: ChromeOS
  carries Chrome's mark and Simple Icons has none of its own.
- The marks are trademarks of their owners (Microsoft, Apple, Google, the
  Linux Foundation and the distributions). They are used only to name the
  system found on evidence -- nominative use -- and imply no endorsement;
  see Simple Icons' DISCLAIMER.md.

## VirusTotal — `Icons/VirusTotal_logo.svg`, `Icons/tabler/virustotal-wordmark.svg`

The VirusTotal wordmark, shown in the VirusTotal tab to identify the service
being queried. Trademark of Google LLC; used to identify the integration only.

`virustotal-wordmark.svg` is the same artwork with its `#394eff` fill replaced
by `currentColor`, so it takes the interface foreground colour instead of a
blue that matched nothing else on the toolbar. The letterforms are unchanged.
