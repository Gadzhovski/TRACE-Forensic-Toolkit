"""TRACE's settings: what each one is, where it lives, and applying them
(no Qt).

Two scopes:

* **user** -- the examiner's own preferences, in config.ini beside the
  theme: who they are, where cases go, how sizes read, the listing's
  filters, the log's detail. They change nothing about what is found.
* **case** -- anything that changes what TRACE finds or sends, kept in the
  case (`case.setting('settings')`) so every run on that case uses the
  same values, and every change is written to its audit trail: the
  display time zone, the network policy, analysis limits and hashes,
  carving defaults, which indicators are extracted. A quick-triage session
  has no case and uses the defaults.

`apply_case` puts a case's values into the modules that use them. It is
called when the window opens a case or the settings change, and at the
start of every background job, which runs in its own process and opens
the case itself.

What is deliberately *not* a setting: the UTC pin (the same image must
read the same everywhere) and the validation of carved files (loosening
it turns noise into "evidence").
"""

import configparser
import json
import logging

logger = logging.getLogger('TRACE.Settings')

MB = 1024 * 1024

#: key -> (default, label, help). Order is the dialog's.
USER = {
    'examiner': ('', "Examiner",
                 "Your name: suggested for new cases, filled into reports."),
    'organisation': ('', "Organisation",
                     "Filled into reports' headers."),
    'case_folder': ('', "Default case folder",
                    "Where New Case and Open Case start looking."),
    'size_units': ('binary', "Sizes",
                   "binary: 1 KB = 1,024 bytes (as Windows shows them); "
                   "decimal: 1 kB = 1,000 bytes (as drive makers and macOS "
                   "do)."),
    'show_deleted': (True, "Show deleted entries in the listing",
                     "Deleted files and folders the file system still "
                     "lists, marked as deleted."),
    'show_system': (True, "Show file system metadata files",
                    "NTFS's $MFT, $LogFile and the like, and other names "
                    "beginning with $."),
    'debug_log': (False, "Detailed log",
                  "Write debug detail to trace.log -- for reporting a "
                  "problem; the log grows quickly."),
}

#: Indicator kinds the search index can extract (search_index).
INDICATORS = ('email', 'url', 'domain', 'ip', 'ipv6', 'phone', 'card',
              'iban', 'btc', 'hash')

CASE = {
    'display_zone': ('', "Show times also in",
                     "Evidence times are kept and shown in UTC. Name a time "
                     "zone (e.g. Europe/Sofia) to show each time in it too, "
                     "beside the UTC time -- never instead of it."),
    'offline': (False, "Offline: nothing is sent from this case",
                "Blocks every network request -- VirusTotal lookups and "
                "uploads, map tiles -- for this case."),
    'vt_uploads': (True, "Allow VirusTotal uploads",
                   "Off: hash lookups only; a file is never sent."),
    'hash_md5': (True, "MD5", "File hashes computed by the analysis."),
    'hash_sha1': (True, "SHA-1", "File hashes computed by the analysis."),
    'max_analysis_mb': (2048, "Largest file analysed (MB)",
                        "Larger files are typed but not hashed or scored."),
    'max_inspect_mb': (64, "Content checks read up to (MB)",
                       "EXIF, document authors, hidden data and executables "
                       "are read from files up to this size."),
    'high_entropy': (7.5, "High entropy from (bits per byte)",
                     "A file's mean entropy at or above this is flagged "
                     "(compressed formats excepted)."),
    'archive_depth': (8, "Archive nesting followed",
                      "How many archives inside archives are opened."),
    'archive_member_mb': (64, "Largest archive member read (MB)",
                          "Members larger than this are listed, not read."),
    'carve_source': ('unallocated', "Carve by default",
                     "unallocated, slack or image (the whole image)."),
    'carve_min_kb': (0, "Smallest carved file kept (KB)",
                     "Carves below this are not kept; 0 keeps every size "
                     "a format allows."),
    'analyse_carves': (True, "Analyse carved files",
                       "Type, entropy, hidden data, photo metadata, authors "
                       "and executables for every carve."),
    'carved_folder': ('', "Write carved files to",
                      "Empty: the case's carved/ folder. A folder on "
                      "another drive keeps large carves off the case's."),
    'export_folder': ('', "Export to",
                      "Where exports and saved files are offered; empty: "
                      "the case's exports/ folder."),
    'indicators': (list(INDICATORS), "Indicators extracted",
                   "Which kinds indexing extracts. Phone numbers, for one, "
                   "can be noise in some cases."),
}

CARVE_SOURCES = ('unallocated', 'slack', 'image')
SIZE_UNITS = ('binary', 'decimal')


# --- user settings ---------------------------------------------------------------

_SECTION = 'Settings'


def _config_path():
    from trace_app.infra.paths import config_file
    return config_file()


def read_user():
    """Every user setting, the saved value or its default."""
    values = {key: spec[0] for key, spec in USER.items()}
    parser = configparser.ConfigParser()
    try:
        parser.read(_config_path())
        for key in USER:
            if parser.has_option(_SECTION, key):
                values[key] = json.loads(parser.get(_SECTION, key))
    except (configparser.Error, OSError, ValueError) as exc:
        logger.debug("User settings unreadable: %s", exc)
    return values


def save_user(values):
    parser = configparser.ConfigParser()
    try:
        parser.read(_config_path())
    except (configparser.Error, OSError):
        pass
    if not parser.has_section(_SECTION):
        parser.add_section(_SECTION)
    for key in USER:
        if key in values:
            parser.set(_SECTION, key, json.dumps(values[key]))
    try:
        with open(_config_path(), 'w', encoding='utf-8') as handle:
            parser.write(handle)
    except OSError as exc:
        logger.warning("Could not save settings: %s", exc)
    apply_user(values)


_user_cache = None


def user(key):
    """One user setting (read once, refreshed by save_user)."""
    global _user_cache
    if _user_cache is None:
        _user_cache = read_user()
    return _user_cache.get(key, USER[key][0])


def apply_user(values=None):
    """Put the user settings into effect: size units and the log level."""
    global _user_cache
    _user_cache = dict(values) if values is not None else read_user()
    from trace_app.infra import utils
    utils.SIZE_UNITS = _user_cache.get('size_units', 'binary')
    level = logging.DEBUG if _user_cache.get('debug_log') else logging.INFO
    logging.getLogger().setLevel(level)
    logging.getLogger('TRACE').setLevel(level)


# --- case settings ----------------------------------------------------------------

def defaults():
    return {key: (list(spec[0]) if isinstance(spec[0], list) else spec[0])
            for key, spec in CASE.items()}


def for_case(case):
    """Every case setting, saved or default; the defaults for no case."""
    values = defaults()
    if case is not None:
        stored = case.setting('settings') or {}
        values.update({k: v for k, v in stored.items() if k in CASE})
    return values


def save_case(case, values):
    """Store a case's settings, and audit what changed and from what."""
    before = for_case(case)
    after = dict(before)
    after.update({k: v for k, v in values.items() if k in CASE})
    changed = {k: (before[k], after[k]) for k in CASE
               if before[k] != after[k]}
    if not changed:
        return {}
    case.set_setting('settings', after)
    case.record_event(
        'settings changed',
        '; '.join(f"{CASE[k][1]}: {_show(old)} -> {_show(new)}"
                  for k, (old, new) in changed.items()))
    apply_case(case)
    return changed


def _show(value):
    if isinstance(value, bool):
        return 'on' if value else 'off'
    if isinstance(value, list):
        return ', '.join(value) or 'none'
    return str(value) if value not in (None, '') else '(default)'


_case_values = defaults()


def current(key):
    """A case setting as last applied in this process."""
    return _case_values.get(key, CASE[key][0])


def apply_case(case):
    """Put a case's settings into effect in this process."""
    global _case_values, _exports
    values = for_case(case)
    _case_values = values
    _exports = case.exports_dir if case is not None else None
    from trace_app.core import analysis, archives, content_checks, \
        search_index
    analysis.MAX_ANALYSIS_BYTES = int(values['max_analysis_mb']) * MB
    content_checks.MAX_INSPECT_BYTES = int(values['max_inspect_mb']) * MB
    analysis.HIGH_ENTROPY = float(values['high_entropy'])
    analysis.HASH_ALGORITHMS = tuple(
        name for name, on in (('md5', values['hash_md5']),
                              ('sha1', values['hash_sha1']),
                              ('sha256', True)) if on)
    archives.MAX_NESTING = int(values['archive_depth'])
    archives.MAX_MEMBER_BYTES = int(values['archive_member_mb']) * MB
    search_index.ENABLED_INDICATORS = frozenset(values['indicators'])
    return values


_exports = None


def export_dir():
    """Where exports and saved files are offered: the case's chosen export
    folder, else its exports/ folder; '' with no case (the dialog's own
    default)."""
    return _exports or ''


def network_refusal(kind='network'):
    """Why the current case forbids a request ('network' or 'upload'), or
    None when it may go ahead."""
    if current('offline'):
        return ("This case is offline (Options ▸ Settings ▸ Privacy): "
                "nothing is sent from it.")
    if kind == 'upload' and not current('vt_uploads'):
        return ("Uploads are turned off for this case (Options ▸ Settings ▸ "
                "Privacy): hash lookups only.")
    return None


def statement(values):
    """Lines for a report: the settings that shaped what was found."""
    lines = []
    zone = values.get('display_zone')
    lines.append("Times are UTC" + (f"; also shown in {zone}" if zone
                                     else ''))
    hashes = ['SHA-256'] + [label for key, label in (('hash_md5', 'MD5'),
                                                     ('hash_sha1', 'SHA-1'))
                            if values.get(key)]
    lines.append("File hashes: " + ', '.join(hashes))
    lines.append(f"Files over {values['max_analysis_mb']:,} MB typed but not "
                 f"hashed; content checks read files up to "
                 f"{values['max_inspect_mb']:,} MB")
    lines.append(f"High entropy from {values['high_entropy']} bits/byte; "
                 f"archives opened {values['archive_depth']} deep, members up "
                 f"to {values['archive_member_mb']:,} MB")
    lines.append("Network: " + ("offline -- nothing sent" if
                                values.get('offline') else
                                ("lookups and uploads allowed" if
                                 values.get('vt_uploads') else
                                 "hash lookups only")))
    return lines


def chosen_dir(chosen, case_name):
    """The folder for one case inside an examiner-chosen location (a
    larger drive for carved files, say): `chosen`/<case name>, or None
    when nothing is chosen."""
    import os
    chosen = (chosen or '').strip()
    if not chosen:
        return None
    safe = ''.join(c if c.isalnum() or c in '-_.' else '_'
                   for c in case_name or '')[:60].strip('._') or 'case'
    return os.path.join(chosen, safe)


class StoredCase:
    """A case folder's settings, read-only, without opening the case --
    for a background job, which must not write an audit line merely to
    learn its settings."""

    def __init__(self, folder):
        import os
        import sqlite3
        self.folder = folder
        path = os.path.join(folder, 'case.db')
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            rows = dict(connection.execute(
                "SELECT key, value FROM case_info WHERE key IN "
                "('name', 'setting:settings')").fetchall())
        finally:
            connection.close()
        self.name = rows.get('name') or ''
        try:
            self._settings = json.loads(rows.get('setting:settings') or
                                        'null')
        except ValueError:
            self._settings = None

    def setting(self, key, default=None):
        return self._settings if key == 'settings' and self._settings \
            is not None else default

    @property
    def exports_dir(self):
        import os
        return chosen_dir((self._settings or {}).get('export_folder'),
                          self.name) or os.path.join(self.folder, 'exports')


# --- the display time zone -----------------------------------------------------------

def zones():
    """Every IANA time zone name this installation knows, sorted."""
    import zoneinfo
    return sorted(zoneinfo.available_timezones())


def valid_zone(name):
    if not name:
        return True
    try:
        import zoneinfo
        zoneinfo.ZoneInfo(name)
        return True
    except Exception:
        return False


def alongside(text):
    """A UTC time as shown: itself, then -- when the case names a display
    zone -- the same moment there: '2026-10-04 23:07:58 UTC  ·  2026-10-05
    02:07:58 EEST'. Only for display: stored times are never changed.
    Times with no zone (FAT's local wall-clock, '(local, no zone)') and
    anything that is not a time are returned as they are."""
    zone = current('display_zone')
    if not zone or not isinstance(text, str) or not text or \
            'local' in text:
        return text
    import datetime
    import zoneinfo
    stamp = text[:-4] if text.endswith(' UTC') else text
    try:
        moment = datetime.datetime.strptime(
            stamp.replace('T', ' ')[:19], '%Y-%m-%d %H:%M:%S').replace(
            tzinfo=datetime.timezone.utc)
        there = moment.astimezone(zoneinfo.ZoneInfo(zone))
    except (ValueError, zoneinfo.ZoneInfoNotFoundError):
        return text
    shown = text if text.endswith('UTC') else f"{text} UTC"
    return f"{shown}  ·  {there:%Y-%m-%d %H:%M:%S} {there.tzname()}"
