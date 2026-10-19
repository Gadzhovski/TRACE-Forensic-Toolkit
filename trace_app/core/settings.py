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

import json
import logging
from trace_app.infra.sqlite_uri import connect_read_only

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
    'modules_folder': ('', "External modules folder",
                       "Where Tools ▸ External Modules installs iLEAPP, "
                       "aLEAPP and the like. Empty: a 'modules' folder "
                       "beside TRACE when TRACE's folder can be written to "
                       "(it then travels with a TRACE copied to a USB "
                       "stick), else TRACE's folder in your user data -- "
                       "always there for the macOS app."),
    'check_updates': (True, "Allow checking for new versions",
                      "TRACE may ask GitHub for its newest release -- one "
                      "request, carrying nothing but TRACE's version, and "
                      "nothing is downloaded. Off: never asked, not even "
                      "from Help ▸ About ▸ Check for Updates. Never while a "
                      "case is offline."),
    'check_updates_at_start': (True, "Check when TRACE starts",
                               "A few seconds after the window opens, the "
                               "newest release is asked for once; a newer "
                               "one is named in the status bar, linking its "
                               "release page. Off: only when Check for "
                               "Updates is clicked."),
    'ui_scale': ('100%', "Interface size",
                 "Everything larger or smaller -- text, controls, icons -- "
                 "on top of the scaling the system already applies for the "
                 "screen. For a large or high-resolution screen. Takes "
                 "effect when TRACE starts again (View ▸ Interface Size "
                 "offers to restart). The text of one list can also be "
                 "made larger on its own: Ctrl + mouse wheel, or Ctrl+= / "
                 "Ctrl+- / Ctrl+0."),
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
    'verify_order': ('alongside analysis', "Verify evidence hashes",
                     "alongside analysis: hashing reads the image file in "
                     "order while analysis reads its files -- best on SSDs "
                     "and network storage. after analysis: findings first, "
                     "then hashes -- best on one slow hard disk. before "
                     "analysis: hashes confirmed before anything else is "
                     "read."),
    'debug_log': (False, "Detailed log",
                  "Write debug detail to trace.log -- for reporting a "
                  "problem; the log grows quickly."),
    'worker_processes': (0, "Worker processes for indexing",
                         "How many processes pull text out of files while "
                         "an image is indexed. 0: automatic -- every core "
                         "but two, at most 8. Fewer leaves the computer "
                         "freer for other work; runs of under 2,000 files "
                         "use one."),
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
    'carve_write_copies': (False, "Also write carved files to disk",
                           "Off: a carved file is a reference -- its offset "
                           "(and fragments) in the image, with its hashes -- "
                           "read from the evidence when viewed, as X-Ways "
                           "and Autopsy keep theirs; export the ones you "
                           "need (Carved files ▸ Export). On: every carve is "
                           "also copied into the folder below as it is "
                           "found."),
    'carved_folder': ('', "Write carved files to",
                      "Where copies go when they are written while "
                      "carving. Empty: the case's carved/ folder. A folder "
                      "on another drive keeps large carves off the "
                      "case's."),
    'export_folder': ('', "Export to",
                      "Where exports and saved files are offered; empty: "
                      "the case's exports/ folder."),
    'index_memory_files': (True, "Index page, swap and hibernation files",
                           "pagefile.sys, swapfile.sys and hiberfil.sys hold "
                           "what was in memory: they are indexed in pieces "
                           "as free space is, each hit pointing at its bytes "
                           "on the image."),
    'index_unallocated': (True, "Index text in unallocated space",
                          "The text in free space -- between partitions, "
                          "and the clusters no live file holds -- is indexed "
                          "too, as items named by sector, so a search finds "
                          "what is in no file -- by the module Search free "
                          "space and memory files (Recovery), a job of its "
                          "own after the file index. Off: that module "
                          "indexes the memory files only."),
    'indicators': (list(INDICATORS), "Indicators extracted",
                   "Which kinds indexing extracts. Phone numbers, for one, "
                   "can be noise in some cases."),
    # --- what goes where (the Results page) --------------------------------
    'activity_categories': ([], "Activity kept",
                            "Which kinds of record the Activity module "
                            "keeps from the evidence (the Activity tab, "
                            "Triage, the Timeline and the report all read "
                            "them). Leaving out a large kind you do not "
                            "need -- macOS FSEvents fill Files and folders "
                            "by the tens of thousands -- makes the case "
                            "smaller and every view quicker. Applies when "
                            "the module runs; a change offers to run it "
                            "again. All ticked: every kind, including "
                            "kinds a later TRACE adds."),
    'timeline_sources': ([], "Timeline shows",
                         "The sources the Timeline starts with when it "
                         "opens; its Filters ▸ Sources still shows any of "
                         "them on demand. Nothing is removed from the "
                         "case. Default: everything but the case's own "
                         "events (the audit trail)."),
    'timeline_activity_categories': ([], "Activity on the Timeline",
                                     "Which kinds of Activity record appear "
                                     "on the Timeline. The Activity tab "
                                     "still lists every kind. All ticked: "
                                     "every kind."),
    'module_destinations': (None, "Where external tools' results go",
                            "iLEAPP, aLEAPP and the other tools read far "
                            "more than TRACE shows by default. TRACE sorts "
                            "each artifact a tool fills: evidence (calls, "
                            "messages, web history, places, accounts, "
                            "apps), other records, device telemetry (logs, "
                            "battery and health samples, usage counters). "
                            "Tick where each kind goes. Timeline and "
                            "Search copy every row into the case: that is "
                            "what makes a large extraction slow and its "
                            "case big, and why telemetry stays out by "
                            "default. Whatever is chosen, every row stays "
                            "in the tool's own database, browsed in the "
                            "Modules tab. A change applies to the runs "
                            "already in the case, in the background (a "
                            "large addition is asked first)."),
    'module_import_rows': (250000, "Largest artifact copied (rows)",
                           "An artifact with more rows than this is not "
                           "copied into the Timeline or Search, whatever "
                           "kind it is -- iLEAPP reads 21 million "
                           "unified-log entries from one sysdiagnose. It "
                           "stays in the tool's own database, browsed in "
                           "the Modules tab and Activity ▸ Others, and "
                           "the run says which. Evidence above it goes "
                           "into Activity up to this many rows. 0: no "
                           "limit."),
    'module_link_readings': (True, "Show a record read twice once",
                             "When TRACE and a tool (or two tools) read the "
                             "same message, call, visit or place, the "
                             "Activity tab, Triage, the Timeline and the "
                             "report show it once, naming every reader. "
                             "Off: each reading is a row of its own."),
}

#: Case settings whose empty list means "all of them".
ALL_WHEN_EMPTY = ('activity_categories', 'timeline_sources',
                  'timeline_activity_categories')

CARVE_SOURCES = ('unallocated', 'slack', 'memory', 'image')
VERIFY_ORDERS = ('alongside analysis', 'after analysis', 'before analysis')
SIZE_UNITS = ('binary', 'decimal')


# --- user settings ---------------------------------------------------------------

_SECTION = 'Settings'


def read_user():
    """Every user setting, the saved value or its default."""
    from trace_app.infra import config_store
    values = {key: spec[0] for key, spec in USER.items()}
    parser = config_store.load()
    for key in USER:
        if parser.has_option(_SECTION, key):
            try:
                values[key] = json.loads(parser.get(_SECTION, key))
            except ValueError as exc:
                logger.debug("User setting %s unreadable: %s", key, exc)
    return values


def save_user(values):
    from trace_app.infra import config_store
    config_store.set_values(_SECTION, {key: json.dumps(values[key])
                                       for key in USER if key in values})
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
    values = {key: json.loads(json.dumps(spec[0]))
              for key, spec in CASE.items()}
    from trace_app.core.modules import destinations
    values['module_destinations'] = destinations.normalise(None)
    return values


def for_case(case):
    """Every case setting, saved or default; the defaults for no case."""
    values = defaults()
    if case is not None:
        stored = case.setting('settings') or {}
        values.update({k: v for k, v in stored.items() if k in CASE})
    from trace_app.core.modules import destinations
    values['module_destinations'] = destinations.normalise(
        values.get('module_destinations'))
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
        '; '.join(f"{CASE[k][1]}: {_show(old, k)} -> {_show(new, k)}"
                  for k, (old, new) in changed.items()))
    apply_case(case)
    return changed


#: Case settings that change what is read from the evidence: (the module
#: that reads it, when a change needs it again -- 'on' turned on, 'any'
#: any change, 'added' a kind added). Everything else applies at once (it
#: is read when shown) or to the next run of its module (carving).
RERUN = {
    'hash_md5': ('analysis', 'on'),
    'hash_sha1': ('analysis', 'on'),
    'max_analysis_mb': ('analysis', 'any'),
    'max_inspect_mb': ('analysis', 'any'),
    'archive_depth': ('index', 'any'),
    'archive_member_mb': ('index', 'any'),
    'indicators': ('index', 'added'),
    'index_unallocated': ('index_free', 'on'),
    'index_memory_files': ('index_free', 'on'),
    'activity_categories': ('activity', 'any'),
}


def rerun_needed(changed):
    """{module: [labels of the settings that need it]} for a save_case
    result {key: (old, new)} -- what the evidence already read must be read
    again by, for the change to reach it."""
    out = {}
    for key, (old, new) in changed.items():
        if key not in RERUN:
            continue
        module, when = RERUN[key]
        if when == 'on':
            needed = bool(new) and not bool(old)
        elif when == 'added':
            needed = bool(set(new or ()) - set(old or ()))
        else:
            needed = old != new
        if needed:
            out.setdefault(module, []).append(CASE[key][1])
    return out


def _show(value, key=None):
    if isinstance(value, bool):
        return 'on' if value else 'off'
    if key == 'module_destinations':
        from trace_app.core.modules import destinations
        return '; '.join(destinations.describe(value))
    if isinstance(value, list):
        return ', '.join(value) or ('all' if key in ALL_WHEN_EMPTY
                                    else 'none')
    return str(value) if value not in (None, '') else '(default)'


_case_values = defaults()


def current(key):
    """A case setting as last applied in this process."""
    if key not in _case_values:
        return defaults()[key]
    return _case_values[key]


def chosen(key, every):
    """A list setting's choice as a set: `every` (all known) when it is
    empty (ALL_WHEN_EMPTY)."""
    value = current(key) or ()
    return set(value) if value else set(every)


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
    from trace_app.core import indexer
    indexer.INDEX_UNALLOCATED = bool(values['index_unallocated'])
    indexer.INDEX_MEMORY_FILES = bool(values['index_memory_files'])
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
    lines.append("Carved files: " + (
        "written to disk as found, and referenced in the image"
        if values.get('carve_write_copies') else
        "kept as references into the image (offset, fragments, hashes) and "
        "read from it; exported copies checked against the recorded "
        "SHA-256"))
    limit = int(values.get('module_import_rows') or 0)
    from trace_app.core.modules import destinations
    lines.append("External tools' results, as TRACE sorted them -- " +
                 '; '.join(destinations.describe(
                     values.get('module_destinations'))))
    lines.append("External tools' artifacts " + (
        f"of up to {limit:,} rows copied into the Timeline and Search; "
        f"larger ones kept in the tool's database" if limit else
        "copied into the Timeline and Search whole") +
        "; every row stays in the tool's own database")
    lines.append("A record read by TRACE and by a tool shown " + (
        "once, naming both" if values.get('module_link_readings', True)
        else "once per reading"))
    kinds = values.get('activity_categories') or []
    if kinds:
        lines.append("Activity kept: " + ', '.join(kinds))
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
        self.folder = folder
        path = os.path.join(folder, 'case.db')
        connection = connect_read_only(path)
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
