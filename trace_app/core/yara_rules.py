"""YARA: the examiner's rules, run over every file and every carved file.

Rules are kept in a library in `user_data_dir()/yara/`, one folder per set:
the rule files are *copied* there when imported (a file or a whole folder,
its sub-folders and `include`s kept), with each file's SHA-256 in the
manifest -- so a case's results can always be traced to the exact rules
that made them, even after the originals change. Which sets a case uses is
the case's setting (`case.setting('yara')`).

The engine is yara-x (VirusTotal's YARA in Rust). It has no wheel for
Windows on ARM; there `available()` is False and the features using it say
so (infra/capabilities.py).

A match is a finding (module 'yara', one per rule per file): the rule, its
namespace (the set), tags and metadata, and each matched string with its
offset and the bytes matched. A set's grade says how serious its matches
are; a rule's own `severity` / `score` / `threat_level` metadata can raise
it.

No Qt here.
"""

import datetime
import hashlib
import json
import logging
import os
import re
import shutil
import uuid

logger = logging.getLogger('TRACE.YARA')

MODULE_YARA = 'yara'

RULE_EXTENSIONS = ('.yar', '.yara', '.rule', '.rules', '.yr')
LIBRARY_FILE = 'library.json'

#: Largest file scanned whole; larger ones are scanned in their first part.
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
#: Seconds a single file may take before the scan of it is abandoned.
SCAN_TIMEOUT = 30
#: Matched bytes kept per string match, and matches per string.
SNIPPET_BYTES = 64
MATCHES_PER_STRING = 10

GRADES = ('suspicious', 'notable')


class YaraError(Exception):
    """Rules could not be imported or compiled."""


class ScanCancelled(Exception):
    """The examiner stopped the scan."""


def available():
    from trace_app.infra import capabilities
    return capabilities.available('yara')


def unavailable_reason():
    from trace_app.infra import capabilities
    return capabilities.reason('yara')


def default_options():
    return {'enabled': False, 'sets': {}, 'include_carved': True,
            'max_bytes': DEFAULT_MAX_BYTES}


def case_options(case, library=None):
    stored = case.setting('yara') if case is not None else None
    options = default_options()
    if stored:
        options.update(stored)
    elif library is not None and library.sets():
        options['enabled'] = True
    return options


def set_enabled_in(options, entry):
    chosen = (options.get('sets') or {}).get(entry['id'])
    return entry.get('enabled_by_default', True) if chosen is None \
        else bool(chosen)


# --- the library ------------------------------------------------------------------

class Library:
    def __init__(self, folder=None):
        if folder is None:
            from trace_app.infra.paths import user_data_dir
            folder = os.path.join(user_data_dir(), 'yara')
        self.folder = folder
        os.makedirs(folder, exist_ok=True)
        self._path = os.path.join(folder, LIBRARY_FILE)

    def _load(self):
        try:
            with open(self._path, encoding='utf-8') as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return {'sets': []}
        except (OSError, ValueError) as exc:
            logger.error("YARA library unreadable: %s", exc)
            return {'sets': []}
        data.setdefault('sets', [])
        return data

    def _save(self, data):
        temporary = self._path + '.tmp'
        with open(temporary, 'w', encoding='utf-8') as handle:
            json.dump(data, handle, indent=2)
        os.replace(temporary, self._path)

    def sets(self):
        out = []
        for entry in self._load()['sets']:
            entry = dict(entry)
            entry['available'] = os.path.isdir(self.set_folder(entry))
            out.append(entry)
        return out

    def get(self, set_id):
        return next((e for e in self.sets() if e['id'] == set_id), None)

    def set_folder(self, entry):
        return os.path.join(self.folder, entry['id'])

    def update(self, set_id, **fields):
        allowed = {'name', 'grade', 'description', 'enabled_by_default'}
        if set(fields) - allowed:
            raise ValueError("Not a rule set field")
        if 'grade' in fields and fields['grade'] not in GRADES:
            raise ValueError("Unknown grade")
        data = self._load()
        for entry in data['sets']:
            if entry['id'] == set_id:
                entry.update(fields)
                self._save(data)
                return entry
        raise YaraError("No such rule set")

    def remove(self, set_id):
        data = self._load()
        gone = [e for e in data['sets'] if e['id'] == set_id]
        data['sets'] = [e for e in data['sets'] if e['id'] != set_id]
        self._save(data)
        for entry in gone:
            shutil.rmtree(self.set_folder(entry), ignore_errors=True)

    def import_rules(self, source, name=None, grade='suspicious',
                     description=''):
        """Copy a rule file, or every rule file under a folder, into the
        library and check they compile. Raises YaraError naming the file,
        line and column of the first error; nothing is kept then."""
        if grade not in GRADES:
            raise ValueError("Unknown grade")
        source = os.path.abspath(source)
        files = _rule_files(source)
        if not files:
            raise YaraError(f"No YARA rule files ({', '.join(RULE_EXTENSIONS)}"
                            f") in {os.path.basename(source)}.")
        set_id = uuid.uuid4().hex
        target = os.path.join(self.folder, set_id)
        base = source if os.path.isdir(source) else os.path.dirname(source)
        hashes = {}
        try:
            os.makedirs(target)
            if os.path.isdir(source):
                # The whole tree, so `include "../common.yar"` still works.
                for path in _all_files(source):
                    relative = os.path.relpath(path, base)
                    destination = os.path.join(target, relative)
                    os.makedirs(os.path.dirname(destination), exist_ok=True)
                    shutil.copy2(path, destination)
            else:
                shutil.copy2(source, os.path.join(target,
                                                  os.path.basename(source)))
            for path in files:
                relative = os.path.relpath(path, base).replace('\\', '/')
                with open(path, 'rb') as handle:
                    hashes[relative] = hashlib.sha256(handle.read()) \
                        .hexdigest()
            # A file another one includes is compiled through that one;
            # compiling it as well declares its rules twice.
            included = _included_files(files)
            top = sorted(os.path.relpath(p, base).replace('\\', '/')
                         for p in files if os.path.normcase(p) not in
                         included)
            entry = {
                'id': set_id,
                'name': name or os.path.splitext(os.path.basename(
                    source.rstrip('/\\')))[0],
                'grade': grade, 'description': description,
                'source': source, 'files': top,
                'sha256': hashes, 'enabled_by_default': True,
                'added_utc': _utc_now(),
            }
            rules = compile_sets(self, [entry])
            entry['rule_count'] = sum(1 for _ in rules)
        except Exception:
            shutil.rmtree(target, ignore_errors=True)
            raise
        data = self._load()
        data['sets'].append(entry)
        self._save(data)
        return entry


def _rule_files(source):
    if os.path.isdir(source):
        return sorted(p for p in _all_files(source)
                      if p.lower().endswith(RULE_EXTENSIONS))
    return [source] if os.path.isfile(source) else []


_INCLUDE = re.compile(r'^\s*include\s+"([^"]+)"', re.MULTILINE)


def _included_files(files):
    """normcased paths of the rule files that others include."""
    included = set()
    for path in files:
        try:
            with open(path, encoding='utf-8', errors='replace') as handle:
                text = handle.read()
        except OSError:
            continue
        for target in _INCLUDE.findall(text):
            included.add(os.path.normcase(os.path.normpath(os.path.join(
                os.path.dirname(path), target))))
    return included


def _all_files(folder):
    for root, _dirs, names in os.walk(folder):
        for name in names:
            yield os.path.join(root, name)


def compile_sets(library, entries):
    """yara_x.Rules for these sets, each in a namespace of its own (the
    set's id, so two sets may both define `rule Mimikatz`). Raises
    YaraError with the compiler's own message."""
    import yara_x
    compiler = yara_x.Compiler()
    compiler.enable_includes(True)
    for entry in entries:
        folder = library.set_folder(entry)
        compiler.new_namespace(f"set_{entry['id']}")
        compiler.add_include_dir(folder)
        for relative in entry['files']:
            path = os.path.join(folder, relative)
            try:
                with open(path, encoding='utf-8', errors='replace') as handle:
                    text = handle.read()
            except OSError as exc:
                raise YaraError(f"{relative}: {exc}") from exc
            # Includes resolve against the rule file's own folder.
            compiler.add_include_dir(os.path.dirname(path))
            try:
                compiler.add_source(text, origin=f"{entry['name']}/"
                                                 f"{relative}")
            except yara_x.CompileError as exc:
                raise YaraError(str(exc)) from exc
    return compiler.build()


# --- matching -----------------------------------------------------------------

_SEVERE = {'high', 'critical', 'severe', 'malicious', 'malware'}


def grade_for(rule_meta, rule_tags, set_grade):
    """A set's grade, raised to suspicious by the rule's own say-so."""
    meta = {str(k).lower(): v for k, v in rule_meta}
    severity = str(meta.get('severity', meta.get('threat_level', ''))) \
        .lower()
    try:
        score = float(meta.get('score', 0))
    except (TypeError, ValueError):
        score = 0
    if severity in _SEVERE or score >= 70 or \
            {t.lower() for t in rule_tags} & {'malware', 'apt', 'ransomware'}:
        return 'suspicious'
    return set_grade


def describe_matches(results, data, sets_by_namespace):
    """[(kind, grade, summary, detail)] for a scan's matching rules."""
    found = []
    for rule in results.matching_rules:
        entry = sets_by_namespace.get(rule.namespace, {})
        strings = []
        for pattern in rule.patterns:
            for match in list(pattern.matches)[:MATCHES_PER_STRING]:
                piece = data[match.offset:match.offset
                             + min(match.length, SNIPPET_BYTES)]
                strings.append({'identifier': pattern.identifier,
                                'offset': match.offset,
                                'length': match.length,
                                'data': printable(piece)})
        meta = list(rule.metadata)
        grade = grade_for(meta, rule.tags, entry.get('grade', 'suspicious'))
        set_name = entry.get('name', rule.namespace)
        detail = {'rule': rule.identifier, 'set': set_name,
                  'tags': list(rule.tags),
                  'meta': {str(k): _plain(v) for k, v in meta},
                  'strings': strings}
        summary = f"YARA {rule.identifier} ({set_name})"
        if strings:
            summary += f" -- {len(strings)} string match" \
                       f"{'es' if len(strings) != 1 else ''}"
        found.append((rule.identifier, grade, summary, detail))
    return found


def printable(data):
    """Matched bytes as text when they are text, else as hex."""
    try:
        text = data.decode('utf-8')
        if all(c.isprintable() or c in '\t' for c in text):
            return text
    except UnicodeDecodeError:
        pass
    if len(data) >= 4 and all(data[i] == 0 for i in range(1, len(data), 2)):
        try:
            text = data.decode('utf-16-le')
            if all(c.isprintable() for c in text):
                return text + '  (UTF-16)'
        except UnicodeDecodeError:
            pass
    return data.hex(' ')


def _plain(value):
    return value if isinstance(value, (str, int, float, bool)) else str(value)


# --- one image ---------------------------------------------------------------------

def scan_evidence(image_handler, case, evidence_id, library, options=None,
                  progress=None, should_stop=None):
    """Scan every file (and carved file) of one image with the rules the
    case uses; replaces earlier YARA findings for it. Returns the number of
    files with a match."""
    import yara_x
    from trace_app.core import walk
    options = options or case_options(case, library)
    entries = [e for e in library.sets()
               if set_enabled_in(options, e) and e.get('available')]
    if not options.get('enabled') or not entries:
        case.clear_findings(evidence_id, MODULE_YARA)
        return 0
    rules = compile_sets(library, entries)
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(SCAN_TIMEOUT)
    by_namespace = {f"set_{e['id']}": e for e in entries}
    limit = int(options.get('max_bytes') or DEFAULT_MAX_BYTES)

    case.clear_findings(evidence_id, MODULE_YARA)
    case.record_event('yara scan started', f"evidence id={evidence_id} sets="
                      + ', '.join(f"{e['name']}" for e in entries))
    total = walk.count_files(image_handler, should_stop)
    carved = case.carved_files(evidence_id) if options.get(
        'include_carved', True) else []
    total += len(carved)
    done = matched = errors = 0
    batch = []

    def scan(data, ref, name, path, size):
        nonlocal matched, errors
        try:
            results = scanner.scan(data)
        except yara_x.TimeoutError:
            errors += 1
            logger.warning("YARA timed out on %s", path)
            return
        except Exception as exc:
            errors += 1
            logger.warning("YARA could not scan %s: %s", path, exc)
            return
        found = describe_matches(results, data, by_namespace)
        if found:
            matched += 1
            for kind, grade, summary, detail in found:
                batch.append((ref, name, path, size, kind, grade, summary,
                              json.dumps(detail, default=str)))

    try:
        for entry in walk.iter_files(image_handler, should_stop):
            done += 1
            if progress:
                progress(done, total, entry.path)
            try:
                data = entry.read(limit)
            except Exception as exc:
                logger.debug("Unreadable %s: %s", entry.path, exc)
                continue
            scan(data, entry.ref, entry.name, entry.path, entry.size)
            if len(batch) >= 200:
                case.add_module_findings(evidence_id, MODULE_YARA, batch)
                batch = []
        from trace_app.core.carving import read_carved
        for row in carved:
            if should_stop and should_stop():
                raise walk.WalkCancelled()
            done += 1
            if progress:
                progress(done, total, row.get('name') or '')
            try:
                data = read_carved(image_handler.read, row['offset'],
                                   min(row['size'], limit),
                                   row.get('fragments'))
            except Exception:
                continue
            if data:
                scan(data, row['artifact_ref'], row.get('name'),
                     f"carved: {row.get('name')}", row.get('size'))
    except walk.WalkCancelled:
        case.add_module_findings(evidence_id, MODULE_YARA, batch)
        case.record_event('yara scan cancelled',
                          f"evidence id={evidence_id} files={done} "
                          f"matched={matched}")
        raise ScanCancelled() from None
    case.add_module_findings(evidence_id, MODULE_YARA, batch)
    case.record_event('yara scan finished',
                      f"evidence id={evidence_id} files={done} "
                      f"matched={matched} unscanned={errors} sets="
                      + ', '.join(f"{e['name']} ({len(e['files'])} files)"
                                  for e in entries))
    return matched


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        '%Y-%m-%dT%H:%M:%S+00:00')

