"""The examiner's libraries -- hash sets, keyword lists, Sigma and YARA
rule sets: each a folder under user_data_dir() with a JSON manifest,
library.json, listing its entries, and the case's choice among them kept
as a case setting.

`Library` is the manifest: read (an unreadable one is logged and read as
empty -- the examiner's own files, not evidence), written whole through a
temporary file, entries updated by an allowed set of fields and removed
with what they own. `RuleSetLibrary` adds the rule sets' layout: each set's
files copied into a folder named by its id. The modules keep what differs:
how an entry is imported, what it holds, how it is used."""

import json
import logging
import os
import shutil
from collections.abc import Collection

logger = logging.getLogger('TRACE.Library')

LIBRARY_FILE = 'library.json'


class Library:
    #: Folder under user_data_dir() when none is given.
    SUBFOLDER = ''
    #: The manifest's list of entries ('sets', or 'lists' for keywords).
    KEY = 'sets'
    #: Named in the log when the manifest cannot be read.
    LABEL = 'Library'
    #: Fields `update` may change, and {field: allowed values}.
    FIELDS: frozenset[str] = frozenset()
    CHOICES: dict[str, Collection[str]] = {}
    #: Raised for an id the manifest does not hold.
    ERROR: type[Exception] = LookupError
    MISSING = "No such entry"
    #: `update`'s message for a field it does not take.
    NOT_A_FIELD = "Not a library field"
    #: Keep non-ASCII text readable in the manifest (keyword terms).
    ENSURE_ASCII = True

    def __init__(self, folder=None):
        if folder is None:
            from trace_app.infra.paths import user_data_dir
            folder = os.path.join(user_data_dir(), self.SUBFOLDER)
        self.folder = folder
        os.makedirs(folder, exist_ok=True)
        self._path = os.path.join(folder, LIBRARY_FILE)

    # --- the manifest -----------------------------------------------------

    def _load(self):
        try:
            with open(self._path, encoding='utf-8') as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return {self.KEY: []}
        except (OSError, ValueError) as exc:
            logger.error("%s library unreadable: %s", self.LABEL, exc)
            return {self.KEY: []}
        data.setdefault(self.KEY, [])
        return data

    def _save(self, data):
        temporary = self._path + '.tmp'
        with open(temporary, 'w', encoding='utf-8') as handle:
            json.dump(data, handle, indent=2, ensure_ascii=self.ENSURE_ASCII)
        os.replace(temporary, self._path)

    def entries(self):
        """Every entry, as dicts, in the order they were added, each with
        `available` when the entry says whether its data is there."""
        out = []
        for entry in self._load()[self.KEY]:
            entry = dict(entry)
            self._describe(entry)
            out.append(entry)
        return out

    def get(self, entry_id):
        return next((e for e in self.entries() if e['id'] == entry_id), None)

    def update(self, entry_id, **fields):
        unknown = set(fields) - self.FIELDS
        if unknown:
            raise ValueError(self.NOT_A_FIELD.format(
                fields=', '.join(sorted(unknown))))
        for field, allowed in self.CHOICES.items():
            if field in fields and fields[field] not in allowed:
                raise ValueError(f"Unknown {field} {fields[field]}")
        fields = self._prepare(fields)
        data = self._load()
        for entry in data[self.KEY]:
            if entry['id'] == entry_id:
                entry.update(fields)
                self._changed(entry)
                self._save(data)
                return entry
        raise self.ERROR(self.MISSING)

    def remove(self, entry_id):
        data = self._load()
        gone = [e for e in data[self.KEY] if e['id'] == entry_id]
        data[self.KEY] = [e for e in data[self.KEY] if e['id'] != entry_id]
        self._save(data)
        for entry in gone:
            self._discard(entry)

    def _add(self, entry):
        data = self._load()
        data[self.KEY].append(entry)
        self._save(data)
        return entry

    # --- what each library adds -------------------------------------------

    def _describe(self, entry):
        """Add what `entries()` reports beyond the manifest."""

    def _prepare(self, fields):
        """Normalise fields given to `update`."""
        return fields

    def _changed(self, entry):
        """Stamp an entry `update` changed."""

    def _discard(self, entry):
        """Remove what a removed entry owned."""


class RuleSetLibrary(Library):
    """Rule files copied into <folder>/<set id>/."""

    def set_folder(self, entry):
        return os.path.join(self.folder, entry['id'])

    def _describe(self, entry):
        entry['available'] = os.path.isdir(self.set_folder(entry))

    def _discard(self, entry):
        shutil.rmtree(self.set_folder(entry), ignore_errors=True)


# --- the case's choice ------------------------------------------------------

def case_options(case, setting, defaults, library=None):
    """The case's options under `setting`, `defaults` filled in. A library
    starts switched on once it holds anything: importing an entry is asking
    to use it."""
    stored = case.setting(setting) if case is not None else None
    options = defaults
    if stored:
        options.update(stored)
    elif library is not None and library.entries():
        options['enabled'] = True
    return options


def enabled_in(options, entry, key='sets'):
    """Is library entry `entry` used under these case options? The
    examiner's choice for the case, else the entry's own default."""
    chosen = (options.get(key) or {}).get(entry['id'])
    return entry.get('enabled_by_default', True) if chosen is None \
        else bool(chosen)
