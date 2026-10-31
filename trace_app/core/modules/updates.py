"""Newer releases of the installed external tools (no Qt).

The LEAPPs publish often (all five on 2026-10-24), and an examiner who
installed one keeps it until told: the Modules tab and Supported Features
say when a newer release is published, and External Modules offers it.
Nothing is pinned here -- the newest published release this TRACE can
install (`install.preferred`) is the one suggested, so releases made after
this TRACE are suggested too.

GitHub allows 60 unauthenticated API calls an hour and a check asks once
per tool, so each tool's release list is kept in `<tool dir>/releases.json`
and asked again only after `MAX_AGE`. A check is refused, like TRACE's own
update check (core/updates.refusal), when the examiner turned checking off
or the open case is offline -- and then only what is already kept is used.
Nothing is downloaded here: installing stays a click in External Modules.
"""

import datetime
import json
import logging
import os

from trace_app.core.modules import install, paths

logger = logging.getLogger('TRACE.Modules')

CACHE = 'releases.json'
#: How long a tool's release list is trusted before GitHub is asked again.
MAX_AGE = datetime.timedelta(hours=12)


def refusal():
    """Why GitHub may not be asked now, or None (the same rule as TRACE's
    own update check: Options ▸ Settings ▸ Privacy & Network, offline)."""
    from trace_app.core import updates
    return updates.refusal()


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _cache_path(spec):
    return os.path.join(paths.tool_dir(spec.id), CACHE)


def cached(spec):
    """(releases, checked UTC datetime) last read for `spec`, or
    (None, None)."""
    try:
        with open(_cache_path(spec), encoding='utf-8') as handle:
            data = json.load(handle)
        checked = datetime.datetime.fromisoformat(data['checked_utc'])
        found = data['releases']
        if not isinstance(found, list):
            return None, None
        return found, checked
    except (OSError, ValueError, KeyError, TypeError):
        return None, None


def _keep(spec, found):
    try:
        os.makedirs(paths.tool_dir(spec.id), exist_ok=True)
        partial = _cache_path(spec) + '.partial'
        with open(partial, 'w', encoding='utf-8') as handle:
            json.dump({'checked_utc': _now().isoformat(),
                       'releases': found}, handle, indent=1)
        os.replace(partial, _cache_path(spec))
    except OSError as exc:
        logger.warning("Could not keep %s's release list: %s", spec.name,
                       exc)


def releases(spec, session=None, force=False, asked=False):
    """`spec`'s published releases, newest first: the kept list while it
    is younger than MAX_AGE (always, when GitHub may not be asked), else
    asked again. `force` asks whenever asking is allowed. `asked`: the
    examiner asked (External Modules) -- then only an offline case stops
    it, not automatic checks being turned off. Raises
    install.InstallError when nothing is kept and GitHub cannot answer."""
    found, checked = cached(spec)
    fresh = found is not None and checked is not None and \
        _now() - checked < MAX_AGE
    why = install.refusal() if asked else refusal()
    if (fresh and not force) or (found is not None and why):
        return found
    if why:
        raise install.InstallError(why)
    try:
        found = install.releases(spec, session)
    except install.InstallError:
        kept, _checked = cached(spec)
        if kept is not None:
            return kept
        raise
    _keep(spec, found)
    return found


def check(specs, session=None, force=False):
    """{tool id: (installed version or None, release to offer or None,
    error text)} for `specs` -- for every tool, installed or not, so a
    view can say "newest published" too. Never raises."""
    out = {}
    for spec in specs:
        record = install.installed(spec)
        try:
            found = releases(spec, session, force)
            error = ''
        except install.InstallError as exc:
            found, error = None, str(exc)
        except Exception as exc:            # reported, never raised here
            found, error = None, f"{type(exc).__name__}: {exc}"
        offered = install.preferred(spec, found) if found else None
        out[spec.id] = (record['version'] if record else None, offered,
                        error)
    return out


def pending(result):
    """[(tool id, installed version, newer version)] from check()'s answer:
    the installed tools a newer release is published for."""
    out = []
    for tool_id, (current, offered, _error) in result.items():
        if not current or not offered:
            continue
        new = install.parse_version(offered['version'])
        old = install.parse_version(current)
        if new and old and new > old:
            out.append((tool_id, current, offered['version']))
    return out
