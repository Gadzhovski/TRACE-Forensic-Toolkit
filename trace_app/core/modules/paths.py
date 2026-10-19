"""Where external tools are installed (no Qt).

`modules_dir()`, in order:

1. the examiner's own folder (Options ▸ Settings ▸ External modules
   folder) -- a USB stick, a larger disk;
2. `<TRACE folder>/modules` when TRACE's own folder can be written to: the
   unpacked Windows zip (so a TRACE copied to a stick carries its tools),
   or the repository when run from source on any system;
3. the per-user data folder (infra/paths.user_data_dir): always for the
   packaged macOS app -- TRACE.app is sealed by its signature, and read-only
   when run from the disk image -- and for a Windows copy in a folder TRACE
   may not write to (Program Files).

Each tool lives in `<modules dir>/<tool id>/<version>/`, with
`<modules dir>/<tool id>/installed.json` saying which version is in use.
"""

import os
import sys
import uuid

FOLDER = 'modules'


def trace_folder():
    """The folder TRACE runs from: the packaged program's, or the
    repository's."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    from trace_app.infra import paths
    return paths._PROJECT_ROOT


def _writable(folder):
    """Whether a file can be made in `folder` (made if missing): asked by
    doing it, as permissions alone do not say (read-only media, ACLs)."""
    try:
        os.makedirs(folder, exist_ok=True)
        probe = os.path.join(folder, f'.write-test-{uuid.uuid4().hex}')
        with open(probe, 'wb') as handle:
            handle.write(b'')
        os.remove(probe)
        return True
    except OSError:
        return False


def default_dir():
    """Where tools go when the examiner has not chosen (see the module)."""
    frozen_mac = getattr(sys, 'frozen', False) and sys.platform == 'darwin'
    if not frozen_mac:
        beside = os.path.join(trace_folder(), FOLDER)
        if _writable(beside):
            return beside
    from trace_app.infra.paths import user_data_dir
    return os.path.join(user_data_dir(), FOLDER)


def modules_dir():
    """The folder external tools are installed in (created)."""
    from trace_app.core import settings
    chosen = (settings.user('modules_folder') or '').strip()
    folder = os.path.abspath(chosen) if chosen else default_dir()
    os.makedirs(folder, exist_ok=True)
    return folder


def tool_dir(tool_id):
    return os.path.join(modules_dir(), tool_id)
