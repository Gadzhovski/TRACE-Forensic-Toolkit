"""A tool's logo, from its installed copy (no Qt).

The five LEAPPs' logos ship with TRACE (Icons/modules/, read first by
icons.module_logo, so a tool shows its logo before it is installed). For a
tool with none there, the logo is the program's own icon, read from what
was installed and kept beside it as logo.png --

* Windows: the program's first icon group (core/pe_icons, 256 px PNG in
  the LEAPPs' builds);
* macOS: the app bundle's .icns (Info.plist's CFBundleIconFile), read by
  Pillow;
* Linux: the AppImage's .DirIcon (or a PNG at its root).

None when there is none to read: callers fall back to the modules icon.
"""

import io
import logging
import os
import plistlib

logger = logging.getLogger('TRACE.Modules')

CACHED = 'trace-logo.png'
SIZE = 128


def _png(data):
    from PIL import Image
    with Image.open(io.BytesIO(data)) as image:
        image.load()
        picture = image.convert('RGBA')
    picture.thumbnail((SIZE, SIZE))
    out = io.BytesIO()
    picture.save(out, 'PNG')
    return out.getvalue()


def _windows(executable):
    from trace_app.core.pe_icons import program_icon
    with open(executable, 'rb') as handle:
        data = handle.read()
    return program_icon(lambda at, length: data[at:at + length], 256)


def _macos(executable):
    contents = os.path.dirname(os.path.dirname(executable))
    resources = os.path.join(contents, 'Resources')
    name = None
    try:
        with open(os.path.join(contents, 'Info.plist'), 'rb') as handle:
            name = plistlib.load(handle).get('CFBundleIconFile')
    except (OSError, ValueError):
        pass
    candidates = []
    if name:
        candidates.append(name if name.endswith('.icns') else name + '.icns')
    try:
        candidates += sorted(n for n in os.listdir(resources)
                             if n.endswith('.icns'))
    except OSError:
        return None
    for candidate in candidates:
        path = os.path.join(resources, candidate)
        if os.path.isfile(path):
            with open(path, 'rb') as handle:
                return handle.read()
    return None


def _linux(executable):
    root = os.path.dirname(executable)
    candidates = [os.path.join(root, '.DirIcon')]
    try:
        candidates += [os.path.join(root, n) for n in sorted(os.listdir(root))
                       if n.lower().endswith('.png')]
    except OSError:
        pass
    for path in candidates:
        if os.path.isfile(path):
            with open(path, 'rb') as handle:
                return handle.read()
    return None


def tool_logo(spec):
    """A tool's logo for the window: kept at `<modules dir>/<tool>/logo.png`
    once read, so runs keep it after the tool is updated or removed."""
    import shutil
    from trace_app.core.modules import install, paths
    kept = os.path.join(paths.tool_dir(spec.id), 'logo.png')
    if os.path.isfile(kept):
        return kept
    made = logo_path(install.installed(spec))
    if made is None:
        return None
    try:
        shutil.copyfile(made, kept)
        return kept
    except OSError:
        return made


def logo_path(record):
    """The PNG of an installed tool's logo (made once), or None."""
    if not record:
        return None
    cached = os.path.join(record['folder'], CACHED)
    if os.path.isfile(cached):
        return cached
    executable = record['executable']
    try:
        if executable.lower().endswith('.exe'):
            data = _windows(executable)
        elif '.app' + os.sep in executable or '.app/' in executable:
            data = _macos(executable)
        else:
            data = _linux(executable)
        if not data:
            return None
        with open(cached, 'wb') as handle:
            handle.write(_png(data))
        return cached
    except Exception as exc:
        logger.debug("No logo for %s: %s", executable, exc)
        return None
