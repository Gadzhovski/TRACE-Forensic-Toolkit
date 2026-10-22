"""What the installers check before saying TRACE is installed (no Qt
window, nothing written).

`python -m trace_app.infra.install_check` imports what TRACE cannot start
without -- the forensic engines, Qt's widgets, libmagic -- and asks
preflight whether libmagic actually works. A missing system library shows
up here, while the installer can still say which package it is, rather
than at the first start. Exit status 1 with one line per problem.
"""

import sys

#: Imported in this order: trace_app first, because on macOS it chooses
#: the bundled libmagic before anything imports `magic`.
MODULES = ('trace_app', 'pytsk3', 'pyewf', 'PySide6.QtWidgets', 'magic')


def problems():
    """One line per thing that does not load or work."""
    found = []
    for name in MODULES:
        try:
            __import__(name)
        except Exception as exc:
            found.append(f"{name}: {type(exc).__name__}: {exc}")
    try:
        from trace_app.infra.preflight import check_dependencies
        for name, detail, hint in check_dependencies():
            found.append(f"{name}: {detail} (install with: {hint})")
    except Exception as exc:
        found.append(f"preflight: {type(exc).__name__}: {exc}")
    return found


def main():
    found = problems()
    if found:
        print('\n'.join(found))
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main())
