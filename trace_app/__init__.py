"""TRACE - Toolkit for Retrieval and Analysis of Cyber Evidence.

Layout:
    core/   disk image access, background workers, lookups. No UI imports.
    ui/     the Qt application: main window, viewer tabs, dialogs.
    infra/  paths, constants, shared helpers, startup checks.

The rule worth keeping: nothing in core/ may import from ui/.
"""

__version__ = "1.2.0"
