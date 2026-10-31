"""Asking, off the window's thread, whether newer releases of the installed
external tools are published (core/modules/updates).

`ReleaseCheck` is a QThread (network and a small JSON file -- not CPU);
keep it in a KeptThreads until it has ended. It asks about installed tools
only, so with none installed nothing is sent anywhere."""

from PySide6.QtCore import QThread, Signal

from trace_app.core.modules import install, updates
from trace_app.core.modules.spec import TOOLS


class ReleaseCheck(QThread):
    """`checked(generation, result)`: result = core/modules/updates.check
    for the installed tools."""
    checked = Signal(int, object)

    def __init__(self, generation=0, force=False, parent=None):
        super().__init__(parent)
        self.generation, self.force = generation, force

    def run(self):
        specs = [spec for spec in TOOLS.values() if install.installed(spec)]
        try:
            result = updates.check(specs, force=self.force)
        except Exception:                   # check() never raises; belt
            result = {}
        self.checked.emit(self.generation, result)


def pending_names(result):
    """[(tool name, installed version, newer version)] for display."""
    return [(TOOLS[tool_id].name, old, new)
            for tool_id, old, new in updates.pending(result)]
