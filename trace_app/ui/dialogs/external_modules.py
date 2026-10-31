"""Tools ▸ External Modules: install, update and remove iLEAPP, aLEAPP...
(core/modules).

One row per tool: what it reads, its licence, the version installed, the
newest published and the version this TRACE was tested with. Install and
Update offer the newest published release (install.preferred -- never a
pinned one, so releases made after this TRACE are offered too) and
download it from the tool's GitHub releases -- only when clicked,
never while the case is offline -- checked against the release's
SHA256SUMS before anything is unpacked. Downloads run on a thread (network
and disk, not CPU), kept until it has really ended (KeptThreads).
"""


from PySide6.QtCore import QThread, QUrl, Qt, Signal, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QDialogButtonBox, QHBoxLayout, QLabel,
                               QPushButton, QVBoxLayout)

from trace_app.core.modules import install, paths, updates
from trace_app.core.modules.spec import TOOLS
from trace_app.ui import icons
from trace_app.ui.dialogs import message
from trace_app.ui.widgets.dialog_page import PageDialog, badge, hint, set_tone
from trace_app.ui.widgets.kept_threads import KeptThreads
from trace_app.ui.widgets.progress_card import SlimBar


class _Releases(QThread):
    """Ask GitHub for a tool's releases."""
    found = Signal(str, object, str)

    def __init__(self, spec, parent=None):
        super().__init__(parent)
        self.spec = spec

    def run(self):
        try:
            # Asked afresh (the examiner opened this to see), and kept for
            # the Modules tab's and Supported Features' notices.
            self.found.emit(self.spec.id,
                            updates.releases(self.spec, force=True,
                                             asked=True), '')
        except install.InstallError as exc:
            self.found.emit(self.spec.id, [], str(exc))
        except Exception as exc:            # reported, never raised here
            self.found.emit(self.spec.id, [], f"{type(exc).__name__}: {exc}")


class _Install(QThread):
    progressed = Signal(str, object, object, str)
    ended = Signal(str, object, str)

    def __init__(self, spec, version, found, parent=None):
        super().__init__(parent)
        self.spec, self.version, self.found = spec, version, found
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            record = install.install(
                self.spec, self.version, found=self.found,
                progress=lambda done, total, text: self.progressed.emit(
                    self.spec.id, done, total, text),
                should_stop=lambda: self._stop)
            self.ended.emit(self.spec.id, record, '')
        except install.InstallCancelled:
            self.ended.emit(self.spec.id, None, 'cancelled')
        except install.InstallError as exc:
            self.ended.emit(self.spec.id, None, str(exc))
        except Exception as exc:
            self.ended.emit(self.spec.id, None,
                            f"{type(exc).__name__}: {exc}")


class ExternalModulesDialog(PageDialog):
    """`recorder(action, detail)` audits installs (the case's trail when
    one is open)."""

    def __init__(self, parent=None, recorder=None):
        super().__init__(
            "External Modules",
            "Parsers by other authors that TRACE downloads, checks and runs "
            "for you. Each is fetched only when you click Install, from its "
            "own GitHub releases, and must match the SHA-256 the release "
            "publishes.",
            icon=icons.MODULES, parent=parent)
        self.setMinimumWidth(720)
        self.recorder = recorder
        self.changed = False
        self._threads = KeptThreads(self)
        self._releases = {}
        self._rows = {}
        self._installing = {}
        self.where_label = self.note(
            f"Installed in: {paths.modules_dir()}  (Options ▸ Settings ▸ "
            f"External modules folder)")
        self.section("Tools")
        # The tools scroll; the header and Close stay put. Five tools stood
        # taller than a laptop's screen and pushed Close off its bottom.
        for spec in TOOLS.values():
            self._rows[spec.id] = self._tool_card(spec)
        self.finish_body()
        self.set_footer_hint(
            "TRACE runs a tool on files it copies out of the evidence; its "
            "results appear under Extractions from Modules.")
        self.button_box(QDialogButtonBox.Close)
        self._fit_screen(self.content)
        for spec in TOOLS.values():
            self._show(spec)
        self.check_releases()

    def _fit_screen(self, content):
        """As tall as the tools need, never taller than the screen it
        opens on (the list scrolls instead)."""
        from PySide6.QtGui import QGuiApplication
        screen = self.screen() or QGuiApplication.primaryScreen()
        available = screen.availableGeometry().height() if screen else 900
        wanted = content.sizeHint().height() + 160
        self.resize(max(self.minimumWidth(), 780),
                    max(360, min(wanted, int(available * 0.85))))

    def _tool_card(self, spec):
        frame, box = self.card()
        row = QHBoxLayout()
        row.setSpacing(14)
        box.addLayout(row)
        # The tool's own logo (shipped, or read from its program).
        logo = QLabel()
        logo.setObjectName("moduleLogo")
        logo.setPixmap(icons.module_logo(spec.id).pixmap(40, 40))
        row.addWidget(logo, 0, Qt.AlignTop)
        words = QVBoxLayout()
        words.setSpacing(4)
        heading = QHBoxLayout()
        heading.setSpacing(10)
        title = QLabel(spec.name)
        title.setObjectName("pageCardTitle")
        heading.addWidget(title)
        status = badge("")
        heading.addWidget(status)
        heading.addStretch(1)
        words.addLayout(heading)
        meta = hint(f"{spec.licence} licence · "
                    f"<a href='{spec.releases_page}'>Releases on GitHub</a>")
        meta.setOpenExternalLinks(True)
        words.addWidget(meta)
        about = hint(spec.description)
        words.addWidget(about)
        state = QLabel()
        state.setObjectName("pageCardFacts")
        state.setWordWrap(True)
        words.addWidget(state)
        bar = SlimBar(text='above')
        bar.setVisible(False)
        words.addWidget(bar)
        row.addLayout(words, 1)
        actions = QVBoxLayout()
        actions.setSpacing(6)
        install_button = QPushButton("Install")
        install_button.clicked.connect(lambda: self.install(spec))
        remove_button = QPushButton("Remove")
        remove_button.clicked.connect(lambda: self.remove(spec))
        folder_button = QPushButton("Open Folder")
        folder_button.clicked.connect(lambda: self.open_folder(spec))
        for button in (install_button, remove_button, folder_button):
            button.setMinimumWidth(120)
            actions.addWidget(button)
        actions.addStretch(1)
        row.addLayout(actions)
        return {'state': state, 'bar': bar, 'install': install_button,
                'remove': remove_button, 'folder': folder_button,
                'logo': logo, 'badge': status, 'card': frame}

    # --- state -----------------------------------------------------------

    def _show(self, spec, note=''):
        row = self._rows[spec.id]
        record = install.installed(spec)
        found = self._releases.get(spec.id)
        offered = install.preferred(spec, found) if found else None
        lines = [f"Installed: {record['version']} (since "
                 f"{record['installed_utc']} UTC)" if record
                 else "Not installed."]
        if offered:
            lines.append(f"Newest published: {offered['version']} "
                         f"({offered['published']})")
        lines.append(f"Tested with this release of TRACE: "
                     f"{spec.tested_version}")
        if note:
            lines.append(note)
        row['state'].setText('\n'.join(lines))
        busy = spec.id in self._installing
        if offered is None:
            # Releases not known yet (GitHub is asked as the dialog opens):
            # what is installed, not "Install" for a second until the
            # answer comes back.
            row['install'].setText("Installed" if record else "Install")
            row['install'].setEnabled(False)
        elif record and record['version'] == offered['version']:
            row['install'].setText("Installed")
            row['install'].setEnabled(False)
        else:
            row['install'].setText(("Update to " if record else "Install ")
                                   + offered['version'])
            row['install'].setEnabled(not busy)
        row['remove'].setEnabled(bool(record) and not busy)
        row['folder'].setEnabled(bool(record))
        if busy:
            word, tone = "Installing…", 'info'
        elif record and offered and record['version'] != offered['version']:
            word, tone = "Update available", 'warn'
        elif record:
            word, tone = f"Installed {record['version']}", 'ok'
        else:
            word, tone = "Not installed", 'muted'
        row['badge'].setText(word)
        set_tone(row['badge'], tone)

    def check_releases(self):
        why = install.refusal()
        for spec in TOOLS.values():
            if why:
                self._show(spec, why)
                continue
            self._rows[spec.id]['state'].setText(
                self._rows[spec.id]['state'].text() +
                "\nAsking GitHub for releases…")
            thread = _Releases(spec, self)
            thread.found.connect(self._found)
            self._threads[('releases', spec.id)] = thread
            thread.start()

    @Slot(str, object, str)
    def _found(self, tool_id, found, error):
        self._releases[tool_id] = found
        self._show(TOOLS[tool_id], f"Releases not read: {error}"
                   if error else '')

    # --- actions ---------------------------------------------------------

    def install(self, spec):
        found = self._releases.get(spec.id)
        offered = install.preferred(spec, found) if found else None
        if offered is None:
            return None
        asset = spec.asset_name(offered['version'])
        size = (offered['assets'].get(asset) or {}).get('size', 0)
        if not message.question(
                self, f"Install {spec.name}",
                f"Download {spec.name} {offered['version']} "
                f"({size / 1e6:.0f} MB) from GitHub?",
                f"{asset} from {spec.releases_page}. It is checked against "
                f"the release's SHA256SUMS.txt, unpacked into "
                f"{paths.tool_dir(spec.id)} and started once to check it "
                f"works. {spec.name} is by its own authors ({spec.licence} "
                f"licence); TRACE runs it on copies of evidence files."):
            return None
        row = self._rows[spec.id]
        row['bar'].setVisible(True)
        row['bar'].setRange(0, 0)
        thread = _Install(spec, offered['version'], found, self)
        thread.progressed.connect(self._progressed)
        thread.ended.connect(self._installed)
        self._installing[spec.id] = thread
        self._threads[('install', spec.id)] = thread
        self._show(spec, "Installing…")
        thread.start()
        return thread

    @Slot(str, object, object, str)
    def _progressed(self, tool_id, done, total, text):
        bar = self._rows[tool_id]['bar']
        if total:
            bar.setRange(0, 1000)
            bar.setValue(int(1000 * min(done, total) / total))
        else:
            bar.setRange(0, 0)
        bar.setFormat(text)
        bar.setTextVisible(True)

    @Slot(str, object, str)
    def _installed(self, tool_id, record, error):
        spec = TOOLS[tool_id]
        self._installing.pop(tool_id, None)
        self._rows[tool_id]['bar'].setVisible(False)
        if record:
            self.changed = True
            icons._module_logos.pop(spec.id, None)
            self._rows[tool_id]['logo'].setPixmap(
                icons.module_logo(spec.id).pixmap(40, 40))
            self._record('external module installed',
                         f"{spec.name} {record['version']} ({record['asset']}"
                         f", SHA-256 {record['sha256']}) from "
                         f"{record['url']} into {record['folder']}")
            self._show(spec, f"{spec.name} {record['version']} installed "
                             f"and checked.")
        else:
            self._show(spec, "Cancelled." if error == 'cancelled' else
                       f"Not installed: {error}")

    def remove(self, spec):
        record = install.installed(spec)
        if record is None or not message.question(
                self, f"Remove {spec.name}",
                f"Remove {spec.name} {record['version']}?",
                "Its program is deleted. The results of earlier runs stay "
                "in their cases."):
            return None
        removed = install.remove(spec)
        self.changed = True
        self._record('external module removed',
                     f"{spec.name} {removed} from {record['folder']}")
        self._show(spec, f"{spec.name} {removed} removed.")
        return removed

    def open_folder(self, spec):
        record = install.installed(spec)
        if record:
            QDesktopServices.openUrl(QUrl.fromLocalFile(record['folder']))

    def _record(self, action, detail):
        if self.recorder is not None:
            try:
                self.recorder(action, detail)
            except Exception:
                pass

    def reject(self):
        # A running thread must never lose its last reference (Qt aborts):
        # an install is cancelled and finished before the dialog closes.
        if self._installing:
            if not message.question(
                    self, "External Modules",
                    "An install is still running. Cancel it?",
                    "What was downloaded so far is deleted."):
                return
            for thread in self._installing.values():
                thread.stop()
            for thread in list(self._installing.values()):
                thread.wait()
        self._threads.clear(timeout=60000)
        super().reject()
