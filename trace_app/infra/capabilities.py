"""What this installation of TRACE can do, feature by feature.

Every library TRACE uses installs from a pre-built wheel -- no compiler
anywhere -- but not every one has a wheel for every platform (yara-x and
pi-heif have none for Windows on ARM), and a system library can be missing
(libmagic on Linux without apt's libmagic1). Rather than let a feature fail
when clicked, each one is listed here with what provides it, checked once,
and shown in Options > Supported Features. Features ask `available(key)`
and grey themselves out with `reason(key)`.

No Qt here (infra/).
"""

import importlib
import logging
import platform
import sys

logger = logging.getLogger('TRACE.Capabilities')


class Capability:
    """One feature and the component that provides it."""

    def __init__(self, key, group, feature, component, probe, note='',
                 missing_hint=''):
        self.key = key
        self.group = group
        self.feature = feature
        self.component = component
        self._probe = probe
        self.note = note
        self.missing_hint = missing_hint
        self._result = None

    def check(self):
        """(available, version or '', detail if not)."""
        if self._result is None:
            try:
                version = self._probe() or ''
                self._result = (True, str(version), '')
            except Exception as exc:          # any failure: not available
                detail = f"{type(exc).__name__}: {exc}"
                self._result = (False, '', detail)
        return self._result

    @property
    def available(self):
        return self.check()[0]

    @property
    def version(self):
        return self.check()[1]

    def reason(self):
        """Why it is unavailable, in the words a user needs."""
        ok, _version, detail = self.check()
        if ok:
            return ''
        hint = self.missing_hint or _platform_hint(self)
        return f"{self.component} is not installed or did not load " \
               f"({detail}). {hint}".strip()


def _module_version(name, attribute='get_version'):
    def probe():
        module = importlib.import_module(name)
        if attribute and hasattr(module, attribute):
            value = getattr(module, attribute)
            return value() if callable(value) else value
        return getattr(module, '__version__', '')
    return probe


def _libmagic():
    from trace_app.infra.preflight import libmagic_identity
    import magic
    magic.Magic()
    identity = libmagic_identity()
    return identity[0] if identity else ''


def _heif():
    import pi_heif
    return getattr(pi_heif, '__version__', '')


def _yara():
    import yara_x
    yara_x.compile('rule t { condition: true }')
    return getattr(yara_x, '__version__', '') or _dist_version('yara-x')


def _qt_multimedia():
    from PySide6 import QtMultimedia  # noqa: F401
    import PySide6
    return PySide6.__version__


def _dist_version(name):
    try:
        from importlib.metadata import version
        return version(name)
    except Exception:
        return ''


def _tsk():
    import pytsk3
    return pytsk3.TSK_VERSION_STR


_NO_WHEEL_ARM = ("There is no pre-built package for Windows on ARM, and "
                 "TRACE never compiles one.")


def _platform_hint(capability):
    if capability.key in ('yara', 'heic') and sys.platform == 'win32' \
            and platform.machine().upper() in ('ARM64', 'AARCH64'):
        return _NO_WHEEL_ARM
    if capability.key == 'libmagic' and sys.platform.startswith('linux'):
        return "Install it with: sudo apt install libmagic1"
    return "Reinstall with: pip install -r requirements.txt"


#: Groups in display order.
GROUPS = ('Evidence images', 'Volumes and encryption', 'File analysis',
          'Windows and browser evidence',
          'Linux, macOS, chat and cloud evidence', 'Viewing')


def _zstd():
    from trace_app.core import zstd_decode
    if zstd_decode.standard_library() is not None:
        return 'Python ' + platform.python_version() + ' standard library'
    return 'built in'


def _built_in(module):
    def probe():
        importlib.import_module(module)
        return 'built in'
    return probe

CAPABILITIES = (
    Capability('tsk', 'Evidence images', "File systems (NTFS, FAT, exFAT, "
               "ext2/3/4, HFS+, ISO 9660...)", 'The Sleuth Kit (pytsk3)', _tsk),
    Capability('ewf', 'Evidence images', "EnCase images (.E01, .Ex01) and "
               "logical evidence files (.L01, .Lx01)",
               'libewf', _module_version('pyewf')),
    Capability('ad1', 'Evidence images', "AccessData AD1 logical images "
               "(not encrypted ones)", 'TRACE', _built_in(
                   'trace_app.core.ad1')),
    Capability('logical', 'Evidence images', "Folders, ZIP and TAR as "
               "evidence (triage collections, extractions)", 'Python',
               _built_in('trace_app.core.logical_sources')),
    Capability('vmdk', 'Evidence images', "VMware disks (.vmdk)", 'libvmdk',
               _module_version('pyvmdk')),
    Capability('vhdi', 'Evidence images', "Hyper-V / Virtual PC disks "
               "(.vhd, .vhdx)", 'libvhdi', _module_version('pyvhdi')),
    Capability('qcow', 'Evidence images', "QEMU disks (.qcow2)", 'libqcow',
               _module_version('pyqcow')),
    Capability('modi', 'Evidence images', "Mac disk images (.dmg -- zlib, "
               "bzip2, LZFSE, LZMA, ADC -- .sparseimage, .sparsebundle)",
               'libmodi', _module_version('pymodi')),
    Capability('bde', 'Volumes and encryption', "BitLocker volumes",
               'libbde', _module_version('pybde')),
    Capability('fvde', 'Volumes and encryption', "FileVault 2 (Core "
               "Storage) volumes", 'libfvde', _module_version('pyfvde')),
    Capability('apfs', 'Volumes and encryption', "APFS containers, "
               "encrypted volumes included", 'libfsapfs',
               _module_version('pyfsapfs')),
    Capability('luks', 'Volumes and encryption', "LUKS-encrypted Linux "
               "volumes", 'libluksde', _module_version('pyluksde')),
    Capability('lvm', 'Volumes and encryption', "Linux LVM logical volumes",
               'libvslvm', _module_version('pyvslvm')),
    Capability('vss', 'Volumes and encryption', "Volume Shadow Copies",
               'libvshadow', _module_version('pyvshadow')),
    Capability('libmagic', 'File analysis', "File type from content",
               'libmagic', _libmagic),
    Capability('yara', 'File analysis', "YARA rule scanning", 'yara-x',
               _yara),
    Capability('sigma', 'File analysis', "Sigma rules over Windows event "
               "logs", 'PyYAML', _module_version('yaml', '__version__')),
    Capability('ios_encrypted', 'Volumes and encryption', "Encrypted iPhone "
               "backups, opened with their password", 'cryptography',
               _module_version('cryptography', '__version__')),
    Capability('pdf', 'File analysis', "PDF and e-book reading, the case "
               "report's PDF", 'PyMuPDF', _module_version('pymupdf',
                                                         'VersionBind')),
    Capability('7z', 'File analysis', "7-Zip archives", 'py7zr',
               lambda: _dist_version('py7zr') or __import__('py7zr') and ''),
    Capability('rar', 'File analysis', "RAR archives (listing; stored "
               "members)", 'rarfile',
               lambda: _dist_version('rarfile') or __import__('rarfile')
               and ''),
    Capability('pst', 'Windows and browser evidence', "Outlook PST / OST "
               "mailboxes", 'libpff', _module_version('pypff')),
    Capability('esedb', 'Windows and browser evidence', "SRUM and Edge/IE "
               "WebCache (ESE databases)", 'libesedb',
               _module_version('pyesedb')),
    Capability('msiecf', 'Windows and browser evidence', "Internet "
               "Explorer history (index.dat)", 'libmsiecf',
               _module_version('pymsiecf')),
    Capability('registry', 'Windows and browser evidence', "Registry hives",
               'python-registry',
               lambda: _dist_version('python-registry')
               or __import__('Registry') and ''),
    Capability('thumbsdb', 'Windows and browser evidence', "Thumbs.db "
               "thumbnail caches (OLE)", 'olefile',
               lambda: importlib.import_module('olefile').__version__),
    Capability('journal', 'Linux, macOS, chat and cloud evidence',
               "systemd journal (plain, XZ and LZ4 fields), wtmp, shell "
               "histories, auth logs", 'TRACE',
               _built_in('trace_app.core.activity.linux')),
    Capability('zstd', 'Linux, macOS, chat and cloud evidence',
               "systemd journal fields compressed with zstd (systemd 246+)",
               'TRACE', _zstd),
    Capability('macos', 'Linux, macOS, chat and cloud evidence',
               "KnowledgeC, quarantine events, recent items (bookmarks), "
               "install history, utmpx", 'TRACE',
               _built_in('trace_app.core.activity.macos')),
    Capability('chat', 'Linux, macOS, chat and cloud evidence',
               "Skype, iMessage, Android SMS, Dropbox, Google Drive, "
               "OneDrive", 'TRACE', _built_in('trace_app.core.activity.chat')),
    Capability('heic', 'Viewing', "HEIC / HEIF photos (iPhone)", 'pi-heif',
               _heif),
    Capability('multimedia', 'Viewing', "Audio and video playback",
               'Qt Multimedia', _qt_multimedia),
)

_BY_KEY = {c.key: c for c in CAPABILITIES}


def get(key):
    return _BY_KEY[key]


def available(key):
    capability = _BY_KEY.get(key)
    return capability.available if capability is not None else False


def reason(key):
    capability = _BY_KEY.get(key)
    return capability.reason() if capability is not None else ''


def system_summary():
    """[(label, value)] describing this installation."""
    from trace_app import __version__
    return [
        ('TRACE', __version__),
        ('Python', f"{platform.python_version()} "
                   f"({platform.python_implementation()})"),
        ('System', f"{platform.system()} {platform.release()}"),
        ('Architecture', platform.machine()),
        ('Packaged build', 'yes' if getattr(sys, 'frozen', False) else 'no'),
    ]


def report_text():
    """The whole table as plain text, for copying into a bug report."""
    lines = [f"{label}: {value}" for label, value in system_summary()]
    for group in GROUPS:
        lines.append('')
        lines.append(group)
        for capability in CAPABILITIES:
            if capability.group != group:
                continue
            ok, version, _detail = capability.check()
            state = f"available ({capability.component} {version})".replace(
                ' )', ')') if ok else "UNAVAILABLE -- " + capability.reason()
            lines.append(f"  {capability.feature}: {state}")
    return '\n'.join(lines)


def log_unavailable():
    """One line per missing feature in the log, at startup."""
    missing = [c for c in CAPABILITIES if not c.available]
    for capability in missing:
        logger.warning("Unavailable: %s -- %s", capability.feature,
                       capability.reason())
    return missing
