"""VBA macros in Office documents (no Qt; olefile -- BSD, already a
dependency -- and MS-OVBA; oletools needs GPL pcodedmp).

Where the code is:

* Word / Excel 97-2003 (.doc, .xls, .dot...): an OLE file with a VBA
  project storage ('Macros/VBA', '_VBA_PROJECT_CUR/VBA')
* OOXML (.docm, .xlsm, .pptm, .dotm...): a ZIP member '*vbaProject.bin',
  itself an OLE file with a 'VBA' storage
* (legacy .ppt keeps its project inside the PowerPoint Document stream;
  not read -- said so)

A VBA storage holds 'dir' (compressed: the project's modules, their
stream names, where each one's source starts and the code page) and one
stream per module whose source, from that offset on, is compressed too
(MS-OVBA 2.4.1). The source is what the author wrote; p-code is not read.

`extract(data)` -> Project | None. `indicators(project)` names what makes
macros dangerous -- running by themselves (AutoOpen, Document_Open,
Workbook_Open...), starting programs, downloading, writing files, calling
Windows APIs, hiding strings -- and `grade`: macros alone are notable;
code that runs itself and downloads, executes or writes is suspicious.
"""

import io
import re
import zipfile

OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
MAX_SOURCE = 4 * 1024 * 1024


class VbaError(ValueError):
    pass


class Module:
    __slots__ = ('name', 'stream', 'source')

    def __init__(self, name, stream, source):
        self.name, self.stream, self.source = name, stream, source


class Project:
    """The macros found: modules (name, source), where they were found."""

    def __init__(self, where):
        self.where = where
        self.modules = []
        self.problems = []
        self.excel4 = False

    @property
    def source(self):
        return '\n\n'.join(f"' ---- {m.name} ----\n{m.source}"
                           for m in self.modules)


# --- MS-OVBA 2.4.1 decompression ---------------------------------------------

def decompress(data, start=0):
    """A CompressedContainer from `start`: signature 0x01, then chunks of up
    to 4,096 bytes, each stored or LZ77-compressed."""
    if start >= len(data) or data[start] != 1:
        raise VbaError("not a compressed container")
    out = bytearray()
    position = start + 1
    while position + 2 <= len(data):
        header = data[position] | data[position + 1] << 8
        size = (header & 0x0FFF) + 3
        compressed = header & 0x8000
        if (header >> 12) & 0x07 != 0b011:
            raise VbaError("bad chunk signature")
        chunk_end = min(position + size, len(data))
        position += 2
        if not compressed:
            out += data[position:position + 4096]
            position += 4096
            continue
        chunk_start = len(out)
        while position < chunk_end:
            flags = data[position]
            position += 1
            for bit in range(8):
                if position >= chunk_end:
                    break
                if not flags & (1 << bit):
                    out.append(data[position])
                    position += 1
                    continue
                if position + 1 >= chunk_end:
                    raise VbaError("truncated copy token")
                token = data[position] | data[position + 1] << 8
                position += 2
                done = len(out) - chunk_start
                bits = max((done - 1).bit_length(), 4)
                length_mask = 0xFFFF >> bits
                length = (token & length_mask) + 3
                offset = (token >> (16 - bits)) + 1
                if offset > done:
                    raise VbaError("copy token points before the chunk")
                for _ in range(length):
                    out.append(out[-offset])
        position = chunk_end
        if len(out) > MAX_SOURCE * 4:
            break
    return bytes(out)


# --- the dir stream ----------------------------------------------------------

def _modules(dir_data):
    """(code page, [(module name, stream name, source offset)])."""
    codepage = 1252
    modules, current = [], None
    position = 0
    while position + 6 <= len(dir_data):
        record = int.from_bytes(dir_data[position:position + 2], 'little')
        size = int.from_bytes(dir_data[position + 2:position + 6], 'little')
        position += 6
        if record == 0x0009:            # PROJECTVERSION: 6 bytes, not 4
            size = 6
        value = dir_data[position:position + size]
        position += size
        if record == 0x0003 and len(value) >= 2:     # PROJECTCODEPAGE
            codepage = int.from_bytes(value[:2], 'little')
        elif record == 0x0019:                       # MODULENAME
            current = {'name': _text(value, codepage), 'stream': None,
                       'offset': 0}
        elif record == 0x0047 and current is not None:   # MODULENAMEUNICODE
            current['name'] = value.decode('utf-16-le', 'replace') or \
                current['name']
        elif record == 0x001A and current is not None:   # MODULESTREAMNAME
            current['stream'] = _text(value, codepage)
        elif record == 0x0032 and current is not None:   # ...UNICODE
            current['stream'] = value.decode('utf-16-le', 'replace') or \
                current['stream']
        elif record == 0x0031 and current is not None and len(value) >= 4:
            current['offset'] = int.from_bytes(value[:4], 'little')
        elif record == 0x002B and current is not None:   # module end
            modules.append(current)
            current = None
    return codepage, [(m['name'], m['stream'] or m['name'], m['offset'])
                      for m in modules]


def _text(raw, codepage):
    try:
        return raw.decode(f'cp{codepage}')
    except (LookupError, UnicodeDecodeError):
        return raw.decode('latin-1')


# --- finding the project -----------------------------------------------------

def _from_ole(data, where, project):
    import olefile
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except (OSError, IOError, ValueError):
        return
    with ole:
        for path in ole.listdir():
            if len(path) < 2 or path[-1].lower() != 'dir' or \
                    path[-2].lower() != 'vba':
                continue
            storage = path[:-1]
            try:
                codepage, modules = _modules(decompress(
                    ole.openstream(path).read()))
            except VbaError as exc:
                project.problems.append(f"{'/'.join(path)}: {exc}")
                continue
            for name, stream, offset in modules:
                stream_path = storage + [stream]
                if not ole.exists('/'.join(stream_path)):
                    project.problems.append(f"module {name}: stream missing")
                    continue
                raw = ole.openstream(stream_path).read()
                try:
                    code = decompress(raw, offset)
                except VbaError as exc:
                    project.problems.append(f"module {name}: {exc}")
                    continue
                project.modules.append(Module(
                    name, '/'.join(stream_path),
                    _text(code[:MAX_SOURCE], codepage).replace('\r\n', '\n')))
        if not project.modules and ole.exists('PowerPoint Document') and \
                any(p[-1] == 'VBA' for p in ole.listdir(storages=True)):
            project.problems.append("PowerPoint 97-2003 keeps its VBA "
                                    "project inside the presentation stream; "
                                    "it is not read")


def extract(data):
    """The macros in an Office document, or None if it has none."""
    data = bytes(data)
    project = None
    if data.startswith(OLE_MAGIC):
        if 'VBA'.encode('utf-16-le') not in data and \
                'Macros'.encode('utf-16-le') not in data:
            return None
        project = Project('VBA project in the document')
        _from_ole(data, project.where, project)
    elif data.startswith(b'PK\x03\x04'):
        try:
            package = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            return None
        with package:
            names = package.namelist()
            bins = [n for n in names if n.lower().endswith('vbaproject.bin')]
            excel4 = any(n.lower().startswith('xl/macrosheets/')
                         for n in names)
            if not bins and not excel4:
                return None
            project = Project(', '.join(bins) or 'Excel 4.0 macro sheets')
            project.excel4 = excel4
            for name in bins:
                info = package.getinfo(name)
                if info.file_size > 64 * 1024 * 1024:
                    project.problems.append(f"{name} too large to read")
                    continue
                _from_ole(package.read(name), name, project)
    if project is None or not (project.modules or project.excel4 or
                               project.problems):
        return None
    return project


# --- what makes them dangerous ---------------------------------------------------

#: (category, words): matched whole-word, any case, in the source.
_AUTO = ('AutoOpen', 'Auto_Open', 'AutoExec', 'AutoNew', 'AutoClose',
         'Auto_Close', 'Document_Open', 'Document_New', 'Document_Close',
         'DocumentOpen', 'DocumentBeforeClose', 'Workbook_Open',
         'Workbook_Activate', 'Workbook_BeforeClose', 'Auto_Activate',
         'Presentation_Open', 'App_DocumentOpen', 'Document_ContentControlOnEnter',
         'InkPicture1_Painted', 'Frame1_Layout')
_SIGNS = (
    ('runs programs', ('Shell', 'ShellExecute', 'ShellExecuteA',
                       'WScript.Shell', 'Shell.Application', 'Run',
                       'Exec', 'Create', 'Win32_Process', 'MacScript',
                       'AppleScriptTask', 'ExecuteExcel4Macro')),
    ('downloads', ('URLDownloadToFile', 'URLDownloadToFileA',
                   'Msxml2.XMLHTTP', 'Microsoft.XMLHTTP', 'MSXML2.ServerXMLHTTP',
                   'WinHttp.WinHttpRequest', 'InternetOpen', 'InternetReadFile',
                   'Net.WebClient', 'DownloadFile', 'DownloadString')),
    ('writes files', ('ADODB.Stream', 'SaveToFile', 'Scripting.FileSystemObject',
                      'CreateTextFile', 'FileCopy', 'Kill', 'Open', 'Put',
                      'Binary', 'Output')),
    ('calls Windows APIs', ('Declare', 'Lib', 'VirtualAlloc', 'RtlMoveMemory',
                            'CreateThread', 'WriteProcessMemory', 'CallWindowProc',
                            'EnumSystemLanguageGroupsW')),
    ('hides what it does', ('Chr', 'ChrW', 'ChrB', 'StrReverse', 'Base64',
                            'CallByName', 'Environ', 'Xor', 'Hex')),
    ('starts PowerShell or a shell', ('powershell', 'cmd.exe', 'cmd /c',
                                      'mshta', 'rundll32', 'regsvr32',
                                      'certutil', 'bitsadmin')),
)
_URL = re.compile(r'https?://[^\s"\'()<>]+', re.IGNORECASE)
_EXE = re.compile(r'\b[\w\-]+\.(?:exe|dll|scr|bat|cmd|ps1|vbs|js|hta)\b',
                  re.IGNORECASE)


def _found(source, words):
    hits = []
    for word in words:
        if ' ' in word or '.' in word or '/' in word:
            if word.lower() in source.lower():
                hits.append(word)
        elif re.search(rf'(?<![\w.]){re.escape(word)}(?![\w])', source,
                       re.IGNORECASE):
            hits.append(word)
    return hits


def indicators(project):
    """{'autoexec': [...], 'signs': {category: [words]}, 'urls': [...],
    'files': [...], 'grade': 'suspicious'|'notable'}."""
    source = project.source
    auto = _found(source, _AUTO)
    signs = {}
    for category, words in _SIGNS:
        hits = _found(source, words)
        # 'Open ... For Output/Binary' only counts as writing with both.
        if category == 'writes files' and hits == ['Open']:
            hits = []
        if hits:
            signs[category] = hits
    dangerous = {'runs programs', 'downloads', 'writes files',
                 'calls Windows APIs', 'starts PowerShell or a shell'}
    grade = 'suspicious' if (auto or project.excel4) and \
        dangerous & set(signs) else 'notable'
    return {'autoexec': auto, 'signs': signs,
            'urls': sorted(set(_URL.findall(source)))[:50],
            'files': sorted(set(_EXE.findall(source)))[:50],
            'grade': grade}


def summary(project, found=None):
    """One sentence for a finding or a notice bar."""
    found = found or indicators(project)
    count = len(project.modules)
    parts = [f"VBA macros: {count} module{'s' if count != 1 else ''}"
             + (f" ({', '.join(m.name for m in project.modules[:6])})"
                if count else '')]
    if project.excel4:
        parts.append("Excel 4.0 macro sheets")
    if found['autoexec']:
        parts.append(f"run by themselves ({', '.join(found['autoexec'][:4])})")
    for category, words in found['signs'].items():
        parts.append(f"{category} ({', '.join(words[:4])})")
    if found['urls']:
        parts.append(f"URLs: {', '.join(found['urls'][:3])}")
    if project.problems:
        parts.append('; '.join(project.problems[:2]))
    return '; '.join(parts) + '.'
