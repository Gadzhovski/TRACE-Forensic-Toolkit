"""What an executable is, read from its own headers: Windows PE, Linux ELF
and macOS Mach-O (thin or universal).

Pure Python over bytes, no Qt and nothing executed. For each file:
format and architecture, kind (program, library, driver, ...), the time
the linker recorded (or that it recorded a hash in its place), sections
with their sizes, permissions and entropy, the libraries and functions it
imports, what it exports, the name and version it gives itself, the PDB
or build id it was built with, whether it carries a code signature and
whose (present is not verified: nothing here checks a signature), and
bytes appended after its end.

`indicators()` grades what is worth an examiner's attention: a packer's
section names, a section both writable and executable, executable code
that is near-random, a name that differs from the one the file gives
itself, imports that together inject into another process, a PE checksum
that does not match. Each indicator says what it is; none is a verdict.
"""

import collections
import logging
import math
import struct
from datetime import datetime, timezone

logger = logging.getLogger('TRACE.Executables')

#: Sections read for entropy, at most this much of each.
ENTROPY_SAMPLE = 16 * 1024 * 1024
#: Code at or above this many bits per byte is packed or encrypted.
PACKED_ENTROPY = 7.2
#: Imports and exports kept per file.
MAX_NAMES = 2000

_PE_MACHINES = {0x14c: 'x86', 0x8664: 'x64', 0x1c0: 'ARM', 0x1c4: 'ARMv7',
                0xaa64: 'ARM64', 0xa641: 'ARM64EC', 0x200: 'Itanium',
                0xebc: 'EFI byte code', 0x166: 'MIPS', 0x1f0: 'PowerPC',
                0x5064: 'RISC-V 64'}
_PE_SUBSYSTEMS = {1: 'native', 2: 'Windows GUI', 3: 'Windows console',
                  5: 'OS/2 console', 7: 'POSIX console', 9: 'Windows CE',
                  10: 'EFI application', 11: 'EFI boot driver',
                  12: 'EFI runtime driver', 13: 'EFI ROM', 14: 'Xbox',
                  16: 'Windows boot application'}
_ELF_MACHINES = {2: 'SPARC', 3: 'x86', 8: 'MIPS', 20: 'PowerPC',
                 21: 'PowerPC 64', 22: 'S/390', 40: 'ARM', 43: 'SPARC V9',
                 50: 'Itanium', 62: 'x86-64', 183: 'ARM64', 243: 'RISC-V',
                 258: 'LoongArch'}
_ELF_TYPES = {1: 'relocatable object', 2: 'program', 3: 'shared object',
              4: 'core dump'}
_ELF_OSABI = {0: '', 3: 'Linux', 6: 'Solaris', 9: 'FreeBSD', 12: 'OpenBSD'}
_MACHO_CPUS = {7: 'x86', 0x01000007: 'x86-64', 12: 'ARM', 0x0100000c: 'ARM64',
               0x0200000c: 'ARM64_32', 18: 'PowerPC', 0x01000012: 'PowerPC 64'}
_MACHO_TYPES = {1: 'object', 2: 'program', 3: 'fixed VM library',
                4: 'core dump', 5: 'preloaded program', 6: 'library',
                7: 'dynamic linker', 8: 'bundle', 9: 'library stub',
                10: 'debug symbols', 11: 'kernel extension', 12: 'fileset'}
_MACHO_PLATFORMS = {1: 'macOS', 2: 'iOS', 3: 'tvOS', 4: 'watchOS',
                    5: 'bridgeOS', 6: 'Mac Catalyst', 7: 'iOS simulator',
                    11: 'visionOS'}

#: Section names packers and protectors leave.
PACKER_SECTIONS = {
    'upx0': 'UPX', 'upx1': 'UPX', 'upx2': 'UPX', '.upx0': 'UPX',
    '.aspack': 'ASPack', '.adata': 'ASPack', '.mpress1': 'MPRESS',
    '.mpress2': 'MPRESS', '.petite': 'Petite', '.themida': 'Themida',
    '.winlice': 'WinLicense', '.vmp0': 'VMProtect', '.vmp1': 'VMProtect',
    '.vmp2': 'VMProtect', '.enigma1': 'Enigma', '.enigma2': 'Enigma',
    'pec1': 'PECompact', 'pec2': 'PECompact', '.pec': 'PECompact',
    '.nsp0': 'NsPack', '.nsp1': 'NsPack', 'mew': 'MEW', '.perplex': 'Perplex',
    '.yp': 'Y0da', '.packed': 'packer', 'fsg!': 'FSG', '.rlpack': 'RLPack',
    '.kkrunchy': 'kkrunchy', '.boom': 'The Boomerang', '.ccg': 'CCG',
}

#: Imports that, all together, write code into another process and run it.
INJECTION_SETS = (
    ('process injection', {'openprocess', 'virtualallocex',
                           'writeprocessmemory', 'createremotethread'}),
    ('process injection', {'openprocess', 'virtualallocex',
                           'writeprocessmemory', 'ntcreatethreadex'}),
    ('process hollowing', {'createprocessa', 'unmapviewofsection',
                           'writeprocessmemory', 'setthreadcontext'}),
    ('process hollowing', {'createprocessw', 'unmapviewofsection',
                           'writeprocessmemory', 'setthreadcontext'}),
    ('keystroke capture', {'setwindowshookexa', 'getasynckeystate'}),
    ('keystroke capture', {'setwindowshookexw', 'getasynckeystate'}),
)


class NotExecutable(ValueError):
    pass


def kind_of(head):
    """'pe', 'elf', 'macho', 'fat' or '' from a file's first bytes."""
    if head[:2] == b'MZ' and len(head) >= 0x40:
        return 'pe'
    if head[:4] == b'\x7fELF':
        return 'elf'
    if head[:4] in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                    b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe'):
        return 'macho'
    if head[:4] == b'\xca\xfe\xba\xbe' and len(head) >= 8:
        # Java class files share the magic; their next field is a version
        # (45 and up), a universal binary's is its count of architectures.
        if 0 < struct.unpack_from('>I', head, 4)[0] < 20:
            return 'fat'
    return ''


def entropy(data):
    """Bits per byte of (at most ENTROPY_SAMPLE of) `data`."""
    data = data[:ENTROPY_SAMPLE]
    if not data:
        return 0.0
    length = len(data)
    return -sum(c / length * math.log2(c / length)
                for c in collections.Counter(data).values())


def analyse(data):
    """Everything the headers say, as a dict; None when `data` is not an
    executable this reads, or too damaged to."""
    kind = kind_of(data[:64])
    try:
        if kind == 'pe':
            return _pe(data)
        if kind == 'elf':
            return _elf(data)
        if kind == 'macho':
            return _macho(data, 0, len(data))
        if kind == 'fat':
            return _fat(data)
    except (struct.error, NotExecutable, IndexError, ValueError):
        return None
    except Exception as exc:               # hostile headers: never fatal
        logger.debug("Executable not analysed: %r", exc)
        return None
    return None


def _utc(seconds):
    try:
        return datetime.fromtimestamp(seconds, timezone.utc).strftime(
            '%Y-%m-%d %H:%M:%S')
    except (OverflowError, OSError, ValueError):
        return None


def _cstring(data, offset, limit=1024, encoding='latin-1'):
    if offset < 0 or offset >= len(data):
        return ''
    end = data.find(b'\x00', offset, offset + limit)
    if end < 0:
        end = min(len(data), offset + limit)
    return data[offset:end].decode(encoding, 'replace')


def _rwx(read, write, execute):
    return ''.join((('r' if read else '-'), ('w' if write else '-'),
                    ('x' if execute else '-')))


# --- PE ----------------------------------------------------------------------------

class _Pe:
    def __init__(self, data):
        self.data = data
        self.pe = struct.unpack_from('<I', data, 0x3C)[0]
        if data[self.pe:self.pe + 4] != b'PE\x00\x00':
            raise NotExecutable('no PE header')
        (self.machine, self.count, self.stamp, _, _, self.optional_size,
         self.characteristics) = struct.unpack_from('<HHIIIHH', data,
                                                    self.pe + 4)
        self.opt = self.pe + 24
        self.magic = struct.unpack_from('<H', data, self.opt)[0]
        if self.magic not in (0x10b, 0x20b):
            raise NotExecutable('no optional header')
        self.plus = self.magic == 0x20b
        directories = self.opt + (112 if self.plus else 96)
        count = struct.unpack_from(
            '<I', data, self.opt + (108 if self.plus else 92))[0]
        self.dirs = []
        for index in range(min(count, 16)):
            if directories + index * 8 + 8 > self.opt + self.optional_size:
                break
            self.dirs.append(struct.unpack_from('<II', data,
                                                directories + index * 8))
        table = self.opt + self.optional_size
        self.sections = []
        for index in range(min(self.count, 96)):
            at = table + index * 40
            name = data[at:at + 8].rstrip(b'\x00').decode('latin-1', 'replace')
            vsize, vaddr, rsize, rptr = struct.unpack_from('<IIII', data,
                                                           at + 8)
            flags = struct.unpack_from('<I', data, at + 36)[0]
            self.sections.append((name, vsize, vaddr, rsize, rptr, flags))

    def directory(self, index):
        return self.dirs[index] if index < len(self.dirs) else (0, 0)

    def offset(self, rva):
        for _name, vsize, vaddr, rsize, rptr, _flags in self.sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                if rva - vaddr >= rsize:
                    return None
                return rptr + rva - vaddr
        # Headers are mapped as they are in the file.
        if self.sections and rva < self.sections[0][2]:
            return rva
        return None

    def u32(self, offset):
        return struct.unpack_from('<I', self.data, offset)[0]

    def string_at(self, rva, limit=512):
        offset = self.offset(rva)
        return _cstring(self.data, offset, limit) if offset is not None else ''

    def imports(self):
        rva, size = self.directory(1)
        offset = self.offset(rva) if rva else None
        out = []
        if offset is None:
            return out
        width = 8 if self.plus else 4
        ordinal_bit = 1 << (63 if self.plus else 31)
        total = 0
        for index in range(512):
            entry = offset + index * 20
            if entry + 20 > len(self.data):
                break
            lookup, _, _, name_rva, first = struct.unpack_from(
                '<IIIII', self.data, entry)
            if not (lookup or name_rva or first):
                break
            dll = self.string_at(name_rva, 256)
            functions = []
            thunk = self.offset(lookup or first)
            while thunk is not None and thunk + width <= len(self.data) \
                    and total < MAX_NAMES:
                value = struct.unpack_from('<Q' if self.plus else '<I',
                                           self.data, thunk)[0]
                if not value:
                    break
                if value & ordinal_bit:
                    functions.append(f'ordinal {value & 0xFFFF}')
                else:
                    name = self.string_at((value & 0x7FFFFFFF) + 2, 256)
                    if name:
                        functions.append(name)
                thunk += width
                total += 1
            out.append({'library': dll, 'functions': functions})
        return out

    def delay_imports(self):
        rva, _ = self.directory(13)
        offset = self.offset(rva) if rva else None
        names = []
        while offset is not None and offset + 32 <= len(self.data) and \
                len(names) < 256:
            attributes, name_rva = struct.unpack_from('<II', self.data,
                                                      offset)
            if not name_rva:
                break
            # Version 1 (attribute bit 0) holds RVAs; version 0, addresses.
            if not attributes & 1:
                name_rva -= self.image_base() & 0xFFFFFFFF
            names.append(self.string_at(name_rva, 256))
            offset += 32
        return [n for n in names if n]

    def image_base(self):
        return struct.unpack_from('<Q' if self.plus else '<I', self.data,
                                  self.opt + (24 if self.plus else 28))[0]

    def exports(self):
        rva, _ = self.directory(0)
        offset = self.offset(rva) if rva else None
        if offset is None or offset + 40 > len(self.data):
            return None
        name_rva = self.u32(offset + 12)
        count = self.u32(offset + 24)
        names_rva = self.u32(offset + 32)
        names = []
        table = self.offset(names_rva) if names_rva else None
        for index in range(min(count, MAX_NAMES)):
            if table is None or table + index * 4 + 4 > len(self.data):
                break
            names.append(self.string_at(self.u32(table + index * 4), 256))
        return {'name': self.string_at(name_rva, 256),
                'functions': self.u32(offset + 20), 'names': names}

    def resources(self, wanted_type):
        """(data offset, size) of every resource of one type."""
        rva, _ = self.directory(2)
        base = self.offset(rva) if rva else None
        out = []
        if base is None:
            return out

        def entries(at):
            named, ids = struct.unpack_from('<HH', self.data, at + 12)
            for index in range(min(named + ids, 4096)):
                yield struct.unpack_from('<II', self.data,
                                         at + 16 + index * 8)

        def leaves(at, depth):
            if depth > 3:
                return
            for _name, target in entries(at):
                if target & 0x80000000:
                    yield from leaves(base + (target & 0x7FFFFFFF), depth + 1)
                else:
                    yield base + target

        for ident, target in entries(base):
            if ident == wanted_type and target & 0x80000000:
                for leaf in leaves(base + (target & 0x7FFFFFFF), 1):
                    data_rva, size = struct.unpack_from('<II', self.data,
                                                        leaf)
                    offset = self.offset(data_rva)
                    if offset is not None:
                        out.append((offset, size))
        return out

    def version_info(self):
        for offset, size in self.resources(16):
            facts = _version_strings(self.data[offset:offset + size])
            if facts:
                return facts
        return {}

    def debug(self):
        rva, size = self.directory(6)
        offset = self.offset(rva) if rva else None
        facts = {}
        for index in range(min(size // 28, 32) if offset is not None else 0):
            entry = offset + index * 28
            kind, length, _address, pointer = struct.unpack_from(
                '<IIII', self.data, entry + 12)
            if kind == 2 and self.data[pointer:pointer + 4] == b'RSDS':
                guid = self.data[pointer + 4:pointer + 20]
                facts['pdb'] = _cstring(self.data, pointer + 24,
                                        min(length, 1024), 'utf-8')
                facts['pdb_guid'] = _guid(guid)
                facts['pdb_age'] = struct.unpack_from('<I', self.data,
                                                      pointer + 20)[0]
            elif kind == 2 and self.data[pointer:pointer + 4] == b'NB10':
                facts['pdb'] = _cstring(self.data, pointer + 16,
                                        min(length, 1024))
            elif kind == 16:
                facts['reproducible'] = True
        return facts

    def signature(self):
        offset, size = self.directory(4)        # a file offset, not an RVA
        if not offset or not size or offset + 8 > len(self.data):
            return None
        length, revision, kind = struct.unpack_from('<IHH', self.data, offset)
        facts = {'offset': offset, 'size': size,
                 'type': {2: 'Authenticode (PKCS #7)',
                          1: 'X.509'}.get(kind, f'type {kind}')}
        if kind == 2:
            facts.update(_pkcs7_signer(
                self.data[offset + 8:offset + min(length, size)]))
        return facts


def _guid(raw):
    a, b, c = struct.unpack_from('<IHH', raw)
    return f"{a:08X}-{b:04X}-{c:04X}-{raw[8:10].hex().upper()}-" \
           f"{raw[10:16].hex().upper()}"


def _version_strings(blob):
    """StringFileInfo values and the fixed file version from VS_VERSIONINFO."""
    facts = {}

    def node(at, end, depth):
        if at + 6 > end or depth > 4:
            return end
        length, value_length, kind = struct.unpack_from('<HHH', blob, at)
        if length < 6:
            return end
        stop = min(at + length, end)
        key_end = at + 6
        while key_end + 2 <= stop and blob[key_end:key_end + 2] != b'\x00\x00':
            key_end += 2
        key = blob[at + 6:key_end].decode('utf-16-le', 'replace')
        value_at = (key_end + 2 + 3) & ~3
        if kind == 1:
            raw = blob[value_at:value_at + value_length * 2]
            value = raw.decode('utf-16-le', 'replace').split('\x00', 1)[0]
            value_end = value_at + value_length * 2
        else:
            value = blob[value_at:value_at + value_length]
            value_end = value_at + value_length
        if key == 'VS_VERSION_INFO' and len(value) >= 52 and \
                struct.unpack_from('<I', value, 0)[0] == 0xFEEF04BD:
            ms, ls, pms, pls = struct.unpack_from('<IIII', value, 8)
            facts['file_version_fixed'] = \
                f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
            facts['product_version_fixed'] = \
                f"{pms >> 16}.{pms & 0xFFFF}.{pls >> 16}.{pls & 0xFFFF}"
        elif depth == 3 and kind == 1 and value.strip():
            facts.setdefault(key, value.strip())
        child = (value_end + 3) & ~3
        while child < stop:
            following = node(child, stop, depth + 1)
            if following <= child:
                break
            child = (following + 3) & ~3
        return stop

    try:
        node(0, len(blob), 0)
    except struct.error:
        pass
    return facts


# --- DER, just enough to name an Authenticode signer ------------------------------

def _der(data, at):
    """(tag, start of content, end of content) of the element at `at`."""
    tag = data[at]
    length = data[at + 1]
    at += 2
    if length & 0x80:
        count = length & 0x7F
        if not count or count > 4:
            raise ValueError('indefinite or huge length')
        length = int.from_bytes(data[at:at + count], 'big')
        at += count
    if at + length > len(data):
        raise ValueError('element runs past the data')
    return tag, at, at + length


def _children(data, start, end):
    at = start
    while at < end:
        tag, begin, stop = _der(data, at)
        yield tag, begin, stop, at
        at = stop


_NAME_OIDS = {bytes.fromhex('550403'): 'CN', bytes.fromhex('55040a'): 'O',
              bytes.fromhex('550406'): 'C'}


def _name(data, start, end):
    """{'CN': ..., 'O': ...} of an X.501 Name."""
    out = {}
    for _tag, set_start, set_end, _ in _children(data, start, end):
        for _t, seq_start, seq_end, _ in _children(data, set_start, set_end):
            parts = list(_children(data, seq_start, seq_end))
            if len(parts) == 2 and parts[0][0] == 0x06:
                label = _NAME_OIDS.get(data[parts[0][1]:parts[0][2]])
                if label:
                    tag, begin, stop, _ = parts[1]
                    raw = data[begin:stop]
                    out[label] = (raw.decode('utf-16-be', 'replace')
                                  if tag == 0x1E else
                                  raw.decode('utf-8', 'replace'))
    return out


def _certificate(data, start, end):
    """(serial, issuer, subject, not before, not after) of one X.509."""
    tbs = next(_children(data, start, end))
    fields = list(_children(data, tbs[1], tbs[2]))
    if fields and fields[0][0] == 0xA0:            # explicit version
        fields = fields[1:]
    serial = data[fields[0][1]:fields[0][2]]
    issuer = _name(data, fields[2][1], fields[2][2])
    validity = [data[b:e].decode('ascii', 'replace')
                for _t, b, e, _ in _children(data, fields[3][1],
                                             fields[3][2])]
    subject = _name(data, fields[4][1], fields[4][2])
    return serial, issuer, subject, validity


def _asn1_time(text):
    if len(text) == 13:                            # UTCTime YYMMDDHHMMSSZ
        year = int(text[:2])
        text = ('19' if year >= 50 else '20') + text
    if len(text) < 14:
        return text
    return f"{text[:4]}-{text[4:6]}-{text[6:8]} {text[8:10]}:{text[10:12]}:" \
           f"{text[12:14]}"


def _pkcs7_signer(blob):
    """Who signed (as the signature says -- nothing is verified here)."""
    try:
        _tag, start, end = _der(blob, 0)                    # ContentInfo
        parts = list(_children(blob, start, end))
        _t, start, end, _ = parts[1]                        # [0] explicit
        _tag, start, end = _der(blob, start)                # SignedData
        fields = list(_children(blob, start, end))
        certificates = {}
        signer_serial = None
        for tag, begin, stop, _ in fields:
            if tag == 0xA0:                                 # certificates
                for ctag, cbegin, cstop, _ in _children(blob, begin, stop):
                    if ctag == 0x30:
                        serial, issuer, subject, validity = _certificate(
                            blob, cbegin, cstop)
                        certificates[serial] = (issuer, subject, validity)
            elif tag == 0x31:                               # signerInfos
                for _st, sbegin, sstop, _ in _children(blob, begin, stop):
                    info = list(_children(blob, sbegin, sstop))
                    if len(info) > 1 and info[1][0] == 0x30:
                        ias = list(_children(blob, info[1][1], info[1][2]))
                        signer_serial = blob[ias[1][1]:ias[1][2]]
                    break
        if signer_serial not in certificates:
            return {'certificates': len(certificates)}
        issuer, subject, validity = certificates[signer_serial]
        return {'signer': subject.get('CN') or subject.get('O') or '',
                'signer_organisation': subject.get('O', ''),
                'issuer': issuer.get('CN') or issuer.get('O') or '',
                'valid_from': _asn1_time(validity[0]) if validity else '',
                'valid_to': _asn1_time(validity[1]) if len(validity) > 1
                else '',
                'certificates': len(certificates)}
    except (ValueError, IndexError, StopIteration):
        return {}


def _pe(data):
    pe = _Pe(data)
    machine = _PE_MACHINES.get(pe.machine, f'machine {pe.machine:#x}')
    subsystem = struct.unpack_from('<H', data, pe.opt + 68)[0]
    dll = bool(pe.characteristics & 0x2000)
    clr = pe.directory(14)[0] != 0
    if subsystem == 1:
        kind = 'driver'
    elif dll:
        kind = 'library'
    elif subsystem in (10, 11, 12, 13):
        kind = 'EFI image'
    else:
        kind = 'program'
    debug = pe.debug()
    facts = {
        'format': ('PE32+' if pe.plus else 'PE32') + (' .NET' if clr else ''),
        'architecture': machine,
        'kind': kind,
        'subsystem': _PE_SUBSYSTEMS.get(subsystem, f'subsystem {subsystem}'),
        'linker': f"{data[pe.opt + 2]}.{data[pe.opt + 3]}",
        'entry_point': f"{struct.unpack_from('<I', data, pe.opt + 16)[0]:#x}",
        'image_base': f"{pe.image_base():#x}",
    }
    if debug.pop('reproducible', False):
        facts['compiled'] = None
        facts['compiled_note'] = (f"reproducible build: {pe.stamp:#010x} is "
                                  f"a hash of the contents, not a time")
    else:
        facts['compiled'] = _utc(pe.stamp) if pe.stamp else None
        if not pe.stamp:
            facts['compiled_note'] = 'no time recorded'
    facts.update(debug)
    characteristics = struct.unpack_from('<H', data, pe.opt + 70)[0]
    facts['protections'] = [label for bit, label in (
        (0x0040, 'ASLR'), (0x0100, 'DEP'), (0x4000, 'CFG'),
        (0x0400, 'no SEH'), (0x0020, 'high-entropy ASLR'))
        if characteristics & bit]
    sections = []
    end = 0
    for name, vsize, vaddr, rsize, rptr, flags in pe.sections:
        body = data[rptr:rptr + rsize] if rsize else b''
        if rsize:
            end = max(end, rptr + rsize)
        sections.append({
            'name': name, 'virtual_size': vsize, 'raw_size': rsize,
            'offset': rptr,
            'flags': _rwx(flags & 0x40000000, flags & 0x80000000,
                            flags & 0x20000000),
            'code': bool(flags & 0x20 or flags & 0x20000000),
            'entropy': round(entropy(body), 3)})
    facts['sections'] = sections
    imports = pe.imports()
    facts['imports'] = imports
    facts['delay_imports'] = pe.delay_imports()
    exports = pe.exports()
    if exports:
        facts['exports'] = exports
    version = pe.version_info()
    if version:
        facts['version'] = version
    signature = pe.signature()
    if signature:
        facts['signature'] = signature
    # Appended data: past the last section, apart from the signature
    # (which the PE format itself puts at the end).
    tail = len(data)
    if signature and signature['offset'] >= end and \
            signature['offset'] + signature['size'] >= len(data):
        tail = signature['offset']
    elif signature and signature['offset'] >= end:
        end = max(end, signature['offset'] + signature['size'])
    header_end = pe.opt + pe.optional_size + 40 * pe.count
    end = max(end, header_end)
    if tail > end:
        facts['overlay'] = {'offset': end, 'size': tail - end,
                            'entropy': round(entropy(data[end:tail]), 3),
                            'starts': _what_starts(data[end:end + 16])}
    stored = struct.unpack_from('<I', data, pe.opt + 64)[0]
    if stored:
        from trace_app.core.carve_verify import pe_checksum
        computed = pe_checksum(data, pe.opt + 64)
        facts['checksum'] = {'stored': f'{stored:#010x}',
                             'computed': f'{computed:#010x}',
                             'matches': computed == stored}
    return facts


def _what_starts(head):
    for magic, label in ((b'PK\x03\x04', 'ZIP'), (b'7z\xbc\xaf', '7z'),
                         (b'Rar!', 'RAR'), (b'MZ', 'executable'),
                         (b'MSCF', 'cabinet'), (b'\x1f\x8b', 'gzip'),
                         (b'%PDF', 'PDF'), (b'NullsoftInst', 'NSIS'),
                         (b'\xef\xbe\xad\xdeNullsoft', 'NSIS'),
                         (b'Inno Setup', 'Inno Setup'),
                         (b'\xd0\xcf\x11\xe0', 'OLE (MSI)')):
        if head.startswith(magic) or magic in head:
            return label
    return ''


# --- ELF ---------------------------------------------------------------------------

def _elf(data):
    if len(data) < 52:
        raise NotExecutable('short')
    bits = {1: 32, 2: 64}.get(data[4])
    order = {1: '<', 2: '>'}.get(data[5])
    if bits is None or order is None:
        raise NotExecutable('bad ident')
    if bits == 64:
        (etype, machine, _version, entry, phoff, shoff, _flags, _ehsize,
         phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from(
            order + 'HHIQQQIHHHHHH', data, 16)
    else:
        (etype, machine, _version, entry, phoff, shoff, _flags, _ehsize,
         phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from(
            order + 'HHIIIIIHHHHHH', data, 16)

    segments = []
    interpreter = None
    for index in range(min(phnum, 256)):
        at = phoff + index * phentsize
        if at + phentsize > len(data):
            break
        if bits == 64:
            ptype, pflags, offset, _va, _pa, filesz = struct.unpack_from(
                order + 'IIQQQQ', data, at)
        else:
            ptype, offset, _va, _pa, filesz, _memsz, pflags = \
                struct.unpack_from(order + 'IIIIIII', data, at)
        segments.append((ptype, pflags, offset, filesz))
        if ptype == 3:
            interpreter = _cstring(data, offset, filesz)

    sections = []
    raw_sections = []
    for index in range(min(shnum, 1024)):
        at = shoff + index * shentsize
        if not shoff or at + shentsize > len(data):
            break
        if bits == 64:
            name, stype, flags, _addr, offset, size, link, _info = \
                struct.unpack_from(order + 'IIQQQQII', data, at)
        else:
            name, stype, flags, _addr, offset, size, link, _info = \
                struct.unpack_from(order + 'IIIIIIII', data, at)
        raw_sections.append((name, stype, flags, offset, size, link))
    names_at = raw_sections[shstrndx][3] if shstrndx < len(raw_sections) \
        else None
    end = max(phoff + phentsize * phnum, shoff + shentsize * shnum)
    by_name = {}
    for name, stype, flags, offset, size, link in raw_sections:
        label = _cstring(data, names_at + name, 256) if names_at else ''
        on_disk = stype != 8 and stype != 0        # NOBITS, NULL
        if on_disk:
            end = max(end, offset + size)
        by_name.setdefault(label, (stype, offset, size, link))
        if stype == 0:
            continue
        body = data[offset:offset + size] if on_disk else b''
        sections.append({'name': label, 'raw_size': size if on_disk else 0,
                         'virtual_size': size, 'offset': offset,
                         'flags': _rwx(flags & 2, flags & 1, flags & 4),
                         'code': bool(flags & 4),
                         'entropy': round(entropy(body), 3)})
    for _ptype, _pflags, offset, filesz in segments:
        end = max(end, offset + filesz)

    if etype == 3:
        kind = 'program (position-independent)' if interpreter else \
            'shared object'
    else:
        kind = _ELF_TYPES.get(etype, f'type {etype}')
    facts = {'format': f'ELF{bits}' + (' big-endian' if order == '>' else ''),
             'architecture': _ELF_MACHINES.get(machine,
                                               f'machine {machine}'),
             'kind': kind, 'entry_point': f'{entry:#x}',
             'sections': sections,
             'linking': 'dynamic' if interpreter or 'dynamic' in
             {s['name'].lstrip('.') for s in sections} else 'static'}
    osabi = _ELF_OSABI.get(data[7], f'OS ABI {data[7]}')
    if osabi:
        facts['os'] = osabi
    if interpreter:
        facts['interpreter'] = interpreter

    # Libraries (DT_NEEDED, DT_SONAME) from .dynamic and its string table.
    dynamic = by_name.get('.dynamic')
    if dynamic and dynamic[3] < len(raw_sections):
        strings_at = raw_sections[dynamic[3]][3]
        entry_size = 16 if bits == 64 else 8
        libraries, rpath = [], []
        for at in range(dynamic[1], dynamic[1] + dynamic[2], entry_size):
            if at + entry_size > len(data):
                break
            tag, value = struct.unpack_from(
                order + ('qQ' if bits == 64 else 'iI'), data, at)
            if tag == 0:
                break
            if tag == 1:
                libraries.append(_cstring(data, strings_at + value, 256))
            elif tag == 14:
                facts['soname'] = _cstring(data, strings_at + value, 256)
            elif tag in (15, 29):
                rpath.append(_cstring(data, strings_at + value, 1024))
        facts['imports'] = [{'library': lib, 'functions': []}
                            for lib in libraries]
        if rpath:
            facts['rpath'] = rpath
    # Imported and exported functions from .dynsym.
    dynsym = by_name.get('.dynsym')
    if dynsym and dynsym[3] < len(raw_sections):
        strings_at = raw_sections[dynsym[3]][3]
        entry_size = 24 if bits == 64 else 16
        imported, exported = [], []
        for at in range(dynsym[1] + entry_size, dynsym[1] + dynsym[2],
                        entry_size):
            if at + entry_size > len(data) or \
                    len(imported) + len(exported) >= MAX_NAMES:
                break
            if bits == 64:
                name, info, _other, shndx = struct.unpack_from(
                    order + 'IBBH', data, at)
            else:
                name, _value, _size, info, _other, shndx = \
                    struct.unpack_from(order + 'IIIBBH', data, at)
            label = _cstring(data, strings_at + name, 256)
            if not label or (info & 0xF) not in (0, 1, 2):
                continue
            (imported if shndx == 0 else exported).append(label)
        if imported:
            facts.setdefault('imports', []).append(
                {'library': '(dynamic symbols)', 'functions': imported})
        if exported:
            facts['exports'] = {'name': facts.get('soname', ''),
                                'functions': len(exported),
                                'names': exported}
    note = by_name.get('.note.gnu.build-id')
    if note:
        namesz, descsz = struct.unpack_from(order + 'II', data, note[1])
        start = note[1] + 12 + ((namesz + 3) & ~3)
        facts['build_id'] = data[start:start + descsz].hex()
    comment = by_name.get('.comment')
    if comment:
        compilers = [c.decode('utf-8', 'replace') for c in
                     data[comment[1]:comment[1] + min(comment[2], 4096)]
                     .split(b'\x00') if c.strip()]
        if compilers:
            facts['compiler'] = list(dict.fromkeys(compilers))[:4]
    if b'UPX!' in data[:4096] or b'UPX!' in data[-4096:]:
        facts['packer'] = 'UPX'
    if len(data) > end:
        facts['overlay'] = {'offset': end, 'size': len(data) - end,
                            'entropy': round(entropy(data[end:]), 3),
                            'starts': _what_starts(data[end:end + 16])}
    return facts


# --- Mach-O ------------------------------------------------------------------------

def _fat(data):
    count = struct.unpack_from('>I', data, 4)[0]
    slices = []
    for index in range(count):
        cpu, _sub, offset, size, _align = struct.unpack_from(
            '>iiIII', data, 8 + index * 20)
        slices.append((cpu & 0xFFFFFFFF, offset, size))
    if not slices:
        raise NotExecutable('empty universal binary')
    first = _macho(data, slices[0][1], slices[0][1] + slices[0][2])
    first['format'] = 'Mach-O universal'
    first['architectures'] = [_MACHO_CPUS.get(cpu, f'CPU {cpu:#x}')
                              for cpu, _o, _s in slices]
    first['architecture'] = ', '.join(first['architectures'])
    end = max(offset + size for _c, offset, size in slices)
    if len(data) > end:
        first['overlay'] = {'offset': end, 'size': len(data) - end,
                            'entropy': round(entropy(data[end:]), 3),
                            'starts': _what_starts(data[end:end + 16])}
    else:
        first.pop('overlay', None)
    return first


def _macho(data, base, limit):
    magic = data[base:base + 4]
    order = '<' if magic in (b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe') \
        else '>'
    bits = 64 if magic in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf') else 32
    cpu, _sub, filetype, ncmds, _sizeofcmds, flags = struct.unpack_from(
        order + 'iiIIII', data, base + 4)
    cpu &= 0xFFFFFFFF
    at = base + (32 if bits == 64 else 28)
    facts = {'format': f'Mach-O {bits}-bit',
             'architecture': _MACHO_CPUS.get(cpu, f'CPU {cpu:#x}'),
             'kind': _MACHO_TYPES.get(filetype, f'type {filetype}'),
             'sections': [], 'imports': []}
    if flags & 0x200000:
        facts['protections'] = ['PIE']
    end = at
    for _ in range(min(ncmds, 4096)):
        if at + 8 > limit:
            break
        command, size = struct.unpack_from(order + 'II', data, at)
        if size < 8:
            break
        if command in (0x1, 0x19):                     # LC_SEGMENT(_64)
            wide = command == 0x19
            segname = _cstring(data, at + 8, 16)
            if wide:
                _vm, _vmsize, fileoff, filesize, maxprot, initprot, nsects, \
                    _f = struct.unpack_from(order + 'QQQQiiII', data, at + 24)
                header = at + 72
            else:
                _vm, _vmsize, fileoff, filesize, maxprot, initprot, nsects, \
                    _f = struct.unpack_from(order + 'IIIIiiII', data, at + 24)
                header = at + 56
            end = max(end, base + fileoff + filesize)
            for index in range(min(nsects, 256)):
                sat = header + index * (80 if wide else 68)
                sectname = _cstring(data, sat, 16)
                if wide:
                    _a, ssize, soffset = struct.unpack_from(order + 'QQI',
                                                            data, sat + 32)
                else:
                    _a, ssize, soffset = struct.unpack_from(order + 'III',
                                                            data, sat + 32)
                sflags = struct.unpack_from(order + 'I', data,
                                            sat + (64 if wide else 56))[0]
                zerofill = (sflags & 0xFF) in (1, 0xC, 0x12)
                body = b'' if zerofill or not soffset else \
                    data[base + soffset:base + soffset + ssize]
                facts['sections'].append({
                    'name': f'{segname},{sectname}', 'virtual_size': ssize,
                    'raw_size': 0 if zerofill else ssize,
                    'offset': soffset,
                    'flags': _rwx(initprot & 1, initprot & 2, initprot & 4),
                    'code': bool(sflags & 0x80000400),
                    'entropy': round(entropy(body), 3)})
            if maxprot & 2 and maxprot & 4 and initprot & 2 and initprot & 4:
                facts.setdefault('wx_segments', []).append(segname)
        elif command in (0xC, 0x80000018, 0x8000001F, 0x80000023):
            name_offset = struct.unpack_from(order + 'I', data, at + 8)[0]
            facts['imports'].append({
                'library': _cstring(data, at + name_offset,
                                    size - name_offset),
                'functions': [],
                'weak': command == 0x80000018})
        elif command == 0xD:                           # LC_ID_DYLIB
            name_offset = struct.unpack_from(order + 'I', data, at + 8)[0]
            facts['install_name'] = _cstring(data, at + name_offset,
                                             size - name_offset)
        elif command == 0x1B:                          # LC_UUID
            raw = data[at + 8:at + 24]
            facts['uuid'] = _guid_be(raw)
        elif command == 0x32:                          # LC_BUILD_VERSION
            platform, minos, sdk = struct.unpack_from(order + 'III', data,
                                                      at + 8)
            facts['platform'] = _MACHO_PLATFORMS.get(platform,
                                                     f'platform {platform}')
            facts['minimum_os'] = _xyz(minos)
            facts['sdk'] = _xyz(sdk)
        elif command in (0x24, 0x25, 0x2F, 0x30):      # LC_VERSION_MIN_*
            version, sdk = struct.unpack_from(order + 'II', data, at + 8)
            facts['platform'] = {0x24: 'macOS', 0x25: 'iOS', 0x2F: 'tvOS',
                                 0x30: 'watchOS'}[command]
            facts['minimum_os'] = _xyz(version)
            facts['sdk'] = _xyz(sdk)
        elif command == 0x1D:                          # LC_CODE_SIGNATURE
            offset, sigsize = struct.unpack_from(order + 'II', data, at + 8)
            facts['signature'] = dict(
                {'offset': offset, 'size': sigsize, 'type': 'code signature'},
                **_code_signature(data[base + offset:
                                       base + offset + sigsize]))
            end = max(end, base + offset + sigsize)
        elif command == 0x80000028:                    # LC_MAIN
            facts['entry_point'] = \
                f"{struct.unpack_from(order + 'Q', data, at + 8)[0]:#x}"
        elif command == 0x21 or command == 0x2C:      # encryption info
            cryptid = struct.unpack_from(order + 'I', data, at + 16)[0]
            if cryptid:
                facts['encrypted'] = True
        at += size
    if limit > end and base == 0:
        facts['overlay'] = {'offset': end, 'size': limit - end,
                            'entropy': round(entropy(data[end:limit]), 3),
                            'starts': _what_starts(data[end:end + 16])}
    return facts


def _xyz(value):
    return f"{value >> 16}.{(value >> 8) & 0xFF}.{value & 0xFF}"


def _guid_be(raw):
    text = raw.hex().upper()
    return f"{text[:8]}-{text[8:12]}-{text[12:16]}-{text[16:20]}-{text[20:]}"


def _code_signature(blob):
    """Identifier, team and whether ad hoc, from an embedded signature."""
    facts = {}
    try:
        magic, _length, count = struct.unpack_from('>III', blob, 0)
        if magic != 0xFADE0CC0:
            return facts
        for index in range(min(count, 64)):
            slot, offset = struct.unpack_from('>II', blob, 12 + index * 8)
            kind = struct.unpack_from('>I', blob, offset)[0]
            if kind == 0xFADE0C02 and 'identifier' not in facts:
                version, flags = struct.unpack_from('>II', blob, offset + 8)
                ident = struct.unpack_from('>I', blob, offset + 20)[0]
                facts['identifier'] = _cstring(blob, offset + ident, 256)
                facts['ad_hoc'] = bool(flags & 0x2)
                if version >= 0x20200:
                    team = struct.unpack_from('>I', blob, offset + 48)[0]
                    if team:
                        facts['team'] = _cstring(blob, offset + team, 64)
            elif kind == 0xFADE0B01:                   # CMS wrapper
                cms = blob[offset + 8:offset +
                           struct.unpack_from('>I', blob, offset + 4)[0]]
                if cms:
                    signer = _pkcs7_signer(cms)
                    if signer.get('signer'):
                        facts['signer'] = signer['signer']
                        facts['issuer'] = signer.get('issuer', '')
    except struct.error:
        pass
    return facts


# --- what is worth attention -------------------------------------------------------

def all_functions(facts):
    return {f.lower() for entry in facts.get('imports') or []
            for f in entry.get('functions') or []}


def _base(name):
    return name.lower().rsplit('/', 1)[-1].rsplit('\\', 1)[-1]


def indicators(facts, name=''):
    """[(grade, text)] -- 'suspicious' or 'notable' -- for one analysis."""
    out = []
    packers = sorted({PACKER_SECTIONS[s['name'].lower()]
                      for s in facts.get('sections') or []
                      if s['name'].lower() in PACKER_SECTIONS})
    if facts.get('packer'):
        packers = sorted(set(packers) | {facts['packer']})
    if packers:
        out.append(('notable', f"Packed with {', '.join(packers)}"))
    writable_code = [s['name'] for s in facts.get('sections') or []
                     if s['flags'] == 'rwx' or s['flags'] == '-wx']
    writable_code += facts.get('wx_segments') or []
    if writable_code:
        out.append(('notable', "Writable and executable: "
                    + ', '.join(n or '(unnamed)' for n in writable_code)))
    random_code = [s['name'] for s in facts.get('sections') or []
                   if s['code'] and s['raw_size'] >= 1024
                   and s['entropy'] >= PACKED_ENTROPY]
    if random_code and not packers:
        out.append(('notable', "Code that is near-random (packed or "
                    "encrypted): " + ', '.join(n or '(unnamed)'
                                               for n in random_code)))
    functions = all_functions(facts)
    seen = set()
    for label, wanted in INJECTION_SETS:
        if label not in seen and all(
                any(f.endswith(w) or f.rstrip('aw') == w.rstrip('aw')
                    for f in functions) for w in wanted):
            seen.add(label)
            out.append(('suspicious' if label != 'keystroke capture'
                        else 'notable',
                        f"Imports used together for {label}: "
                        + ', '.join(sorted(wanted))))
    version = facts.get('version') or {}
    original = version.get('OriginalFilename') or ''
    if name and original:
        mine, theirs = _base(name), _base(original)
        for suffix in ('.mui', '.mun'):
            theirs = theirs.removesuffix(suffix)
            mine = mine.removesuffix(suffix)
        if theirs and mine != theirs and \
                mine.rsplit('.', 1)[0] != theirs.rsplit('.', 1)[0]:
            out.append(('notable', f"Calls itself {original}"))
    checksum = facts.get('checksum')
    if checksum and not checksum['matches'] and facts.get('kind') == 'driver':
        out.append(('notable', "Driver whose PE checksum does not match "
                    "(altered after linking)"))
    if facts.get('encrypted'):
        out.append(('notable', "Encrypted (App Store protection)"))
    return out


def summary(facts):
    """One line: format, architecture, kind, time, signer."""
    parts = [facts.get('format', ''), facts.get('architecture', ''),
             facts.get('kind', '')]
    text = ' '.join(p for p in parts if p)
    if facts.get('compiled'):
        text += f", linked {facts['compiled']}"
    signer = signed_by(facts)
    if signer is not None:
        text += f", signed{' ' + signer if signer else ''} (not verified)"
    elif not facts.get('format', '').startswith('ELF'):
        text += ", unsigned"            # ELF has no signature to look for
    return text


def signed_by(facts):
    """'by <name>', 'ad hoc', '' (signed, signer unread) or None
    (unsigned)."""
    signature = facts.get('signature')
    if not signature:
        return None
    who = signature.get('signer') or signature.get('team')
    if who:
        return f"by {who}"
    return 'ad hoc' if signature.get('ad_hoc') else ''


def digest(facts, flags):
    """What a finding stores: everything but the long lists, which are
    cut to their libraries and counts."""
    kept = {k: v for k, v in facts.items()
            if k not in ('imports', 'exports', 'sections')}
    kept['sections'] = [{k: s[k] for k in ('name', 'raw_size', 'flags',
                                           'entropy')}
                        for s in facts.get('sections') or []][:64]
    kept['libraries'] = [entry['library'] for entry in
                         facts.get('imports') or []
                         if entry['library'] != '(dynamic symbols)'][:200]
    kept['imported_functions'] = len(all_functions(facts))
    exports = facts.get('exports')
    if exports:
        kept['exports'] = {'name': exports.get('name', ''),
                           'functions': exports.get('functions', 0)}
    kept['indicators'] = [{'grade': g, 'text': t} for g, t in flags]
    kept['signed'] = signed_by(facts)
    return kept
