"""Live disks, read-only: listing them, and reading them through a
privileged helper (no Qt).

Reading a physical disk needs administrator rights on every platform, and a
GUI should not run as root (Wayland refuses it, macOS discourages it, and a
privileged GUI is a large attack surface). So TRACE stays unprivileged and
starts a small helper -- this module, run as `--live-reader` -- with the
platform's own prompt: UAC on Windows, pkexec (polkit) on Linux, the
administrator dialog (osascript) on macOS. The helper opens the one device
read-only, connects back to TRACE on 127.0.0.1, proves itself with a random
token, and answers read requests until TRACE closes the connection. It
never writes, and can only read the device it was started for.

Listing needs no privilege: Windows asks each \\\\.\\PhysicalDriveN for its
size and model (DeviceIoControl with no access rights), Linux reads
/sys/block, macOS asks `diskutil` (part of the system, not Homebrew).

A live disk is not an image: if it is mounted and in use it changes while
it is read, and TRACE does not stop the operating system writing to it.
Its hashes are what was read, when -- never "verified". For evidence, use a
hardware write blocker and image the disk.

The protocol, both ways little-endian: the helper sends 32 token bytes, an
8-byte size and a status line; then each request is (offset u64, length
u32), each reply (length u32, data) -- length 0xFFFFFFFF followed by a u32
and an error message when the read fails.
"""

import logging
import os
import secrets
import socket
import struct
import subprocess
import sys
import threading

logger = logging.getLogger('TRACE.LiveDisk')

#: Largest single read the helper serves.
MAX_READ = 16 * 1024 * 1024
#: How long TRACE waits for the helper (the prompt) before giving up.
CONNECT_TIMEOUT = 120
#: How long one read may take before the disk counts as stalled: an error
#: then, never a window waiting forever on a disk that stopped answering.
READ_TIMEOUT = 60
#: Reads are fetched in aligned blocks and the most recent kept: The Sleuth
#: Kit reads a file system in many small pieces, and each request is a
#: round trip to the helper. Large reads (hashing) bypass the cache.
CACHE_BLOCK = 256 * 1024
CACHE_BLOCKS = 256                   # 64 MB
CACHE_BYPASS = 4 * 1024 * 1024
_FAILED = 0xFFFFFFFF


class LiveDiskError(Exception):
    """A live disk could not be listed, opened or read."""


# --- recognising a device path -------------------------------------------------------

def is_device_path(path):
    """Whether `path` names a physical disk rather than an image file."""
    if not path:
        return False
    lowered = str(path).lower()
    if sys.platform == 'win32':
        return lowered.startswith('\\\\.\\physicaldrive')
    return lowered.startswith('/dev/')


# --- listing ----------------------------------------------------------------------

def list_disks():
    """[{'path', 'name', 'size', 'model', 'removable', 'system', 'detail'}]
    -- the physical disks this machine has, without opening any for data."""
    try:
        if sys.platform == 'win32':
            return _windows_disks()
        if sys.platform == 'darwin':
            return _mac_disks()
        return _linux_disks()
    except Exception as exc:
        logger.warning("Disks not listed: %s", exc)
        return []


def _windows_disks():
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD,
                                   wintypes.DWORD, wintypes.LPVOID,
                                   wintypes.DWORD, wintypes.DWORD,
                                   wintypes.HANDLE)
    kernel.DeviceIoControl.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID)
    invalid = wintypes.HANDLE(-1).value
    # IOCTL_DISK_GET_DRIVE_GEOMETRY_EX needs no access rights (the length
    # IOCTL needs read access): DISK_GEOMETRY (24 bytes), then the size.
    get_geometry = 0x000700A0
    query_property = 0x002D1400             # IOCTL_STORAGE_QUERY_PROPERTY
    system_drive = os.environ.get('SystemDrive', 'C:')
    system_disk = _windows_disk_of(system_drive, kernel)
    out = []
    for number in range(32):
        path = f'\\\\.\\PhysicalDrive{number}'
        # No access rights asked for: sizes and descriptions need none, so
        # listing works without elevation.
        handle = kernel.CreateFileW(path, 0, 3, None, 3, 0, None)
        if handle in (None, invalid):
            continue
        try:
            geometry = ctypes.create_string_buffer(256)
            returned = wintypes.DWORD(0)
            size = None
            if kernel.DeviceIoControl(handle, get_geometry, None, 0,
                                      geometry, 256,
                                      ctypes.byref(returned), None):
                size = struct.unpack_from('<q', geometry.raw, 24)[0]
            model, bus, removable = '', '', False
            query = struct.pack('<II4s', 0, 0, b'\0' * 4)   # device property
            buffer = ctypes.create_string_buffer(1024)
            if kernel.DeviceIoControl(handle, query_property, query,
                                      len(query), buffer, 1024,
                                      ctypes.byref(returned), None):
                raw = buffer.raw
                removable = bool(raw[10])
                vendor_at, product_at = struct.unpack_from('<II', raw, 12)
                bus_type = struct.unpack_from('<I', raw, 28)[0]
                model = ' '.join(_c_string(raw, at) for at in
                                 (vendor_at, product_at) if at).strip()
                bus = {7: 'USB', 11: 'SATA', 17: 'NVMe', 3: 'ATA',
                       1: 'SCSI', 8: 'RAID', 12: 'SD', 13: 'MMC',
                       14: 'Virtual'}.get(bus_type, '')
            out.append({'path': path, 'name': f'Disk {number}',
                        'size': size, 'model': model, 'removable': removable,
                        'system': number == system_disk,
                        'detail': bus})
        finally:
            kernel.CloseHandle(handle)
    return out


def _c_string(raw, at):
    end = raw.find(b'\0', at)
    return raw[at:end if end >= 0 else None].decode('ascii', 'replace') \
        .strip()


def _windows_disk_of(drive, kernel):
    """The disk number holding a drive letter (the system disk), or None."""
    import ctypes
    from ctypes import wintypes
    handle = kernel.CreateFileW(f'\\\\.\\{drive.rstrip(chr(92))}', 0, 3,
                                None, 3, 0, None)
    if handle in (None, wintypes.HANDLE(-1).value):
        return None
    try:
        buffer = ctypes.create_string_buffer(64)
        returned = wintypes.DWORD(0)
        # IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: the first extent's disk.
        if kernel.DeviceIoControl(handle, 0x00560000, None, 0, buffer, 64,
                                  ctypes.byref(returned), None):
            count, _pad, disk = struct.unpack_from('<III', buffer.raw, 0)
            return disk if count else None
    finally:
        kernel.CloseHandle(handle)
    return None


def _linux_disks():
    out = []
    root = '/sys/block'
    mounted = _linux_mounted_disks()
    for name in sorted(os.listdir(root)):
        if name.startswith(('loop', 'ram', 'zram', 'dm-', 'md', 'sr',
                            'fd')):
            continue
        base = os.path.join(root, name)

        def read(relative, default=''):
            try:
                with open(os.path.join(base, relative)) as handle:
                    return handle.read().strip()
            except OSError:
                return default
        try:
            size = int(read('size', '0')) * 512
        except ValueError:
            size = None
        model = ' '.join(filter(None, (read('device/vendor'),
                                       read('device/model'))))
        out.append({'path': f'/dev/{name}', 'name': name, 'size': size,
                    'model': model, 'removable': read('removable') == '1',
                    'system': name in mounted.get('/', set()),
                    'detail': 'NVMe' if name.startswith('nvme') else ''})
    return out


def _linux_mounted_disks():
    """{mount point: {disk names}} -- to mark the disk holding '/'."""
    out = {}
    try:
        with open('/proc/mounts') as handle:
            for line in handle:
                device, point = line.split()[:2]
                if device.startswith('/dev/'):
                    disk = os.path.basename(os.path.realpath(device))
                    stem = disk.rstrip('0123456789')
                    if stem.endswith('p') and stem[:-1].rstrip(
                            '0123456789') != stem[:-1]:
                        stem = stem[:-1]          # nvme0n1p2 -> nvme0n1
                    out.setdefault(point, set()).update({disk, stem})
    except OSError:
        pass
    return out


def _mac_disks():
    import plistlib
    listing = plistlib.loads(subprocess.run(
        ['diskutil', 'list', '-plist', 'physical'], capture_output=True,
        check=True, timeout=30).stdout)
    out = []
    for name in listing.get('WholeDisks', []):
        try:
            info = plistlib.loads(subprocess.run(
                ['diskutil', 'info', '-plist', name], capture_output=True,
                check=True, timeout=30).stdout)
        except Exception:
            info = {}
        out.append({
            'path': f'/dev/r{name}', 'name': name,
            'size': info.get('TotalSize') or info.get('Size'),
            'model': info.get('MediaName', ''),
            'removable': bool(info.get('Removable') or
                              info.get('RemovableMedia')),
            'system': bool(info.get('Internal')) and name == 'disk0',
            'detail': info.get('BusProtocol', '')})
    return out


# --- the helper (runs elevated) ---------------------------------------------------------

def _device_size(handle, path):
    try:
        size = os.lseek(handle, 0, os.SEEK_END)
        if size > 0:
            return size
    except OSError:
        pass
    if sys.platform == 'win32':
        import ctypes
        import msvcrt
        from ctypes import wintypes
        length = ctypes.c_longlong(0)
        returned = wintypes.DWORD(0)
        if ctypes.windll.kernel32.DeviceIoControl(
                wintypes.HANDLE(msvcrt.get_osfhandle(handle)), 0x0007405C,
                None, 0, ctypes.byref(length), 8, ctypes.byref(returned),
                None):
            return length.value
    if sys.platform == 'darwin':
        import fcntl
        block_size = struct.unpack('<I', fcntl.ioctl(
            handle, 0x40046418, b'\0' * 4))[0]          # DKIOCGETBLOCKSIZE
        blocks = struct.unpack('<Q', fcntl.ioctl(
            handle, 0x40086419, b'\0' * 8))[0]          # DKIOCGETBLOCKCOUNT
        return block_size * blocks
    raise LiveDiskError(f"The size of {path} could not be read")


class _AlignedReader:
    """Reads a raw device in whole sectors (Windows and macOS refuse
    unaligned reads on a raw disk)."""

    SECTOR = 4096

    def __init__(self, handle, size):
        self.handle, self.size = handle, size

    def read(self, offset, length):
        length = min(length, self.size - offset)
        if length <= 0:
            return b''
        start = offset - offset % self.SECTOR
        end = offset + length
        # Whole sectors, but never past the end: a device's size is whole
        # 512-byte sectors, not always whole 4 KB ones.
        end = min(end + (-end) % self.SECTOR, self.size)
        os.lseek(self.handle, start, os.SEEK_SET)
        data = bytearray()
        while len(data) < end - start:
            piece = os.read(self.handle, end - start - len(data))
            if not piece:
                break
            data += piece
        return bytes(data[offset - start:offset - start + length])


def serve(device, port, token_hex):
    """The helper: open `device` read-only, connect to 127.0.0.1:`port`,
    prove the token, answer reads. Returns an exit code."""
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0)
    try:
        handle = os.open(device, flags)
        size = _device_size(handle, device)
    except Exception as exc:
        status, size, handle = f"error {exc}", 0, None
    else:
        status = 'ok'
    try:
        connection = socket.create_connection(('127.0.0.1', int(port)),
                                              timeout=30)
    except OSError:
        return 2
    connection.settimeout(None)
    _no_delay(connection)
    with connection:
        connection.sendall(bytes.fromhex(token_hex) + struct.pack('<Q', size)
                           + status.encode('utf-8', 'replace')[:200]
                           .ljust(200, b' '))
        if handle is None:
            return 1
        reader = _AlignedReader(handle, size)
        while True:
            request = _receive(connection, 12)
            if request is None:
                break
            offset, length = struct.unpack('<QI', request)
            try:
                data = reader.read(offset, min(length, MAX_READ))
                connection.sendall(struct.pack('<I', len(data)) + data)
            except OSError as exc:
                message = str(exc).encode('utf-8', 'replace')[:500]
                connection.sendall(struct.pack('<II', _FAILED, len(message))
                                   + message)
        os.close(handle)
    return 0


def _no_delay(connection):
    """Requests are tiny and each waits for its answer: Nagle's algorithm
    would hold them back."""
    try:
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass


def _receive(connection, count):
    data = bytearray()
    while len(data) < count:
        piece = connection.recv(count - len(data))
        if not piece:
            return None
        data += piece
    return bytes(data)


# --- the client (TRACE) ------------------------------------------------------------------

def helper_command(device, port, token_hex):
    """The command line that runs the helper: the packaged app itself, or
    this Python with main.py."""
    arguments = ['--live-reader', device, str(port), token_hex]
    if getattr(sys, 'frozen', False):
        return [sys.executable] + arguments
    main = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), 'main.py')
    return [sys.executable, main] + arguments


def elevation_method():
    """How the helper gets administrator rights here -- or raises
    LiveDiskError saying what is missing (the capability probe)."""
    if is_privileged():
        return 'already administrator'
    if sys.platform == 'win32':
        return 'UAC prompt'
    from shutil import which
    if sys.platform == 'darwin':
        if not which('osascript'):
            raise LiveDiskError("osascript is missing")
        return 'administrator prompt (osascript)'
    if not which('pkexec'):
        raise LiveDiskError("pkexec (polkit) is needed to read a disk as "
                            "administrator; or start TRACE with sudo")
    return 'pkexec'


def _start_elevated(command):
    """Run `command` with the platform's administrator prompt; returns
    immediately (the helper connects back)."""
    if sys.platform == 'win32':
        import ctypes
        executable, arguments = command[0], subprocess.list2cmdline(
            command[1:])
        result = ctypes.windll.shell32.ShellExecuteW(
            None, 'runas', executable, arguments, None, 0)
        if result <= 32:
            raise LiveDiskError("Administrator rights were not given "
                                "(or the prompt was cancelled)")
        return
    import shlex
    if sys.platform == 'darwin':
        script = ' '.join(shlex.quote(part) for part in command) + \
            ' >/dev/null 2>&1 &'
        apple = ('do shell script ' + _applescript_string(script) +
                 ' with administrator privileges')
        subprocess.Popen(['osascript', '-e', apple])
        return
    from shutil import which
    if not which('pkexec'):
        raise LiveDiskError("pkexec (polkit) is needed to read a disk as "
                            "administrator; or start TRACE with sudo")
    subprocess.Popen(['pkexec'] + command)


def _applescript_string(text):
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"') + '"'


class LiveDisk:
    """A connection to the helper reading one device -- libyal-shaped
    (`read_buffer_at_offset`, `size`), so it is read like a virtual disk.
    Reads are serialised: one request, one reply."""

    def __init__(self, device, elevate=True, timeout=CONNECT_TIMEOUT,
                 command=None):
        self.device = device
        self._lock = threading.Lock()
        self._cache, self._broken = {}, None
        token = secrets.token_bytes(32)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(4)
        listener.settimeout(timeout)
        port = listener.getsockname()[1]
        command = command or helper_command(device, port, token.hex())
        try:
            if elevate:
                _start_elevated(command)
            else:
                self._process = subprocess.Popen(command)
            self._socket = self._accept(listener, token, timeout)
        finally:
            listener.close()
        header = _receive(self._socket, 8 + 200)
        if header is None:
            raise LiveDiskError("The disk reader closed without answering")
        self.size = struct.unpack_from('<Q', header, 0)[0]
        status = header[8:].decode('utf-8', 'replace').strip()
        if status != 'ok':
            self.close()
            raise LiveDiskError(f"{device} could not be opened: "
                                f"{status[6:] or status}")

    @staticmethod
    def _accept(listener, token, timeout):
        """The helper's connection: whatever else connects to the port and
        cannot prove the token is dropped."""
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                connection, _address = listener.accept()
            except socket.timeout:
                break
            connection.settimeout(10)
            try:
                offered = _receive(connection, 32)
            except OSError:
                offered = None
            if offered is not None and secrets.compare_digest(offered,
                                                              token):
                connection.settimeout(READ_TIMEOUT)
                _no_delay(connection)
                return connection
            connection.close()
        raise LiveDiskError("The disk reader did not start (the "
                            "administrator prompt was cancelled or timed "
                            "out)")

    def read_buffer_at_offset(self, length, offset):
        """`length` bytes at `offset`, through the block cache."""
        if length <= 0 or offset >= self.size:
            return b''
        length = min(length, self.size - offset)
        with self._lock:
            if length >= CACHE_BYPASS:
                return self._fetch(length, offset)
            cache = self._cache
            out = bytearray()
            block = offset - offset % CACHE_BLOCK
            while block < offset + length:
                data = cache.pop(block, None)
                if data is None:
                    data = self._fetch(min(CACHE_BLOCK, self.size - block),
                                       block)
                    while len(cache) >= CACHE_BLOCKS:
                        cache.pop(next(iter(cache)))
                cache[block] = data             # most recent last
                begin = max(offset - block, 0)
                out += data[begin:offset + length - block]
                if len(data) < CACHE_BLOCK:
                    break
                block += CACHE_BLOCK
            return bytes(out)

    def _fetch(self, length, offset):
        """One request to the helper (lock held). A socket that times out
        or breaks mid-reply is out of step for good: closed, and every later
        read says so."""
        if self._broken:
            raise LiveDiskError(self._broken)
        try:
            return self._request(length, offset)
        except OSError as exc:
            if getattr(exc, 'reported', False):
                raise                           # the helper's own answer
            self._broken = (f"The disk reader stopped answering "
                            f"({exc or type(exc).__name__}); add the disk "
                            f"again to reconnect")
            self.close()
            raise LiveDiskError(self._broken) from exc

    def _request(self, length, offset):
        out = bytearray()
        while length > 0 and offset < self.size:
            take = min(length, MAX_READ)
            self._socket.sendall(struct.pack('<QI', offset, take))
            reply = _receive(self._socket, 4)
            if reply is None:
                raise ConnectionError("the connection closed")
            count = struct.unpack('<I', reply)[0]
            if count == _FAILED:
                size = struct.unpack('<I', _receive(self._socket, 4))[0]
                message = _receive(self._socket, size) or b''
                error = OSError(f"Read at {offset:,} failed: "
                                f"{message.decode('utf-8', 'replace')}")
                error.reported = True
                raise error
            if not count:
                break                           # the end of the disk
            data = _receive(self._socket, count)
            if data is None:
                raise ConnectionError("the connection closed mid-reply")
            out += data
            offset += len(data)
            length -= len(data)
        return bytes(out)

    def close(self):
        try:
            self._socket.close()
        except Exception:
            pass


# --- sharing one helper across the app and its jobs -----------------------------------

#: The environment variable telling TRACE's own background jobs (child
#: processes, which inherit it) where the window's relay for each live disk
#: is: JSON {device: [port, token hex]}.
RELAY_ENVIRONMENT = 'TRACE_LIVE_RELAYS'

#: This process's open disks: {device: LiveDisk or RelayClient}. A disk
#: stays open while TRACE runs -- every reader of it (the evidence page,
#: the window, a job) shares the one administrator prompt's helper.
_OPEN = {}
_OPEN_LOCK = threading.Lock()


def is_privileged():
    """Running as administrator / root already: no prompt is needed."""
    if sys.platform == 'win32':
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, 'geteuid') and os.geteuid() == 0


class RelayClient:
    """A job's connection to the window's relay for a live disk: the same
    protocol as the helper's, minus the prompt."""

    def __init__(self, device, port, token_hex):
        self.device = device
        self._lock = threading.Lock()
        self._cache, self._broken = {}, None
        self._socket = socket.create_connection(('127.0.0.1', int(port)),
                                                timeout=30)
        self._socket.sendall(bytes.fromhex(token_hex))
        header = _receive(self._socket, 8 + 200)
        if header is None:
            raise LiveDiskError("The live disk relay refused this job")
        self._socket.settimeout(READ_TIMEOUT)
        _no_delay(self._socket)
        self.size = struct.unpack_from('<Q', header, 0)[0]

    # LiveDisk's reading, cache and all (set below).
    read_buffer_at_offset = _fetch = _request = None

    def close(self):
        try:
            self._socket.close()
        except Exception:
            pass


class _Relay:
    """Serves a LiveDisk to TRACE's own child processes on 127.0.0.1, each
    connection proving a token only they were given."""

    def __init__(self, disk):
        self.disk = disk
        self.token = secrets.token_bytes(32)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True,
                         name='live-disk-relay').start()

    def _accept(self):
        while True:
            try:
                connection, _address = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(connection,),
                             daemon=True).start()

    def _serve(self, connection):
        with connection:
            connection.settimeout(10)
            try:
                offered = _receive(connection, 32)
            except OSError:
                return
            if offered is None or not secrets.compare_digest(offered,
                                                             self.token):
                return
            connection.settimeout(None)
            _no_delay(connection)
            connection.sendall(struct.pack('<Q', self.disk.size)
                               + b'ok'.ljust(200, b' '))
            while True:
                request = _receive(connection, 12)
                if request is None:
                    return
                offset, length = struct.unpack('<QI', request)
                try:
                    data = self.disk.read_buffer_at_offset(
                        min(length, MAX_READ), offset)
                    connection.sendall(struct.pack('<I', len(data)) + data)
                except Exception as exc:
                    message = str(exc).encode('utf-8', 'replace')[:500]
                    connection.sendall(struct.pack('<II', _FAILED,
                                                   len(message)) + message)

    def close(self):
        try:
            self.listener.close()
        except Exception:
            pass


def _publish(device, relay):
    import json
    relays = json.loads(os.environ.get(RELAY_ENVIRONMENT) or '{}')
    relays[device] = [relay.port, relay.token.hex()]
    os.environ[RELAY_ENVIRONMENT] = json.dumps(relays)


def open_disk(device, elevate=None):
    """The shared connection to `device`: this process's own if open, else
    the window's relay (in a job), else a new helper behind the
    administrator prompt (skipped when TRACE already runs privileged)."""
    import json
    with _OPEN_LOCK:
        disk = _OPEN.get(device)
        if disk is not None:
            return disk
        relays = json.loads(os.environ.get(RELAY_ENVIRONMENT) or '{}')
        if device in relays:
            disk = RelayClient(device, *relays[device])
        else:
            disk = LiveDisk(device, elevate=not is_privileged()
                            if elevate is None else elevate)
            disk.relay = _Relay(disk)
            _publish(device, disk.relay)
        _OPEN[device] = disk
        return disk


def close_all():
    """Close every live disk this process opened (TRACE is exiting)."""
    with _OPEN_LOCK:
        for disk in _OPEN.values():
            relay = getattr(disk, 'relay', None)
            if relay is not None:
                relay.close()
            disk.close()
        _OPEN.clear()


class _Shared:
    """What LibyalImgInfo is given: reads through the shared connection,
    and closing one image does not close the disk for the others."""

    def __init__(self, disk):
        self._disk = disk

    def read_buffer_at_offset(self, length, offset):
        return self._disk.read_buffer_at_offset(length, offset)

    def close(self):
        pass


def open_live_disk(device, elevate=None):
    """(img_info for TSK, note) for a physical disk, read live."""
    from trace_app.core.containers import LibyalImgInfo
    disk = open_disk(device, elevate)
    return (LibyalImgInfo(_Shared(disk), disk.size),
            "Live disk (read-only preview)")


RelayClient.read_buffer_at_offset = LiveDisk.read_buffer_at_offset
RelayClient._fetch = LiveDisk._fetch
RelayClient._request = LiveDisk._request
