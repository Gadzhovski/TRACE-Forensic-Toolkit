"""Running an installed tool's command line (no Qt).

The tool is a program of its own -- a PyInstaller build, as TRACE's packaged
app is -- started as a child process with arguments as a list (no shell) in
the tool's own folder (it needs its folder on Windows and macOS), and in a
*clean* environment: TRACE's process carries settings meant only for itself
that would mislead another frozen program (see clean_environment). The tool
gets its own process group, so Cancel ends it and everything it started.
"""

import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time

logger = logging.getLogger('TRACE.Modules')

#: Variables TRACE (or PyInstaller, Qt, pylibmagic) sets for its own
#: process. Inherited, they make another frozen program load TRACE's
#: libraries (DYLD_LIBRARY_PATH -> pylibmagic's libmagic on macOS) or take
#: itself for TRACE's own child (PyInstaller's _PYI_* / _MEIPASS2).
_TRACE_ONLY = ('DYLD_LIBRARY_PATH', 'DYLD_FALLBACK_LIBRARY_PATH', 'MAGIC',
               'QT_SCALE_FACTOR', 'QT_QPA_PLATFORM', 'QT_PLUGIN_PATH',
               'QT_QPA_PLATFORM_PLUGIN_PATH', 'QTWEBENGINEPROCESS_PATH',
               'TRACE_UI_SCALE_SET', 'TRACE_REOPEN_CASE', 'TRACE_QUICK_TRIAGE',
               'TRACE_CASE_SETUP', 'TRACE_LIVE_RELAYS',
               'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONIOENCODING',
               'TCL_LIBRARY', 'TK_LIBRARY', 'SSL_CERT_FILE')
_TRACE_PREFIXES = ('_PYI_', '_MEIPASS', 'PYINSTALLER_')


class ToolError(Exception):
    """The tool could not be run, or ended without its result."""


class ToolCancelled(Exception):
    """The examiner stopped the run."""


def clean_environment(base=None):
    """The environment a tool starts in: the examiner's, without what
    TRACE set for itself.

    On Linux a frozen TRACE has LD_LIBRARY_PATH pointing into its own
    bundle; PyInstaller keeps the examiner's value in LD_LIBRARY_PATH_ORIG,
    which is put back. PYINSTALLER_RESET_ENVIRONMENT=1 tells the tool's
    bootloader it is a program of its own, not TRACE's child -- what
    PyInstaller documents for starting one frozen program from another.
    TZ (UTC, TRACE's rule) is kept."""
    env = dict(os.environ if base is None else base)
    for key in list(env):
        if key in _TRACE_ONLY or key.startswith(_TRACE_PREFIXES):
            env.pop(key, None)
    if 'LD_LIBRARY_PATH_ORIG' in env:
        env['LD_LIBRARY_PATH'] = env.pop('LD_LIBRARY_PATH_ORIG')
    elif getattr(sys, 'frozen', False):
        env.pop('LD_LIBRARY_PATH', None)
    env['PYINSTALLER_RESET_ENVIRONMENT'] = '1'
    # The tools print as they work; UTF-8 whatever the console's code page.
    env['PYTHONUTF8'] = '1'
    return env


def _group_kwargs():
    if sys.platform.startswith('win'):
        flags = subprocess.CREATE_NEW_PROCESS_GROUP
        flags |= getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        return {'creationflags': flags}
    return {'start_new_session': True}


def _stop(process):
    """End the tool and whatever it started."""
    if process.poll() is not None:
        return
    try:
        if sys.platform.startswith('win'):
            subprocess.run(['taskkill', '/T', '/F', '/PID', str(process.pid)],
                           capture_output=True, timeout=30)
        else:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except Exception as exc:
        logger.debug("Stopping the tool: %s", exc)
        process.kill()
    try:
        process.wait(10)
    except subprocess.TimeoutExpired:
        pass


#: '[12/1174] sms [sms] artifact started at 12:47:32 UTC'
PROGRESS = re.compile(r'^\[(\d+)/(\d+)\]\s+(.*?)\s+artifact started')


def mask(text, secrets):
    """`text` with every one of `secrets` (a backup password) starred."""
    for secret in secrets or ():
        if secret:
            text = text.replace(secret, '********')
    return text


class _Follower:
    """The newest '[n/N] ... started' line in a log the tool writes as it
    goes (LEAPP's Screen_Output.html, HTML with <br> line ends), read from
    where the last look stopped."""

    _TAG = re.compile(r'<[^>]+>')

    def __init__(self, path):
        self.path, self.offset, self.rest = path, 0, ''

    def newest(self):
        import html
        try:
            with open(self.path, 'rb') as handle:
                handle.seek(self.offset)
                data = handle.read(4 * 1024 * 1024)
        except OSError:
            return None
        if not data:
            return None
        self.offset += len(data)
        text = self.rest + data.decode('utf-8', 'replace')
        lines = re.split(r'<br\s*/?>|\n', text)
        self.rest = lines.pop()             # may be half written
        found = None
        for line in lines:
            line = html.unescape(self._TAG.sub('', line)).strip()
            if PROGRESS.match(line):
                found = line
        return found


def run(arguments, cwd, log_path, should_stop=None, progress=None,
        timeout=None, secrets=(), follow=None):
    """Run `arguments` (the program first) in `cwd`, writing everything it
    prints to `log_path`. `progress(done, total, line)` hears each line
    ('[n/N] ... artifact started' gives done/total). Returns the exit code;
    raises ToolCancelled when `should_stop()` turns true. Any of `secrets`
    the tool prints is starred before it is written or reported. `follow`
    is a log the tool writes as it goes, read for progress: its piped
    output reaches us in blocks -- iLEAPP's line for artifact 647 arrived
    29 minutes late, behind a 21-million-row unified log, so the job sat
    on 'Processing started' for half an hour."""
    stop = should_stop or (lambda: False)
    follower = _Follower(follow) if follow else None
    try:
        process = subprocess.Popen(
            arguments, cwd=cwd, env=clean_environment(),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, **_group_kwargs())
    except OSError as exc:
        raise ToolError(f"{os.path.basename(arguments[0])} could not be "
                        f"started: {exc}") from exc
    state = {'done': 0, 'total': 0}

    def pump(handle):
        for raw in iter(process.stdout.readline, b''):
            line = mask(raw.decode('utf-8', 'replace').rstrip(), secrets)
            handle.write(line + '\n')
            match = PROGRESS.match(line)
            if match and int(match.group(1)) >= state['done']:
                state['done'], state['total'] = (int(match.group(1)),
                                                 int(match.group(2)))
            elif match:
                continue            # the followed log is ahead of the pipe
            if progress is not None and line:
                progress(state['done'], state['total'], line)
    started = time.monotonic()
    with open(log_path, 'a', encoding='utf-8') as handle:
        reader = threading.Thread(target=pump, args=(handle,), daemon=True,
                                  name='tool output')
        reader.start()
        while process.poll() is None:
            if follower is not None:
                line = follower.newest()
                match = PROGRESS.match(line) if line else None
                if match and int(match.group(1)) > state['done']:
                    state['done'], state['total'] = (int(match.group(1)),
                                                     int(match.group(2)))
                    if progress is not None:
                        progress(state['done'], state['total'],
                                 mask(line, secrets))
            if stop():
                _stop(process)
                reader.join(5)
                raise ToolCancelled()
            if timeout and time.monotonic() - started > timeout:
                _stop(process)
                reader.join(5)
                raise ToolError(f"{os.path.basename(arguments[0])} did not "
                                f"finish in {timeout} s")
            time.sleep(0.2)
        reader.join(30)
    return process.returncode


def version_of(executable, timeout=120):
    """What `executable --version` says (its first line), or ''."""
    try:
        out = subprocess.run([executable, '--version'],
                             cwd=os.path.dirname(executable),
                             env=clean_environment(), capture_output=True,
                             timeout=timeout, stdin=subprocess.DEVNULL,
                             **_group_kwargs())
    except (OSError, subprocess.TimeoutExpired):
        return ''
    text = (out.stdout or b'').decode('utf-8', 'replace').strip()
    return text.splitlines()[0] if text else ''
