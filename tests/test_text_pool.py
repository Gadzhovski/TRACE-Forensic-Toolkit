"""Text extraction on worker processes (core/text_pool.py): the rows come
back in the order given and equal to extraction in-process."""

import random

from trace_app.core import text_pool


def _samples():
    rng = random.Random(9)
    out = []
    for index in range(40):
        noise = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 3000)))
        text = (f"mail{index}@example.org see https://host{index}.example/x "
                f"and 10.0.{index}.7").encode()
        out.append((noise + text + noise, f"file{index}.bin"))
    out.append((b'', 'empty.bin'))
    out.append((b'\x7fELF' + b'\x00' * 64 + b'/lib/ld-linux.so.2', 'prog'))
    return out


def test_workers_give_what_one_process_gives_in_order():
    samples = _samples()
    alone, pooled = [], []
    single = text_pool.TextPipeline(
        lambda text, ents, payload: alone.append((payload, text, ents)))
    for number, (content, name) in enumerate(samples):
        single.submit(content, name, 1 << 20, number)
    single.close()

    pool = text_pool.TextPipeline(
        lambda text, ents, payload: pooled.append((payload, text, ents)),
        workers=2)
    assert pool.parallel
    for number, (content, name) in enumerate(samples):
        pool.submit(content, name, 1 << 20, number)
        if number == 3:
            pool.put('known', 'already', [('email', 'x@y.z')])
    pool.close()

    assert [p for p, _t, _e in pooled] == \
        list(range(4)) + ['known'] + list(range(4, len(samples)))
    pooled = [row for row in pooled if row[0] != 'known']
    assert pooled == alone
    found = dict((p, e) for p, _t, e in alone)
    assert ('email', 'mail5@example.org') in found[5]
    assert ('ip', '10.0.5.7') in found[5]


def test_a_cancel_drops_what_is_not_written():
    written = []
    pool = text_pool.TextPipeline(
        lambda text, ents, payload: written.append(payload), workers=2)
    for number in range(10):
        pool.submit(b'hello world ' * 100, f"{number}.txt", 1 << 20, number)
    pool.close(cancel=True)
    assert written == []            # nothing half-written after a cancel


def _alive(pid):
    """Whether process `pid` still runs (Windows or POSIX)."""
    import os
    import sys
    if sys.platform == 'win32':
        import ctypes
        kernel = ctypes.windll.kernel32
        handle = kernel.OpenProcess(0x1000, False, pid)   # query limited
        if not handle:
            return False
        code = ctypes.c_ulong()
        kernel.GetExitCodeProcess(handle, ctypes.byref(code))
        kernel.CloseHandle(handle)
        return code.value == 259                           # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:                                # a zombie has exited: reap it
        return os.waitpid(pid, os.WNOHANG) == (0, 0)
    except ChildProcessError:
        return True


def test_a_job_process_ends_with_the_process_that_started_it(tmp_path):
    """Jobs are not daemons (indexing starts a pool of its own); a job, or
    a pool worker, whose parent is killed must end too, not run on."""
    import os
    import subprocess
    import sys
    import textwrap
    import time
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script = tmp_path / 'parent.py'
    script.write_text(textwrap.dedent(f"""
        import multiprocessing, os, sys, time
        sys.path.insert(0, {root!r})

        def child():
            from trace_app.core.background import watch_parent
            watch_parent()
            time.sleep(120)

        if __name__ == '__main__':
            process = multiprocessing.get_context('spawn').Process(
                target=child)
            process.start()
            print(process.pid, flush=True)
            time.sleep(5)               # the child is up and watching
            os._exit(0)                 # gone without a word
    """))
    out = subprocess.run([sys.executable, str(script)], capture_output=True,
                         text=True, timeout=120)
    pid = int(out.stdout.split()[0])
    deadline = time.monotonic() + 30
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.5)
    assert not _alive(pid), "the child ran on after its parent died"
