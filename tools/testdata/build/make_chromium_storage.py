"""Build Chromium's own Local Storage, Session Storage and IndexedDB, for
core/leveldb.py, activity/chromium_storage.py and core/indexeddb.py.

Readers of a browser's storage checked only against their own idea of
LevelDB and of V8's serialisation would agree with themselves; these are
written by Chromium itself. A page served from a local server writes known
keys and values -- every kind of value V8 serialises (strings Latin-1 and
two-byte, numbers, BigInt, Date, RegExp, arrays dense and sparse, nested
objects, Map, Set, ArrayBuffer and typed arrays), IndexedDB keys of every
type, a value large enough for Chromium to compress -- then overwrites and
deletes some, and reports what it did. The browser is closed properly (so
everything reaches disk); the databases and the page's report are kept:

    chromium-storage/Local Storage/leveldb/...
    chromium-storage/Session Storage/...
    chromium-storage/IndexedDB/http_127.0.0.1_8765.indexeddb.leveldb/...
    chromium-storage/key.json

Chromium comes from Playwright, pinned (PLAYWRIGHT below), so the same
browser build writes the same formats everywhere. Locally, in Docker:

    docker run --rm -v "$PWD:/src" -w /src \\
        mcr.microsoft.com/playwright/python:v1.55.0-noble sh -c \\
        "pip3 install -q --break-system-packages playwright==1.55.0 && \\
         python3 tools/testdata/build/make_chromium_storage.py"

and in Linux CI after `pip install playwright==1.55.0 && playwright install
--with-deps chromium`.
"""

import functools
import http.server
import json
import os
import shutil
import sys
import tempfile
import threading

PLAYWRIGHT = '1.55.0'
PORT = 8765
ORIGIN = f'http://127.0.0.1:{PORT}'

PAGE = r"""<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>
<div id="state">running</div><script>
const report = {local: {}, local_deleted: [], local_overwritten: {},
                session: {}, idb: {}, idb_deleted: []};
// --- Local Storage: Latin-1 and two-byte values, an overwrite, a delete.
const local = {
  'greeting': 'hello world',
  'latin': 'café crème',
  'cyrillic': 'Привет мир',
  'emoji': 'chat 💬 log',
  'json': JSON.stringify({user: 'sam', token: 'abc123', n: 7}),
  'ключ': 'a non-Latin key'};
for (const [k, v] of Object.entries(local)) localStorage.setItem(k, v);
localStorage.setItem('changed', 'first value');
localStorage.setItem('changed', 'second value');
report.local_overwritten['changed'] = ['first value', 'second value'];
localStorage.setItem('gone', 'deleted value');
localStorage.removeItem('gone');
report.local_deleted.push(['gone', 'deleted value']);
Object.assign(report.local, local, {changed: 'second value'});
// --- Session Storage.
sessionStorage.setItem('draft', 'unsent message text');
sessionStorage.setItem('tab', 'таб');
report.session = {draft: 'unsent message text', tab: 'таб'};

// --- IndexedDB: every value type, keys of every type, deletes.
function typed(value) {
  // How the report writes a value the key file can hold.
  if (value === undefined) return {t: 'undefined'};
  if (value === null) return {t: 'null'};
  if (typeof value === 'bigint') return {t: 'bigint', v: value.toString()};
  if (typeof value === 'number') {
    if (Number.isNaN(value)) return {t: 'nan'};
    return {t: 'number', v: value};
  }
  if (typeof value === 'string' || typeof value === 'boolean')
    return {t: typeof value, v: value};
  if (value instanceof Date) return {t: 'date', v: value.getTime()};
  if (value instanceof RegExp) return {t: 'regexp', v: value.source,
                                       f: value.flags};
  if (value instanceof Map) return {t: 'map', v: [...value].map(
      ([k, x]) => [typed(k), typed(x)])};
  if (value instanceof Set) return {t: 'set', v: [...value].map(typed)};
  if (value instanceof ArrayBuffer) return {t: 'arraybuffer',
      v: Array.from(new Uint8Array(value))};
  if (ArrayBuffer.isView(value)) return {t: value.constructor.name,
      v: Array.from(new Uint8Array(value.buffer, value.byteOffset,
                                   value.byteLength))};
  if (Array.isArray(value)) {
    const out = {t: 'array', length: value.length, v: {}};
    value.forEach((x, i) => { out.v[i] = typed(x); });
    return out;
  }
  const out = {t: 'object', v: {}};
  for (const [k, x] of Object.entries(value)) out.v[k] = typed(x);
  return out;
}
const sparse = []; sparse[0] = 'a'; sparse[1000] = 'b';
const values = {
  'string': 'plain ASCII string',
  'two-byte': '日本語のテキスト',
  'int': 42, 'negative': -7, 'float': 3.14159, 'big': 2 ** 53 + 2,
  'bigint': 123456789012345678901234567890n, 'true': true, 'false': false,
  'null': null, 'undefined': undefined, 'nan': NaN,
  'date': new Date(1700000000123),
  'regexp': /h(e)llo/gi,
  'array': [1, 'two', 3.5, [4, 5], {six: 6}],
  'sparse': sparse,
  'object': {from: 'sam', to: ['alex', 'kim'], read: false,
             sent: new Date(1690000000000),
             nested: {deeper: {deepest: 'yes'}}},
  'map': new Map([['a', 1], [2, 'b']]),
  'set': new Set(['x', 'y', 3]),
  'arraybuffer': new Uint8Array([0, 1, 2, 254, 255]).buffer,
  'uint8': new Uint8Array([9, 8, 7]),
  'int32': new Int32Array([-1, 2, 300000]),
  'float64': new Float64Array([1.5, -2.25]),
  'large': 'compressible text '.repeat(1500),
  'shared': null};
const shared = {same: 'object'};
values['shared'] = {first: shared, second: shared};
const keys = [1, 2.5, -3, 'text key', 'файл',
              new Date(1600000000000), [1, 'a'], new Uint8Array([1, 2, 3])];
const open = indexedDB.open('traceTest', 1);
open.onupgradeneeded = e => {
  const db = e.target.result;
  db.createObjectStore('values');
  const messages = db.createObjectStore('messages', {keyPath: 'id'});
  messages.createIndex('by_sender', 'from');
  db.createObjectStore('keys');
  db.createObjectStore('bulk');
};
open.onsuccess = e => {
  const db = e.target.result;
  const t = db.transaction(['values', 'messages', 'keys'], 'readwrite');
  report.idb.values = {};
  for (const [k, v] of Object.entries(values)) {
    t.objectStore('values').put(v, k);
    report.idb.values[k] = typed(v);
  }
  report.idb.messages = [];
  for (let i = 1; i <= 20; i++) {
    const m = {id: i, from: i % 2 ? 'sam' : 'alex',
               text: 'message ' + i, sent: new Date(1690000000000 + i * 60000)};
    t.objectStore('messages').put(m);
    report.idb.messages.push(typed(m));
  }
  report.idb.keys = [];
  keys.forEach((k, i) => {
    t.objectStore('keys').put('value ' + i, k);
    report.idb.keys.push([typed(k), 'value ' + i]);
  });
  t.oncomplete = () => {
    const t2 = db.transaction(['messages'], 'readwrite');
    t2.objectStore('messages').delete(7);
    t2.objectStore('messages').delete(8);
    report.idb_deleted = [7, 8];
    t2.oncomplete = () => {
      // Megabytes more, so LevelDB flushes its log to a sorted table
      // (.ldb, Snappy blocks) as it does on a used profile.
      const t3 = db.transaction(['bulk'], 'readwrite');
      let seed = 1;
      const noise = n => { let s = '';
        for (let i = 0; i < n; i++) {
          seed = (seed * 1103515245 + 12345) % 2147483648;
          s += String.fromCharCode(97 + seed % 26); }
        return s; };
      report.bulk = {};
      for (let i = 0; i < 300; i++) {
        const v = 'bulk ' + i + ' ' + noise(20000);
        t3.objectStore('bulk').put(v, i);
        report.bulk[i] = v.length;
      }
      t3.oncomplete = () => {
        window.report = report;
        document.getElementById('state').innerText = 'done';
      };
    };
  };
};
</script></body></html>
"""


def serve(folder):
    handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                directory=folder)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', PORT), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    from playwright.sync_api import sync_playwright
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', '..', '..',
        'test_images', 'built', 'chromium-storage')
    out = os.path.abspath(out)
    work = tempfile.mkdtemp()
    with open(os.path.join(work, 'page.html'), 'w', encoding='utf-8') as f:
        f.write(PAGE)
    server = serve(work)
    profile = os.path.join(work, 'profile')
    try:
        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(
                profile, headless=True)
            page = context.new_page()
            page.goto(f'{ORIGIN}/page.html')
            page.wait_for_function(
                "document.getElementById('state').innerText === 'done'")
            report = page.evaluate('window.report')
            agent = page.evaluate('navigator.userAgent')
            context.close()           # flushes every database to disk
    finally:
        server.shutdown()
    if os.path.exists(out):
        shutil.rmtree(out)
    default = os.path.join(profile, 'Default')
    for sub in ('Local Storage', 'Session Storage', 'IndexedDB'):
        source = os.path.join(default, sub)
        if os.path.isdir(source):
            shutil.copytree(source, os.path.join(out, sub),
                            ignore=shutil.ignore_patterns('LOCK'))
    report['browser'] = agent
    report['playwright'] = PLAYWRIGHT
    report['origin'] = ORIGIN
    with open(os.path.join(out, 'key.json'), 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=1, ensure_ascii=False)
    print(f"{agent}: storage written to {out}")


if __name__ == '__main__':
    main()
