"""VirusTotal v3: look a hash up, or upload a file and wait for its report.

No Qt here, so the client can be driven from a script or a test and the
network never runs on the UI thread by accident -- every call in this module
blocks, and is meant to be made from a worker.

Two things the previous client got wrong, and why this one is shaped as it is:

* An upload went up zipped, so VirusTotal analysed the ZIP rather than the
  file, and the report was then fetched by a SHA-256 the upload response does
  not contain. The bytes go up as they are here, and the report is fetched by
  the hash computed locally -- which is also the hash the examiner recorded.
* Rate limiting was a counter that refused the fourth request in a minute and
  told the examiner to try again. A batch of twenty lookups needs the client to
  wait its turn instead, so the limiter sleeps -- in short steps, so a cancel
  is noticed within a fraction of a second rather than after the minute.
"""

import logging
import threading
import time
from datetime import date, datetime, timezone

import requests

logger = logging.getLogger('TRACE.VirusTotal')

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui/file/{sha256}"

#: Files up to this size go to /files directly; larger ones need an upload URL.
DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024

#: VirusTotal's own ceiling for a file upload.
MAX_UPLOAD = 650 * 1024 * 1024

#: The public API's quota. A premium key is not limited this way, but nothing
#: in the response says which kind a key is, so the free tier is assumed.
PER_MINUTE = 4
PER_DAY = 500

#: How often a submitted file's analysis is checked, and for how long. Each
#: check spends a request from the same four a minute, so polling faster only
#: delays the other work in the queue.
POLL_INTERVAL = 20
POLL_LIMIT = 15 * 60

STATUS_FOUND = 'found'
STATUS_NOT_FOUND = 'not_found'
STATUS_PENDING = 'pending'
STATUS_ERROR = 'error'

#: Engine verdicts that count against a file.
DETECTED = ('malicious', 'suspicious')


class VirusTotalError(Exception):
    """A request failed in a way worth showing the examiner."""


class AuthError(VirusTotalError):
    """The API key was refused."""


class QuotaExhausted(VirusTotalError):
    """The day's allowance is spent; waiting will not help until tomorrow."""


class Cancelled(VirusTotalError):
    """The examiner stopped the work while it was waiting."""


class RateLimiter:
    """Hands out requests no faster than the quota allows.

    A sliding window rather than a per-minute counter: four requests at
    0:59 and four more at 1:01 is eight in two seconds, which is what the old
    counter allowed and what VirusTotal answers with HTTP 429.
    """

    def __init__(self, per_minute=PER_MINUTE, per_day=PER_DAY,
                 clock=time.monotonic, sleep=time.sleep, today=date.today):
        self.per_minute = per_minute
        self.per_day = per_day
        self._clock = clock
        self._sleep = sleep
        self._today = today
        self._stamps = []
        self._day = today()
        self._day_count = 0
        self._lock = threading.Lock()

    def acquire(self, should_stop=None, on_wait=None):
        """Block until a request may be made, then count it."""
        announced = False
        while True:
            with self._lock:
                if self._today() != self._day:
                    self._day = self._today()
                    self._day_count = 0
                if self._day_count >= self.per_day:
                    raise QuotaExhausted(
                        f"Today's {self.per_day} VirusTotal requests are "
                        f"used up. The allowance resets at midnight UTC.")

                now = self._clock()
                self._stamps = [s for s in self._stamps if now - s < 60]
                if len(self._stamps) < self.per_minute:
                    self._stamps.append(now)
                    self._day_count += 1
                    return
                wait = 60 - (now - self._stamps[0])

            if on_wait is not None and not announced:
                on_wait(wait)
                announced = True
            # Short steps, so a cancel is honoured promptly.
            self._sleep(min(0.25, max(wait, 0.01)))
            if should_stop is not None and should_stop():
                raise Cancelled("Cancelled while waiting for the rate limit.")

    def penalise(self):
        """VirusTotal said 429: treat the whole minute as spent."""
        with self._lock:
            now = self._clock()
            self._stamps = [now] * self.per_minute


_limiters = {}
_limiters_lock = threading.Lock()


def limiter_for(api_key):
    """One limiter per key, shared by every client using it.

    The quota belongs to the key, not to a worker: two lookups started a
    second apart must draw from the same four a minute.
    """
    with _limiters_lock:
        if api_key not in _limiters:
            _limiters[api_key] = RateLimiter()
        return _limiters[api_key]


def report_url(sha256):
    return GUI.format(sha256=sha256)


def _utc(timestamp):
    if not timestamp:
        return ''
    try:
        return datetime.fromtimestamp(int(timestamp), timezone.utc).strftime(
            '%Y-%m-%d %H:%M:%S UTC')
    except (TypeError, ValueError, OSError):
        return ''


def normalise_report(payload, sha256=''):
    """The parts of a v3 file object TRACE shows, in one flat dict.

    `total` counts the engines that reached a verdict. Engines that do not
    support the file type, or timed out, are left out, as VirusTotal's own
    page does: "0/72" should mean 72 engines looked and none objected.
    """
    attributes = (payload.get('data') or {}).get('attributes') or {}
    stats = attributes.get('last_analysis_stats') or {}
    results = attributes.get('last_analysis_results') or {}

    engines = []
    for engine, result in results.items():
        engines.append({
            'engine': result.get('engine_name') or engine,
            'category': result.get('category') or '',
            'result': result.get('result') or '',
            'version': result.get('engine_version') or '',
            'update': result.get('engine_update') or '',
        })
    # Detections first, then alphabetical: the rows an examiner opens the
    # report for should not be somewhere in the middle of seventy.
    engines.sort(key=lambda e: (e['category'] not in DETECTED,
                                e['category'] != 'malicious',
                                e['engine'].lower()))

    positives = int(stats.get('malicious', 0)) + int(stats.get('suspicious', 0))
    total = positives + int(stats.get('undetected', 0)) + int(
        stats.get('harmless', 0))
    digest = attributes.get('sha256') or sha256

    return {
        'status': STATUS_FOUND,
        'sha256': digest,
        'md5': attributes.get('md5', ''),
        'sha1': attributes.get('sha1', ''),
        'type': attributes.get('type_description', ''),
        'size': attributes.get('size'),
        'name': attributes.get('meaningful_name', ''),
        'names': list(attributes.get('names') or [])[:10],
        'tags': list(attributes.get('tags') or []),
        'reputation': attributes.get('reputation'),
        'first_seen': _utc(attributes.get('first_submission_date')),
        'scan_date': _utc(attributes.get('last_analysis_date')),
        'stats': {k: int(v) for k, v in stats.items()
                  if isinstance(v, (int, float))},
        'positives': positives,
        'total': total,
        'engines': engines,
        'permalink': report_url(digest),
    }


def _error_text(response):
    try:
        error = response.json().get('error') or {}
        detail = error.get('message') or error.get('code')
    except ValueError:
        detail = ''
    return f"HTTP {response.status_code}" + (f": {detail}" if detail else '')


class VirusTotalClient:
    """Blocking calls to the v3 API, paced by the key's rate limiter."""

    def __init__(self, api_key, session=None, limiter=None, should_stop=None,
                 on_wait=None, sleep=time.sleep, clock=time.monotonic):
        if not api_key:
            raise AuthError("No VirusTotal API key is set.")
        self.api_key = api_key
        self.session = session or requests.Session()
        self.limiter = limiter or limiter_for(api_key)
        self.should_stop = should_stop or (lambda: False)
        self.on_wait = on_wait
        self._sleep = sleep
        self._clock = clock

    # --- plumbing ---------------------------------------------------------

    def _request(self, method, url, timeout=60, **kwargs):
        if not url.startswith('http'):
            url = API + url
        headers = {'x-apikey': self.api_key, 'Accept': 'application/json'}
        for attempt in range(3):
            self.limiter.acquire(self.should_stop, self.on_wait)
            try:
                response = self.session.request(method, url, headers=headers,
                                                timeout=timeout, **kwargs)
            except requests.RequestException as exc:
                raise VirusTotalError(f"Could not reach VirusTotal: {exc}")

            if response.status_code in (401, 403):
                raise AuthError(
                    "VirusTotal refused the API key. Check it under "
                    "Options ▸ API Keys.")
            if response.status_code == 429:
                # Another client on the same key, or a quota we do not know
                # about: give the minute back and try again.
                logger.info("VirusTotal rate limit hit; waiting a minute")
                self.limiter.penalise()
                continue
            return response
        raise VirusTotalError(
            "VirusTotal kept refusing requests for exceeding the rate limit.")

    def _wait(self, seconds):
        deadline = self._clock() + seconds
        while self._clock() < deadline:
            if self.should_stop():
                raise Cancelled("Cancelled.")
            self._sleep(0.25)

    # --- the two operations ----------------------------------------------

    def lookup(self, sha256):
        """The report for a hash, or a not-found result."""
        response = self._request('GET', f"/files/{sha256}")
        if response.status_code == 404:
            return {'status': STATUS_NOT_FOUND, 'sha256': sha256,
                    'permalink': report_url(sha256)}
        if response.status_code != 200:
            raise VirusTotalError(_error_text(response))
        try:
            payload = response.json()
        except ValueError:
            raise VirusTotalError("VirusTotal sent a response TRACE could "
                                  "not read.")
        return normalise_report(payload, sha256)

    def upload(self, data, name, sha256, on_progress=None):
        """Submit `data` and wait for its report.

        Returns the report, or a pending result carrying the analysis id if
        VirusTotal has not finished within POLL_LIMIT -- the file is submitted
        either way, and looking the hash up later will find it.
        """
        if len(data) > MAX_UPLOAD:
            raise VirusTotalError(
                f"VirusTotal accepts files up to {MAX_UPLOAD // (1024 * 1024)}"
                f" MB; this one is {len(data) // (1024 * 1024)} MB.")

        url = "/files"
        if len(data) > DIRECT_UPLOAD_LIMIT:
            response = self._request('GET', "/files/upload_url")
            if response.status_code != 200:
                raise VirusTotalError(_error_text(response))
            url = response.json().get('data') or ''
            if not url:
                raise VirusTotalError("VirusTotal did not provide an upload "
                                      "address for a large file.")

        if on_progress:
            on_progress("Uploading")
        response = self._request('POST', url, timeout=600,
                                 files={'file': (name or sha256, data)})
        if response.status_code != 200:
            raise VirusTotalError(_error_text(response))
        analysis_id = ((response.json().get('data') or {}).get('id') or '')
        if not analysis_id:
            raise VirusTotalError("VirusTotal accepted the file but returned "
                                  "no analysis to follow.")

        started = self._clock()
        while self._clock() - started < POLL_LIMIT:
            if on_progress:
                on_progress("Waiting for VirusTotal to finish scanning")
            self._wait(POLL_INTERVAL)
            response = self._request('GET', f"/analyses/{analysis_id}")
            if response.status_code != 200:
                raise VirusTotalError(_error_text(response))
            status = (((response.json().get('data') or {})
                       .get('attributes') or {}).get('status'))
            if status == 'completed':
                report = self.lookup(sha256)
                if report['status'] == STATUS_FOUND:
                    report['analysis_id'] = analysis_id
                    return report
                # The analysis can complete a moment before the file object
                # is queryable; go round once more.

        return {'status': STATUS_PENDING, 'sha256': sha256,
                'analysis_id': analysis_id, 'permalink': report_url(sha256)}
