#!/usr/bin/env python3
"""IS8 KPI dashboard server.

The dashboard used to page through Airtable from the browser: 237
sequential requests and about 80 seconds before anything showed, on every
visit. This server keeps the tables the dashboard reads in memory, pulls
only what changed in the background, and hands the browser one gzipped
payload. The Airtable token never leaves the server.

Endpoints
  GET  /                    dashboard HTML (nothing secret in it)
  POST /api/login           access code -> session token
  GET  /api/data            cached tables; ?v=<version> answers {"unchanged": true} when current
  POST /api/refresh         pull fresh data from Airtable now, then answer
  POST /api/patch           write one record through to Airtable and the cache
  GET  /api/platform-stats  n8n Kit / Typeform totals, cached 10 minutes
  GET  /api/health          sync status per table
  GET  /api/ready           200 once the first full sync is done (Railway healthcheck)
  GET  /health              liveness, no secrets

Stdlib only; runs on Python 3.9+ (Docker image is 3.12).
"""
import gzip
import hashlib
import hmac
import http.client
import http.server
import json
import os
import re
import ssl
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

TOKEN = os.environ.get('AIRTABLE_TOKEN', '')
PORT = int(os.environ.get('PORT', 8080))
BASE_ID = 'apppAaY1mCbpmXSGd'
HERE = os.path.dirname(os.path.abspath(__file__))
INDEX_PATH = os.path.join(HERE, 'index.html')

# SHA-256 of the access code (same code as the old in-browser gate).
PW_SHA256 = os.environ.get('DASHBOARD_PW_SHA256', '2ce77d9c6d54b013c56da8a059e17c456476cb773f21e87a0df677f476e1a966')
SESSION_SECRET = hashlib.sha256(('is8-kpi-session:' + os.environ.get('SESSION_SECRET', TOKEN)).encode()).digest()
SESSION_TTL = 30 * 86400

PLATFORM_STATS_URL = 'https://scalewisemedia.app.n8n.cloud/webhook/platform-stats'
PLATFORM_STATS_TTL = 10 * 60

# Airtable allows 5 requests/second per base, shared with the n8n workflows
# that write calls, dials and payments. A 429 locks the whole base for 30
# seconds and those writes would fail with it, so this server stays at 3/s.
RATE_PER_SEC = 3.0

ACTIVE_WINDOW = 10 * 60   # a dashboard request in the last 10 min means someone is looking
ACTIVE_INTERVAL = 120     # pull changes every 2 min while someone is looking
IDLE_INTERVAL = 15 * 60   # and every 15 min otherwise
IDLE_FULL_FACTOR = 4      # full resyncs run 4x less often while idle

BOOT_ID = hashlib.sha256(str(time.time()).encode()).hexdigest()[:6]
RID = re.compile(r'^rec[A-Za-z0-9]{14}$')


def log(msg):
    print(time.strftime('%H:%M:%S ') + msg, flush=True)


def iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')


# ───────────────────────────────────────────────────────────── Airtable client

class AirtableError(Exception):
    def __init__(self, status, body):
        if isinstance(body, bytes):
            body = body.decode('utf-8', 'replace')
        super().__init__('Airtable %s: %s' % (status, str(body)[:300]))
        self.status = status
        self.body = str(body)


class RateLimiter:
    def __init__(self, per_sec):
        self.interval = 1.0 / per_sec
        self.lock = threading.Lock()
        self.next_at = 0.0
        self.blocked_until = 0.0

    def wait(self):
        with self.lock:
            now = time.monotonic()
            at = max(now, self.next_at, self.blocked_until)
            self.next_at = at + self.interval
        delay = at - time.monotonic()
        if delay > 0:
            time.sleep(delay)

    def block(self, seconds):
        with self.lock:
            self.blocked_until = max(self.blocked_until, time.monotonic() + seconds)


LIMITER = RateLimiter(RATE_PER_SEC)
SSL_CTX = ssl.create_default_context()
_local = threading.local()
AT_STATUS = {'last_ok': None, 'last_error': None}


def _conn():
    c = getattr(_local, 'conn', None)
    if c is None:
        c = http.client.HTTPSConnection('api.airtable.com', timeout=60, context=SSL_CTX)
        _local.conn = c
    return c


def _drop_conn():
    c = getattr(_local, 'conn', None)
    if c is not None:
        try:
            c.close()
        except Exception:
            pass
    _local.conn = None


def airtable(method, path, body=None, attempts=4):
    """One Airtable REST call through the shared rate limit. Keeps one
    keep-alive connection per thread (saves a TLS handshake per page)."""
    headers = {'Authorization': 'Bearer ' + TOKEN, 'Accept-Encoding': 'gzip'}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers['Content-Type'] = 'application/json'
    last = None
    for attempt in range(attempts):
        if attempt:
            time.sleep(0.5 if attempt == 1 else min(2 ** attempt, 10))
        LIMITER.wait()
        try:
            c = _conn()
            c.request(method, path, body=data, headers=headers)
            r = c.getresponse()
            raw = r.read()
            if r.getheader('Content-Encoding') == 'gzip':
                raw = gzip.decompress(raw)
        except (OSError, http.client.HTTPException) as e:
            _drop_conn()
            last = e
            continue
        if r.status == 429:
            LIMITER.block(30)
            last = AirtableError(429, 'rate limited')
            continue
        if r.status >= 500:
            last = AirtableError(r.status, raw)
            continue
        if r.status >= 400:
            # Bad token, formula or field name: retrying will not help.
            AT_STATUS['last_error'] = '%s %s' % (r.status, raw[:120].decode('utf-8', 'replace'))
            raise AirtableError(r.status, raw)
        AT_STATUS['last_ok'] = time.time()
        return json.loads(raw)
    AT_STATUS['last_error'] = str(last)[:160]
    raise last


def list_records(table_id, formula='', fields=None, on_page=None):
    for restart in range(2):
        out, offset = [], None
        try:
            while True:
                params = [('pageSize', '100')]
                if formula:
                    params.append(('filterByFormula', formula))
                for f in fields or []:
                    params.append(('fields[]', f))
                if offset:
                    params.append(('offset', offset))
                d = airtable('GET', '/v0/%s/%s?%s' % (BASE_ID, table_id, urllib.parse.urlencode(params)))
                recs = d.get('records', [])
                out.extend(recs)
                if on_page:
                    on_page(len(recs))
                offset = d.get('offset')
                if not offset:
                    return out
        except AirtableError as e:
            # Pagination cursors expire if a listing runs too long; start it over once.
            if restart == 0 and e.status == 422 and 'ITERATOR' in e.body:
                continue
            raise
    return out


# ───────────────────────────────────────────────────────────── table cache

class Table:
    def __init__(self, key, table_id, date_field=None, days=None, full_every=300, shards=1):
        self.key = key
        self.id = table_id
        self.date_field = date_field
        self.days = days
        self.full_every = full_every   # seconds between full resyncs (the only way to see deletions)
        self.shards = shards           # parallel date slices for a full sync of a big table
        self.fields = None             # field names to request; None = every field
        self.records = {}              # record id -> {id, createdTime, fields}
        self.loaded = False
        self.busy = False
        self.op_full = False
        self.want_full = False
        self.next_at = 0.0
        self.last_full = 0.0
        self.since = None              # UTC datetime; changes after this are not in the cache yet
        self.synced_at = None          # time.time() of the last successful pull
        self.done_started = 0.0        # start time of the last finished pull, success or not
        self.error = None
        self.pages = 0
        self.local_writes = {}         # record id -> time.time() of a write made through /api/patch

    def window_formula(self):
        if not self.date_field:
            return ''
        return "IS_AFTER({%s}, DATEADD(TODAY(), -%d, 'days'))" % (self.date_field, self.days)

    def cutoff(self):
        # DATEADD(TODAY(), -days) in an Airtable formula is midnight UTC `days` ago.
        return (datetime.now(timezone.utc).date() - timedelta(days=self.days)).isoformat()

    def in_window(self, rec):
        if not self.date_field:
            return True
        v = (rec.get('fields') or {}).get(self.date_field)
        if not v or not isinstance(v, str):
            return False
        c = self.cutoff()
        if len(v) <= 10:
            return v > c                          # date field
        return v > c + 'T00:00:00.000Z'           # dateTime field; ISO strings sort by time

    def shard_formulas(self):
        base = self.window_formula()
        start = datetime.fromisoformat(self.cutoff()).replace(tzinfo=timezone.utc)
        step = (datetime.now(timezone.utc) - start) / self.shards
        cuts = [start + step * i for i in range(1, self.shards)]
        out, lo = [], None
        for hi in cuts + [None]:              # last slice is open-ended (future-dated rows)
            parts = [base]
            if lo is not None:
                parts.append("IS_AFTER({%s}, '%s')" % (self.date_field, iso(lo)))
            if hi is not None:
                parts.append("NOT(IS_AFTER({%s}, '%s'))" % (self.date_field, iso(hi)))
            out.append('AND(%s)' % ', '.join(parts))
            lo = hi
        return out


TABLES = {
    'calls':       Table('calls',       'tblRt7VOLkoT5KPEO', 'Call Date',     90,  full_every=5 * 60),
    'callLog':     Table('callLog',     'tblbGDsdB9AtcDUb4', 'Date',          90,  full_every=6 * 3600, shards=6),
    'meta':        Table('meta',        'tblkZxSk3a214vcHf', 'Date',          90,  full_every=15 * 60),
    'optins':      Table('optins',      'tblTgHxLivupDLxw1', 'Date Opted In', 365, full_every=6 * 3600, shards=6),
    'commissions': Table('commissions', 'tblo9FfovRHFAYzkp',                       full_every=5 * 60),
}

DATA_LOCK = threading.RLock()
SYNC_DONE = threading.Condition()
WAKE = threading.Event()
STATE = {'version': 0, 'last_activity': 0.0, 'catchup_since': 0.0}
OP_POOL = ThreadPoolExecutor(max_workers=len(TABLES), thread_name_prefix='op')
SHARD_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix='shard')


def bump():
    STATE['version'] += 1


def is_active(now=None):
    return (now or time.time()) - STATE['last_activity'] < ACTIVE_WINDOW


def keep_local_writes(t, fresh, started):
    """A pull that began before a dashboard edit must not undo that edit."""
    cutoff = time.time() - 900
    t.local_writes = {rid: ts for rid, ts in t.local_writes.items() if ts > cutoff}
    for rid, ts in t.local_writes.items():
        if ts > started and rid in t.records:
            fresh[rid] = t.records[rid]


def full_sync(t, started):
    started_utc = datetime.now(timezone.utc)
    t.pages = 0

    def on_page(n):
        t.pages += 1

    if t.shards > 1 and t.date_field:
        parts = list(SHARD_POOL.map(lambda f: list_records(t.id, f, t.fields, on_page), t.shard_formulas()))
        recs = [r for part in parts for r in part]
    else:
        recs = list_records(t.id, t.window_formula(), t.fields, on_page)
    fresh = {r['id']: r for r in recs}
    with DATA_LOCK:
        keep_local_writes(t, fresh, started)
        changed = fresh != t.records
        t.records = fresh
        t.loaded = True
        t.last_full = time.time()
        t.since = started_utc
        if changed:
            bump()
    return len(recs), t.pages, changed


def incremental_sync(t, started):
    started_utc = datetime.now(timezone.utc)
    since = t.since - timedelta(seconds=120)   # overlap absorbs clock skew between us and Airtable
    recs = list_records(t.id, "IS_AFTER(LAST_MODIFIED_TIME(), '%s')" % iso(since), t.fields)
    added = updated = removed = 0
    with DATA_LOCK:
        for r in recs:
            rid = r['id']
            if t.local_writes.get(rid, 0) > started:
                continue
            if t.in_window(r):
                old = t.records.get(rid)
                if old != r:
                    t.records[rid] = r
                    if old is None:
                        added += 1
                    else:
                        updated += 1
            elif rid in t.records:
                del t.records[rid]
                removed += 1
        t.since = started_utc
        if added or updated or removed:
            bump()
    return added, updated, removed


def run_op(t, full):
    started = time.time()
    t0 = time.monotonic()
    try:
        try:
            if full:
                n, pages, changed = full_sync(t, started)
                if changed or pages > 5:
                    log('[sync] %s full: %d records, %d pages, %.1fs' % (t.key, n, pages, time.monotonic() - t0))
            else:
                a, u, r = incremental_sync(t, started)
                if a or u or r:
                    log('[sync] %s: +%d ~%d -%d' % (t.key, a, u, r))
        except AirtableError as e:
            if e.status == 422 and 'UNKNOWN_FIELD_NAME' in e.body and t.fields is not None:
                log('[sync] %s: a field was renamed in Airtable, fetching every field instead' % t.key)
                t.fields = None
                full = True
                full_sync(t, started)
            else:
                raise
        with DATA_LOCK:
            t.synced_at = time.time()
            t.error = None
    except Exception as e:
        with DATA_LOCK:
            t.error = str(e)[:200]
        log('[sync] %s %s FAILED: %s' % (t.key, 'full' if full else 'incremental', str(e)[:200]))
    finally:
        with DATA_LOCK:
            t.busy = False
            t.done_started = started
            interval = ACTIVE_INTERVAL if is_active() else IDLE_INTERVAL
            t.next_at = time.time() + (min(60, interval) if t.error else interval)
        with SYNC_DONE:
            SYNC_DONE.notify_all()


def tick():
    now = time.time()
    active = is_active(now)
    for t in TABLES.values():
        with DATA_LOCK:
            if t.busy:
                continue
            every = t.full_every * (1 if active else IDLE_FULL_FACTOR)
            full = (not t.loaded) or t.want_full or (now - t.last_full >= every)
            if t.loaded and t.since is None:
                full = True
            if not (full or now >= t.next_at):
                continue
            t.busy, t.op_full, t.want_full = True, full, False
        OP_POOL.submit(run_op, t, full)


def scheduler():
    choose_fields()
    while True:
        try:
            tick()
        except Exception as e:
            log('[sync] scheduler error: %s' % e)
        WAKE.wait(1.0)
        WAKE.clear()


def note_activity():
    now = time.time()
    was_idle = not is_active(now)
    STATE['last_activity'] = now
    if was_idle and all_loaded():
        if any(now - (t.synced_at or 0) > ACTIVE_INTERVAL for t in TABLES.values()):
            STATE['catchup_since'] = now
            with DATA_LOCK:
                for t in TABLES.values():
                    t.next_at = 0
            WAKE.set()


def waitable(t):
    # A big table in the middle of its periodic full resync finishes on its own schedule.
    return not (t.busy and t.op_full and t.shards > 1 and t.loaded)


def catching_up():
    since = STATE['catchup_since']
    if not since:
        return False
    if all(t.done_started >= since for t in TABLES.values() if waitable(t)):
        STATE['catchup_since'] = 0.0
        return False
    return True


def request_refresh(timeout=20.0):
    """Pull fresh data now: small tables in full (shows deletions), big ones incrementally."""
    req = time.time()
    with DATA_LOCK:
        for t in TABLES.values():
            t.next_at = 0
            if t.shards == 1:
                t.want_full = True
    WAKE.set()
    deadline = req + timeout
    with SYNC_DONE:
        while True:
            pending = [t for t in TABLES.values() if waitable(t) and t.done_started < req]
            left = deadline - time.time()
            if not pending or left <= 0:
                return [t.key for t in pending]
            SYNC_DONE.wait(left)


def all_loaded():
    return all(t.loaded for t in TABLES.values())


def synced_at():
    times = [t.synced_at for t in TABLES.values() if t.synced_at]
    if len(times) < len(TABLES):
        return None
    return datetime.fromtimestamp(min(times), timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def warming_status():
    with DATA_LOCK:
        return {
            'warming': True,
            'tablesReady': sum(1 for t in TABLES.values() if t.loaded),
            'tablesTotal': len(TABLES),
            'records': sum(len(t.records) for t in TABLES.values()) + sum(t.pages * 100 for t in TABLES.values() if not t.loaded),
            'error': next((t.error for t in TABLES.values() if t.error), None),
        }


def choose_fields():
    """Request only the fields index.html mentions. Computed from the page at
    boot, so a new field used by the dashboard is picked up on the next deploy."""
    try:
        with open(INDEX_PATH, encoding='utf-8') as fh:
            html = fh.read()
        schema = airtable('GET', '/v0/meta/bases/%s/tables' % BASE_ID)
    except Exception as e:
        log('[boot] field scan skipped (%s); fetching every field' % str(e)[:120])
        return

    def mentioned(name):
        if ("'%s'" % name) in html or ('"%s"' % name) in html:
            return True
        return bool(re.match(r'^[A-Za-z_$][\w$]*$', name)) and re.search(r'\.' + re.escape(name) + r'\b', html) is not None

    by_id = {s['id']: s for s in schema.get('tables', [])}
    for t in TABLES.values():
        s = by_id.get(t.id)
        if not s:
            continue
        names = [f['name'] for f in s.get('fields', []) if mentioned(f['name'])]
        if t.date_field and t.date_field not in names:
            names.append(t.date_field)
        t.fields = names
    log('[boot] fields per table: ' + ', '.join('%s %d' % (t.key, len(t.fields or [])) for t in TABLES.values()))


# ───────────────────────────────────────────────────────────── payload

PAYLOAD = {'key': None, 'gz': None, 'raw': None}
PAYLOAD_LOCK = threading.Lock()


def payload():
    day = datetime.now(timezone.utc).date().isoformat()   # windows move at midnight UTC
    with PAYLOAD_LOCK:
        key = '%s-%d-%s' % (BOOT_ID, STATE['version'], day)
        if PAYLOAD['key'] == key:
            return PAYLOAD
        with DATA_LOCK:
            key = '%s-%d-%s' % (BOOT_ID, STATE['version'], day)
            # Insertion order = Airtable's own order (full syncs rebuild it; new rows append),
            # so anything in the page that takes the first match behaves as before.
            tables = {k: [r for r in t.records.values() if t.in_window(r)] for k, t in TABLES.items()}
        raw = json.dumps({'version': key, 'tables': tables}, separators=(',', ':')).encode()
        PAYLOAD.update(key=key, raw=raw, gz=gzip.compress(raw, 6))
        return PAYLOAD


# ───────────────────────────────────────────────────────────── platform stats

STATS = {'data': None, 'at': 0.0, 'busy': False}
STATS_LOCK = threading.Lock()


def _fetch_stats():
    try:
        req = urllib.request.Request(PLATFORM_STATS_URL, headers={'User-Agent': 'is8-kpi-dashboard'})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
        with STATS_LOCK:
            STATS['data'], STATS['at'] = data, time.time()
    except Exception as e:
        log('[stats] platform-stats failed: %s' % str(e)[:120])
    finally:
        with STATS_LOCK:
            STATS['busy'] = False


def platform_stats():
    with STATS_LOCK:
        data, age = STATS['data'], time.time() - STATS['at']
        stale = data is None or age > PLATFORM_STATS_TTL
        start = stale and not STATS['busy']
        if start:
            STATS['busy'] = True
    if data is None:
        if start:
            _fetch_stats()
        else:
            for _ in range(200):
                time.sleep(0.1)
                if STATS['data'] is not None or not STATS['busy']:
                    break
        return STATS['data']
    if start:
        threading.Thread(target=_fetch_stats, daemon=True).start()
    return data


# ───────────────────────────────────────────────────────────── auth

FAILS = {}
FAILS_LOCK = threading.Lock()


def make_session():
    exp = str(int(time.time()) + SESSION_TTL)
    return exp + '.' + hmac.new(SESSION_SECRET, exp.encode(), hashlib.sha256).hexdigest()


def valid_session(tok):
    exp, _, sig = (tok or '').partition('.')
    if not exp.isdigit() or int(exp) < time.time():
        return False
    good = hmac.new(SESSION_SECRET, exp.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(good, sig)


def too_many_fails(ip):
    now = time.time()
    with FAILS_LOCK:
        recent = [ts for ts in FAILS.get(ip, []) if now - ts < 600]
        FAILS[ip] = recent
        return len(recent) >= 10


def note_fail(ip):
    with FAILS_LOCK:
        FAILS.setdefault(ip, []).append(time.time())


# ───────────────────────────────────────────────────────────── HTTP

INDEX = {'mtime': None, 'raw': b'', 'gz': b'', 'etag': ''}


def index_page():
    m = os.path.getmtime(INDEX_PATH)
    if INDEX['mtime'] != m:
        with open(INDEX_PATH, 'rb') as fh:
            raw = fh.read()
        INDEX.update(mtime=m, raw=raw, gz=gzip.compress(raw, 9), etag='"%s"' % hashlib.sha256(raw).hexdigest()[:16])
    return INDEX


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'is8-kpi'
    sys_version = ''

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        self.route('GET')

    def do_POST(self):
        self.route('POST')

    # helpers
    def client_ip(self):
        fwd = self.headers.get('X-Forwarded-For', '')
        return fwd.split(',')[0].strip() if fwd else self.client_address[0]

    def gzip_ok(self):
        return 'gzip' in (self.headers.get('Accept-Encoding') or '')

    def send_bytes(self, status, body, ctype, gz=None, headers=None):
        use_gz = gz is not None and self.gzip_ok()
        data = gz if use_gz else body
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'same-origin')
        if use_gz:
            self.send_header('Content-Encoding', 'gzip')
        if gz is not None:
            self.send_header('Vary', 'Accept-Encoding')
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, status, obj, headers=None):
        h = {'Cache-Control': 'no-store'}
        h.update(headers or {})
        self.send_bytes(status, json.dumps(obj, separators=(',', ':')).encode(), 'application/json; charset=utf-8', headers=h)

    def read_json(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n <= 0 or n > 65536:
            return {}
        try:
            return json.loads(self.rfile.read(n))
        except ValueError:
            return {}

    def authed(self):
        auth = self.headers.get('Authorization') or ''
        return auth.startswith('Bearer ') and valid_session(auth[7:])

    def sync_headers(self):
        return {'X-Synced-At': synced_at() or '', 'X-Syncing': '1' if catching_up() else '0'}

    # routes
    def route(self, method):
        path, _, query = self.path.partition('?')
        try:
            if method == 'GET' and path in ('/', '/index.html'):
                return self.serve_index()
            if method == 'GET' and path == '/health':
                return self.send_json(200, {'ok': True, 'ready': all_loaded()})
            if method == 'GET' and path == '/api/ready':
                if all_loaded():
                    return self.send_json(200, {'ready': True})
                return self.send_json(503, warming_status())
            if method == 'POST' and path == '/api/login':
                return self.api_login()
            if path.startswith('/api/'):
                if not self.authed():
                    return self.send_json(401, {'error': 'Session expired. Enter the access code again.'})
                if method == 'GET' and path == '/api/data':
                    return self.api_data(query)
                if method == 'POST' and path == '/api/refresh':
                    return self.api_refresh()
                if method == 'POST' and path == '/api/patch':
                    return self.api_patch()
                if method == 'GET' and path == '/api/platform-stats':
                    return self.api_stats()
                if method == 'GET' and path == '/api/health':
                    return self.api_health()
            return self.send_json(404, {'error': 'Not found'})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            log('[http] %s %s failed: %r' % (method, path, e))
            try:
                self.send_json(500, {'error': 'Server error'})
            except Exception:
                pass

    def serve_index(self):
        page = index_page()
        if self.headers.get('If-None-Match') == page['etag']:
            self.send_response(304)
            self.send_header('ETag', page['etag'])
            self.end_headers()
            return
        self.send_bytes(200, page['raw'], 'text/html; charset=utf-8', gz=page['gz'],
                        headers={'Cache-Control': 'no-cache', 'ETag': page['etag']})

    def api_login(self):
        ip = self.client_ip()
        if too_many_fails(ip):
            return self.send_json(429, {'error': 'Too many attempts. Try again in 10 minutes.'})
        pw = str(self.read_json().get('password') or '')
        if hmac.compare_digest(hashlib.sha256(pw.encode()).hexdigest(), PW_SHA256):
            return self.send_json(200, {'token': make_session()})
        note_fail(ip)
        time.sleep(0.4)
        return self.send_json(401, {'error': 'Incorrect access code.'})

    def api_data(self, query):
        note_activity()
        if not all_loaded():
            return self.send_json(503, warming_status())
        p = payload()
        v = urllib.parse.parse_qs(query).get('v', [''])[0]
        headers = self.sync_headers()
        if v and v == p['key']:
            return self.send_json(200, {'unchanged': True, 'version': v}, headers)
        headers['Cache-Control'] = 'no-store'
        self.send_bytes(200, p['raw'], 'application/json; charset=utf-8', gz=p['gz'], headers=headers)

    def api_refresh(self):
        note_activity()
        if not all_loaded():
            return self.send_json(503, warming_status())
        pending = request_refresh()
        errors = {t.key: t.error for t in TABLES.values() if t.error}
        return self.send_json(200, {'ok': not errors, 'pending': pending, 'errors': errors}, self.sync_headers())

    def api_patch(self):
        note_activity()
        body = self.read_json()
        t = TABLES.get(body.get('table'))
        rid = body.get('id') or ''
        fields = body.get('fields')
        if not t or not RID.match(rid) or not isinstance(fields, dict) or not fields:
            return self.send_json(400, {'error': 'Bad request'})
        allowed = set(t.fields) if t.fields else None
        if allowed is not None:
            unknown = [f for f in fields if f not in allowed]
            if unknown:
                return self.send_json(400, {'error': 'Not an editable field: ' + ', '.join(unknown)[:200]})
        try:
            rec = airtable('PATCH', '/v0/%s/%s/%s' % (BASE_ID, t.id, rid), {'fields': fields, 'typecast': True}, attempts=3)
        except Exception as e:
            log('[patch] %s %s failed: %s' % (t.key, rid, str(e)[:200]))
            return self.send_json(502, {'error': str(e)[:200]})
        if allowed is not None:
            rec['fields'] = {k: v for k, v in (rec.get('fields') or {}).items() if k in allowed}
        with DATA_LOCK:
            t.local_writes[rid] = time.time()
            if t.in_window(rec):
                t.records[rid] = rec
            else:
                t.records.pop(rid, None)
            bump()
        return self.send_json(200, {'ok': True, 'record': rec})

    def api_stats(self):
        data = platform_stats()
        if data is None:
            return self.send_json(502, {'error': 'Kit and Typeform totals are unavailable right now.'})
        return self.send_json(200, data)

    def api_health(self):
        note_activity()
        with DATA_LOCK:
            tables = {
                k: {
                    'records': sum(1 for r in t.records.values() if t.in_window(r)),
                    'syncedAt': datetime.fromtimestamp(t.synced_at, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') if t.synced_at else None,
                    'lastFull': datetime.fromtimestamp(t.last_full, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') if t.last_full else None,
                    'error': t.error,
                } for k, t in TABLES.items()
            }
        return self.send_json(200, {
            'ready': all_loaded(),
            'syncedAt': synced_at(),
            'records': sum(v['records'] for v in tables.values()),
            'tables': tables,
            'airtableError': AT_STATUS['last_error'],
        })


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def boot():
    if not TOKEN:
        log('[boot] AIRTABLE_TOKEN is not set; the dashboard cannot load data')
    threading.Thread(target=scheduler, name='scheduler', daemon=True).start()
    t0 = time.monotonic()

    def report():
        while not all_loaded():
            time.sleep(1)
        log('[boot] all tables cached in %.1fs: %s' % (
            time.monotonic() - t0, ', '.join('%s %d' % (t.key, len(t.records)) for t in TABLES.values())))
    threading.Thread(target=report, daemon=True).start()


if __name__ == '__main__':
    boot()
    log('[boot] listening on :%d' % PORT)
    Server(('0.0.0.0', PORT), Handler).serve_forever()
