"""Owner-only command runner. This is a shared container, not a VM sandbox."""
import ctypes
import hashlib
import hmac
import json
import os
import re
import resource
import selectors
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = '1.2.0'
KEY = os.environ.get('ECC_RUNNER_SECRET', '')
BOOT = str(uuid.uuid4())
ROOT = Path(os.environ.get('ECC_RUNNER_ROOT', '/var/lib/ecc'))
GUEST = 10001
MAX_FILE = 98304
MAX_OUTPUT = 65536
LOCK = threading.Lock()
SESSIONS = {}
RESULTS = {}


class Problem(Exception):
    def __init__(self, message, status=400):
        self.status = status
        super().__init__(message)


def identifier(value):
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise Problem('A UUID is required.')


def guest_limits():
    os.setsid()
    resource.setrlimit(resource.RLIMIT_CPU, (15, 16))
    # V8 reserves a large virtual address cage; JS heap is capped separately.
    resource.setrlimit(resource.RLIMIT_AS, (16 * 1024**3, 16 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024**2, 16 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NPROC, (24, 24))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) != 0:
        os._exit(126)
    os.setgroups([])
    os.setgid(GUEST)
    os.setuid(GUEST)


def kill_guests():
    # Kill detached grandchildren too; all guest operations are serialized.
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid == GUEST:
                os.kill(int(entry.name), signal.SIGKILL)
        except (ProcessLookupError, FileNotFoundError, PermissionError):
            pass


def session(value):
    sid = identifier(value)
    s = SESSIONS.get(sid)
    if not s or s['expires'] < time.time():
        raise Problem('Session expired or service restarted. Start a new session; restore saved files.', 409)
    return sid, ROOT / sid


def safe_file(base, path, create=False):
    # Open each component relative to a directory descriptor with O_NOFOLLOW.
    if not isinstance(path, str) or not re.fullmatch(r'[A-Za-z0-9_./-]{1,200}', path):
        raise Problem('Use a relative text-file path.')
    parts = path.split('/')
    if any(p in ('', '.', '..') for p in parts):
        raise Problem('Invalid path.')
    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    os.chown(part, GUEST, GUEST, dir_fd=fd, follow_symlinks=False)
                except FileExistsError:
                    pass
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        flags = os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_WRONLY | os.O_CREAT | os.O_TRUNC if create else os.O_RDONLY)
        out = os.open(parts[-1], flags, 0o600, dir_fd=fd)
        import stat
        if not stat.S_ISREG(os.fstat(out).st_mode):
            os.close(out)
            raise Problem('Only regular text files are supported.')
        if create:
            os.fchown(out, GUEST, GUEST)
        return out
    finally:
        os.close(fd)


def execute(base, command):
    if not isinstance(command, str) or not command.strip() or len(command) > 12000:
        raise Problem('Command must have 1–12000 characters.')
    proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--guest', command], cwd=base,
        env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(base), 'LANG': 'C.UTF-8',
             'TMPDIR': str(base), 'NODE_OPTIONS': '--max-old-space-size=128'},
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sel = selectors.DefaultSelector()
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    for name in output:
        stream = getattr(proc, name)
        os.set_blocking(stream.fileno(), False)
        sel.register(stream, selectors.EVENT_READ, name)
    deadline = time.monotonic() + 15
    outcome = 'complete'
    try:
        while sel.get_map():
            if time.monotonic() >= deadline:
                outcome = 'timeout'
                break
            for key, _ in sel.select(min(.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                output[key.data].extend(chunk)
                if sum(map(len, output.values())) > MAX_OUTPUT:
                    outcome = 'output_limit'
                    break
            if outcome != 'complete':
                break
        if outcome == 'complete':
            try:
                proc.wait(timeout=max(.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                outcome = 'timeout'
    finally:
        kill_guests()
        proc.wait(timeout=3)
        sel.close()
        proc.stdout.close()
        proc.stderr.close()
    remaining = MAX_OUTPUT
    texts = {}
    for name, raw in output.items():
        texts[name] = raw[:remaining].decode('utf-8', errors='replace')
        remaining = max(0, remaining - len(raw))
    return {'outcome': outcome, 'exit_code': proc.returncode, **texts, 'boot_id': BOOT}


def dispatch(path, a):
    now = time.time()
    for sid, s in list(SESSIONS.items()):
        if s['expires'] < now:
            shutil.rmtree(ROOT / sid, ignore_errors=True)
            del SESSIONS[sid]
    if path == '/v1/start':
        sid = identifier(a.get('session_id'))
        if sid not in SESSIONS:
            if len(SESSIONS) >= 1:
                raise Problem('Stop the current session before starting another.', 409)
            base = ROOT / sid
            base.mkdir(mode=0o700)
            os.chown(base, GUEST, GUEST)
            SESSIONS[sid] = {'id': sid, 'expires': now + 1800}
        return {'outcome': 'started', 'session': SESSIONS[sid], 'boot_id': BOOT}
    sid, base = session(a.get('session_id'))
    if path == '/v1/session':
        return {'session': SESSIONS[sid], 'boot_id': BOOT}
    if path == '/v1/exec':
        return execute(base, a.get('command'))
    if path == '/v1/file':
        writing = a.get('action') == 'write'
        if a.get('action') not in ('read', 'write'):
            raise Problem('Choose read or write.')
        raw = a.get('text', '').encode('utf-8') if writing and isinstance(a.get('text', ''), str) else b''
        if len(raw) > MAX_FILE:
            raise Problem('Text file exceeds 96 KiB.', 413)
        try:
            fd = safe_file(base, a.get('path'), writing)
            with os.fdopen(fd, 'wb' if writing else 'rb') as f:
                if writing:
                    f.write(raw)
                else:
                    raw = f.read(MAX_FILE + 1)
                    if len(raw) > MAX_FILE:
                        raise Problem('Text file exceeds 96 KiB.', 413)
            return {'outcome': 'written' if writing else 'read', 'path': a['path'], 'bytes': len(raw),
                    **({} if writing else {'text': raw.decode('utf-8')}), 'boot_id': BOOT}
        except (OSError, UnicodeError):
            raise Problem('File is missing, unsafe, or not UTF-8.', 400)
    if path == '/v1/stop':
        kill_guests()
        shutil.rmtree(base)
        del SESSIONS[sid]
        return {'outcome': 'stopped', 'boot_id': BOOT}
    raise Problem('Unknown endpoint.', 404)


class Handler(BaseHTTPRequestHandler):
    server_version = 'ECC'
    def log_message(self, *_):
        pass  # Never log credentials, commands, or source text.

    def reply(self, value, status=200):
        raw = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path not in ('/', '/health'):
            return self.reply({'error': 'Not found'}, 404)
        self.reply({'ok': True, 'version': VERSION, 'boot_id': BOOT,
                    'kind': 'owner-trusted-code-container', 'max_command_seconds': 15,
                    'session_seconds': 1800, 'network': 'outbound-enabled'})

    def do_POST(self):
        acquired = False
        try:
            self.connection.settimeout(10)
            auth = self.headers.get('Authorization', '')
            if not hmac.compare_digest(auth, 'Bearer ' + KEY):
                raise Problem('Unauthorized', 401)
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                raise Problem('JSON required.', 415)
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 196608:
                raise Problem('Request size limit.', 413)
            raw = self.rfile.read(size)
            a = json.loads(raw)
            if not isinstance(a, dict):
                raise Problem('JSON object required.')
            acquired = LOCK.acquire(blocking=False)
            if not acquired:
                raise Problem('An operation is in progress. Inspect the existing request.', 409)
            if self.path in ('/v1/session', '/v1/result'):
                if self.path == '/v1/result':
                    item = RESULTS.get(identifier(a.get('request_id')))
                    return self.reply(item['result'] if item else {'outcome': 'unknown', 'boot_id': BOOT})
                return self.reply(dispatch(self.path, a))
            rid = identifier(a.get('request_id'))
            digest = hashlib.sha256(self.path.encode() + raw).hexdigest()
            if rid in RESULTS:
                item = RESULTS[rid]
                if item['digest'] != digest:
                    raise Problem('Request ID already belongs to different input.', 409)
                return self.reply(item['result'])
            if len(RESULTS) >= 2000:
                raise Problem('Service operation ledger full; restart after saving files.', 409)
            RESULTS[rid] = {'digest': digest, 'result': {'outcome': 'unknown', 'boot_id': BOOT}}
            result = dispatch(self.path, a)
            RESULTS[rid]['result'] = result
            self.reply(result)
        except Problem as e:
            self.reply({'error': str(e), 'boot_id': BOOT}, e.status)
        except (ValueError, TypeError, KeyError):
            self.reply({'error': 'Invalid request.', 'boot_id': BOOT}, 400)
        except Exception:
            self.reply({'error': 'Operation interrupted. Inspect its request ID before retrying.', 'boot_id': BOOT}, 500)
        finally:
            if acquired:
                LOCK.release()


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--guest':
        guest_limits()
        os.execv('/bin/bash', ['/bin/bash', '-c', sys.argv[2]])
    if os.getuid() != 0 or len(KEY) < 40:
        raise SystemExit('Run as container coordinator root with an ECC_RUNNER_SECRET of at least 40 characters.')
    ROOT.mkdir(mode=0o711, parents=True, exist_ok=True)
    os.chmod(ROOT, 0o711)
    ThreadingHTTPServer(('0.0.0.0', int(os.environ.get('PORT', '10000'))), Handler).serve_forever()
