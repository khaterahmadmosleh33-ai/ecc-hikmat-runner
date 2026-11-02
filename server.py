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

VERSION = '1.3.0'
KEY = os.environ.get('ECC_RUNNER_SECRET', '')
BOOT = str(uuid.uuid4())
ROOT = Path(os.environ.get('ECC_RUNNER_ROOT', '/var/lib/ecc'))
GUEST = int(os.environ.get('ECC_GUEST_UID', '10001'))
if not 10000 <= GUEST < 65534:
    raise SystemExit('ECC_GUEST_UID must be an unprivileged UID from 10000 to 65533.')
MAX_FILE = 98304
MAX_OUTPUT = 65536
LOCK = threading.RLock()
JOBS = {}
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


def kill_guests_direct():
    # Kill detached grandchildren too; all guest operations are serialized.
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            if entry.stat().st_uid == GUEST:
                os.kill(int(entry.name), signal.SIGKILL)
        except (ProcessLookupError, FileNotFoundError, PermissionError):
            pass


def kill_guests():
    # Managed hosts may remove CAP_KILL from coordinator root. A short-lived
    # helper drops to the dedicated guest UID and signals its own UID's tasks.
    subprocess.run([sys.executable, str(Path(__file__).resolve()), '--cleanup'],
                   env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'ECC_GUEST_UID': str(GUEST)},
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=5, check=True)


def reap_orphans():
    # Called only after the serialized foreground child was already waited for.
    deadline = time.monotonic() + .5
    while time.monotonic() < deadline:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
            if not pid:
                time.sleep(.01)
        except ChildProcessError:
            break


def session(value):
    sid = identifier(value)
    s = SESSIONS.get(sid)
    if not s or s.get('closing'):
        raise Problem('Session closed or service restarted. Start a new session; restore saved files.', 409)
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


def job_view(job):
    return {k: v for k, v in job.items() if k not in ('cancel', 'thread')}


def execute(base, command, job):
    proc = None
    sel = selectors.DefaultSelector()
    started = time.monotonic()
    outcome = 'complete'
    try:
        proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--guest', command], cwd=base,
            env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(base), 'LANG': 'C.UTF-8',
                 'TMPDIR': str(base), 'NODE_OPTIONS': '--max-old-space-size=128', 'ECC_GUEST_UID': str(GUEST)},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for name in ('stdout', 'stderr'):
            stream = getattr(proc, name)
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, name)
        while sel.get_map() or proc.poll() is None:
            if job['cancel'].is_set():
                outcome = 'cancelled'
                break
            if job['timeout_seconds'] is not None and time.monotonic() - started >= job['timeout_seconds']:
                outcome = 'timeout'
                break
            for key, _ in sel.select(.1):
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                with LOCK:
                    name = key.data
                    value = job[name].encode('utf-8') + chunk
                    if len(value) > MAX_OUTPUT // 2:
                        job['output_truncated'] = True
                    job[name] = value[-MAX_OUTPUT // 2:].decode('utf-8', errors='replace')
            if not sel.get_map() and proc.poll() is None:
                time.sleep(.05)
    except Exception:
        outcome = 'failed'
    finally:
        # Cancellation may arrive before the helper has dropped privileges.
        # Always kill the exact child/group as well as detached guest descendants.
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            if proc.poll() is None:
                try:
                    proc.kill()
                except (ProcessLookupError, PermissionError):
                    pass
        kill_guests()
        if proc is not None:
            proc.wait(timeout=5)
            kill_guests()
            proc.stdout.close()
            proc.stderr.close()
        reap_orphans()
        sel.close()
        with LOCK:
            job.update(outcome=outcome, exit_code=proc.returncode if proc else None, finished=time.time())
            sid = job['session_id']
            if SESSIONS.get(sid, {}).get('closing'):
                shutil.rmtree(ROOT / sid, ignore_errors=True)
                del SESSIONS[sid]


def start_job(base, sid, a):
    command = a.get('command')
    if not isinstance(command, str) or not command.strip() or len(command) > 12000:
        raise Problem('Command must have 1–12000 characters.')
    timeout = a.get('timeout_seconds')
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 604800):
        raise Problem('Optional timeout must be positive and at most seven days.')
    if any(j['outcome'] == 'running' for j in JOBS.values()):
        raise Problem('A job is running. Inspect or cancel it before starting another.', 409)
    jid = identifier(a.get('request_id'))
    job = dict(job_id=jid, session_id=sid, boot_id=BOOT, outcome='running', started=time.time(),
               finished=None, exit_code=None, stdout='', stderr='', output_truncated=False,
               timeout_seconds=timeout, cancel=threading.Event())
    JOBS[jid] = job
    job['thread'] = threading.Thread(target=execute, args=(base, command, job), daemon=True)
    job['thread'].start()
    return job_view(job)


def dispatch(path, a):
    if path == '/v1/start':
        sid = identifier(a.get('session_id'))
        if sid not in SESSIONS:
            if len(SESSIONS) >= 1:
                raise Problem('Stop the current session before starting another.', 409)
            base = ROOT / sid
            base.mkdir(mode=0o700)
            os.chown(base, GUEST, GUEST)
            SESSIONS[sid] = {'id': sid, 'created': time.time(), 'expires': None}
        return {'outcome': 'started', 'session': SESSIONS[sid], 'boot_id': BOOT}
    if path in ('/v1/job', '/v1/cancel'):
        job = JOBS.get(identifier(a.get('job_id')))
        if not job or job['session_id'] != identifier(a.get('session_id')):
            raise Problem('Job missing or service restarted.', 409)
        if path == '/v1/cancel' and job['outcome'] == 'running':
            job['cancel'].set()
        return job_view(job)
    sid, base = session(a.get('session_id'))
    if path == '/v1/session':
        return {'session': SESSIONS[sid], 'jobs': [job_view(j) for j in JOBS.values() if j['session_id'] == sid], 'boot_id': BOOT}
    if path == '/v1/exec':
        return start_job(base, sid, a)
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
        active = next((j for j in JOBS.values() if j['session_id'] == sid and j['outcome'] == 'running'), None)
        if active:
            SESSIONS[sid]['closing'] = True
            active['cancel'].set()
            return {'outcome': 'stopping', 'job_id': active['job_id'], 'boot_id': BOOT}
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
                    'kind': 'owner-trusted-code-container', 'max_command_seconds': None, 'async_jobs': True,
                    'session_seconds': None, 'network': 'outbound-enabled'})

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
            if self.path == '/v1/probe':
                return self.reply({'ok': True, 'version': VERSION, 'boot_id': BOOT,
                                   'kind': 'owner-trusted-code-container'})
            if self.path in ('/v1/session', '/v1/result', '/v1/job'):
                if self.path == '/v1/result':
                    item = RESULTS.get(identifier(a.get('request_id')))
                    return self.reply(job_view(JOBS[a['request_id']]) if a['request_id'] in JOBS else item['result'] if item else {'outcome': 'unknown', 'boot_id': BOOT})
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
    if len(sys.argv) == 2 and sys.argv[1] == '--cleanup':
        os.setsid()
        if ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) != 0:
            os._exit(126)
        os.setgroups([])
        os.setgid(GUEST)
        os.setuid(GUEST)
        kill_guests_direct()
        sys.exit(0)
    if len(sys.argv) == 3 and sys.argv[1] == '--guest':
        guest_limits()
        os.execv('/bin/bash', ['/bin/bash', '-c', sys.argv[2]])
    if os.getuid() != 0 or len(KEY) < 40:
        raise SystemExit('Run as container coordinator root with an ECC_RUNNER_SECRET of at least 40 characters.')
    if ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) != 0:
        raise SystemExit('The coordinator requires Linux child-subreaper support.')
    ROOT.mkdir(mode=0o711, parents=True, exist_ok=True)
    os.chmod(ROOT, 0o711)
    ThreadingHTTPServer(('0.0.0.0', int(os.environ.get('PORT', '10000'))), Handler).serve_forever()
