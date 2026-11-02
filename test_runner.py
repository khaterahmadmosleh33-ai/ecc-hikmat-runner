import importlib.util
import json
import os
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

spec = importlib.util.spec_from_file_location('runner', Path(__file__).with_name('server.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


@unittest.skipIf(Path('/proc/self/uid_map').exists() and
                all(int(row.split()[2]) <= 1 for row in Path('/proc/self/uid_map').read_text().splitlines()),
                'This environment maps only UID 0; full integration runs in the Docker build.')
class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ecc-runner-test-')
        m.ROOT = Path(self.tmp.name)
        m.ROOT.chmod(0o711)
        m.SESSIONS.clear()
        self.sid = str(uuid.uuid4())
        m.dispatch('/v1/start', {'session_id': self.sid})

    def tearDown(self):
        m.kill_guests()
        self.tmp.cleanup()

    def call(self, path, **data):
        return m.dispatch('/v1/' + path, {'session_id': self.sid, **data})

    def test_execution_and_secret_separation(self):
        os.environ['ECC_RUNNER_SECRET'] = 'never-pass-this-to-guest'
        r = self.call('exec', command="python3 -c 'import os; print(os.getuid()); print(os.environ.get(\"ECC_RUNNER_SECRET\", \"absent\"))'")
        self.assertEqual(r['exit_code'], 0)
        self.assertEqual(r['stdout'], '10001\nabsent\n')
        r = self.call('exec', command='node -p "6 * 7"')
        self.assertEqual(r['exit_code'], 0, r)
        self.assertEqual(r['stdout'].strip(), '42')

    def test_files_and_symlinks(self):
        text = 'سلام حکمت'
        self.call('file', action='write', path='src/main.txt', text=text)
        self.assertEqual(self.call('file', action='read', path='src/main.txt')['text'], text)
        for path in ('../server.py', '/etc/passwd', 'a/../../etc/passwd'):
            with self.assertRaises(m.Problem):
                self.call('file', action='read', path=path)
        self.call('exec', command='ln -s /etc/passwd leak')
        with self.assertRaises(m.Problem):
            self.call('file', action='read', path='leak')
        self.call('exec', command='mkfifo fifo')
        with self.assertRaises(m.Problem):
            self.call('file', action='read', path='fifo')

    def test_output_and_detached_process_cleanup(self):
        r = self.call('exec', command="python3 -c 'print(\"x\" * 100000)' ")
        self.assertEqual(r['outcome'], 'output_limit')
        self.assertLessEqual(len(r['stdout'].encode()) + len(r['stderr'].encode()), m.MAX_OUTPUT)
        r = self.call('exec', command='setsid sleep 120 >/dev/null 2>&1 & echo $!')
        pid = int(r['stdout'])
        time.sleep(.1)
        state = Path('/proc') / str(pid) / 'stat'
        self.assertTrue(not state.exists() or state.read_text().split()[2] == 'Z')
        r = self.call('exec', command='sleep 60')
        self.assertEqual(r['outcome'], 'timeout')

    def test_stop_and_restart_detection(self):
        self.assertEqual(self.call('stop')['outcome'], 'stopped')
        with self.assertRaises(m.Problem):
            self.call('session')

    def test_http_auth_and_idempotency(self):
        # Keep the HTTP API under test in a separate process.
        key = 'a' * 48
        proc = subprocess.Popen(['python3', str(Path(__file__).with_name('server.py'))],
            env={**os.environ, 'ECC_RUNNER_SECRET': key, 'PORT': '18767',
                 'ECC_RUNNER_ROOT': str(m.ROOT / 'http')}, stdout=subprocess.DEVNULL)
        def request(path, data, auth=key):
            req = Request('http://127.0.0.1:18767' + path, json.dumps(data).encode(),
                          headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + auth})
            return json.load(urlopen(req, timeout=20))
        try:
            for _ in range(60):
                try:
                    urlopen('http://127.0.0.1:18767/health', timeout=1).close()
                    break
                except OSError:
                    time.sleep(.05)
            a = {'request_id': str(uuid.uuid4()), 'session_id': str(uuid.uuid4())}
            with self.assertRaises(HTTPError) as e:
                request('/v1/start', a, 'wrong')
            self.assertEqual(e.exception.code, 401)
            self.assertEqual(request('/v1/probe', {})['kind'], 'owner-trusted-code-container')
            first = request('/v1/start', a)
            self.assertEqual(first, request('/v1/start', a))
            b = {'request_id': str(uuid.uuid4()), 'session_id': a['session_id'], 'command': 'echo ran >> count; cat count'}
            first = request('/v1/exec', b)
            self.assertEqual(first['stdout'], 'ran\n')
            self.assertEqual(first, request('/v1/exec', b))
            self.assertEqual(request('/v1/result', {'request_id': b['request_id']}), first)
            with self.assertRaises(HTTPError) as e:
                request('/v1/exec', {**b, 'command': 'echo different'})
            self.assertEqual(e.exception.code, 409)
        finally:
            proc.terminate()
            proc.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
