"""Exercise the real raw-mode terminal UI without an API key or network calls."""
import fcntl
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import tempfile
import termios
import time

ROOT = Path(__file__).resolve().parents[1]


def exercise(arguments):
    with tempfile.TemporaryDirectory(prefix='ack-terminal-') as config:
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 36, 100, 0, 0))
        env = {**os.environ, 'TERM': 'xterm-256color', 'ACK_HOME': config}
        child = subprocess.Popen(['node', str(ROOT / 'bin' / 'ack.mjs'), *arguments], cwd=ROOT,
                                 env=env, stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave)
        output = ''
        first_frame_ms = None
        started = time.monotonic()

        def read(duration=0.12):
            nonlocal output, first_frame_ms
            deadline = time.monotonic() + duration
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], max(0, deadline - time.monotonic()))
                if ready:
                    try:
                        data = os.read(master, 262144)
                    except OSError:
                        break
                    if not data:
                        break
                    output += data.decode('utf8', 'replace')
                    if first_frame_ms is None and 'CONFIDENTIAL CONSOLE' in output:
                        first_frame_ms = (time.monotonic() - started) * 1000

        def send(text):
            os.write(master, text.encode())
            read()

        try:
            read(0.4)
            assert 'CONFIDENTIAL CONSOLE' in output
            if arguments:
                assert 'CODING HARNESSES' in output
                send('\x1b')
            else:
                assert 'Your terminal. Amplified.' in output
            send('code\r')
            assert 'CODING HARNESSES' in output
            send('oh my')
            assert 'Oh My Pi' in output
            send('\x1b')
            send('keys add test-vault\r')
            secret = 'test-secret-must-never-be-rendered'
            send(secret)
            assert secret not in output
            send('\x1b')
            send('theme ember\r')
            send('theme aurora\r')
            send('doctor\r')
            assert 'PASS' in output
            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 60, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            read()
            send('\x0c')
            send('\x1b[5~')
            send('\x1b[6~')
            send('exit\r')
            child.wait(timeout=3)
            assert child.returncode == 0
            assert '\x1b[?1049l' in output
            return first_frame_ms
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
            os.close(master)


if __name__ == '__main__':
    timings = [exercise([]), exercise(['code'])]
    print('PASS: terminal startup, direct code picker, search, hidden input, themes, diagnostics, resize, scroll and clean exit')
    print('First-frame latency: ' + ', '.join(f'{value:.0f}ms' for value in timings))
