#!/usr/bin/env python3
"""Serialize shared venv updates across ACK windows; the OS releases stale locks."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

if os.name == 'nt':
    import msvcrt
else:
    import fcntl

parser = argparse.ArgumentParser()
parser.add_argument('home', type=Path)
parser.add_argument('sdk', type=Path)
parser.add_argument('gateway', type=Path)
parser.add_argument('revision')
parser.add_argument('--force', action='store_true')
args = parser.parse_args()
active = None


def stop(signum, _frame):
    if active is not None and active.poll() is None:
        if os.name == 'nt':
            active.terminate()
        else:
            os.killpg(active.pid, signal.SIGTERM)
        try:
            active.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if os.name == 'nt':
                active.kill()
            else:
                os.killpg(active.pid, signal.SIGKILL)
            active.wait()
    raise SystemExit(128 + signum)


for sig in (signal.SIGTERM, signal.SIGINT, *([signal.SIGHUP] if hasattr(signal, 'SIGHUP') else [])):
    signal.signal(sig, stop)


def run(command):
    global active
    active = subprocess.Popen(command, start_new_session=True)
    try:
        code = active.wait(timeout=240)
    except subprocess.TimeoutExpired:
        stop(signal.SIGTERM, None)
    if code:
        raise SystemExit(code)
    active = None


args.home.mkdir(parents=True, exist_ok=True, mode=0o700)
lock_fd = os.open(args.home / 'runtime-install.lock', os.O_CREAT | os.O_RDWR, 0o600)
with os.fdopen(lock_fd, 'a+') as lock:
    if os.name == 'nt':
        # Retry nonblocking byte-range locks: LK_LOCK gives up after ten seconds,
        # while a package install can legitimately take several minutes.
        import errno
        while True:
            lock.seek(0)
            try:
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                    raise
                time.sleep(0.1)
    else:
        fcntl.flock(lock, fcntl.LOCK_EX)
    marker = args.home / 'gateway.json'
    venv = args.home / 'venv'
    binary = venv / ('Scripts' if os.name == 'nt' else 'bin')
    suffix = '.exe' if os.name == 'nt' else ''
    if not args.force and (binary / f'adverserial-confidential-gateway{suffix}').exists():
        try:
            if json.loads(marker.read_text()).get('revision') == args.revision:
                raise SystemExit(0)
        except (OSError, ValueError):
            pass
    if not (binary / f'python{suffix}').exists():
        run([sys.executable, '-m', 'venv', str(venv)])
    pip = [str(binary / f'python{suffix}'), '-m', 'pip']
    run([*pip, 'install', '--disable-pip-version-check', '--no-input', '--no-deps', '--force-reinstall', str(args.sdk)])
    run([*pip, 'install', '--disable-pip-version-check', '--no-input', str(args.gateway)])
    temporary = marker.with_name(f'gateway.json.{os.getpid()}.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump({'revision': args.revision}, output)
    os.replace(temporary, marker)
