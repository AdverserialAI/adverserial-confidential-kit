"""Exercise the real installer lock without network or package installation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().parents[2] / 'install-runtime.py'


class RuntimeInstallTests(unittest.TestCase):
    def test_two_initializers_install_once_and_a_failed_installer_releases_the_lock(self):
        for fail_once in (False, True):
            with self.subTest(fail_once=fail_once), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                binary = home / 'venv/bin'
                binary.mkdir(parents=True)
                (binary / 'python').touch()
                pip = binary / 'pip'
                pip.write_text(f'''#!{sys.executable}
from pathlib import Path
import sys, time
home=Path(__file__).resolve().parents[2]
with open(home/'calls', 'a') as log: log.write('install\\n')
lock=home/'pip-active'
with open(lock, 'x'): pass
time.sleep(.1)
lock.unlink()
if {fail_once!r} and not (home/'failed-once').exists():
    (home/'failed-once').touch()
    raise SystemExit(1)
if sys.argv[-1]=='gateway-package':
    (home/'venv/bin/adverserial-confidential-gateway').touch()
''')
                pip.chmod(0o700)
                command = [sys.executable, str(INSTALLER), str(home), 'sdk-package', 'gateway-package', 'test@1']
                children = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
                statuses = []
                for child in children:
                    output, error = child.communicate(timeout=15)
                    statuses.append(child.returncode)
                self.assertEqual(sorted(statuses), [0, 1] if fail_once else [0, 0])
                self.assertEqual(len((home / 'calls').read_text().splitlines()), 3 if fail_once else 2)
                self.assertEqual(json.loads((home / 'gateway.json').read_text())['revision'], 'test@1')
                self.assertFalse((home / 'pip-active').exists())
                self.assertEqual(os.stat(home / 'gateway.json').st_mode & 0o777, 0o600)
