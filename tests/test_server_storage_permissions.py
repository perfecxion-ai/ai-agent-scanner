"""Documented server entry points protect new files without chmod on old data."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Supported server entry points require POSIX')


def test_gunicorn_configuration_selects_private_umask_without_changing_process():
    program = '''
import json
import os
import runpy
import sys
config = runpy.run_path(sys.argv[1])
print(json.dumps({"mask": os.umask(0o022), "configured": config["umask"],
                  "hooks": all(callable(config[name]) for name in ("post_fork", "post_worker_init", "worker_exit"))}))
'''
    result = subprocess.run([sys.executable, '-c', program, str(ROOT / 'gunicorn.conf.py')],
                            capture_output=True, text=True, timeout=10, check=True, umask=0o022)
    assert json.loads(result.stdout) == {'mask': 0o022, 'configured': 0o077, 'hooks': True}


@pytest.mark.parametrize('entrypoint', ['container', 'gunicorn_worker', 'gunicorn_fork'])
def test_server_entrypoint_creates_private_sqlite_and_preserves_existing_data(tmp_path, entrypoint):
    old_file = tmp_path / 'existing.sqlite'
    old_file.write_bytes(b'operator-owned fixture')
    old_file.chmod(0o644)
    old_directory = tmp_path / 'existing-volume'
    old_directory.mkdir(mode=0o755)
    old_directory.chmod(0o755)
    # Run each actual entrypoint with an intentionally permissive inherited mask.
    # All work is bounded to pytest's disposable directory, not operator storage.
    program = '''
import json
from pathlib import Path
import sqlite3
import stat
import sys
import runpy
from types import SimpleNamespace
root = Path(sys.argv[1])
def create_storage():
    directory = root / "new-instance"
    directory.mkdir()
    database = directory / "reports.sqlite"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE report (id INTEGER)")
    connection.execute("INSERT INTO report VALUES (1)")
    lock = directory / "reports.sqlite.dispatcher.lock"
    lock.touch()
    journal = directory / "reports.sqlite-journal"
    mode = lambda path: stat.S_IMODE(path.stat().st_mode)
    print(json.dumps({"directory": mode(directory), "database": mode(database),
                      "journal": mode(journal), "lock": mode(lock)}))
    connection.rollback()
    connection.close()
if len(sys.argv) > 2:
    config = runpy.run_path(sys.argv[2])
    worker = SimpleNamespace(cfg=SimpleNamespace(workers=1))
    if sys.argv[3] == "gunicorn_fork":
        config["post_fork"](None, worker)
        create_storage()
    else:
        sys.modules["app"] = SimpleNamespace(start_job_dispatcher=create_storage)
        config["post_worker_init"](worker)
else:
    create_storage()
'''
    command = [sys.executable, '-c', program, str(tmp_path)]
    if entrypoint == 'container':
        command = ['sh', str(ROOT / 'scripts/container-entrypoint.sh'), *command]
    else:
        command.extend([str(ROOT / 'gunicorn.conf.py'), entrypoint])
    result = subprocess.run(command,
                            capture_output=True, text=True, timeout=15, check=True, umask=0o022)
    assert json.loads(result.stdout) == {'directory': 0o700, 'database': 0o600,
                                        'journal': 0o600, 'lock': 0o600}
    assert old_file.read_bytes() == b'operator-owned fixture'
    assert stat.S_IMODE(old_file.stat().st_mode) == 0o644
    assert stat.S_IMODE(old_directory.stat().st_mode) == 0o755


@pytest.mark.parametrize('hook', ['post_fork', 'post_worker_init'])
def test_rejected_gunicorn_worker_count_does_not_change_process_mask(hook):
    program = '''
import json
import os
import runpy
import sys
from types import SimpleNamespace
config = runpy.run_path(sys.argv[1])
try:
    worker = SimpleNamespace(cfg=SimpleNamespace(workers=2))
    args = (None, worker) if sys.argv[2] == "post_fork" else (worker,)
    config[sys.argv[2]](*args)
except RuntimeError as error:
    assert "exactly one" in str(error)
else:
    raise AssertionError("Multiple workers were not rejected")
print(json.dumps({"mask": os.umask(0o022)}))
'''
    result = subprocess.run([sys.executable, '-c', program, str(ROOT / 'gunicorn.conf.py'), hook],
                            capture_output=True, text=True, timeout=10, check=True, umask=0o022)
    assert json.loads(result.stdout) == {'mask': 0o022}


def test_image_build_creates_private_owned_instance_directory():
    dockerfile = (ROOT / 'Dockerfile').read_text()
    assert 'mkdir -m 0700 /app/instance' in dockerfile
    assert 'chown scanner:scanner /app/instance' in dockerfile
    assert 'USER scanner' in dockerfile
