"""Keep workstation instructions and artifacts out of the public source tree."""

import os
from pathlib import Path, PurePosixPath
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def local_only(path):
    name = path.name
    return (name == 'AGENTS.md' or name.startswith('AGENTS.') and name.endswith('.md')
            or name.endswith('.target.json') or name in {'assessment-results.json', 'assessment-results.sarif'}
            or path.as_posix() in {'lab.toml', 'docs/images/scan-demo.png'}
            or any(part in {'.codex', '.claude', '.aiscan-targets'} for part in path.parts))


def test_public_index_has_no_local_instructions_or_workstation_artifacts():
    # The Git index, not the filesystem: local ignored copies must remain usable.
    result = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT,
                            capture_output=True, check=True, timeout=5)
    names = [PurePosixPath(item.decode()) for item in result.stdout.split(b'\0') if item]
    assert not [path.as_posix() for path in names if local_only(path)]


def test_ignore_policy_covers_nested_instructions_without_hiding_public_examples(tmp_path):
    environment = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
    subprocess.run(['git', 'init', '--quiet', str(tmp_path)],
                   env=environment, check=True, capture_output=True, timeout=5)
    (tmp_path / '.gitignore').write_bytes((ROOT / '.gitignore').read_bytes())
    ignored = {'AGENTS.md', 'AGENTS.local.md', 'nested/AGENTS.md', 'nested/AGENTS.override.md',
               '.codex/config.toml', 'nested/.codex/config.toml', 'lab.toml', 'docs/images/scan-demo.png',
               'support.target.json', 'nested/support.target.json', '.aiscan-targets/profile.json',
               'assessment-results.json', 'nested/assessment-results.sarif'}
    public = {'.env.example', 'docs/ENGINEERING_PLAN.md', 'examples/offline-lab/client.py',
              'tests/fixtures/legacy_access_v3/high.json'}
    result = subprocess.run(['git', 'check-ignore', '--stdin'], cwd=tmp_path, env=environment,
                            input='\n'.join(sorted(ignored | public)) + '\n',
                            capture_output=True, text=True, check=True, timeout=5)
    assert set(result.stdout.splitlines()) == ignored
