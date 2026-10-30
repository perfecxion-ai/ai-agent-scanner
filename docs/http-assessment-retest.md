# Scoped native HTTP application retest

Use a disposable clean checkout at the full merged SHA supplied with the handoff.
Set that SHA as `AIS_HTTP_REVISION`; do not substitute a branch name or an earlier
feature commit. Run only after the merged revision passes its required CI checks.

This gate uses the public driver, owned loopback HTTP/HTTPS applications and the
actual CLI. It needs Python, package-index access for isolated installation and a
POSIX local filesystem. Existing model services, target VMs, operator databases,
profiles, credentials, lab configuration, schedules and cloud restarts are not
inputs. The fixture's temporary CA affects only its owned children; no global
trust, deployment or package publication changes are needed.

## Run and retain genuine exits

Run from the checkout in a clean shell without sourcing lab configuration. Keep
earlier captures unchanged. The wrapper creates separate private work and capture
directories. It retains captures and checks removal of its owned work directory
on success and failure. Setup failures stop dependent steps; attempted commands
keep their actual exit status. An absent capture is not success.

```bash
set -eu
: "${AIS_HTTP_REVISION:?Set the full merged SHA from the handoff}"
test -z "$(git status --porcelain)"
git checkout --detach "$AIS_HTTP_REVISION"
test "$(git rev-parse HEAD)" = "$AIS_HTTP_REVISION"
env -i PATH="$PATH" PYTHONUTF8=1 PYTHONNOUSERSITE=1 \
  python3 -I - "$AIS_HTTP_REVISION" <<'PY'
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import site
import subprocess
import sys
import tempfile
import threading
import time

revision = sys.argv[1]
if not re.fullmatch(r'[0-9a-f]{40}', revision):
    raise SystemExit('A full merged revision is required')
checkout = Path.cwd().resolve()
os.umask(0o077)
work = Path(tempfile.mkdtemp(prefix='aiscan-http-retest-work-')).resolve()
captures = Path(tempfile.mkdtemp(prefix='aiscan-http-retest-captures-')).resolve()
work_identity = (work.stat().st_dev, work.stat().st_ino)
print('Captures:', captures, flush=True)
deadline = time.monotonic() + 1800
environment = {'PATH': os.defpath, 'HOME': str(work), 'TMPDIR': str(work),
    'XDG_CONFIG_HOME': str(work), 'XDG_CACHE_HOME': str(work), 'PYTHONUTF8': '1',
    'PYTHONNOUSERSITE': '1', 'PIP_DISABLE_PIP_VERSION_CHECK': '1',
    'PIP_CONFIG_FILE': os.devnull, 'PIP_CACHE_DIR': str(work / 'pip-cache'),
    'SCAN_EVIDENCE_PROFILES_FILE': str(work / 'absent-operator-registry.json')}
failures, exits = [], {}
process_library = None
interrupted = threading.Event()
for number in (signal.SIGTERM, signal.SIGINT):
    signal.signal(number, lambda *_: interrupted.set())

def write(name, value):
    path = captures / name
    with path.open('x', encoding='utf-8') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(value)

def record(name, value):
    write(name, json.dumps(value, indent=2, sort_keys=True) + '\n')

def run(label, command, *, cwd=checkout, seconds=300, structured=False):
    if interrupted.is_set() or time.monotonic() >= deadline:
        raise RuntimeError('outer_work_deadline_or_interruption')
    suffix = '.json' if structured else '.log'
    overflow = threading.Event()
    capture_failed = threading.Event()
    descendants = {}
    def drain(source, destination):
        remaining = 8 * 1024 * 1024
        try:
            while chunk := source.read(65536):
                allowance = remaining
                destination.write(chunk[:allowance])
                remaining -= min(allowance, len(chunk))
                if len(chunk) > allowance:
                    overflow.set()
        except Exception:
            capture_failed.set()
        finally:
            source.close()
    with (captures / (label + suffix)).open('xb') as stdout, \
            (captures / (label + '.stderr')).open('xb') as stderr:
        os.fchmod(stdout.fileno(), 0o600)
        os.fchmod(stderr.fileno(), 0o600)
        process = subprocess.Popen(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        readers = [threading.Thread(target=drain, args=(source, destination), daemon=True)
                   for source, destination in ((process.stdout, stdout), (process.stderr, stderr))]
        stop = min(deadline, time.monotonic() + seconds)
        timed_out = False
        caught = None
        try:
            for reader in readers:
                reader.start()
            while process.poll() is None:
                if process_library is not None:
                    try:
                        for child in process_library.Process(process.pid).children(recursive=True):
                            descendants[(child.pid, child.create_time())] = child
                    except process_library.Error:
                        pass
                if (time.monotonic() >= stop or overflow.is_set() or capture_failed.is_set()
                        or interrupted.is_set()):
                    timed_out = True
                    break
                try:
                    process.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    pass
        except BaseException as error:
            caught = error
        if timed_out or caught is not None:
            failures.append(label + '_outer_timeout_or_output_limit')
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        for child in descendants.values():
            if child.is_running():
                failures.append(label + '_surviving_owned_child')
                try:
                    child.kill()
                except process_library.NoSuchProcess:
                    pass
        if descendants:
            _, alive = process_library.wait_procs(list(descendants.values()), timeout=5)
            if alive:
                failures.append(label + '_unreaped_owned_child')
        for reader in readers:
            if reader.ident is not None:
                reader.join(timeout=5)
            if reader.ident is None or reader.is_alive():
                failures.append(label + '_output_reader_not_stopped')
        if overflow.is_set():
            failures.append(label + '_output_limit')
        if capture_failed.is_set():
            failures.append(label + '_capture_failed')
        code = process.wait(timeout=5)
    exits[label] = code
    write(label + '.exit', str(code) + '\n')
    if code != 0:
        failures.append(label + '_nonzero_exit')
    if caught is not None:
        raise caught
    return code

try:
    source = work / 'source-venv'
    if run('source-venv', [sys.executable, '-m', 'venv', str(source)], seconds=120):
        raise RuntimeError('source_setup_failed')
    source_python = source / 'bin' / 'python'
    if run('source-install', [str(source_python), '-m', 'pip', 'install', '.[dev,server]'], seconds=600):
        raise RuntimeError('source_setup_failed')
    site.addsitedir(str(source / 'lib' / f'python{sys.version_info.major}.{sys.version_info.minor}' / 'site-packages'))
    import psutil
    process_library = psutil
    run('revision', ['git', 'rev-parse', 'HEAD'])
    run('runtime', [str(source_python), '-c',
        'import json,platform,sqlite3; print(json.dumps(dict(python=platform.python_version(),'
        'platform=platform.system(),sqlite=sqlite3.sqlite_version)))'], structured=True)
    run('dependencies', [str(source_python), '-m', 'pip', 'list', '--format=json'], structured=True)
    run('source-build', [str(source_python), '-m', 'scanner_cli', 'build-info', '--json'], structured=True)
    driver = checkout / 'scripts' / 'acceptance-http-assessment.py'
    driver_sha = hashlib.sha256(driver.read_bytes()).hexdigest()
    for label, optimization in [('http-normal', []), ('http-optimized', ['-O'])]:
        run(label, [str(source_python), *optimization, '-Werror', str(driver),
                    '--timeout-seconds', '240'], structured=True)
    focused = [
        'test_http_application_core.py', 'test_http_application_review.py',
        'test_http_target_profiles.py', 'test_http_assessment_cli.py', 'test_http_assessment_acceptance.py',
        'test_prompt_legacy_compatibility.py', 'test_historical_prompt_evidence.py',
        'test_historical_prompt_projection.py', 'test_tenant_observation_contracts.py',
        'test_access_observation_contracts.py', 'test_checkpoints.py',
        'test_cli_checkpoint_store.py', 'test_cli_checkpoint_integration.py',
        'test_cli_checkpoint_process.py', 'test_checkpoint_recovery.py',
        'test_api_risk_projection.py', 'test_prompt_suite_server.py', 'test_job_checkpoints.py',
        'test_prompt_suite_workflow.py', 'test_pipeline_http.py',
        'test_inventory_source_binding.py', 'test_inventory_source_binding_review.py',
        'test_inventory_source_reuse.py',
        'test_inventory_source_reuse_review.py', 'test_http_output_preflight_review.py',
        'test_asset_group_risk_review.py',
    ]
    run('focused-tests', [str(source_python), '-Werror', '-m', 'pytest',
        '-o', 'asyncio_default_fixture_loop_scope=function', '-q',
        *['tests/' + name for name in focused],
        '-k', 'not public_http_gate_runs_actual_cli_and_reaps_all_owned_resources'], seconds=600)
    if run('build', [str(source_python), '-m', 'build', '--outdir', str(work / 'dist')], seconds=300):
        raise RuntimeError('build_failed')
    distributions = sorted((work / 'dist').iterdir())
    record('distributions.json', [{'name': path.name, 'bytes': path.stat().st_size,
        'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in distributions])
    run('twine', [str(source_python), '-m', 'twine', 'check', *map(str, distributions)])
    wheels = list((work / 'dist').glob('*.whl'))
    if len(wheels) != 1:
        raise RuntimeError('wheel_missing_or_ambiguous')
    installed = work / 'installed-venv'
    if run('installed-venv', [sys.executable, '-m', 'venv', str(installed)], seconds=120):
        raise RuntimeError('installed_setup_failed')
    installed_python = installed / 'bin' / 'python'
    if run('wheel-install', [str(installed_python), '-m', 'pip', 'install', str(wheels[0])], seconds=600):
        raise RuntimeError('installed_setup_failed')
    outside = work / 'outside'
    (outside / 'scripts').mkdir(parents=True, mode=0o700)
    copied = outside / 'scripts' / driver.name
    shutil.copyfile(driver, copied)
    copied.chmod(0o600)
    if hashlib.sha256(copied.read_bytes()).hexdigest() != driver_sha:
        raise RuntimeError('driver_copy_changed')
    record('driver-source.json', {'file': 'scripts/acceptance-http-assessment.py',
        'sha256': driver_sha, 'copied_byte_identical': True})
    proof = r'''
import hashlib,json,pathlib,sysconfig
import scanner_cli
import src.core.http_application_policy as policy
from src.core.build_identity import current_identity
library=pathlib.Path(sysconfig.get_path('purelib')).resolve()
modules={'scanner_cli':scanner_cli,'http_application_policy':policy}
paths={name:pathlib.Path(module.__file__).resolve() for name,module in modules.items()}
if not all(path.is_relative_to(library) for path in paths.values()):
    raise SystemExit('Imported code is outside installed site-packages')
driver=pathlib.Path('scripts/acceptance-http-assessment.py')
print(json.dumps({'imports':{name:path.relative_to(library).as_posix() for name,path in paths.items()},
                 'driver_sha256':hashlib.sha256(driver.read_bytes()).hexdigest(),
                 'producer_identity':current_identity(component='cli')}))
'''
    run('installed-proof', [str(installed_python), '-Werror', '-c', proof], cwd=outside, structured=True)
    run('http-installed', [str(installed_python), '-Werror', str(copied),
                          '--timeout-seconds', '240'], cwd=outside, structured=True)
    run('source-status', ['git', 'status', '--porcelain'])
    expected_source = '70299904cb69dafdec45cfe906ff826e095b1df5dab711a54453f3ed28339e48'
    source_identity = json.loads((captures / 'source-build.json').read_text())
    proof_receipt = json.loads((captures / 'installed-proof.json').read_text())
    tree = ast.parse(driver.read_text())
    assertions = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == 'REQUIRED_ASSERTIONS' for target in node.targets))
    expected_counts = {'leak': 35, 'defended': 35, 'https-leak': 1, 'absent': 1,
                       'denied': 1, 'off-pointer': 1, 'duplicate': 1, 'crash': 2}
    expected_exits = {'wizard': 0, 'plan': 0, 'http-leak': 0, 'https-defended': 0,
        'https-leak': 1, 'absent': 1, 'denied': 1, 'off-pointer': 1, 'duplicate': 1,
        'crash': -9, 'recover-json': 1, 'recover-sarif': 1}
    checks = {'revision': (captures / 'revision.log').read_text().strip() == revision,
              'source_status': (captures / 'source-status.log').read_bytes() == b'',
              'source_identity': source_identity['source']['sha256'] == expected_source,
              'installed_identity': proof_receipt['producer_identity'] == source_identity,
              'driver_identity': proof_receipt['driver_sha256'] == driver_sha}
    summary = (captures / 'focused-tests.log').read_text().strip().splitlines()[-1]
    checks['focused_summary'] = (re.search(r'\b[1-9][0-9]* passed\b', summary) is not None
        and '2 deselected' in summary and not re.search(r'\b[0-9]+ (failed|skipped|errors?|warnings?)\b', summary))
    for label, optimization in [('http-normal', 0), ('http-optimized', 1), ('http-installed', 0)]:
        receipt = json.loads((captures / (label + '.json')).read_text())
        codes = receipt.get('command_exits', {})
        checks[label] = (receipt.get('accepted') is True
            and receipt.get('format_version') == 'http-assessment-acceptance-v1'
            and receipt.get('assertions') == list(assertions) and len(assertions) == 11
            and receipt.get('request_counts') == expected_counts and sum(expected_counts.values()) == 77
            and set(codes) == set(expected_exits) | {'collision'} and codes.get('collision') not in (None, 0)
            and all(codes.get(name) == code for name, code in expected_exits.items())
            and receipt['privacy']['required_values_checked'] == 5
            and receipt['privacy']['profile_paths_checked'] == 9
            and receipt['runtime']['optimization'] == receipt['runtime']['cli_child_optimization'] == optimization
            and receipt['runtime']['producer_identity'] == source_identity
            and receipt['runtime']['driver_sha256'] == driver_sha
            and (captures / (label + '.stderr')).stat().st_size == 0)
    record('reconciliation.json', checks)
    failures.extend(name + '_mismatch' for name, passed in checks.items() if not passed)
except BaseException as error:
    failures.append('retest_wrapper_' + type(error).__name__)
finally:
    if interrupted.is_set() or time.monotonic() >= deadline:
        failures.append('outer_work_deadline_or_interruption')
    cleaned = False
    try:
        if (work.stat().st_dev, work.stat().st_ino) != work_identity or work.is_symlink():
            raise RuntimeError('owned_work_directory_changed')
        shutil.rmtree(work)
        cleaned = not work.exists()
        if not cleaned:
            failures.append('owned_work_cleanup_failed')
    except Exception:
        failures.append('owned_work_cleanup_failed')
    record('cleanup.json', {'owned_work_directory_removed': cleaned})
    record('wrapper-result.json', {'accepted': not failures, 'failures': failures, 'step_exits': exits})
    write('driver.exit', ('1' if failures else '0') + '\n')
    record('capture-inventory.json', [{'name': path.name, 'bytes': path.stat().st_size,
        'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(captures.iterdir())
        if path.is_file()])
raise SystemExit(1 if failures else 0)
PY
```

The whole wrapper has a 1,800-second work deadline. Each public driver keeps its
240-second shared work deadline, with a separate bounded outer watchdog and
cleanup grace. Commands are not retried into acceptance. Output captures are
bounded, and the wrapper tracks/reaps owned descendant processes once its isolated
dependencies are installed. Setup commands use owned process groups. Preserve
the genuine outer job exit as well as `driver.exit`; an upload, review or cleanup
failure must remain visible rather than being reported as a successful retest.

## Required results and limits

Both checkout modes and the outside installed-wheel mode must exit zero and
accept all eleven exact assertion names from the pinned public script. Each must
record 77 POSTs: 35 disclosure, 35 defended, five one-request controls and two
requests in the leak-then-stall crash fixture. The 13 recorded CLI exits include
successful setup/plan/completed scans, five expected partial exits of 1, a nonzero
collision refusal, SIGKILL `-9`, and two offline recovery exits of 1. They are not
all expected to be zero. Normal and installed children run with optimization 0;
the optimized driver must propagate optimization 1 to its actual CLI children.

Confirmed disclosure retains supported 70/high, including partial evidence after
a real stalled request and SIGKILL. Defended, absent-marker, denied, off-pointer
and duplicate-response cases retain the documented null/incomplete outcomes.
Nondisclosure never becomes a passed prompt check. The gate validates seven
objective-derived checks, source-3 receipts under ledger 3.0, both public target
views and checkpoint 4.0. JSON/SARIF recovery preserves the acknowledged receipt
and sends no request. Fresh client sessions do not establish a server-side reset
or independent stochastic samples.

The focused command includes the five new HTTP files, frozen legacy
prompt/tenant/access compatibility, application API projections and genuine
checkpoint/process recovery. It also covers the shared observation/group source
binding prerequisite, so this combined native run needs no separate attribution
retest. Only the two separately captured public HTTP modes
are deselected. Require no failed, skipped or warning cases; preserve the actual
selected/deselected counts rather than assuming an earlier suite total. Build,
Twine, installation and import/source reconciliation must also pass. The wheel
must import scanner code from its `site-packages` outside the checkout, and the
copied public driver must retain identical bytes. No scanner function is patched
for that installed workflow. This does not certify standalone source-distribution
test completeness.

Each driver checks five known private values (marker, issued key, response cookie
and two reference names), their encoded forms and nine profile paths across its
owned public surfaces. This is bounded known-value privacy evidence, not proof
that arbitrary secrets are absent. Generated reports, profiles, certificates and
checkpoint/database fixtures are private temporary inputs/outputs removed by the
driver; do not add them to the returned archive.

Return the private capture directory after reviewing every file: actual receipts,
step/job exits, runtime/dependencies, source and installed identities, test/build
logs, reconciliation, inventory and checked cleanup. Keep JSON receipt bytes
unchanged. Logs may contain disposable paths, and failed tests may print synthetic
fixture values; retain originals privately and record which shared text copies
were sanitized and which values/forms were checked. Do not return raw report
payloads, environments, profiles, keys, certificates, SQLite files or unrelated
lab outputs. Capture absence, failed parsing or a missing/unclean source-status
file is a failure.

These owned fixtures establish native CLI/application workflow correctness. They
do not measure real-model sensitivity, prove principal equivalence or canary
seeding, admit custom targets through the server API, or establish deployed
storage, PostgreSQL/distributed support, power-loss durability or enterprise
readiness. No broad model, tenant-cohort, MCP, backup or inventory repeat is needed.
