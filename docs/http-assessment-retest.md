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

## Focused cleanup follow-up

The original full run at `5a9ab356d2f68d1ff4a988dd9d17a26788a9141d`
remains failed: it recorded `focused-tests_surviving_owned_child` without PID or
state diagnostics. The archive cannot establish whether that process was still
running, awaiting natural exit, a zombie or a reused PID. Its successful HTTP
receipts are scoped runtime evidence, not a successful enclosing gate. A later
run with missing mandatory captures does not close that gate.

For the watchdog-only correction, use the new merged revision and watchdog
SHA-256 supplied with the handoff. Before running the block below, export
`AIS_HTTP_RETEST_MODE=focused-cleanup`, `AIS_HTTP_WATCHDOG_SHA256` and
`AIS_HTTP_BASELINE_CAPTURES` pointing to the unchanged first full capture
directory. This mode creates a fresh source environment, captures current
revision/runtime/dependencies/source identity and runs the original 26 focused
files plus `test_native_retest_watchdog.py`. The two full public HTTP cases stay
deselected. It does not repeat the normal/optimized/installed HTTP modes or
build/install a wheel. Current revision must match the new supplied
`AIS_HTTP_REVISION`; source identity and runtime JSON (Linux, Python 3.11.2 and
SQLite 3.40.1 for this requested runner) must equal the retained full baseline,
whose revision must be exactly `5a9ab35` in full. Fixed-name baseline files are
read as bounded, regular, nonsymlink data only. Dependency inventories and any
differences are recorded as qualifications. Changed transitive dependencies do
not fail the gate or establish an identical environment. Source/runtime
mismatches stop scoped acceptance and need review before requesting more work.

The result, reconciliation and required-capture contract identify
`focused-cleanup` explicitly. Acceptance requires every named capture, actual
zero step exits, a present empty source-status file, the pinned helper hash,
clean process diagnostics and checked work-directory cleanup. Review the
six original qualified HTTP receipts separately (three in the primary full run,
three in the selective retry); their absence from
this new capture directory is intentional and cannot establish a full-mode pass.
For a new full assessment, leave `AIS_HTTP_RETEST_MODE=full` and retain the full
contract below.

## Run and retain genuine exits

Run from the checkout in a clean shell without sourcing lab configuration. Keep
earlier captures unchanged. The wrapper creates separate private work and capture
directories. It retains captures and checks removal of its owned work directory
on success and failure. Setup failures stop dependent steps; attempted commands
keep their actual exit status. An absent capture is not success.

```bash
set -eu
: "${AIS_HTTP_REVISION:?Set the full merged SHA from the handoff}"
: "${AIS_HTTP_RETEST_MODE:=full}"
: "${AIS_HTTP_WATCHDOG_SHA256:=}"
test -z "$(git status --porcelain)"
git checkout --detach "$AIS_HTTP_REVISION"
test "$(git rev-parse HEAD)" = "$AIS_HTTP_REVISION"
env -i PATH="$PATH" PYTHONUTF8=1 PYTHONNOUSERSITE=1 \
  python3 -I - "$AIS_HTTP_REVISION" "$AIS_HTTP_RETEST_MODE" "${AIS_HTTP_BASELINE_CAPTURES:-}" "$AIS_HTTP_WATCHDOG_SHA256" <<'PY'
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import signal
import site
import stat
import subprocess
import sys
import tempfile
import threading
import time
import textwrap

revision = sys.argv[1]
if not re.fullmatch(r'[0-9a-f]{40}', revision):
    raise SystemExit('A full merged revision is required')
mode = sys.argv[2]
if mode not in ('full', 'focused-cleanup'):
    raise SystemExit('Mode must be full or focused-cleanup')
if mode == 'focused-cleanup' and not sys.argv[3]:
    raise SystemExit('Focused cleanup requires prior full captures')
expected_helper = sys.argv[4]
if mode == 'focused-cleanup' and not re.fullmatch(r'[0-9a-f]{64}', expected_helper):
    raise SystemExit('Focused cleanup requires the pinned watchdog SHA-256')
baseline = Path(sys.argv[3]).resolve() if mode == 'focused-cleanup' else None
checkout = Path.cwd().resolve()
helper = checkout / 'scripts' / 'native_retest_watchdog.py'
loaded_helper_sha = hashlib.sha256(helper.read_bytes()).hexdigest()
if mode == 'focused-cleanup' and loaded_helper_sha != expected_helper:
    raise SystemExit('Pinned watchdog SHA-256 mismatch')
OwnedChildren = runpy.run_path(str(checkout / 'scripts' / 'native_retest_watchdog.py'))['OwnedChildren']
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
    descendants = OwnedChildren(process_library)
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
                descendants.observe(process)
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
        cleanup = descendants.cleanup()
        record(label + '.process-cleanup.json', cleanup)
        failures.extend(label + '_' + code for code in cleanup['failure_codes'])
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
    helper = checkout / 'scripts' / 'native_retest_watchdog.py'
    helper_sha = hashlib.sha256(helper.read_bytes()).hexdigest()
    record('watchdog-source.json', {'file': 'scripts/native_retest_watchdog.py',
        'sha256': helper_sha, 'expected_sha256': expected_helper or None})
    driver = checkout / 'scripts' / 'acceptance-http-assessment.py'
    driver_sha = hashlib.sha256(driver.read_bytes()).hexdigest()
    if mode == 'full':
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
        'test_asset_group_risk_review.py', 'test_native_retest_watchdog.py',
    ]
    run('focused-tests', [str(source_python), '-Werror', '-m', 'pytest',
        '-o', 'asyncio_default_fixture_loop_scope=function', '-q',
        *['tests/' + name for name in focused],
        '-k', 'not public_http_gate_runs_actual_cli_and_reaps_all_owned_resources'], seconds=600)
    if mode == 'full':
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
        run('installed-proof', [str(installed_python), '-Werror', '-c', textwrap.dedent(proof)], cwd=outside, structured=True)
        run('http-installed', [str(installed_python), '-Werror', str(copied),
                              '--timeout-seconds', '240'], cwd=outside, structured=True)
    run('source-status', ['git', 'status', '--porcelain'])
    expected_source = '70299904cb69dafdec45cfe906ff826e095b1df5dab711a54453f3ed28339e48'
    source_identity = json.loads((captures / 'source-build.json').read_text())
    proof_receipt = (json.loads((captures / 'installed-proof.json').read_text())
        if mode == 'full' else None)
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
              'mode': mode in ('full', 'focused-cleanup'),
              'helper_identity': (hashlib.sha256(helper.read_bytes()).hexdigest() == helper_sha == loaded_helper_sha
                  and re.fullmatch(r'[0-9a-f]{64}', helper_sha) is not None)}
    if mode == 'full':
        checks['installed_identity'] = proof_receipt['producer_identity'] == source_identity
        checks['driver_identity'] = proof_receipt['driver_sha256'] == driver_sha
    else:
        checks['pinned_helper'] = helper_sha == expected_helper
        baseline_limits = {'revision.log': 128, 'runtime.json': 4096,
                           'dependencies.json': 2 * 1024 * 1024, 'source-build.json': 65536}
        baseline_bytes = {}
        for name, limit in baseline_limits.items():
            descriptor = os.open(baseline / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise RuntimeError('baseline_capture_not_regular')
                data = stream.read(limit + 1)
            if not data or len(data) > limit:
                raise RuntimeError('baseline_capture_size_invalid')
            baseline_bytes[name] = data
        record('baseline-source.json', {'revision': baseline_bytes['revision.log'].decode().strip(),
            'captures': [{'name': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                         for name, data in sorted(baseline_bytes.items())]})
        checks['baseline_revision'] = (baseline_bytes['revision.log'].decode().strip()
            == '5a9ab356d2f68d1ff4a988dd9d17a26788a9141d')
        for name in ['runtime.json', 'source-build.json']:
            checks['baseline_' + name] = (json.loads(baseline_bytes[name])
                == json.loads((captures / name).read_bytes()))
        inventories = {}
        for label, data in [('baseline', baseline_bytes['dependencies.json']),
                            ('current', (captures / 'dependencies.json').read_bytes())]:
            values = json.loads(data)
            if not isinstance(values, list) or not values:
                raise RuntimeError('dependency_inventory_invalid')
            inventory = []
            for item in values:
                if not isinstance(item, dict) or any(not isinstance(item.get(key), str)
                        or len(item[key]) > 256 or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+!-]*', item[key]) is None
                        for key in ('name', 'version')):
                    raise RuntimeError('dependency_inventory_invalid')
                inventory.append({'name': item['name'], 'version': item['version']})
            inventories[label] = sorted(inventory, key=lambda item: (item['name'], item['version']))
        dependencies_identical = inventories['baseline'] == inventories['current']
        record('baseline-comparison.json', {'mode': mode,
            'runtime': {'baseline': json.loads(baseline_bytes['runtime.json']),
                        'current': json.loads((captures / 'runtime.json').read_bytes()),
                        'identical': checks['baseline_runtime.json']},
            'dependencies': {**inventories, 'identical': dependencies_identical},
            'qualifications': [] if dependencies_identical else ['dependency_inventory_changed']})
    summary = (captures / 'focused-tests.log').read_text().strip().splitlines()[-1]
    checks['focused_summary'] = (re.search(r'\b[1-9][0-9]* passed\b', summary) is not None
        and '2 deselected' in summary and not re.search(r'\b[0-9]+ (failed|skipped|errors?|warnings?)\b', summary))
    if mode == 'full':
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
    required_steps = ({'source-venv', 'source-install', 'revision', 'runtime', 'dependencies',
        'source-build', 'focused-tests', 'source-status'} if mode == 'focused-cleanup' else
        {'source-venv', 'source-install', 'revision', 'runtime', 'dependencies', 'source-build',
         'http-normal', 'http-optimized', 'focused-tests', 'build', 'twine', 'installed-venv',
         'wheel-install', 'installed-proof', 'http-installed', 'source-status'})
    checks['exact_steps'] = set(exits) == required_steps
    json_steps = {'runtime', 'dependencies', 'source-build', 'http-normal',
                  'http-optimized', 'installed-proof', 'http-installed'}
    required_captures = {'watchdog-source.json', 'source-status.log'}
    if mode == 'focused-cleanup':
        required_captures.update({'baseline-source.json', 'baseline-comparison.json'})
    else:
        required_captures.update({'distributions.json', 'driver-source.json'})
    for name in required_steps:
        required_captures.update({name + ('.json' if name in json_steps else '.log'),
                                 name + '.stderr', name + '.exit', name + '.process-cleanup.json'})
    record('capture-contract.json', {'format_version': 'http-native-captures-v2', 'mode': mode,
        'required_before_finalization': sorted(required_captures),
        'required_after_finalization': ['capture-contract.json', 'reconciliation.json',
            'cleanup.json', 'wrapper-result.json', 'driver.exit', 'capture-inventory.json']})
    checks['required_captures'] = (bool(required_captures)
        and all((captures / name).is_file() for name in required_captures))
    checks['recorded_exits'] = all((captures / (name + '.exit')).read_text() == str(exits[name]) + '\n'
        and exits[name] == 0 for name in required_steps)
    checks['step_diagnostics'] = all((captures / (name + '.process-cleanup.json')).is_file()
        and json.loads((captures / (name + '.process-cleanup.json')).read_text())['failure_codes'] == []
        for name in required_steps)
    record('reconciliation.json', {'format_version': 'http-native-reconciliation-v2',
        'mode': mode, 'checks': checks})
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
    record('wrapper-result.json', {'format_version': 'http-native-wrapper-v2', 'mode': mode,
        'accepted': not failures, 'failures': failures, 'step_exits': exits})
    write('driver.exit', ('1' if failures else '0') + '\n')
    record('capture-inventory.json', [{'name': path.name, 'bytes': path.stat().st_size,
        'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(captures.iterdir())
        if path.is_file()])
raise SystemExit(1 if failures else 0)
PY
```

Save the exact block as a private shell script outside the checkout. The owning
job must capture its exit separately from any later archive/review/upload step.
For example, set `AIS_HTTP_RUN_SCRIPT` to that script and use this launcher in
the enclosing job, keeping the trap through its final step:

```bash
set -eu
umask 077
: "${AIS_HTTP_RUN_SCRIPT:?Set the private saved script path}"
job_captures=$(mktemp -d /tmp/aiscan-http-job-captures-XXXXXXXX)
trap 'job_status=$?; printf "%s\n" "$job_status" > "$job_captures/enclosing-job.exit"' EXIT
set +e
bash "$AIS_HTTP_RUN_SCRIPT" > "$job_captures/pinned-block.stdout" 2> "$job_captures/pinned-block.stderr"
block_status=$?
printf '%s\n' "$block_status" > "$job_captures/pinned-block.exit"
set -e
if test "$block_status" -ne 0; then
    exit "$block_status"
fi
# Keep the EXIT trap active through the owning job's actual remaining steps.
```

Retain `pinned-block.exit`, `enclosing-job.exit`, both job logs and the wrapper's
`driver.exit`. A block exit of 1 and enclosing job exit of 7 are distinct failed
outcomes; neither may be replaced by a successful command within the run. A
missing final exit capture is incomplete evidence.

The whole wrapper has a 1,800-second work deadline. Each public driver keeps its
240-second shared work deadline, with a separate bounded outer watchdog and
cleanup grace. Commands are not retried into acceptance. Output captures are
bounded, and the wrapper tracks/reaps owned descendant processes once its isolated
dependencies are installed. Descendant cleanup allows at most one second of
natural exit/reaping inside one shared five-second cleanup deadline. A living
child requiring a kill remains a failure, as do unknown probes, PID reuse,
cleanup errors and unreaped zombies. Fresh creation-time/status probes precede
signals; replacement PIDs are never signaled. Every attempted step retains a
`process-cleanup.json` with PID, creation time, state, timing and static failure
codes. It contains no command arguments, environment or paths. Tracking and
diagnostics have explicit finite limits whose overflow fails the step. Setup
commands use owned process groups before psutil is installed, and their
diagnostics explicitly mark tracking unavailable. Preserve
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
were sanitized and which values/forms were checked. Keep every original raw log
and capture privately in its capture directory outside the removed work
directory. Sanitize only separate shared copies and retain a manifest naming
each changed copy, its original/shared SHA-256 and the checked values/forms.
Never delete the sole raw log after producing a sanitized copy. Do not return raw report
payloads, environments, profiles, keys, certificates, SQLite files or unrelated
lab outputs. Capture absence, failed parsing or a missing/unclean source-status
file is a failure.

These owned fixtures establish native CLI/application workflow correctness. They
do not measure real-model sensitivity, prove principal equivalence or canary
seeding, admit custom targets through the server API, or establish deployed
storage, PostgreSQL/distributed support, power-loss durability or enterprise
readiness. No broad model, tenant-cohort, MCP, backup or inventory repeat is needed.
