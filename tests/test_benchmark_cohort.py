"""Synthetic offline cohorts validate evidence accounting, not model accuracy."""

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys

import pytest

from src.core.contracts import CheckRecord
from src.evaluation import benchmark_cohort as module
from src.evaluation import prompt_benchmark as producer


MARKER = "synthetic-cohort-secret-fb694102"
ENV = "SCAN_EVIDENCE_COHORT_FIXTURE"
ABSENCE = "No protected disclosure observed in this finite sample; canary seeding and safety are not established"
ROOT = Path(__file__).resolve().parents[1]


def plan():
    roles = ("positive_control", "negative_control", "model", "model")
    return {
        "schema_version": "1.0",
        "protocol": module.PROTOCOL,
        "operator_asserted_revision": "a" * 40,
        "operator_asserted_predeclared": True,
        "cases": [
            {
                "case_id": "case-" + str(index),
                "role": role,
                "report": "case-" + str(index) + ".json",
                "provider": "ollama",
                "model": "fixture-" + str(index),
                "evidence_context_id": "fixture-context-" + str(index),
                "pairs": 10 if role == "model" else 1,
                "seed": 0,
                "operator_asserted_target_revision": "fixture-v1",
                "operator_asserted_model_revision": "model-v1",
                "operator_asserted_canary_seeded": True,
                "state_policy": "stateless_requests",
            }
            for index, role in enumerate(roles)
        ],
    }


def report(declaration, case, *, detected=False):
    settings = producer.BenchmarkConfig(
        "https://192.0.2.1",
        case["provider"],
        case["model"],
        case["evidence_context_id"],
        ENV,
        declaration["operator_asserted_revision"],
        ("192.0.2.1/32",),
        pairs=case["pairs"],
        seed=case["seed"],
    )
    _, _, _, public, _ = producer._prepare(settings)
    runs = []
    for pair, order in enumerate(producer.paired_order(case["pairs"], case["seed"])):
        for arm in order:
            checks = [
                CheckRecord(
                    "prompt_injection." + manifest["category"],
                    manifest["probe_id"],
                    manifest["probe_version"],
                    "completed",
                    "confirmed" if detected else "inconclusive",
                    5,
                    5,
                    None if detected else ABSENCE,
                    case["evidence_context_id"],
                ).to_dict()
                for manifest in public["manifests"][arm]
            ]
            runs.append(
                {
                    "pair": pair,
                    "arm": arm,
                    "status": "completed",
                    "detected": detected,
                    "requests_attempted": 35,
                    "responses_evaluated": 35,
                    "checks": checks,
                    "detected_categories": sorted(
                        item["category"] for item in public["manifests"][arm]
                    )
                    if detected
                    else [],
                    "elapsed_seconds": 35.0,
                    "detection_outcome": "shared_analyzer_observation"
                    if detected
                    else "not_observed_in_complete_run",
                }
            )
    public.update(
        runs=runs, metrics=producer.summarize(runs, case["pairs"]), status="completed"
    )
    return public


def documents(declaration):
    return {
        index: report(declaration, case, detected=case["role"] == "positive_control")
        for index, case in enumerate(declaration["cases"])
    }


@pytest.fixture(autouse=True)
def environment(monkeypatch):
    monkeypatch.setenv(ENV, MARKER)


def write_private(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


@pytest.fixture
def inputs(tmp_path):
    # Only this owned root is canonicalized; the implementation rejects aliases.
    root = tmp_path.resolve(strict=True)
    root.chmod(0o700)
    reports = root / "reports"
    reports.mkdir(mode=0o700)
    declaration = plan()
    write_private(root / "plan.json", declaration)
    for index, document in documents(declaration).items():
        write_private(reports / declaration["cases"][index]["report"], document)
    return root, reports, declaration


def test_completed_controls_and_quiet_models_are_not_security_passes():
    declaration = plan()
    docs = documents(declaration)
    before = deepcopy((declaration, docs))
    result = module.evaluate_cohort(declaration, docs)
    assert result["status"] == "completed" and result["promotion"] == "not_decided"
    assert len(result["cases"]) == 4 and all(
        row["status"] == "completed" for row in result["cases"]
    )
    assert result["cases"][2]["metrics"]["arms"]["candidate"]["detected"] == 0
    assert (declaration, docs) == before


@pytest.mark.parametrize("case_index", [0, 1])
def test_control_mismatch_never_hides_other_planned_cases(case_index):
    declaration = plan()
    docs = documents(declaration)
    docs[case_index] = report(
        declaration, declaration["cases"][case_index], detected=case_index == 1
    )
    result = module.evaluate_cohort(declaration, docs)
    assert result["status"] == "incomplete" and len(result["cases"]) == 4
    assert result["cases"][case_index]["status"] == "control_failed"
    assert all(
        row["status"] == "completed"
        for index, row in enumerate(result["cases"])
        if index != case_index
    )


def test_missing_invalid_and_partial_cases_are_retained():
    declaration = plan()
    docs = documents(declaration)
    del docs[0]
    docs[1]["metrics"]["arms"]["baseline"]["detected"] = 999
    document = docs[2]
    for run in document["runs"]:
        run.update(
            status="not_run",
            detected=False,
            requests_attempted=0,
            responses_evaluated=0,
            checks=[],
            detected_categories=[],
            detection_outcome="not_evaluated",
        )
        run.pop("elapsed_seconds")
    document.update(status="partial", metrics=producer.summarize(document["runs"], 10))
    result = module.evaluate_cohort(declaration, docs)
    assert result["status"] == "incomplete"
    assert [row["status"] for row in result["cases"]] == [
        "missing",
        "invalid",
        "partial",
        "completed",
    ]
    assert result["cases"][2]["metrics"]["paired_complete_cases"]["incomplete"] == 10


@pytest.mark.parametrize(
    "mutation",
    [
        "role",
        "unknown",
        "traversal",
        "duplicate_file",
        "duplicate_case",
        "same_models",
        "no_models",
        "no_negative",
        "too_many",
        "boolean_pairs",
        "wrong_pairs",
        "boolean_seed",
        "missing_provenance",
        "seed_not_asserted",
        "not_predeclared",
        "state_policy",
        "revision",
        "empty",
    ],
)
def test_invalid_plan_has_static_errors(mutation):
    declaration = plan()
    case = declaration["cases"][0]
    if mutation == "role":
        case["role"] = MARKER
    elif mutation == "unknown":
        case["private_secret"] = MARKER
    elif mutation == "traversal":
        case["report"] = "../" + MARKER + ".json"
    elif mutation == "duplicate_file":
        declaration["cases"][1]["report"] = case["report"]
    elif mutation == "duplicate_case":
        declaration["cases"][1]["case_id"] = case["case_id"]
    elif mutation == "same_models":
        declaration["cases"][3]["model"] = declaration["cases"][2]["model"]
    elif mutation == "no_models":
        declaration["cases"][2:] = []
    elif mutation == "no_negative":
        declaration["cases"][1]["role"] = "positive_control"
    elif mutation == "too_many":
        declaration["cases"] *= 3
    elif mutation == "boolean_pairs":
        case["pairs"] = True
    elif mutation == "wrong_pairs":
        declaration["cases"][2]["pairs"] = 1
    elif mutation == "boolean_seed":
        case["seed"] = True
    elif mutation == "missing_provenance":
        del case["operator_asserted_target_revision"]
    elif mutation == "seed_not_asserted":
        case["operator_asserted_canary_seeded"] = False
    elif mutation == "not_predeclared":
        declaration["operator_asserted_predeclared"] = False
    elif mutation == "state_policy":
        case["state_policy"] = MARKER
    elif mutation == "revision":
        declaration["operator_asserted_revision"] = MARKER
    elif mutation == "empty":
        declaration["cases"] = []
    with pytest.raises(module.CohortError) as caught:
        module.evaluate_cohort(declaration, {})
    assert str(caught.value) == module._ERROR and MARKER not in str(caught.value)


def test_no_supplied_strings_escape_even_if_operator_mislabels_a_secret():
    declaration = plan()
    docs = documents(declaration)
    declaration["cases"][0]["case_id"] = MARKER
    declaration["cases"][1]["operator_asserted_target_revision"] = MARKER
    result = module.evaluate_cohort(declaration, docs)
    text = json.dumps(result)
    for private in (
        MARKER,
        ENV,
        "fixture-0",
        "fixture-context-0",
        "case-0.json",
        "fixture-v1",
        "a" * 40,
    ):
        assert private not in text


def test_no_extra_or_boolean_document_indices():
    for docs in ({True: {}}, {9: {}}, []):
        with pytest.raises(module.CohortError):
            module.evaluate_cohort(plan(), docs)


def test_unknown_state_is_visible_not_an_independence_claim():
    declaration = plan()
    declaration["cases"][2]["state_policy"] = "persistent_or_unknown"
    result = module.evaluate_cohort(declaration, documents(declaration))
    assert result["status"] == "completed"
    assert (
        result["cases"][2]["operator_asserted_state_policy"] == "persistent_or_unknown"
    )
    assert "operator assertions" in result["provenance"]
    assert result["promotion"] == "not_decided"


def test_file_gate_is_offline_private_and_no_clobber(inputs, monkeypatch):
    root, reports, _ = inputs

    def forbidden(*args, **kwargs):
        raise AssertionError("Offline gate must not use external services")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setenv("SCAN_EVIDENCE_PROFILES_FILE", str(root / MARKER))
    output = root / "summary.json"
    assert (
        module.check_files(root / "plan.json", reports, output)["status"] == "completed"
    )
    assert output.stat().st_mode & 0o777 == 0o600
    assert not list(root.glob(".cohort-*"))
    before = output.read_bytes()
    with pytest.raises(module.CohortError):
        module.check_files(root / "plan.json", reports, output)
    assert output.read_bytes() == before


@pytest.mark.parametrize(
    "mutation",
    [
        "symlink",
        "fifo",
        "directory",
        "public",
        "executable",
        "hardlink",
        "oversized",
        "invalid_utf8",
        "duplicate",
        "nonfinite",
        "overflow",
        "integer",
        "deep",
        "nodes",
        "changed",
    ],
)
def test_unsafe_report_is_nonblocking_invalid_case_not_lost(
    inputs, monkeypatch, mutation
):
    root, reports, declaration = inputs
    target = reports / declaration["cases"][0]["report"]
    if mutation in ("symlink", "fifo", "directory", "hardlink"):
        target.unlink()
    if mutation == "symlink":
        target.symlink_to(root / "plan.json")
    elif mutation == "fifo":
        os.mkfifo(target, 0o600)
    elif mutation == "directory":
        target.mkdir(mode=0o700)
    elif mutation == "hardlink":
        other = write_private(root / "other-report.json", {})
        os.link(other, target)
    elif mutation == "public":
        target.chmod(0o644)
    elif mutation == "executable":
        target.chmod(0o700)
    elif mutation == "oversized":
        target.write_bytes(b" " * (module.REPORT_BYTES + 1))
    elif mutation == "invalid_utf8":
        target.write_bytes(b"\xff")
    elif mutation == "duplicate":
        target.write_text('{"key":1,"key":2}')
    elif mutation == "nonfinite":
        target.write_text('{"key":NaN}')
    elif mutation == "overflow":
        target.write_text('{"key":1e999}')
    elif mutation == "integer":
        target.write_text('{"key":' + "1" * 1000 + "}")
    elif mutation == "deep":
        target.write_text("[" * 50 + "0" + "]" * 50)
    elif mutation == "nodes":
        target.write_text("[" + ",".join("0" for _ in range(33000)) + "]")
    elif mutation == "changed":
        original = os.read
        target_stat = target.stat()
        mutated = False

        def changed(descriptor, count):
            nonlocal mutated
            result = original(descriptor, count)
            observed = os.fstat(descriptor)
            if (result and not mutated
                    and (observed.st_dev, observed.st_ino) == (target_stat.st_dev, target_stat.st_ino)):
                with target.open("ab") as stream:
                    stream.write(b" ")
                mutated = True
            return result

        monkeypatch.setattr(os, "read", changed)
    result = module.check_files(root / "plan.json", reports, root / "summary.json")
    if mutation == "changed":
        assert mutated
    assert result["status"] == "incomplete" and len(result["cases"]) == 4
    assert result["cases"][0]["status"] == "invalid"
    assert not list(root.glob(".cohort-*"))


@pytest.mark.parametrize(
    "mutation", ["root_symlink", "ancestor_symlink", "root_public", "root_missing"]
)
def test_unsafe_input_root_preserves_all_cases(inputs, mutation):
    root, reports, _ = inputs
    if mutation == "root_symlink":
        alias = root / "alias"
        alias.symlink_to(reports, target_is_directory=True)
        reports = alias
    elif mutation == "ancestor_symlink":
        alias = root / "alias"
        alias.symlink_to(root, target_is_directory=True)
        reports = alias / "reports"
    elif mutation == "root_public":
        reports.chmod(0o755)
    else:
        reports = root / "absent"
    result = module.check_files(root / "plan.json", reports, root / "summary.json")
    assert result["status"] == "incomplete" and len(result["cases"]) == 4
    assert all(row["status"] == "invalid" for row in result["cases"])


@pytest.mark.parametrize(
    "mutation",
    [
        "plan_symlink",
        "plan_public",
        "plan_duplicate",
        "output_symlink",
        "output_public_parent",
    ],
)
def test_invalid_plan_or_output_never_publishes_success(inputs, mutation):
    root, reports, _ = inputs
    plan_file, output = root / "plan.json", root / "summary.json"
    if mutation == "plan_symlink":
        alias = root / "alias.json"
        alias.symlink_to(plan_file)
        plan_file = alias
    elif mutation == "plan_public":
        plan_file.chmod(0o644)
    elif mutation == "plan_duplicate":
        plan_file.write_text('{"cases":[],"cases":[]}')
    elif mutation == "output_symlink":
        output.symlink_to(plan_file)
    else:
        parent = root / "public"
        parent.mkdir(mode=0o755)
        parent.chmod(0o755)
        output = parent / "summary.json"
    before = plan_file.read_bytes()
    with pytest.raises(module.CohortError) as caught:
        module.check_files(plan_file, reports, output)
    assert str(caught.value) == module._ERROR and str(root) not in str(caught.value)
    assert plan_file.read_bytes() == before
    if mutation != "output_symlink":
        assert not output.exists()
    assert not list(root.rglob(".cohort-*"))


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_atomic_output_race_preserves_other_writer(inputs, monkeypatch, kind):
    root, reports, _ = inputs
    output = root / "summary.json"
    original = os.link

    def raced(*args, **kwargs):
        if kind == "symlink":
            output.symlink_to(root / "plan.json")
        else:
            output.write_text("Another writer")
        return original(*args, **kwargs)

    monkeypatch.setattr(os, "link", raced)
    with pytest.raises(module.CohortError):
        module.check_files(root / "plan.json", reports, output)
    if kind == "symlink":
        assert (
            output.is_symlink()
            and output.read_bytes() == (root / "plan.json").read_bytes()
        )
    else:
        assert output.read_text() == "Another writer"
    assert not list(root.glob(".cohort-*"))


def test_interrupted_publication_leaves_no_success_file(inputs, monkeypatch):
    root, reports, _ = inputs
    output = root / "summary.json"

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(module.json, "dump", interrupted)
    with pytest.raises(KeyboardInterrupt):
        module.check_files(root / "plan.json", reports, output)
    assert not output.exists() and not list(root.glob(".cohort-*"))


@pytest.mark.parametrize("case", ["completed", "missing", "failed_control", "invalid"])
def test_real_cli_exit_tracks_gate_not_wrapper(inputs, case):
    root, reports, declaration = inputs
    if case == "missing":
        (reports / declaration["cases"][2]["report"]).unlink()
    elif case == "failed_control":
        write_private(
            reports / declaration["cases"][0]["report"],
            report(declaration, declaration["cases"][0]),
        )
    elif case == "invalid":
        (root / "plan.json").write_text(MARKER)
    output = root / "summary.json"
    child = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/check-prompt-cohort.py"),
            "--plan",
            str(root / "plan.json"),
            "--reports-dir",
            str(reports),
            "--output",
            str(output),
        ],
        cwd=root,
        env={
            "PATH": os.defpath,
            "PYTHONDONTWRITEBYTECODE": "1",
            "SCAN_EVIDENCE_PROFILES_FILE": str(root / MARKER),
        },
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert child.returncode == (0 if case == "completed" else 1)
    assert (
        MARKER not in child.stdout + child.stderr
        and str(root) not in child.stdout + child.stderr
    )
    if case == "invalid":
        assert not output.exists()
    else:
        assert json.loads(output.read_text())["status"] == (
            "completed" if case == "completed" else "incomplete"
        )


def test_parser_errors_are_static(capsys):
    spec = importlib.util.spec_from_file_location(
        "cohort_script", ROOT / "scripts/check-prompt-cohort.py"
    )
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    with pytest.raises(SystemExit):
        loaded.Parser().parse_args(["--unknown-" + MARKER])
    assert MARKER not in capsys.readouterr().err
