#!/usr/bin/env python3
"""Bound the shared pool fixture, including an unresponsive Docker daemon."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

RUNTIME = Path(__file__).resolve().parents[1]
CORE = RUNTIME.parent / "candy-core"
TESTS = ("signed_cli_shared_pool_scales_and_isolates_four_domains",
         "signed_cli_shared_host_lifecycle_scale_gate")


def bounded_run(command: list[str], log: Path, seconds: float) -> int:
    with log.open("w") as output:
        child = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        try:
            return child.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            # Terminate the CLI group even if its children hold pipes open.
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            output.write("\ncode=harness_deadline module=shared_pool_gate\n")
            return 124


def exactly_one_pass(log: str, test: str) -> bool:
    summaries = re.findall(
        r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", log, re.MULTILINE)
    return (summaries == [("1", "0", "0")]
            and len(re.findall(r"^test " + re.escape(test) + r" \.\.\. ok$",
                               log, re.MULTILINE)) == 1)


def self_check() -> None:
    test = TESTS[0]
    passed = f"test {test} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n"
    assert exactly_one_pass(passed, test)
    assert not exactly_one_pass(passed + passed, test)
    assert not exactly_one_pass(passed.replace("1 passed", "0 passed"), test)
    assert not exactly_one_pass(passed.replace(test, "other_test"), test)
    with tempfile.TemporaryDirectory() as directory:
        log = Path(directory) / "timeout.log"
        started = time.monotonic()
        assert bounded_run([sys.executable, "-c", "import time; time.sleep(60)"], log, 0.1) == 124
        assert time.monotonic() - started < 5
        assert "harness_deadline" in log.read_text()
    print(json.dumps({"self_check": "PASS", "checks": [
        "host timeout terminates and reaps process", "exactly one selected test required"]}))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path, nargs="?")
    parser.add_argument("test", choices=TESTS, nargs="?", default=TESTS[0])
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    if args.self_check:
        self_check()
        return 0
    if args.evidence is None:
        parser.error("a fresh evidence directory is required")
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    name = "candy-shared-gate-" + hashlib.sha256(str(evidence).encode()).hexdigest()[:12]
    started = time.monotonic()
    result = {"schema_version": 1, "test": args.test, "gate": "FAIL",
              "scope": "isolated source-worktree fixture; no release or platform acceptance",
              "container": name, "host_deadline_seconds": 300}
    exit_code = 1
    try:
        preflight = bounded_run(["docker", "info", "--format", "{{.ServerVersion}}"],
                                evidence / "docker-preflight.log", 10)
        if preflight != 0:
            result.update(gate="NOT_RUN", code="docker_unavailable", preflight_exit_code=preflight,
                          test_executed=False)
            return 70
        command = ["docker", "run", "--name", name, "--rm", "--network", "none", "--privileged",
                   "-v", f"{RUNTIME}:/workspace", "-v", f"{CORE}:/core",
                   "-v", f"{Path.home()}/.cargo/registry:/usr/local/cargo/registry",
                   "-v", f"{evidence}:/evidence", "-e", "CARGO_TARGET_DIR=/workspace/target-linux-tunio",
                   "-e", "CANDY_NETD_ISOLATED_KERNEL_TEST=1",
                   "-e", "CANDY_CORE_TEST_BINARY=/core/target-linux-shared/debug/candy-core",
                   "-e", "CANDY_NETD_TEST_BINARY=/workspace/target-linux-netd-v2/debug/candy-netd",
                   "-e", "CANDY_AGENT_TEST_BINARY=/workspace/target-linux-netd-v2/debug/candy-sdwan-agent",
                   "-e", "CANDY_SIGNED_FIXTURE_BINARY=/core/target-linux-shared/debug/examples/sdwan_signed_cli_fixture",
                   "-e", "CANDY_SIGNED_EVIDENCE_DIR=/evidence",
                   "-w", "/workspace/linux/common/apps/candy-tunio", "candy-sdwan-perf-runner:20261013",
                   "timeout", "240", "cargo", "test", "--test", "signed_cli", args.test,
                   "--offline", "--", "--exact", "--ignored", "--nocapture"]
        exit_code = bounded_run(command, evidence / "test.log", 300)
        log = (evidence / "test.log").read_text()
        accepted = exit_code == 0 and exactly_one_pass(log, args.test)
        result.update(gate="PASS" if accepted else "FAIL", test_exit_code=exit_code,
                      code="selected_test_passed" if accepted else "test_or_harness_failed",
                      test_executed=bool(re.search(r"^running 1 test$", log, re.MULTILINE)),
                      exact_one_test_passed=accepted)
        return 0 if accepted else 1
    except Exception as error:
        result.update(code="harness_failed", detail=str(error), test_executed=False)
        return 1
    finally:
        # Cleanup also has a host deadline; an unavailable daemon cannot trap us here.
        if result.get("code") != "docker_unavailable":
            try:
                result["cleanup_exit_code"] = bounded_run(
                    ["docker", "rm", "-f", name], evidence / "cleanup.log", 10)
            except Exception as error:
                result["cleanup_error"] = str(error)
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (evidence / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())
