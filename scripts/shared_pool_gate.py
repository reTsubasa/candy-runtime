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
import shutil
import subprocess
import sys
import tempfile
import time

RUNTIME = Path(__file__).resolve().parents[1]
CORE = RUNTIME.parent / "candy-core"
TESTS = ("signed_cli_shared_pool_scales_and_isolates_four_domains",
         "signed_cli_shared_host_lifecycle_scale_gate",
         "signed_cli_bilateral_candidate_reload_preserves_traffic",
         "signed_cli_successor_server_restart_preserves_authorization",
         "signed_cli_runtime_shared_listener_routes_two_domains",
         "signed_cli_mixed_role_quota_and_slow_consumer_isolation")


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
    parser.add_argument("--build", type=Path, help="run verified frozen artifacts directly")
    parser.add_argument("--snapshot-helper", type=Path,
                        help="copy current Linux binaries and this test helper, then test immutable copies")
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
              "container": name, "host_deadline_seconds": 300,
              "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
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
        if args.build:
            build = args.build.resolve()
            if json.loads((build / "result.json").read_text())["gate"] != "BUILD_PASS":
                raise ValueError("frozen artifact build has not passed")
            hashes = json.loads((build / "binary-hashes.json").read_text())
            paths = {"CANDY_CORE_TEST_BINARY": "candy-core", "CANDY_NETD_TEST_BINARY": "candy-netd",
                     "CANDY_AGENT_TEST_BINARY": "candy-agent", "CANDY_SIGNED_FIXTURE_BINARY": "sdwan_signed_cli_fixture"}
            for label in (*paths.values(), "candy-tunio", "signed_cli_helper"):
                if hashlib.sha256((build / "binaries" / label).read_bytes()).hexdigest() != hashes[label]:
                    raise ValueError(f"frozen artifact binary checksum mismatch: {label}")
            source = json.loads((build / "source-freeze.json").read_text())
            result["scope"] = "isolated frozen artifact fixture; no release, platform or performance acceptance"
            result["build"] = str(build)
            result["manifest_sha256"] = source["manifest_sha256"]
            result["binary_hashes"] = hashes
            provenance = build / "build-provenance.json"
            if provenance.exists():
                result["build_provenance_sha256"] = hashlib.sha256(provenance.read_bytes()).hexdigest()
                result["build_provenance"] = json.loads(provenance.read_text())
            command = ["docker", "run", "--name", name, "--rm", "--network", "none", "--privileged",
                       "--cpus", "3", "--memory", "3g", "--pids-limit", "512",
                       "-v", f"{build / 'binaries'}:/binaries:ro",
                       # Cargo embeds this path in debug signed_cli fixtures.
                       "-v", f"{build / 'binaries'}:/build/debug:ro",
                       "-v", f"{build / 'binaries'}:/build/release:ro", "-v", f"{evidence}:/evidence",
                       "-e", "CANDY_NETD_ISOLATED_KERNEL_TEST=1", "-e", "CANDY_SIGNED_EVIDENCE_DIR=/evidence"]
            for variable, label in paths.items():
                command.extend(["-e", f"{variable}=/binaries/{label}"])
            command.extend(["candy-sdwan-perf-runner:20261013", "sh", "-eu", "-c",
                            'for binary in /binaries/candy-core /binaries/candy-netd '
                            '/binaries/candy-agent /binaries/signed_cli_helper '
                            '/build/debug/candy-tunio /build/release/candy-tunio; do '
                            'test -x "$binary" || { echo "code=frozen_binary_unavailable '
                            'module=shared_pool_gate path=$binary" >&2; exit 70; }; done; exec "$@"',
                            "frozen-gate", "timeout", "240",
                            "/binaries/signed_cli_helper", "--exact", args.test, "--ignored", "--nocapture"])
        if args.snapshot_helper:
            if args.build:
                raise ValueError("choose frozen release or local binary snapshot")
            binaries = evidence / "binaries"
            binaries.mkdir()
            sources = {
                "candy-core": CORE / "target-linux-shared/debug/candy-core",
                "candy-netd": RUNTIME / "target-linux-netd-v2/debug/candy-netd",
                "candy-agent": RUNTIME / "target-linux-netd-v2/debug/candy-sdwan-agent",
                "candy-tunio": RUNTIME / "target-linux-tunio/debug/candy-tunio",
                "sdwan_signed_cli_fixture": CORE / "target-linux-shared/debug/examples/sdwan_signed_cli_fixture",
                "signed_cli_helper": args.snapshot_helper.resolve(),
            }
            hashes = {}
            for label, source in sources.items():
                before = hashlib.sha256(source.read_bytes()).hexdigest()
                shutil.copy2(source, binaries / label)
                copied = hashlib.sha256((binaries / label).read_bytes()).hexdigest()
                after = hashlib.sha256(source.read_bytes()).hexdigest()
                if not before == copied == after:
                    raise ValueError(f"binary changed during snapshot: {label}")
                hashes[label] = copied
            (evidence / "binary-hashes.json").write_text(json.dumps(hashes, indent=2) + "\n")
            result.update(scope="isolated immutable binary snapshot; no source, release or platform acceptance",
                          binary_hashes=hashes)
            command = ["docker", "run", "--name", name, "--rm", "--network", "none", "--privileged",
                       "-v", f"{binaries}:/binaries:ro",
                       "-v", f"{binaries}:/workspace/target-linux-tunio/debug:ro",
                       "-v", f"{evidence}:/evidence",
                       "-e", "CANDY_NETD_ISOLATED_KERNEL_TEST=1",
                       "-e", "CANDY_SIGNED_EVIDENCE_DIR=/evidence"]
            for variable, label in {
                "CANDY_CORE_TEST_BINARY": "candy-core",
                "CANDY_NETD_TEST_BINARY": "candy-netd",
                "CANDY_AGENT_TEST_BINARY": "candy-agent",
                "CANDY_SIGNED_FIXTURE_BINARY": "sdwan_signed_cli_fixture",
            }.items():
                command.extend(["-e", f"{variable}=/binaries/{label}"])
            command.extend(["candy-sdwan-perf-runner:20261013", "timeout", "240",
                            "/binaries/signed_cli_helper", "--exact", args.test, "--ignored", "--nocapture"])
        if args.test == "signed_cli_mixed_role_quota_and_slow_consumer_isolation":
            wrapper_source = (args.build.resolve() / "frozen/candy-runtime" if args.build else RUNTIME)
            wrapper_source /= "openwrt/client/packages/candy-client/candy-client"
            tools = evidence / "runtime-tools"
            tools.mkdir()
            wrapper = tools / "candy-client"
            shutil.copy2(wrapper_source, wrapper)
            result["runtime_client_wrapper_sha256"] = hashlib.sha256(wrapper.read_bytes()).hexdigest()
            image_position = command.index("candy-sdwan-perf-runner:20261013")
            core_binary = ("/binaries/candy-core" if args.build or args.snapshot_helper
                           else "/core/target-linux-shared/debug/candy-core")
            command[image_position:image_position] = [
                "-v", f"{tools}:/runtime-tools:ro",
                "-e", "CANDY_PROXY_CLIENT_BINARY=/runtime-tools/candy-client",
                "-e", f"CANDY_CORE_BIN={core_binary}"]
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
