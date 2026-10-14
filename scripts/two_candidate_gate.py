#!/usr/bin/env python3
"""Frozen isolated Linux QUIC candidate gate; requires a quiet test window."""
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys

runtime = Path(__file__).resolve().parents[1]
core = runtime.parent / "candy-core"
evidence = Path(sys.argv[1]).resolve()
if evidence.exists():
    raise SystemExit("choose a fresh evidence directory")
evidence.mkdir(parents=True, mode=0o700)
runid = hashlib.sha256(str(evidence).encode()).hexdigest()[:12]
container = "candy-candidate-gate-" + runid
build_container = container + "-build"
volume = os.environ.get("CANDY_CANDIDATE_BUILD_VOLUME", "candy-candidate-build-" + runid)
if not volume.startswith("candy-candidate-build-"):
    raise SystemExit("build cache must belong to the isolated candidate gate")
manifest = {}
tests = os.environ.get("CANDY_SIGNED_GATE_TESTS", "signed_cli_two_candidate_loss_and_recovery_keep_tun").split(",")
if not tests or any(not name.startswith("signed_cli_") or not name.replace("_", "").isalnum() for name in tests):
    raise SystemExit("explicit signed_cli test names required")
for label, repo in [("core", core), ("runtime", runtime)]:
    files = subprocess.check_output(["git", "-C", str(repo), "ls-files", "-z"]).split(b"\0")
    # Freeze legitimate in-progress source files too (for example a newly
    # introduced module); ignore build outputs and interpreter caches.
    files += [name for name in subprocess.check_output(["git", "-C", str(repo), "ls-files", "--others", "--exclude-standard", "-z"]).split(b"\0") if name.startswith((b"apps/", b"crates/", b"linux/", b"shared/", b"scripts/"))]
    if label == "runtime":
        files += [b"linux/common/apps/candy-tunio/tests/fixtures/candidate_failover.rs", b"linux/common/apps/candy-sdwan-agent/src/cloud_plan_bridge.rs"]
    hashes = {}
    for raw in sorted(set(files)):
        if not raw: continue
        name = raw.decode()
        if name.startswith("docs/artifacts/"):
            continue
        if "__pycache__" in Path(name).parts or any(part.startswith("target-") for part in Path(name).parts) or ("target" in Path(name).parts and "vendor" in Path(name).parts): continue
        source = repo / name
        if not source.is_file(): continue
        data = source.read_bytes()
        target = evidence / "frozen" / label / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    manifest[label] = {"git_sha":subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip(),"status":subprocess.check_output(["git", "-C", str(repo), "status", "--short"], text=True),"files":hashes}
(evidence / "source-manifest.json").write_text(json.dumps(manifest, indent=2))
def docker(args):
    return subprocess.check_output(["docker", *args], text=True)
docker(["volume", "create", volume])
mounts = ["-v", str(evidence/"frozen")+":/workspace:ro", "-v", str(evidence)+":/evidence", "-v", volume+":/build", "-v", str(Path.home()/".cargo/registry")+":/usr/local/cargo/registry:ro"]
# Core and runtime builds need CMake (btls-sys); the test image intentionally
# remains the networking image because it supplies ip/nft for namespace tests.
common_env = ["-e", "CARGO_TARGET_DIR=/build", "-e", "CARGO_BUILD_JOBS=2", "-e", "CANDY_NETD_ISOLATED_KERNEL_TEST=1", "-e", "CANDY_CORE_TEST_BINARY=/build/debug/candy-core", "-e", "CANDY_NETD_TEST_BINARY=/build/debug/candy-netd", "-e", "CANDY_AGENT_TEST_BINARY=/build/debug/candy-sdwan-agent", "-e", "CANDY_SIGNED_FIXTURE_BINARY=/build/debug/examples/sdwan_signed_cli_fixture", "-e", "CANDY_SIGNED_EVIDENCE_DIR=/evidence"]
docker(["run", "-d", "--name", build_container, "--label", "candy.candidate.gate="+str(evidence), "--network", "none", "--privileged", "--cpus", "2", "--memory", "4g", *mounts, *common_env, "candy-core-diag-builder:rust-1.88.0", "sleep", "infinity"])
docker(["run", "-d", "--name", container, "--label", "candy.candidate.gate="+str(evidence), "--network", "none", "--privileged", "--cpus", "2", "--memory", "4g", *mounts, *common_env, "candy-sdwan-perf-runner:20261013", "sleep", "infinity"])
results = []
def step(label, args, target=container, correctness=False):
    result = subprocess.run(["docker", "exec", target, *args], capture_output=True, text=True)
    (evidence/(label+".log")).write_text(result.stdout+"\n"+result.stderr)
    executed = re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", result.stdout+result.stderr) is not None if correctness else None
    passed = result.returncode == 0 and (not correctness or executed)
    results.append({"label":label,"exit":result.returncode,"passed":passed,"exact_one_test_passed":executed})
    print(label, result.returncode, "PASS" if passed else "FAIL", flush=True)
    if not passed and not correctness: raise RuntimeError(label+" failed; evidence retained")
try:
    step("build-core", ["cargo", "build", "--manifest-path", "/workspace/core/Cargo.toml", "--locked", "--offline", "-p", "candy-core-process", "--bin", "candy-core", "--example", "sdwan_signed_cli_fixture"], build_container)
    step("build-runtime", ["cargo", "build", "--manifest-path", "/workspace/runtime/Cargo.toml", "--locked", "--offline", "-p", "candy-netd", "-p", "candy-sdwan-agent", "--features", "candy-sdwan-agent/experimental-tunio-rebind", "--bins"], build_container)
    for index, test in enumerate(tests):
        if index:
            # A failed privileged fixture can leave a veth/namespace behind.
            # Reset only this test container so the next gate gets a fresh
            # network/process namespace; preserve all prior evidence/builds.
            docker(["restart", container])
        step(test, ["timeout", "240", "cargo", "test", "--manifest-path", "/workspace/runtime/linux/common/apps/candy-tunio/Cargo.toml", "--locked", "--offline", "--test", "signed_cli", test, "--", "--exact", "--ignored", "--nocapture"], correctness=True)
    step("binary-sha256", ["sha256sum", "/build/debug/candy-core", "/build/debug/candy-netd", "/build/debug/candy-sdwan-agent", "/build/debug/candy-tunio", "/build/debug/examples/sdwan_signed_cli_fixture"])
finally:
    (evidence/"result.json").write_text(json.dumps({"gate":"PASS" if len(results)==3+len(tests) and all(row["passed"] for row in results) else "FAIL","scope":"selected isolated Linux correctness tests; does not close G0-G6 or performance/convergence targets","tests":tests,"results":results,"container":container,"independent_build_volume":volume}, indent=2))
    (evidence/"container.json").write_text(docker(["inspect", container]))
    for name in (container, build_container):
        docker(["rm", "-f", name])
if any(not row["passed"] for row in results):
    raise SystemExit("one or more selected gates failed; all independent results retained")
