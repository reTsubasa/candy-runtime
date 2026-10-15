#!/usr/bin/env python3
"""Freeze committed Core/Runtime sources and build six Linux artifacts.

This is a release-build primitive only. It does not run performance tests,
publish, sign, or touch an existing evidence directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

RUNTIME = Path(__file__).resolve().parents[1]
CORE = RUNTIME.parent / "candy-core"
IMAGE = os.environ.get("CANDY_BUILD_IMAGE", "candy-core-diag-builder:rust-1.88.0")
CACHE = RUNTIME / "target-linux-netd-v2"
EXCLUDES = {".git", ".codegraph", "node_modules", "dist"}
PREFIXES = ("Cargo", ".cargo", "apps/", "crates/", "linux/", "shared/", "scripts/", "vendor/")
ARTIFACTS = {
    "candy-core": "/build/core/release/candy-core",
    "candy-netd": "/build/release/candy-netd",
    "candy-agent": "/build/release/candy-sdwan-agent",
    "candy-tunio": "/build/release/candy-tunio",
    "sdwan_signed_cli_fixture": "/build/core/release/examples/sdwan_signed_cli_fixture",
    "signed_cli_helper": "/build/release/signed_cli_helper",
}


def run(args: list[str], *, cwd: Path | None = None, capture: bool = True) -> str:
    result = subprocess.run(args, cwd=cwd, check=True, text=True,
                            capture_output=capture)
    return result.stdout if capture else ""


def run_build(args: list[str], log: Path) -> None:
    result = subprocess.run(args, text=True, capture_output=True)
    log.write_text(result.stdout + "\n" + result.stderr)
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, args)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_state(repo: Path) -> dict[str, str]:
    return {
        "head": run(["git", "rev-parse", "HEAD"], cwd=repo).strip(),
        "status": run(["git", "status", "--short"], cwd=repo),
    }


def source_files(repo: Path) -> list[Path]:
    names = run(["git", "ls-files"], cwd=repo).splitlines()
    paths = []
    for name in names:
        path = Path(name)
        if path.parts[0] in EXCLUDES or name.startswith("docs/artifacts/"):
            continue
        if name.startswith(PREFIXES) and (repo / path).is_file():
            paths.append(path)
    return sorted(paths)


def freeze(repo: Path, root: Path, label: str) -> dict:
    state = git_state(repo)
    entries = []
    for relative in source_files(repo):
        source = repo / relative
        destination = root / f"candy-{label}" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        entries.append({"path": f"candy-{label}/{relative}", "sha256": sha256(source),
                        "mode": source.stat().st_mode & 0o777})
    return {"git_sha": state["head"], "status": state["status"], "files": entries}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--self-check", action="store_true",
                        help="validate repository inputs and refuse to build")
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    if evidence.exists():
        raise SystemExit(f"refusing to overwrite existing evidence directory: {evidence}")
    if not CORE.is_dir():
        raise SystemExit(f"missing sibling Core checkout: {CORE}")
    if not CACHE.is_dir():
        raise SystemExit(f"required Cargo cache is missing: {CACHE}")
    if args.self_check:
        if not source_files(CORE) or not source_files(RUNTIME):
            raise SystemExit("committed source manifest is empty")
        print(json.dumps({"self_check": "PASS", "core_head": git_state(CORE)["head"],
                          "runtime_head": git_state(RUNTIME)["head"],
                          "cache": str(CACHE), "image": IMAGE}, indent=2))
        return 0
    evidence.mkdir(parents=True, mode=0o700)
    frozen = evidence / "frozen"
    core = freeze(CORE, frozen, "core")
    runtime = freeze(RUNTIME, frozen, "runtime")
    manifest = {"schema_version": 1, "source_mode": "committed HEAD; working changes excluded",
                "frozen_at": datetime.now(timezone.utc).isoformat(), "revisions": {
                    "candy-core": {"head": core["git_sha"], "status": core["status"]},
                    "candy-runtime": {"head": runtime["git_sha"], "status": runtime["status"]},
                }, "files": core["files"] + runtime["files"]}
    raw = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
    manifest["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    (evidence / "source-manifest.json").write_bytes(
        json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n")
    provenance = {"image": IMAGE, "cache": str(CACHE), "flags": "--release --locked --offline",
                  "runtime_features": ["candy-sdwan-agent/experimental-tunio-rebind"],
                  "artifacts": {}, "git": manifest["revisions"]}
    (evidence / "freeze.json").write_text(json.dumps({
        "source_mode": manifest["source_mode"], "manifest_sha256": manifest["manifest_sha256"],
        "working_tree_status": manifest["revisions"], "excluded": sorted(EXCLUDES),
    }, indent=2) + "\n")
    mounts = ["-v", f"{frozen}:/workspace:ro", "-v", f"{evidence}:/evidence:rw",
              "-v", f"{CACHE}:/build:rw"]
    name = "candy-freeze-build-" + hashlib.sha256(str(evidence).encode()).hexdigest()[:12]
    try:
        run_build(["docker", "run", "--name", name, "--rm", "--network", "none", "--cpus", "2",
             "--memory", "4g", *mounts, IMAGE, "cargo", "build", "--manifest-path",
             "/workspace/candy-core/Cargo.toml", "--target-dir", "/build/core", "--release", "--locked", "--offline",
             "-p", "candy-core-process", "--bin", "candy-core", "--example", "sdwan_signed_cli_fixture"],
            evidence / "build-core.log")
        run_build(["docker", "run", "--name", name + "-runtime", "--rm", "--network", "none", "--cpus", "2",
             "--memory", "4g", *mounts, IMAGE, "cargo", "build", "--manifest-path",
             "/workspace/candy-runtime/Cargo.toml", "--target-dir", "/build", "--release", "--locked", "--offline",
             "--features", "candy-sdwan-agent/experimental-tunio-rebind", "--bins"], evidence / "build-runtime.log")
        # candy-tunio is a deliberately separate workspace.
        run_build(["docker", "run", "--name", name + "-tunio", "--rm", "--network", "none", "--cpus", "2",
             "--memory", "4g", *mounts, IMAGE, "cargo", "build", "--manifest-path",
             "/workspace/candy-runtime/linux/common/apps/candy-tunio/Cargo.toml", "--target-dir", "/build", "--release",
             "--locked", "--offline"], evidence / "build-tunio.log")
        run_build(["docker", "run", "--name", name + "-helper", "--rm", "--network", "none", "--cpus", "2",
             "--memory", "4g", *mounts, IMAGE, "sh", "-ec",
             "cargo test --manifest-path /workspace/candy-runtime/linux/common/apps/candy-tunio/Cargo.toml --target-dir /build --release --locked --offline --test signed_cli --no-run; candidate=$(find /build/release/deps -maxdepth 1 -type f -name 'signed_cli-*' -perm -111 | sort | tail -n 1); test -n \"$candidate\"; cp \"$candidate\" /build/release/signed_cli_helper"], evidence / "build-signed-cli-helper.log")
        for label, path in ARTIFACTS.items():
            source = CACHE / Path(path.removeprefix("/build/"))
            if not source.is_file():
                raise SystemExit(f"required release artifact missing: {label}: {source}")
            target = evidence / "binaries" / label
            target.parent.mkdir(exist_ok=True)
            shutil.copy2(source, target)
            provenance["artifacts"][label] = {"sha256": sha256(target), "bytes": target.stat().st_size}
    finally:
        (evidence / "build-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    (evidence / "result.json").write_text(json.dumps({"gate": "BUILD_PASS", "performance": "NOT_RUN",
                                                       "manifest_sha256": manifest["manifest_sha256"]}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
