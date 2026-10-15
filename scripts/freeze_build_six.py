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
import tempfile
from datetime import datetime, timezone
from pathlib import Path

RUNTIME = Path(__file__).resolve().parents[1]
CORE = RUNTIME.parent / "candy-core"
IMAGE = os.environ.get("CANDY_BUILD_IMAGE", "candy-core-diag-builder:rust-1.88.0")
CACHE = RUNTIME / "target-linux-netd-v2"
EXCLUDES = {".git", ".codegraph", "node_modules", "dist"}
PREFIXES = ("Cargo", ".cargo", "apps/", "crates/", "linux/", "shared/", "scripts/", "vendor/")
ARTIFACTS = {
    "candy-core": "/build/release/candy-core",
    "candy-netd": "/build/release/candy-netd",
    "candy-agent": "/build/release/candy-sdwan-agent",
    "candy-tunio": "/build/release/candy-tunio",
    "sdwan_signed_cli_fixture": "/build/release/examples/sdwan_signed_cli_fixture",
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


def canonical_manifest(entries: list[dict]) -> tuple[bytes, str]:
    """Return the canonical manifest bytes and their recorded digest."""
    body = json.dumps(entries, indent=2, sort_keys=True).encode() + b"\n"
    return body, hashlib.sha256(body).hexdigest()


def select_signed_cli_executable(raw: str) -> str:
    """Select exactly the Cargo JSON artifact for the signed_cli test target."""
    rows = []
    for line in raw.splitlines():
        if not line.lstrip().startswith("{"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    hits = [row["executable"] for row in rows
            if row.get("reason") == "compiler-artifact"
            and row.get("target", {}).get("name") == "signed_cli"
            and row.get("target", {}).get("kind") == ["test"]
            and isinstance(row.get("executable"), str)]
    if len(hits) != 1:
        raise ValueError(f"expected exactly one signed_cli test executable, got {hits!r}")
    return hits[0]


def source_blobs(repo: Path) -> list[tuple[Path, bytes, int]]:
    """Read committed blobs directly from HEAD; never consult the worktree."""
    raw = subprocess.check_output(
        ["git", "ls-tree", "-r", "-z", "--full-tree", "HEAD"], cwd=repo)
    files = []
    for record in raw.rstrip(b"\0").split(b"\0"):
        meta, name = record.split(b"\t", 1)
        mode, kind, object_id = meta.split()
        relative = Path(os.fsdecode(name))
        text = relative.as_posix()
        if kind != b"blob" or text.startswith("docs/artifacts/") or any(
                part in EXCLUDES or part.startswith("target-") for part in relative.parts):
            continue
        if not text.startswith(PREFIXES):
            continue
        data = subprocess.check_output(["git", "cat-file", "blob", object_id], cwd=repo)
        files.append((relative, data, int(mode, 8)))
    return sorted(files, key=lambda item: item[0].as_posix())


def self_check() -> None:
    """Exercise the freeze invariants without Docker, builds, or network access."""
    with tempfile.TemporaryDirectory(prefix="candy-freeze-self-check-") as directory:
        repo = Path(directory) / "repo"
        repo.mkdir()
        run(["git", "init", "-q"], cwd=repo)
        (repo / "apps").mkdir()
        (repo / "apps/committed.rs").write_text("committed HEAD\n")
        (repo / "apps/deleted.rs").write_text("still in HEAD\n")
        run(["git", "add", "apps"], cwd=repo)
        env = os.environ.copy()
        env.update({"GIT_AUTHOR_NAME": "freeze-self-check", "GIT_AUTHOR_EMAIL": "freeze@example.invalid",
                    "GIT_COMMITTER_NAME": "freeze-self-check", "GIT_COMMITTER_EMAIL": "freeze@example.invalid"})
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, env=env, check=True)
        (repo / "apps/committed.rs").write_text("dirty worktree\n")
        (repo / "apps/deleted.rs").unlink()
        (repo / "apps/untracked.rs").write_text("untracked source\n")
        frozen = source_blobs(repo)
        paths = {path.as_posix(): data for path, data, _ in frozen}
        assert paths == {"apps/committed.rs": b"committed HEAD\n",
                         "apps/deleted.rs": b"still in HEAD\n"}, paths

        entries = [{"path": f"candy-runtime/{path}",
                    "sha256": hashlib.sha256(data).hexdigest(), "mode": mode & 0o777}
                   for path, data, mode in frozen]
        body, digest = canonical_manifest(entries)
        manifest_path = repo / "source-manifest.json"
        manifest_path.write_bytes(body)
        assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == digest

    cargo_line = json.dumps({"reason": "compiler-artifact", "target": {
        "name": "signed_cli", "kind": ["test"]}, "executable": "/build/release/deps/signed_cli-abc"})
    assert select_signed_cli_executable("warning\n" + cargo_line) == "/build/release/deps/signed_cli-abc"
    stale = json.dumps({"reason": "compiler-artifact", "target": {
        "name": "other", "kind": ["test"]}, "executable": "/build/release/deps/other-abc"})
    assert select_signed_cli_executable(stale + "\n" + cargo_line) == "/build/release/deps/signed_cli-abc"
    for invalid in ("", cargo_line + "\n" + cargo_line, json.dumps({"reason": "compiler-artifact",
            "target": {"name": "signed_cli", "kind": ["bin"]}, "executable": "/build/stale"})):
        try:
            select_signed_cli_executable(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid Cargo JSON accepted: {invalid}")

    with tempfile.TemporaryDirectory(prefix="candy-freeze-evidence-") as directory:
        existing = Path(directory) / "evidence"
        existing.mkdir()
        try:
            ensure_fresh_evidence(existing)
        except ValueError:
            pass
        else:
            raise AssertionError("existing evidence directory was accepted")
    print(json.dumps({"self_check": "PASS", "checks": [
        "committed HEAD source freeze excludes dirty modifications, deletions, and untracked files",
        "manifest hash roundtrip", "exact signed_cli Cargo artifact selection",
        "existing evidence directory rejection"]}, indent=2))


def ensure_fresh_evidence(evidence: Path) -> None:
    if evidence.exists():
        raise ValueError(f"refusing to overwrite existing evidence directory: {evidence}")


def freeze(repo: Path, root: Path, label: str) -> dict:
    state = git_state(repo)
    entries = []
    for relative, data, mode in source_blobs(repo):
        source = repo / relative
        destination = root / f"candy-{label}" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(mode & 0o777)
        entries.append({"path": f"candy-{label}/{relative}",
                        "sha256": hashlib.sha256(data).hexdigest(), "mode": mode & 0o777})
    return {"git_sha": state["head"], "status": state["status"], "files": entries}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--self-check", action="store_true",
                        help="validate repository inputs and refuse to build")
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    try:
        ensure_fresh_evidence(evidence)
    except ValueError as error:
        raise SystemExit(str(error))
    if not CORE.is_dir():
        raise SystemExit(f"missing sibling Core checkout: {CORE}")
    if not CACHE.is_dir():
        raise SystemExit(f"required Cargo cache is missing: {CACHE}")
    if args.self_check:
        if not source_blobs(CORE) or not source_blobs(RUNTIME):
            raise SystemExit("committed source manifest is empty")
        self_check()
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
    manifest_entries = manifest["files"]
    manifest_body, manifest_digest = canonical_manifest(manifest_entries)
    (evidence / "source-manifest.json").write_bytes(manifest_body)
    source_freeze = {
        "frozen_at": manifest["frozen_at"], "manifest_sha256": manifest_digest,
        "files": len(manifest_entries),
        "source_mode": manifest["source_mode"], "revisions": manifest["revisions"],
        "excluded": "target*, .git, .codegraph, node_modules, dist, artifacts",
    }
    (evidence / "source-freeze.json").write_text(json.dumps(source_freeze, indent=2) + "\n")
    provenance = {"image": IMAGE, "cache": str(CACHE), "flags": "--release --locked --offline",
                  "runtime_features": ["candy-sdwan-agent/experimental-tunio-rebind"],
                  "artifacts": {}, "git": manifest["revisions"]}
    (evidence / "freeze.json").write_text(json.dumps({
        "source_mode": manifest["source_mode"], "manifest_sha256": manifest_digest,
        "working_tree_status": manifest["revisions"], "excluded": sorted(EXCLUDES),
    }, indent=2) + "\n")
    mounts = ["-v", f"{frozen}:/workspace:ro", "-v", f"{evidence}:/evidence:rw",
              "-v", f"{CACHE}:/build:rw"]
    name = "candy-freeze-build-" + hashlib.sha256(str(evidence).encode()).hexdigest()[:12]
    try:
        run_build(["docker", "run", "--name", name, "--rm", "--network", "none", "--cpus", "2",
             "--memory", "4g", *mounts, IMAGE, "cargo", "build", "--manifest-path",
             "/workspace/candy-core/Cargo.toml", "--target-dir", "/build", "--release", "--locked", "--offline",
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
             "cargo test --manifest-path /workspace/candy-runtime/linux/common/apps/candy-tunio/Cargo.toml --target-dir /build --release --locked --offline --test signed_cli --no-run --message-format=json > /evidence/signed-cli-cargo.jsonl; python3 -c 'import json,pathlib,shutil; p=pathlib.Path(\"/evidence/signed-cli-cargo.jsonl\"); rows=[]; [rows.append(json.loads(x)) for x in p.read_text().splitlines() if x.lstrip().startswith(\"{\")]; hits=[r[\"executable\"] for r in rows if r.get(\"reason\")==\"compiler-artifact\" and r.get(\"target\",{}).get(\"name\")==\"signed_cli\" and r.get(\"target\",{}).get(\"kind\")==[\"test\"] and isinstance(r.get(\"executable\"),str)]; assert len(hits)==1, hits; src=pathlib.Path(hits[0]); assert src.is_file(); shutil.copy2(src,\"/build/release/signed_cli_helper\")'"], evidence / "build-signed-cli-helper.log")
        for label, path in ARTIFACTS.items():
            source = CACHE / Path(path.removeprefix("/build/"))
            if not source.is_file():
                raise SystemExit(f"required release artifact missing: {label}: {source}")
            target = evidence / "binaries" / label
            target.parent.mkdir(exist_ok=True)
            shutil.copy2(source, target)
            provenance["artifacts"][label] = {"sha256": sha256(target), "bytes": target.stat().st_size}
        provenance["binary_hashes"] = {
            label: details["sha256"] for label, details in provenance["artifacts"].items()
        }
        rustc = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", *mounts, IMAGE, "rustc", "-Vv"],
            check=True, capture_output=True, text=True)
        provenance["rustc"] = rustc.stdout
        image = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE],
                               check=True, capture_output=True, text=True)
        provenance["image_id"] = image.stdout.strip()
        (evidence / "binary-hashes.json").write_text(
            json.dumps(provenance["binary_hashes"], indent=2, sort_keys=True) + "\n")
    finally:
        (evidence / "build-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    (evidence / "result.json").write_text(json.dumps({"gate": "BUILD_PASS", "performance": "NOT_RUN",
                                                       "manifest_sha256": manifest_digest}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
