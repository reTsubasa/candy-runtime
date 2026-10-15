#!/usr/bin/env python3
"""Build a static netd platform-test artifact without changing the source lockfile."""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_command(arguments, cwd, env, log, timeout):
    with log.open("wb") as stream:
        process = subprocess.Popen(arguments, cwd=cwd, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return process.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            return 124


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--target-dir", type=Path, default=Path("target-openwrt-vm"))
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--kernel-test", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    target = args.target_dir.resolve()
    compiler = subprocess.check_output(["rustc", "-vV"], text=True)
    host = next(line.split(": ", 1)[1] for line in compiler.splitlines() if line.startswith("host: "))
    sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    linker = sysroot / "lib/rustlib" / host / "bin/rust-lld"
    if not linker.is_file():
        parser.error(f"native rust-lld is missing: {linker}")
    report = {"scope": "static x86_64 netd test artifact; not signed release",
              "compiler": compiler, "target": "x86_64-unknown-linux-musl", "jobs": 1,
              "source_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()}
    with tempfile.TemporaryDirectory(prefix="candy-netd-musl-source-") as temp:
        frozen = Path(temp)
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copy2(root / name, frozen / name)
        for directory in ("linux", "shared"):
            shutil.copytree(root / directory, frozen / directory, ignore=shutil.ignore_patterns("target", "__pycache__"))
        sources = {str(path.relative_to(frozen)): digest(path) for path in sorted(frozen.rglob("*")) if path.is_file()}
        report["source_files"] = sources
        shutil.copy2(frozen / "Cargo.lock", args.out / "source-Cargo.lock")
        env = dict(os.environ, CARGO_TARGET_DIR=str(target),
                   CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=str(linker))
        started = time.monotonic()
        exit_code = build_command(["cargo", "build", "--offline", "-j", "1", "--package", "candy-netd",
                                   "--target", report["target"]], frozen, env, args.out / "build.log", args.timeout)
        report["elapsed_s"] = time.monotonic() - started
        report["exit_code"] = exit_code
        shutil.copy2(frozen / "Cargo.lock", args.out / "resolved-Cargo.lock")
        report["test_lock_changed"] = digest(frozen / "Cargo.lock") != sources["Cargo.lock"]
        report["resolved_lock_sha256"] = digest(frozen / "Cargo.lock")
        (args.out / "test-lock.diff").write_text("".join(difflib.unified_diff(
            (args.out / "source-Cargo.lock").read_text().splitlines(keepends=True),
            (frozen / "Cargo.lock").read_text().splitlines(keepends=True),
            fromfile="source-Cargo.lock", tofile="resolved-Cargo.lock")))
        binary = target / report["target"] / "debug/candy-netd"
        if exit_code == 0:
            shutil.copy2(binary, args.out / "candy-netd")
            report["binary_sha256"] = digest(binary)
            report["elf"] = subprocess.check_output(["file", str(binary)], text=True).strip()
            if args.kernel_test:
                kernel_log = args.out / "kernel-build.jsonl"
                exit_code = build_command(["cargo", "test", "--locked", "--offline", "-j", "1",
                    "--package", "candy-netd", "--target", report["target"], "--test", "infrastructure_v2",
                    "--no-run", "--message-format=json"], frozen, env, kernel_log, args.timeout)
                report["kernel_build_exit_code"] = exit_code
                if exit_code == 0:
                    executable = None
                    for line in kernel_log.read_text().splitlines():
                        try:
                            item = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "infrastructure_v2":
                            executable = item.get("executable") or executable
                    if not executable:
                        raise RuntimeError("Cargo did not report the requested kernel test executable")
                    shutil.copy2(executable, args.out / "kernel-test")
                    report["kernel_test_sha256"] = digest(Path(executable))
    (args.out / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "source_files"}, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
