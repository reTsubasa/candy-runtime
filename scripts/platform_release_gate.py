#!/usr/bin/env python3
"""Lightweight, offline platform gates. Never build, sign, publish or install."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import tempfile
import time

RUNTIME = Path(__file__).resolve().parents[1]
CONTRACTS = [
    ("runtime", "packaging/openwrt/tests/package_gate_test.sh"),
    ("runtime", "packaging/openwrt/tests/sdk_container_profile_test.sh"),
    ("runtime", "packaging/openwrt/tests/runtime_release_test.sh"),
    ("runtime", "scripts/openwrt_core_manager_test.sh"),
    ("runtime", "scripts/openwrt_update_manager_test.sh"),
    ("runtime", "scripts/openwrt_runtime_health_check_test.sh"),
    ("runtime", "openwrt/client/tests/update_luci_test.sh"),
    ("release", ".github/scripts/catalog-policy-test.sh"),
    ("release", ".github/scripts/catalog-update-test.sh"),
    ("release", ".github/scripts/sign-core-candidate-test.sh"),
    ("release", ".github/scripts/sign-core-candidate-workflow-test.sh"),
    ("release", ".github/scripts/verify-core-release-metadata-test.sh"),
    ("release", ".github/scripts/verify-linux-runtime-bundle-test.sh"),
]


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def elf_identity(path, profile):
    """Verify static Linux ELF identity without running a foreign executable."""
    data = path.read_bytes()
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[5] != 1:
        raise ValueError("not a little-endian ELF")
    bits, machine = data[4], struct.unpack_from("<H", data, 18)[0]
    if profile not in ("x86_64", "ipq40xx"):
        raise ValueError("unsupported ELF profile; choose x86_64 or ipq40xx")
    expected = {"x86_64": (2, 62), "ipq40xx": (1, 40)}[profile]
    if (bits, machine) != expected:
        raise ValueError(f"wrong class/machine: {(bits, machine)} != {expected}")
    if struct.unpack_from("<H", data, 16)[0] not in (2, 3):
        raise ValueError("ELF must be executable or PIE")
    if bits == 1:
        flags, offset = struct.unpack_from("<I", data, 36)[0], struct.unpack_from("<I", data, 28)[0]
        entry_size, count = struct.unpack_from("<HH", data, 42)
        if flags & 0xFF000000 != 0x05000000 or not flags & 0x400 or flags & 0x200:
            raise ValueError("IPQ40xx requires EABI5 hard-float, not generic ARM/soft-float")
        minimum_entry = 32
        header_size = 52
    else:
        if len(data) < 64:
            raise ValueError("truncated ELF64 header")
        flags, offset = 0, struct.unpack_from("<Q", data, 32)[0]
        entry_size, count = struct.unpack_from("<HH", data, 54)
        minimum_entry = 56
        header_size = 64
    if not count or entry_size < minimum_entry or offset < header_size or offset + count * entry_size > len(data):
        raise ValueError("invalid or unsupported ELF program-header table")
    if any(struct.unpack_from("<I", data, offset + i * entry_size)[0] == 3 for i in range(count)):
        raise ValueError("dynamic interpreter found; OpenWrt candidate must be static")
    return {"class": bits * 32, "machine": machine, "flags": flags,
            "profile": profile, "sha256": sha(path), "size": len(data)}


def apk_identity(apk, sdk, log, require_alignment=True):
    signer = sdk / "apksigner"
    if not signer.is_file():
        raise FileNotFoundError(f"missing Android tool {signer}")
    certs = subprocess.run([str(signer), "verify", "--verbose", "--print-certs", str(apk)],
                           capture_output=True, text=True, timeout=120)
    log.write_text(certs.stdout + certs.stderr)
    if certs.returncode:
        raise ValueError("APK signature verification failed; see log")
    digests = re.findall(r"Signer #\d+ certificate SHA-256 digest: ([0-9a-f]{64})", certs.stdout)
    if len(digests) != 1:
        raise ValueError("expected exactly one APK signer")
    badging = subprocess.check_output([str(sdk / "aapt"), "dump", "badging", str(apk)], text=True, timeout=30)
    package = re.search(r"package: name='([^']+)' versionCode='(\d+)' versionName='([^']+)'", badging)
    if not package:
        raise ValueError("missing APK package/version")
    alignment = subprocess.run([str(sdk / "zipalign"), "-c", "-P", "16", "4", str(apk)],
                               capture_output=True, timeout=30)
    if require_alignment and alignment.returncode:
        raise ValueError("candidate APK fails 16 KiB alignment verification")
    native = re.search(r"^native-code: (.+)$", badging, re.MULTILINE)
    return {"package": package[1], "version_code": int(package[2]), "version_name": package[3],
            "certificate_sha256": digests[0], "native_abis": re.findall(r"'([^']+)'", native[1]) if native else [],
            "sha256": sha(apk), "path": str(apk), "alignment_16k": alignment.returncode == 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="new evidence directory; never overwritten")
    parser.add_argument("--release-repo", type=Path, default=RUNTIME.parent / "candy-release")
    parser.add_argument("--contracts", action="store_true", help="run isolated fixture suites sequentially")
    parser.add_argument("--contract-timeout", type=int, default=600, help="per-suite deadline in seconds")
    parser.add_argument("--contract-only", action="append", default=[], choices=[p for _, p in CONTRACTS],
                        help="select specific fixture suites for failure rechecks")
    parser.add_argument("--elf", action="append", default=[], metavar="x86_64|ipq40xx=PATH")
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--previous-apk", type=Path)
    parser.add_argument("--android-tools", type=Path)
    parser.add_argument("--expected-apk-cert", help="required release signer SHA-256, if known")
    args = parser.parse_args()
    if args.contract_timeout < 1:
        parser.error("--contract-timeout must be positive")
    if args.contract_only and not args.contracts:
        parser.error("--contract-only requires --contracts")
    if args.expected_apk_cert and not args.apk:
        parser.error("--expected-apk-cert requires --apk")
    args.out.mkdir(parents=True, exist_ok=False)
    runner_sha256 = sha(Path(__file__).resolve())
    results = []

    def check(name, scope, action):
        started = time.monotonic()
        try:
            evidence = action()
            status = "PASS"
        except Exception as error:
            status, evidence = "FAIL", {"error": str(error)}
        results.append({"name": name, "scope": scope, "status": status, "evidence": evidence,
                        "elapsed_seconds": round(time.monotonic() - started, 3)})
        print(f"{status} {name}", flush=True)

    def run_contract(repo, relative):
        root = RUNTIME if repo == "runtime" else args.release_repo
        script = root / relative
        log = args.out / (repo + "-" + script.stem + ".log")
        with log.open("w") as output:
            run = subprocess.Popen(["bash", str(script)], cwd=root, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = run.wait(timeout=args.contract_timeout)
            except subprocess.TimeoutExpired:
                os.killpg(run.pid, signal.SIGKILL)
                run.wait()
                raise ValueError(f"suite deadline {args.contract_timeout}s exceeded; log={log.name}")
        if code:
            raise ValueError(f"exit={code}; log={log.name}")
        return {"script_sha256": sha(script), "log": log.name, "fixture_only": True}

    if args.contracts:
        for repo, relative in CONTRACTS:
            if args.contract_only and relative not in args.contract_only:
                continue
            check(f"{repo}:{relative}", "fixture contract", lambda r=repo, p=relative: run_contract(r, p))

    def catalog_signature():
        public = args.release_repo / "keys/catalog-release.pub"
        catalog = args.release_repo / "channels/stable.json"
        signature = args.release_repo / "channels/stable.json.sig"
        command = ["usign", "-V", "-p", str(public), "-m", str(catalog), "-x", str(signature)]
        subprocess.run(command, check=True, capture_output=True, timeout=15)
        with tempfile.TemporaryDirectory(prefix="candy-catalog-tamper-") as temporary:
            changed = Path(temporary) / "stable.json"
            changed.write_bytes(catalog.read_bytes() + b"\n ")
            command[command.index("-m") + 1] = str(changed)
            if subprocess.run(command, capture_output=True, timeout=15).returncode == 0:
                raise ValueError("modified catalog accepted")
        return {"catalog_sha256": sha(catalog), "public_key_sha256": sha(public),
                "tampered_catalog_rejected": True, "does_not_validate_new_candidates": True}

    check("existing catalog signature and tamper rejection", "real cryptographic verification", catalog_signature)
    for specification in args.elf:
        def elf_candidate(specification=specification):
            if "=" not in specification:
                raise ValueError("--elf must be x86_64=PATH or ipq40xx=PATH")
            profile, path = specification.split("=", 1)
            return elf_identity(Path(path), profile)
        check("ELF:" + specification, "artifact metadata", elf_candidate)
    if args.apk:
        def apk_pair():
            if not args.previous_apk or not args.android_tools:
                raise ValueError("--previous-apk and --android-tools are required")
            old = apk_identity(args.previous_apk, args.android_tools, args.out / "previous-apk.log", False)
            new = apk_identity(args.apk, args.android_tools, args.out / "candidate-apk.log")
            (args.out / "apk-identities.json").write_text(json.dumps({"previous": old, "candidate": new}, indent=2) + "\n")
            for key in ("package", "certificate_sha256"):
                if old[key] != new[key]:
                    raise ValueError(f"APK {key} mismatch: {old[key]} -> {new[key]}")
            if new["version_code"] <= old["version_code"]:
                raise ValueError("candidate APK versionCode must increase")
            if not set(old["native_abis"]).issubset(new["native_abis"]):
                raise ValueError("candidate lost an installed ABI")
            return {"previous": old, "candidate": new, "device_install_not_run": True}
        check("APK signature/package/version/ABI upgrade compatibility", "artifact metadata", apk_pair)
        if args.expected_apk_cert:
            def release_signer():
                identities = json.loads((args.out / "apk-identities.json").read_text())
                required = args.expected_apk_cert.lower()
                if not re.fullmatch(r"[0-9a-f]{64}", required):
                    raise ValueError("expected signer must be a SHA-256 hex digest")
                candidate = identities["candidate"]["certificate_sha256"]
                if candidate != required:
                    raise ValueError(f"release signer differs from candidate: required={required}, candidate={candidate}; migration required for differently signed installed APK")
                return {"required_certificate_sha256": required}
            check("APK required release signer", "artifact signing policy", release_signer)
    pending = [
        "current frozen OpenWrt x86_64 and IPQ40xx release build with matching Core, Runtime and provenance",
        "real signed candidate bundles and complete extracted-payload verification before release",
        "OpenWrt x86_64 procd boot/install/upgrade/failed-activation rollback and persistent configuration",
        "IPQ40xx ARMv7 kernel ABI/TUN/procd boot/install/upgrade/rollback on physical device",
        "Android device or isolated emulator install-over-old, VPN service, TUN data path and recovery",
        "Android rollback policy: preserve exported config; ordinary production APK downgrade is not guaranteed",
    ]
    sources = {}
    for name, root in (("runtime", RUNTIME), ("release", args.release_repo)):
        try:
            sources[name] = {"head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True, stderr=subprocess.DEVNULL).strip(),
                             "worktree_modified": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True, stderr=subprocess.DEVNULL))}
        except (OSError, subprocess.SubprocessError) as error:
            sources[name] = {"error": str(error)}
    report = {"schema_version": 1, "overall": "FAIL" if any(r["status"] == "FAIL" for r in results) else "INCOMPLETE",
              "sources_at_report": sources, "gate_runner_sha256_at_start": runner_sha256,
              "results": results, "not_run": pending, "tools": {name: shutil.which(name) for name in
              ("docker", "qemu-system-x86_64", "qemu-system-arm", "qemu-arm", "adb", "usign", "jq", "node")}}
    (args.out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return 1 if report["overall"] == "FAIL" else 2


if __name__ == "__main__":
    raise SystemExit(main())
