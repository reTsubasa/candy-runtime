#!/usr/bin/env python3
"""Disposable, resource-bounded OpenWrt/procd gate; never a platform PASS by itself."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import tarfile
import tempfile
import time
import urllib.request


RELEASE = "25.12.5"
# Independently published in openwrt/keyring, usign/b5043e70f9a75cde.
# Git blob 82d7677e2370c7abf87e70abd2e77c4daf660331, checked 2026-10-15.
RELEASE_KEY = ("untrusted comment: Public usign key for unattended snapshot builds\n"
               "RWS1BD5w+adc3j2Hqg9+b66CvLR7NlHbsj7wjNVj0XGt/othDgIAOJS+\n")
SCOPE = "OpenWrt real procd with lifecycle probe; optional real netd; no complete SD-WAN acceptance"


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def manifest_digest(text, filename):
    found = []
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        if match and match[2] == filename:
            found.append(match[1])
    if len(found) != 1:
        raise ValueError("signed manifest must contain exactly one matching image")
    return found[0]


def static_x86_elf(path):
    raw = Path(path).read_bytes()
    if len(raw) < 64 or raw[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", raw, 18)[0] != 62:
        raise ValueError("netd must be a little-endian x86_64 ELF")
    offset = struct.unpack_from("<Q", raw, 32)[0]
    size, count = struct.unpack_from("<HH", raw, 54)
    if size < 56 or count == 0 or offset + size * count > len(raw):
        raise ValueError("malformed ELF program headers")
    if any(struct.unpack_from("<I", raw, offset + size * index)[0] == 3 for index in range(count)):
        raise ValueError("netd must be static: dynamic ELF interpreter found")


def download(url, target, limit):
    request = urllib.request.Request(url, headers={"User-Agent": "candy-platform-gate/1"})
    with urllib.request.urlopen(request, timeout=30) as response, target.open("wb") as out:
        if not response.url.startswith("https://downloads.openwrt.org/"):
            raise ValueError("unexpected download redirect")
        size = 0
        while block := response.read(1024 * 1024):
            size += len(block)
            if size > limit:
                raise ValueError("download exceeds bounded artifact size")
            out.write(block)


def acquire(cache, release, usign):
    if not re.fullmatch(r"25\.12\.[0-9]+", release):
        raise ValueError("release must be a stable 25.12.x version")
    name = f"openwrt-{release}-x86-64-generic-ext4-combined.img.gz"
    base = f"https://downloads.openwrt.org/releases/{release}/targets/x86/64/"
    cache.mkdir(parents=True, exist_ok=True)
    for item in ("sha256sums", "sha256sums.sig"):
        download(base + item, cache / item, 2 * 1024 * 1024)
    key = cache / "release.pub"
    key.write_text(RELEASE_KEY)
    subprocess.run([usign, "-V", "-p", str(key), "-m", str(cache / "sha256sums"),
                    "-x", str(cache / "sha256sums.sig")], check=True, timeout=15)
    expected = manifest_digest((cache / "sha256sums").read_text(), name)
    image = cache / name
    if not image.exists() or sha256(image) != expected:
        download(base + name, image, 128 * 1024 * 1024)
    if sha256(image) != expected:
        raise ValueError("official image checksum mismatch")
    return image, {"release": release, "url": base + name, "sha256": expected,
                   "manifest_sha256": sha256(cache / "sha256sums"),
                   "usign_fingerprint": "b5043e70f9a75cde", "signature_verified": True}


def acquire_kernel_packages(cache, release):
    if release != RELEASE:
        raise ValueError("kernel fixture package set is pinned to 25.12.5")
    base = f"https://downloads.openwrt.org/releases/{release}/packages/x86_64/base/"
    packages = [base + name for name in ("packages.adb", "ip-full-6.18.0-r2.apk", "libbpf1-1.6.2-r1.apk",
                "libelf1-0.192-r1.apk", "libmnl0-1.0.5-r1.apk", "zlib-1.3.1-r1.apk", "libcap-2.69-r1.apk")]
    kernel_base = (f"https://downloads.openwrt.org/releases/{release}/targets/x86/64/"
                   "kmods/6.12.94-1-a7bc15f451f9652701ba04af9cfb0b95/")
    packages += [kernel_base + "packages.adb", kernel_base + "kmod-tun-6.12.94-r1.apk"]
    cache.mkdir(parents=True, exist_ok=True)
    paths, evidence = [], []
    for url in packages:
        repository = "kmods" if "/kmods/" in url else "base"
        (cache / repository).mkdir(exist_ok=True)
        path = cache / repository / url.rsplit("/", 1)[1]
        download(url, path, 8 * 1024 * 1024)
        paths.append((path, "repos/" + repository + "/" + path.name))
        evidence.append({"url": url, "sha256": sha256(path), "trust": "guest signed APK repository verification required"})
    return paths, evidence


def command(args, deadline, **kwargs):
    return subprocess.run(args, check=True, timeout=max(1, deadline - time.monotonic()), **kwargs)


def run_vm(args, image, report):
    deadline = time.monotonic() + args.timeout
    with tempfile.TemporaryDirectory(prefix="candy-openwrt-gate-") as tmp:
        work = Path(tmp)
        disk = work / "openwrt.img"
        with gzip.open(image, "rb") as src, disk.open("wb") as dst:
            written = 0
            while block := src.read(1024 * 1024):
                written += len(block)
                if written > 512 * 1024 * 1024:
                    raise ValueError("decompressed image exceeds 512 MiB")
                dst.write(block)
        key = work / "id_ed25519"
        command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], deadline)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        ssh = ["ssh", "-F", "/dev/null", "-i", str(key), "-p", str(port),
               "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", "-o", "StrictHostKeyChecking=accept-new",
               "-o", f"UserKnownHostsFile={work / 'known_hosts'}", "root@127.0.0.1"]
        qemu = [args.qemu, "-machine", "q35", "-accel", "tcg,thread=single", "-smp", "1",
                "-m", "512", "-display", "none", "-monitor", "none", "-serial", "stdio",
                "-no-reboot", "-snapshot", "-drive", f"file={disk},format=raw,if=virtio",
                "-netdev", f"user,id=isolated,restrict=on,hostfwd=tcp:127.0.0.1:{port}-:22",
                "-device", "virtio-net-pci,netdev=isolated"]
        report["qemu"] = {"vcpus": 1, "memory_mib": 512, "snapshot": True,
                          "guest_egress": "restricted", "ssh_bind": "127.0.0.1", "timeout_s": args.timeout}
        with (args.out / "serial.log").open("wb") as serial:
            process = subprocess.Popen(qemu, stdin=subprocess.PIPE, stdout=serial,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                booted = False
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError(f"QEMU exited during boot: {process.returncode}")
                    if b"Please press Enter to activate this console" in (args.out / "serial.log").read_bytes():
                        booted = True
                        break
                    time.sleep(0.5)
                if not booted:
                    raise TimeoutError("OpenWrt console boot deadline")
                process.stdin.write(b"\n")
                process.stdin.flush()
                while time.monotonic() < deadline:
                    if b"root@" in (args.out / "serial.log").read_bytes():
                        break
                    time.sleep(0.5)
                else:
                    raise TimeoutError("OpenWrt interactive shell deadline")
                public = shlex.quote(key.with_suffix(".pub").read_text().strip())
                bootstrap = ("mkdir -p /etc/dropbear; chmod 700 /etc/dropbear; "
                             f"printf '%s\\n' {public} >/etc/dropbear/authorized_keys; "
                             "chmod 600 /etc/dropbear/authorized_keys; "
                             "i=0; while [ ! -d /sys/class/net/br-lan ] && [ $i -lt 60 ]; do "
                             "sleep 1; i=$((i+1)); done; "
                             "/etc/init.d/firewall stop; "
                             "ip addr add 10.0.2.15/24 dev br-lan; ip link set br-lan up; "
                             "/etc/init.d/dropbear restart\n")
                process.stdin.write(bootstrap.encode())
                process.stdin.flush()
                while time.monotonic() < deadline:
                    try:
                        ready = subprocess.run(ssh + ["true"], stdout=subprocess.DEVNULL,
                                               stderr=subprocess.DEVNULL, timeout=5)
                    except subprocess.TimeoutExpired:
                        continue
                    if ready.returncode == 0:
                        break
                    time.sleep(1)
                else:
                    raise TimeoutError("isolated guest SSH deadline")
                payload = io.BytesIO()
                with tarfile.open(fileobj=payload, mode="w:gz") as archive:
                    archive.add(Path(__file__).with_name("openwrt_vm_guest.sh"), arcname="guest.sh")
                    if args.netd:
                        static_x86_elf(args.netd)
                        archive.add(args.netd, arcname="candy-netd")
                        report["netd_sha256"] = sha256(args.netd)
                    if args.kernel_test:
                        static_x86_elf(args.kernel_test)
                        archive.add(args.kernel_test, arcname="kernel-test")
                        report["kernel_test_sha256"] = sha256(args.kernel_test)
                        for path, name in args.kernel_packages:
                            archive.add(path, arcname=name)
                command(ssh + ["mkdir -p /tmp/candy-gate; tar -xz -C /tmp/candy-gate"], deadline,
                        input=payload.getvalue(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                with (args.out / "guest.log").open("wb") as log:
                    guest = subprocess.run(ssh + ["sh /tmp/candy-gate/guest.sh"],
                                           timeout=max(1, deadline - time.monotonic()),
                                           stdout=log, stderr=subprocess.STDOUT)
                evidence = command(ssh + ["tar -cz -C /tmp/candy-gate evidence"], deadline,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                (args.out / "guest-evidence.tar.gz").write_bytes(evidence.stdout)
                if guest.returncode:
                    raise RuntimeError(f"guest gate failed: {guest.returncode}; see guest.log and evidence")
                with tarfile.open(fileobj=io.BytesIO(evidence.stdout), mode="r:gz") as archive:
                    report["guest"] = json.load(archive.extractfile("evidence/result.json"))
                report["status"] = "PASS_NARROW_PROCD"
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                report["qemu_process_reaped"] = process.poll() is not None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache/candy-openwrt-vm")
    parser.add_argument("--release", default=RELEASE)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--netd", type=Path)
    parser.add_argument("--kernel-test", type=Path, help="musl infrastructure_v2 test executable")
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--usign", default=shutil.which("usign") or str(Path.home() / ".local/bin/usign"))
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--download-only", action="store_true")
    args = parser.parse_args()
    if not 90 <= args.timeout <= 600:
        parser.error("timeout must be 90..600 seconds")
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    report = {"status": "NOT_RUN", "scope": SCOPE, "whole_platform": "NOT_RUN",
              "runner_sha256": sha256(__file__),
              "guest_script_sha256": sha256(Path(__file__).with_name("openwrt_vm_guest.sh")),
              "remaining": ["packaged production init integration", "signed Agent/Core/TUN packet path",
                            "update and rollback", "IPQ40xx physical platform", "Android Rust integration"]}
    try:
        if args.plan:
            report["plan"] = {"release": args.release, "vcpus": 1, "memory_mib": 512,
                              "network": "restrict=on; loopback-only SSH", "snapshot": True}
        else:
            image, report["official_image"] = acquire(args.cache.resolve(), args.release, args.usign)
            if args.download_only:
                report["status"] = "VERIFIED_IMAGE_ONLY"
            else:
                if args.kernel_test:
                    args.kernel_packages, report["kernel_packages"] = acquire_kernel_packages(args.cache / "packages", args.release)
                run_vm(args, image, report)
    except (Exception, KeyboardInterrupt) as error:
        report["status"] = "FAIL"
        report["error"] = f"{type(error).__name__}: {error}"
    (args.out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 1 if report["status"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
