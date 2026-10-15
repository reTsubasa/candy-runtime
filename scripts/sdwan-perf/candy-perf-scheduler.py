#!/usr/bin/env python3
"""Sample test-service scheduling without reading command lines or credentials."""
import argparse
import json
import os
from pathlib import Path
import time


def read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def sample():
    own_cgroup = read("/proc/self/cgroup")
    processes = []
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            executable = os.readlink(f"{entry.path}/exe")
            if not executable.startswith("/bench/binaries/") or read(f"{entry.path}/cgroup") != own_cgroup:
                continue
            tasks = []
            for task in os.scandir(f"{entry.path}/task"):
                schedstat = read(f"{task.path}/schedstat")
                if schedstat is not None:
                    tasks.append({"tid": int(task.name), "schedstat": schedstat})
            processes.append({"pid": int(entry.name), "executable": executable,
                              "stat": read(f"{entry.path}/stat"), "tasks": tasks})
        except OSError:
            continue
    return {"schema_version": 1, "monotonic_ns": time.monotonic_ns(),
            "unix_ns": time.time_ns(), "cpu_stat": read("/sys/fs/cgroup/cpu.stat"),
            "cpu_pressure": read("/sys/fs/cgroup/cpu.pressure"),
            "vm_cpu": (read("/proc/stat") or "").splitlines()[:1],
            "vm_softirq": read("/proc/softirqs"), "processes": processes}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--samples", type=int)
    args = parser.parse_args()
    if args.interval < 0.05 or args.samples is not None and args.samples < 1:
        parser.error("interval >=0.05 seconds and a positive sample count required")
    with args.output.open("x") as output:
        count = 0
        next_sample = time.monotonic()
        probe_interval = min(0.01, args.interval)
        next_probe = next_sample
        probes = 0
        late_probes = 0
        max_lateness = 0.0
        while args.samples is None or count < args.samples:
            now = time.monotonic()
            lateness = max(0, now - next_probe)
            probes += 1
            late_probes += lateness >= 0.05
            max_lateness = max(max_lateness, lateness)
            if now >= next_sample:
                started = time.monotonic_ns()
                row = sample()
                row["heartbeat"] = {
                    "probe_interval_seconds": probe_interval,
                    "probes": probes,
                    "late_50ms_probes": late_probes,
                    "max_lateness_ns": round(max_lateness * 1e9),
                    "snapshot_elapsed_ns": time.monotonic_ns() - started,
                }
                output.write(json.dumps(row, separators=(",", ":")) + "\n")
                output.flush()
                count += 1
                probes = late_probes = 0
                max_lateness = 0.0
                next_sample = now + args.interval
            # Skip missed probes instead of introducing a catch-up busy loop.
            next_probe = time.monotonic() + probe_interval
            time.sleep(probe_interval)


if __name__ == "__main__":
    main()
