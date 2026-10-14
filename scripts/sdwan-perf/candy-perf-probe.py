#!/usr/bin/env python3
"""Test-only echo/sequence probes; bind exclusively to the isolated benchmark LAN."""
import argparse
import json
import math
import selectors
import socket
import struct
import threading
import time
from pathlib import Path


def receive_exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise EOFError("echo peer closed the transaction")
        data.extend(chunk)
    return bytes(data)


def serve_tcp(listener):
    def connection(stream):
        with stream:
            stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                while True:
                    stream.sendall(receive_exact(stream, 64))
            except (OSError, EOFError):
                return
    while True:
        stream, _ = listener.accept()
        threading.Thread(target=connection, args=(stream,), daemon=True).start()


def serve_udp(listener):
    while True:
        payload, address = listener.recvfrom(65535)
        listener.sendto(payload, address)


def percentile(samples, percent):
    return sorted(samples)[max(0, math.ceil(len(samples) * percent / 100) - 1)] if samples else None


def write_result(args, result):
    result.update({"schema_version": 1, "mode": args.mode, "target": args.address,
                   "payload_bytes": args.size, "duration_seconds": args.seconds})
    Path(args.output).write_text(json.dumps(result), encoding="ascii")


def tcp_client(args):
    samples, failures = [], []
    with socket.create_connection((args.address, 5202), timeout=2,
                                  source_address=(args.bind, 0) if args.bind else None) as stream:
        stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        stream.settimeout(2)
        start = time.monotonic()
        sequence = 0
        while time.monotonic() - start < args.seconds:
            payload = struct.pack("!Q", sequence) + bytes(range(56))
            before = time.perf_counter_ns()
            try:
                stream.sendall(payload)
                if receive_exact(stream, 64) != payload:
                    raise ValueError("echo payload differs")
                if time.monotonic() - start >= args.warm:
                    samples.append((time.perf_counter_ns() - before) / 1e6)
            except (OSError, EOFError, ValueError) as error:
                failures.append(str(error))
                break
            sequence += 1
            time.sleep(max(0, 0.01 - (time.perf_counter_ns() - before) / 1e9))
    write_result(args, {"latency_ms": samples, "p50_ms": percentile(samples, 50),
                        "p95_ms": percentile(samples, 95), "p99_ms": percentile(samples, 99),
                        "completed_transactions": len(samples), "errors": failures,
                        "scope": "64-byte persistent TCP echo over the actual SD-WAN LAN route"})


def udp_client(args):
    body = bytes(index % 251 for index in range(args.size - 8))
    seen, sent, send_errors, corrupt, duplicates, reordered = set(), 0, 0, 0, 0, 0
    largest, rate = -1, 2000
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        # Explicitly exercise IPv4 fragmentation when payload + IP/UDP exceeds the TUN MTU.
        stream.setsockopt(socket.IPPROTO_IP, 10, 0)  # IP_MTU_DISCOVER / IP_PMTUDISC_DONT
        if args.bind:
            stream.bind((args.bind, 0))
        stream.connect((args.address, 5203))
        stream.setblocking(False)
        selector = selectors.DefaultSelector()
        selector.register(stream, selectors.EVENT_READ)
        start = time.monotonic()
        while time.monotonic() - start < args.seconds + 1:
            elapsed = time.monotonic() - start
            due = min(int(elapsed * rate), int(args.seconds * rate))
            while sent < due:
                try:
                    stream.send(struct.pack("!Q", sent) + body)
                except OSError:
                    send_errors += 1
                sent += 1
            for _, _ in selector.select(0.001):
                while True:
                    try:
                        payload = stream.recv(65535)
                    except BlockingIOError:
                        break
                    if len(payload) != args.size or payload[8:] != body:
                        corrupt += 1
                        continue
                    sequence, = struct.unpack("!Q", payload[:8])
                    if sequence >= sent:
                        corrupt += 1
                    elif sequence in seen:
                        duplicates += 1
                    else:
                        reordered += sequence < largest
                        largest = max(largest, sequence)
                        seen.add(sequence)
            if sent == int(args.seconds * rate) and len(seen) == sent:
                break
    write_result(args, {"sent_packets": sent, "received_unique_packets": len(seen),
                        "lost_packets": sent - len(seen), "send_errors": send_errors,
                        "corrupt_packets": corrupt, "duplicate_packets": duplicates,
                        "out_of_order_packets": reordered, "offered_pps": rate,
                        "fragmentation_enabled": True, "expected_ipv4_packet_bytes": args.size + 28,
                        "scope": "validated echoed UDP sequence and payload at a low offered packet rate"})


parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=["server", "tcp-client", "udp-client"])
parser.add_argument("--address", required=True)
parser.add_argument("--bind")
parser.add_argument("--output")
parser.add_argument("--seconds", type=float, default=5)
parser.add_argument("--warm", type=float, default=0)
parser.add_argument("--size", type=int, default=64)
args = parser.parse_args()
if args.mode == "server":
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((args.address, 5202))
    tcp.listen(16)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.IPPROTO_IP, 10, 0)
    udp.bind((args.address, 5203))
    if args.output:
        Path(args.output).write_text(json.dumps({"ready": True}), encoding="ascii")
    threading.Thread(target=serve_tcp, args=(tcp,), daemon=True).start()
    serve_udp(udp)
elif args.mode == "tcp-client":
    tcp_client(args)
else:
    if args.size < 8:
        parser.error("UDP payload must have space for its sequence")
    udp_client(args)
