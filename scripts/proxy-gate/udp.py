#!/usr/bin/env python3
"""Bounded UDP rate, overload and recovery probes for the isolated fixture."""
import argparse
import concurrent.futures
import hashlib
import json
import socket
import struct
import threading
import time


class RatePacer:
    """Preserve nominal timing evidence without catch-up bursts after pauses."""

    def __init__(self, start, pps, clock=time.monotonic, sleep=time.sleep):
        self.start = start
        self.period = 1 / pps
        self.clock, self.sleep = clock, sleep
        self.last_sent = None

    def wait(self, sequence):
        nominal = self.start + sequence * self.period
        target = max(nominal, self.last_sent + self.period) if self.last_sent is not None else nominal
        while self.clock() < target:
            self.sleep(target - self.clock())
        now = self.clock()
        self.last_sent = now
        return nominal, target, now


def rate(size, pps, seconds, case, direct=False):
    sent, received, planned, paced = {}, {}, {}, {}
    duplicates, corrupt, foreign = [], [], []
    prefix = hashlib.sha256(case.encode()).digest()[:8]
    body = hashlib.shake_256(prefix).digest(size - 16)
    count = int(pps * seconds)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        conn.settimeout(.05)
        destination = ('10.202.0.2', 19001) if direct else ('127.0.0.1', 15001)
        # Warm the flow without counting bootstrap/admission as rate loss.
        warm = prefix + struct.pack('!Q', (1 << 64) - 1) + body
        conn.sendto(warm, destination)
        conn.settimeout(3)
        if conn.recvfrom(65535)[0] != warm:
            raise RuntimeError('UDP warmup payload mismatch')
        conn.settimeout(.05)
        start = time.monotonic() + .1
        pacer = RatePacer(start, pps)
        end = start + seconds
        sender_done = threading.Event()
        sender_finished = [None]
        hard_deadline = end + 6

        def receive():
            while time.monotonic() < hard_deadline:
                if sender_done.is_set() and time.monotonic() >= sender_finished[0] + 1:
                    break
                try:
                    payload, _ = conn.recvfrom(65535)
                except socket.timeout:
                    continue
                now = time.monotonic()
                if len(payload) != size or payload[:8] != prefix:
                    foreign.append(payload[:16].hex())
                    continue
                sequence = struct.unpack('!Q', payload[8:16])[0]
                if sequence == (1 << 64) - 1:
                    continue
                if sequence >= count or payload[16:] != body:
                    corrupt.append(sequence)
                elif sequence in received:
                    duplicates.append(sequence)
                else:
                    received[sequence] = now

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            receiver = executor.submit(receive)
            try:
                for sequence in range(count):
                    nominal, target, now = pacer.wait(sequence)
                    if now >= end + 5:
                        raise TimeoutError('UDP generator exceeded bounded send window')
                    payload = prefix + struct.pack('!Q', sequence) + body
                    planned[sequence], paced[sequence] = nominal, target
                    sent[sequence] = now
                    conn.sendto(payload, destination)
            finally:
                sender_finished[0] = time.monotonic()
                sender_done.set()
            receiver.result(timeout=2)
        missing = sorted(set(sent) - set(received))
        late = [sequence for sequence, at in sent.items()
                if at > planned[sequence] + .02]
        return {'payload_bytes': size, 'offered_pps': pps, 'seconds': seconds,
                'sent': len(sent), 'unique_received': len(received),
                'missing': missing, 'duplicates': duplicates, 'corrupt': corrupt,
                'foreign': foreign, 'generator_late_over_20ms': late,
                'load_validity_gate': 'FAIL' if late else 'PASS',
                'network_integrity_gate': 'FAIL' if missing or duplicates or corrupt or foreign else 'PASS',
                'transmissions': [{'sequence': sequence, 'scheduled_at': planned[sequence],
                                   'paced_at': paced[sequence],
                                   'sent_at': at, 'reply_at': received.get(sequence),
                                   'generator_lag_ms': (at - planned[sequence]) * 1000}
                                  for sequence, at in sent.items()],
                'start': start, 'end': end, 'last_sent_at': max(sent.values()),
                'receiver_drain_until': min(hard_deadline, sender_finished[0] + 1),
                'receiver_payload_mbps': sum(start <= at <= end for at in received.values())
                    * size * 8 / seconds / 1e6,
                'gate': 'PASS' if not (missing or duplicates or corrupt or foreign or late) else 'FAIL'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=3)
    parser.add_argument('--direct', action='store_true')
    args = parser.parse_args()
    if not 1 <= args.seconds <= 30:
        parser.error('seconds must be 1..30')
    rows = []
    result = {'gate': 'FAIL', 'scope': 'bounded rate and burst; not maximum UDP PPS acceptance',
              'rates': rows, 'direct': args.direct}
    try:
        for size in (64, 512, 1200, 4096):
            rows.append(rate(size, 100, args.seconds, f'normal-{size}', args.direct))
        # Deliberately overload the receive pipeline. Loss is allowed only here.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as burst:
            burst.settimeout(.01)
            payload = hashlib.shake_256(b'isolated-overload').digest(4096)
            destination = ('10.202.0.2', 19001) if args.direct else ('127.0.0.1', 15001)
            before = time.monotonic()
            for _ in range(4096):
                burst.sendto(payload, destination)
            result['overload'] = {'packets': 4096, 'payload_bytes': 4096,
                                  'elapsed_seconds': time.monotonic() - before}
        time.sleep(1)
        rows.append(rate(1200, 100, args.seconds, 'after-overload', args.direct))
        if rows[-1]['gate'] != 'PASS':
            # Retain the original recovery failure; a later observation only
            # identifies whether it remains stuck or recovers without restart.
            time.sleep(2)
            result['late_recovery'] = rate(1200, 100, args.seconds,
                                           'late-after-overload', args.direct)
        if not args.direct:
            import guest
            result['later_tcp_payload_bytes'] = guest.tcp_probe(617)
        result['gate'] = 'PASS' if all(row['gate'] == 'PASS' for row in rows) else 'FAIL'
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    print(json.dumps(result))
    return 0 if result['gate'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
