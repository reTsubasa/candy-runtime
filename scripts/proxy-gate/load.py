#!/usr/bin/env python3
"""Synchronized, payload-verified TCP load inside the isolated Linux fixture."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time

BLOCK = 65536
SERVER = '10.202.0.2'
PORT = 19003


def receive(conn, count):
    data = bytearray(count)
    view = memoryview(data)
    offset = 0
    while offset < count:
        size = conn.recv_into(view[offset:])
        if not size:
            if offset == 0:
                return None
            raise RuntimeError('partial load record at EOF')
        offset += size
    return data


def read_json(conn):
    data = bytearray()
    while len(data) < 16384:
        byte = conn.recv(1)
        if not byte:
            raise RuntimeError('EOF before load control record')
        if byte == b'\n':
            return json.loads(data)
        data.extend(byte)
    raise RuntimeError('oversized load control record')


def write_json(conn, value):
    conn.sendall(json.dumps(value, separators=(',', ':')).encode() + b'\n')


def tcp_info(conn):
    raw = conn.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256)
    fields = {'rto_us': 8, 'snd_mss': 16, 'rcv_mss': 20, 'unacked': 24,
              'sacked': 28, 'lost': 32, 'retrans': 36, 'rtt_us': 68,
              'rttvar_us': 72, 'snd_cwnd': 80, 'reordering': 88,
              'rcv_space': 96, 'total_retrans': 100}
    return {'linux_tcp_info_hex': raw.hex(),
            **{name: struct.unpack_from('=I', raw, offset)[0]
               for name, offset in fields.items() if len(raw) >= offset + 4}}


def transfer(conn, sender, seed, start, end, warmup):
    expected = hashlib.shake_256(seed.encode()).digest(BLOCK)
    digest = hashlib.sha256()
    count = 0
    measured = 0
    if sender:
        while time.monotonic() < start - warmup:
            time.sleep(.001)
        while time.monotonic() < end:
            conn.sendall(struct.pack('!Q', count))
            conn.sendall(expected)
            digest.update(expected)
            count += 1
        conn.shutdown(socket.SHUT_WR)
        report = read_json(conn)
        if report['blocks'] != count or report['stream_sha256'] != digest.hexdigest():
            raise RuntimeError('sender/receiver payload digest or count mismatch')
        report['sender_tcp_info'] = tcp_info(conn)
        # The sender has half-closed its data socket. Persist its final kernel
        # counters through the fixture's shared evidence mount, not app bytes.
        path = Path('/gate') / ('sender-' + hashlib.sha256(seed.encode()).hexdigest() + '.json')
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps(report['sender_tcp_info']))
        temporary.replace(path)
        return report
    first = last = None
    while True:
        before = time.monotonic()
        header = receive(conn, 8)
        if header is None:
            break
        payload = receive(conn, BLOCK)
        after = time.monotonic()
        if struct.unpack('!Q', header)[0] != count or payload != expected:
            raise RuntimeError('load payload or sequence mismatch')
        digest.update(payload)
        count += 1
        if before >= start and after <= end:
            measured += len(payload)
            first = before if first is None else first
            last = after
    report = {'blocks': count, 'measured_payload_bytes': measured,
              'stream_sha256': digest.hexdigest(), 'payload_verified': True,
              'receiver_tcp_info': tcp_info(conn),
              'first_measured_at': first, 'last_measured_at': last}
    write_json(conn, report)
    return report


def serve_connection(conn):
    with conn:
        try:
            conn.settimeout(10)
            hello = read_json(conn)
            if hello.get('direction') not in ('upload', 'download'):
                raise RuntimeError('invalid load direction')
            if not isinstance(hello.get('seed'), str) or len(hello['seed']) > 128:
                raise RuntimeError('invalid load seed')
            write_json(conn, {'ready': True, 'monotonic': time.monotonic()})
            window = read_json(conn)
            start, end = window['start'], window['end']
            now = time.monotonic()
            if not now + 1 < start < now + 35 or not 1 <= end - start <= 120:
                raise RuntimeError('invalid bounded load window')
            if not 1 <= window['warmup'] <= 30:
                raise RuntimeError('invalid bounded warmup')
            transfer(conn, hello['direction'] == 'download', hello['seed'], start, end, window['warmup'])
        except (OSError, RuntimeError, ValueError, KeyError) as error:
            print(f'load target: {type(error).__name__}: {error}', flush=True)


def target():
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((SERVER, PORT))
        listener.listen(64)
        while True:
            conn, _ = listener.accept()
            threading.Thread(target=serve_connection, args=(conn,), daemon=True).start()


def latency(address, start, end):
    slots = threading.BoundedSemaphore(32)
    futures, rows = [], []

    def probe(index, scheduled):
        before = time.monotonic()
        error = None
        try:
            with socket.create_connection(address, timeout=2) as conn:
                conn.settimeout(2)
                payload = hashlib.sha256(f'load-latency:{index}'.encode()).digest()
                conn.sendall(payload)
                if receive(conn, len(payload)) != payload:
                    raise RuntimeError('loaded latency payload mismatch')
        except (OSError, RuntimeError) as failure:
            error = str(failure)
        finally:
            slots.release()
        after = time.monotonic()
        return {'scheduled_at': scheduled, 'started_at': before, 'finished_at': after,
                'ms': (after - before) * 1000, 'schedule_lag_ms': (before - scheduled) * 1000,
                'offered_latency_ms': (after - scheduled) * 1000, 'error': error}

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        index = 0
        while (scheduled := start + index * .05) < end:
            delay = scheduled - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            if not slots.acquire(blocking=False):
                now = time.monotonic()
                rows.append({'scheduled_at': scheduled, 'started_at': now,
                             'finished_at': now, 'ms': 0,
                             'schedule_lag_ms': (now - scheduled) * 1000,
                             'offered_latency_ms': (now - scheduled) * 1000,
                             'error': 'bounded latency probe capacity exhausted'})
            else:
                futures.append(executor.submit(probe, index, scheduled))
            index += 1
        rows.extend(future.result(timeout=5) for future in futures)
    return sorted(rows, key=lambda row: row['scheduled_at'])


def summarize_latency(rows, start, end):
    expected = round((end - start) * 20)
    scheduled = sorted(row['scheduled_at'] for row in rows)
    if len(rows) != expected or any(abs(at - (start + index * .05)) > .000001
                                    for index, at in enumerate(scheduled)):
        raise RuntimeError('latency offered sequence missing, duplicated or outside its measurement window')
    # Keep the whole offered cohort, including replies arriving after bulk stops.
    values = sorted(row['ms'] for row in rows if row['error'] is None)
    errors = sum(row['error'] is not None for row in rows)
    maximum_lag = max(row['schedule_lag_ms'] for row in rows)
    return {'samples': len(values), 'errors': errors, 'offered': len(rows),
            'expected': expected, 'cohort': 'scheduled_in_measurement_window; completion_may_follow_end',
            'p50_ms': values[(len(values) - 1) // 2] if values else None,
            'p99_ms': values[min(len(values) - 1, int(len(values) * .99))] if values else None,
            'generator_max_lag_ms': maximum_lag}


def stream_plan(direction, flows, connections=1):
    if direction not in ('upload', 'download', 'bidirectional') or flows not in (1, 4, 16) or connections not in (1, 4):
        raise ValueError('invalid bounded load matrix')
    directions = ('upload', 'download') if direction == 'bidirectional' else (direction,)
    return [{'connection': connection, 'direction': axis, 'flow': flow}
            for connection in range(connections) for axis in directions for flow in range(flows)]


def run_round(kind, direction, flows, seconds, case, warmup, connections=1):
    sockets = []
    latency_process = None
    result = {'gate': 'FAIL', 'kind': kind, 'direction': direction, 'flows': flows,
              'scope': 'shared Linux monotonic clock; two isolated namespaces',
              'block_bytes': BLOCK, 'seconds': seconds, 'warmup_seconds': warmup,
              'independent_connections': connections, 'flows_per_connection_per_direction': flows,
              'generator_cpu_affinity': sorted(os.sched_getaffinity(0))}
    try:
        plan = stream_plan(direction, flows, connections)
        clock_checks = []
        for index, stream in enumerate(plan):
            address = (SERVER, PORT) if kind == 'direct' else (
                '127.0.0.1', (19303 if kind == 'baseline' else 15303) + stream['connection'] * 100)
            conn = socket.create_connection(address, timeout=5)
            sockets.append(conn)
            conn.settimeout(10)
            before = time.monotonic()
            write_json(conn, {'direction': stream['direction'], 'seed': f'{case}:{index}'})
            ready = read_json(conn)
            after = time.monotonic()
            if not ready['ready'] or not before - .01 <= ready['monotonic'] <= after + .01:
                raise RuntimeError('test peers do not share the expected monotonic clock')
            clock_checks.append({'before': before, 'remote': ready['monotonic'], 'after': after})
        start = time.monotonic() + warmup + .5
        end = start + seconds
        for conn in sockets:
            write_json(conn, {'start': start, 'end': end, 'warmup': warmup})
        probe_path = Path('/gate') / ('latency-' + hashlib.sha256(case.encode()).hexdigest() + '.json')
        with probe_path.open('w') as output, probe_path.with_suffix('.stderr').open('w') as error_output:
            latency_process = subprocess.Popen(
                [sys.executable, __file__, 'latency', '--kind', kind,
                 '--start', str(start), '--end', str(end)],
                stdout=output, stderr=error_output, start_new_session=True)
            result['latency_process_pid'] = latency_process.pid
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(plan)) as executor:
                transfers = [executor.submit(transfer, conn, plan[index]['direction'] == 'upload',
                                            f'{case}:{index}', start, end, warmup)
                             for index, conn in enumerate(sockets)]
                receivers = [future.result(timeout=seconds + warmup + 15) for future in transfers]
            if latency_process.wait(timeout=5) != 0:
                raise RuntimeError('independent latency worker failed; see retained stderr')
        rows = json.loads(probe_path.read_text())
        for index, receiver in enumerate(receivers):
            seed = f'{case}:{index}'
            path = Path('/gate') / ('sender-' + hashlib.sha256(seed.encode()).hexdigest() + '.json')
            deadline = time.monotonic() + 2
            while not path.exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError('missing confirmed sender kernel counters')
                time.sleep(.01)
            receiver['sender_tcp_info'] = json.loads(path.read_text())
            receiver.update(plan[index])
        result.update(clock_checks=clock_checks, receiver_streams=receivers,
                      latency_observations=rows, start=start, end=end)
        summary = summarize_latency(rows, start, end)
        payload = sum(row['measured_payload_bytes'] for row in receivers)
        result.update(receiver_mbps=payload * 8 / seconds / 1e6,
                      receiver_mbps_by_direction={axis: sum(row['measured_payload_bytes'] for row in receivers
                                                           if row['direction'] == axis) * 8 / seconds / 1e6
                                                  for axis in sorted({stream['direction'] for stream in plan})},
                      measured_payload_bytes=payload, payload_integrity='PASS',
                      loaded_latency=summary)
        maximum_lag = summary['generator_max_lag_ms']
        result['latency_generator_max_lag_ms'] = maximum_lag
        result['latency_generator_validity'] = 'PASS' if maximum_lag <= 20 else 'FAIL'
        if maximum_lag > 20:
            raise RuntimeError(f'latency generator scheduling lag exceeds 20 ms: {maximum_lag:.3f} ms')
        if summary['errors'] or summary['samples'] != seconds * 20:
            raise RuntimeError(f'incomplete loaded latency: {summary}')
        if any(row['measured_payload_bytes'] == 0 for row in receivers):
            raise RuntimeError('a load stream delivered no data during the measurement window')
        result['gate'] = 'PASS'
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        if latency_process is not None and latency_process.poll() is None:
            latency_process.terminate()
            try:
                latency_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                latency_process.kill()
                latency_process.wait(timeout=3)
        for conn in sockets:
            conn.close()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['target', 'round', 'latency'])
    parser.add_argument('--kind', choices=['direct', 'baseline', 'proxy'], default='proxy')
    parser.add_argument('--direction', choices=['upload', 'download', 'bidirectional'], default='download')
    parser.add_argument('--connections', type=int, choices=[1, 4], default=1)
    parser.add_argument('--flows', type=int, choices=[1, 4, 16], default=1)
    parser.add_argument('--seconds', type=int, default=10)
    parser.add_argument('--warmup', type=int, default=10)
    parser.add_argument('--case', default='isolated-load')
    parser.add_argument('--start', type=float)
    parser.add_argument('--end', type=float)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 120 or not 1 <= args.warmup <= 30:
        parser.error('seconds must be 1..120')
    if args.action == 'target':
        target()
        return 0
    if args.action == 'latency':
        if args.start is None or args.end is None or not 1 <= args.end - args.start <= 120:
            parser.error('latency requires a bounded --start/--end window')
        address = (SERVER, 19000) if args.kind == 'direct' else (
            '127.0.0.1', 19000 if args.kind == 'baseline' else 15000)
        print(json.dumps(latency(address, args.start, args.end)))
        return 0
    result = run_round(args.kind, args.direction, args.flows, args.seconds, args.case, args.warmup, args.connections)
    print(json.dumps(result))
    return 0 if result['gate'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
