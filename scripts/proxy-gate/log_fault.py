#!/usr/bin/env python3
"""Fault only the owned fixture's platform logger, preserving business traffic."""
import argparse
import array
import concurrent.futures
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import termios
import time

ROOT = Path('/gate')
FIFO = ROOT / 'master.stderr.fifo'


def state():
    master = json.loads((ROOT / 'master.process.json').read_text())
    pid = master['pid']
    raw = Path(f'/proc/{pid}/stat').read_text()
    if int(raw[raw.rfind(')') + 2:].split()[19]) != master['start_ticks']:
        raise RuntimeError('master incarnation changed')
    processes = []
    for entry in Path('/proc').glob('[0-9]*'):
        try:
            argv = (entry / 'cmdline').read_bytes().split(b'\0')
            raw = (entry / 'stat').read_text()
            fields = raw[raw.rfind(')') + 2:].split()
            if int(entry.name) != pid and not (
                    int(fields[1]) == pid and argv[:3] ==
                    [b'/gate/candy-core', b'server', b'proxy-worker']):
                continue
            loggers = [{'tid': int(task.name), 'wchan': (task / 'wchan').read_text().strip()}
                       for task in (entry / 'task').iterdir()
                       if (task / 'comm').read_text().strip() == 'candy-log-expor']
            processes.append({'pid': int(entry.name), 'start_ticks': int(fields[19]),
                              'loggers': loggers})
        except FileNotFoundError:
            continue
    with FIFO.open('rb', buffering=0) as pipe:
        queued = array.array('i', [0])
        fcntl.ioctl(pipe.fileno(), termios.FIONREAD, queued, True)
        capacity = fcntl.fcntl(pipe.fileno(), fcntl.F_GETPIPE_SZ)
    fd = os.open(FIFO, os.O_WRONLY | os.O_NONBLOCK)
    try:
        try:
            os.write(fd, b'x')
            write_rejected = False
        except BlockingIOError:
            write_rejected = True
    finally:
        os.close(fd)
    # Pipe page/slot fragmentation can exhaust capacity before byte count reaches
    # F_GETPIPE_SZ. Require actual EAGAIN and blocked exporter threads instead.
    if not write_rejected or not queued[0] or len(processes) != 3 or any(
            len(p['loggers']) != 1 or p['loggers'][0]['wchan'] != 'pipe_write'
            for p in processes):
        raise RuntimeError(f'platform sink not proven blocked: {queued[0]}/{capacity} {processes}')
    return {'gate': 'PASS', 'pipe_bytes': queued[0], 'pipe_capacity': capacity,
            'nonblocking_write_rejected': write_rejected,
            'processes': sorted(processes, key=lambda process: process['pid'])}


def request(index):
    payload = hashlib.sha256(f'log-fault-{index}'.encode()).digest() * 2
    with socket.create_connection(('127.0.0.1', 15000), timeout=5) as conn:
        conn.settimeout(5)
        conn.sendall(payload)
        conn.shutdown(socket.SHUT_WR)
        received = bytearray()
        while chunk := conn.recv(4096):
            received.extend(chunk)
        if bytes(received) != payload:
            raise RuntimeError('request payload/FIN mismatch during blocked logging')
    return len(payload)


def traffic():
    with socket.create_connection(('127.0.0.1', 15000), timeout=5) as held:
        held.settimeout(5)

        def exchange(payload):
            held.sendall(payload)
            received = bytearray()
            while len(received) < len(payload):
                chunk = held.recv(4096)
                if not chunk:
                    raise RuntimeError('held connection closed during log fault')
                received.extend(chunk)
            if bytes(received) != payload:
                raise RuntimeError('held connection payload mismatch')

        exchange(b'before-log-flood')
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            counts = list(executor.map(request, range(640)))
        exchange(b'after-log-flood')
        later = request(10000)
    return {'gate': 'PASS', 'requests': len(counts), 'payload_bytes': sum(counts),
            'held_connection': 'PASS', 'later_request_bytes': later,
            'elapsed_seconds': time.monotonic() - started}


def drain():
    fd = os.open(FIFO, os.O_RDONLY | os.O_NONBLOCK)
    captured = bytearray()
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                chunk = os.read(fd, 65536)
                if not chunk:
                    raise RuntimeError('all platform log writers disappeared')
                captured.extend(chunk)
                if len(captured) > 8 * 1024 * 1024:
                    raise RuntimeError('bounded platform log capture exceeded')
            except BlockingIOError:
                time.sleep(.01)
    finally:
        os.close(fd)
        (ROOT / 'recovered-platform.log').write_bytes(captured)
    import re
    drops = [int(value) for value in re.findall(rb'code=logging_backpressure module=logging dropped_records=(\d+)', captured)]
    if not drops or max(drops) == 0:
        raise RuntimeError('no positive dropped-record summary after platform sink recovery')
    return {'gate': 'PASS', 'captured_bytes': len(captured), 'dropped_record_reports': drops}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('state', 'traffic', 'drain'))
    args = parser.parse_args()
    try:
        result = globals()[args.action]()
    except Exception as error:
        result = {'gate': 'FAIL', 'error': f'{type(error).__name__}: {error}'}
    print(json.dumps(result))
    return 0 if result['gate'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
