#!/usr/bin/env python3
"""Verify admission exhaustion preserves existing flows and recovers a new owner."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import re
import socket
import time

import guest


def exchange(conn, marker):
    payload = hashlib.shake_256(marker.encode()).digest(4096)
    conn.sendall(payload)
    response = bytearray()
    while len(response) < len(payload):
        chunk = conn.recv(len(payload) - len(response))
        if not chunk:
            raise RuntimeError('admission gate existing flow closed')
        response.extend(chunk)
    if response != payload:
        raise RuntimeError('admission gate payload mismatch')


def connect(port, marker, seconds):
    deadline = time.monotonic() + seconds
    while True:
        conn = None
        try:
            conn = socket.create_connection(('127.0.0.1', port), timeout=.5)
            conn.settimeout(1)
            exchange(conn, marker)
            return conn
        except OSError:
            if conn is not None:
                conn.close()
            if time.monotonic() >= deadline:
                return None
            time.sleep(.1)


def main():
    root = Path('/gate')
    matches = re.findall(r'effective_connections=(\d+)', (root / 'master.log').read_text())
    labels, flows = [], []
    result = {'gate': 'FAIL', 'cleanup': [], 'scope': 'effective transport admission, one existing fixture owner'}
    try:
        if not matches or not 2 <= int(matches[-1]) <= 16:
            raise RuntimeError('missing or out-of-bound effective connection budget')
        effective = int(matches[-1])
        result['effective_connections'] = effective
        config = json.loads((root / 'recommended/client.json').read_text())
        for index in range(effective):
            label = f'admission-{index}'
            port = 18000 + index
            settings = json.loads(json.dumps(config))
            settings['name'] = label
            settings['forwards'] = [{'network': 'tcp', 'local': f'127.0.0.1:{port}',
                                     'target': '10.202.0.2:19000'}]
            guest.write_json(root / f'recommended/{label}.json', settings)
            guest.client('recommended', label)
            labels.append(label)
            conn = connect(port, label, 5)
            if index < effective - 1:
                if conn is None:
                    raise RuntimeError(f'{label}: admission rejected below effective budget')
                flows.append((label, conn))
                continue
            if conn is not None:
                conn.close()
                raise RuntimeError('effective transport budget was exceeded')
            if 'the server refused to accept a new connection' not in (root / f'{label}.log').read_text():
                raise RuntimeError('expected explicit capacity rejection was not observed')
            result['capacity_rejection'] = 'PASS'
            for owner, flow in flows:
                exchange(flow, owner + '-at-capacity')
            result['at_capacity_tcp_bytes'] = guest.tcp_probe(991)
            result['existing_flows_preserved'] = len(flows)
            released, old = flows.pop(0)
            old.close()
            with contextlib.redirect_stdout(io.StringIO()):
                guest.stop(released)
            recovered = connect(port, label + '-recovered', 20)
            if recovered is None:
                raise RuntimeError('new owner did not recover after one admission was released')
            flows.append((label, recovered))
            for owner, flow in flows:
                exchange(flow, owner + '-after-recovery')
            result.update(gate='PASS', new_owner_recovered='PASS',
                          after_recovery_tcp_bytes=guest.tcp_probe(992))
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        for _, conn in flows:
            conn.close()
        for label in reversed(labels):
            try:
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    guest.stop(label)
                result['cleanup'].append(json.loads(output.getvalue()))
            except Exception as error:
                result['gate'] = 'FAIL'
                result['cleanup'].append({'label': label, 'error': str(error)})
    print(json.dumps(result))
    return 0 if result['gate'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
