#!/usr/bin/env python3
"""Held TCP/UDP drain gate, only inside the disposable Linux Proxy fixture."""
import argparse
import concurrent.futures
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import threading
import time

ROOT = Path('/gate')
CONTROL = Path('/control/drain.sock')
TAIL = b'active-drain-tail-after-client-fin'


def receive(conn, length):
    body = bytearray()
    while len(body) < length:
        chunk = conn.recv(length - len(body))
        if not chunk:
            raise RuntimeError(f'TCP closed with {length - len(body)} bytes outstanding')
        body.extend(chunk)
    return bytes(body)


def encode(value):
    body = json.dumps(value).encode()
    return struct.pack('!I', len(body)) + body


def owner(peer, protocol):
    port = f'{peer[1]:04X}'
    inodes = set()
    for line in Path(f'/proc/net/{protocol}').read_text().splitlines()[1:]:
        fields = line.split()
        if fields[1].split(':')[1] == port:
            inodes.add(fields[9])
    found = []
    unix = {}
    for line in Path('/proc/net/unix').read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 8 and int(fields[3], 16) & 0x10000:
            unix[fields[6]] = fields[7]
    for entry in Path('/proc').glob('[0-9]*'):
        try:
            command = (entry / 'cmdline').read_bytes().split(b'\0')
            if command[:3] != [b'/gate/candy-core', b'server', b'proxy-worker']:
                continue
            sockets = set()
            for fd in (entry / 'fd').iterdir():
                try:
                    link = os.readlink(fd)
                    if link.startswith('socket:['):
                        sockets.add(link[8:-1])
                except OSError:
                    continue
            if sockets & inodes:
                environment = dict(value.split(b'=', 1) for value in
                                   (entry / 'environ').read_bytes().split(b'\0') if b'=' in value)
                worker_id = int(environment[b'CANDY_WORKER_ID'])
                epochs = [int(match.group(1)) for inode in sockets if inode in unix
                          if (match := re.fullmatch(rf'driver-{worker_id}-(\d+)\.sock',
                                                   Path(unix[inode]).name))]
                if len(epochs) != 1:
                    raise RuntimeError(f'worker {worker_id} has no unique epoch listener')
                found.append({'pid': int(entry.name),
                              'worker_id': worker_id, 'owner_epoch': epochs[0],
                              'peer': list(peer), 'inode': sorted(sockets & inodes)})
        except (OSError, ValueError):
            continue
    if len(found) != 1:
        raise RuntimeError(f'expected one {protocol} egress owner, got {found}')
    return found[0]


def target():
    tcp_ready = threading.Event()
    def tcp():
        def echo(conn, peer):
            with conn:
                conn.settimeout(20)
                try:
                    receive(conn, 32)
                    conn.sendall(encode(owner(peer, 'tcp')))
                    while chunk := conn.recv(65536):
                        conn.sendall(chunk)
                    conn.sendall(TAIL)
                    conn.shutdown(socket.SHUT_WR)
                except (OSError, RuntimeError) as error:
                    print(str(error), flush=True)
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('10.202.0.2', 19004))
            listener.listen(16)
            tcp_ready.set()
            while True:
                conn, peer = listener.accept()
                threading.Thread(target=echo, args=(conn, peer), daemon=True).start()
    threading.Thread(target=tcp, daemon=True).start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(('10.202.0.2', 19005))
        if not tcp_ready.wait(timeout=5):
            raise RuntimeError('TCP target listener failed to become ready')
        (ROOT / 'active-drain-target.ready').write_text('ready\n')
        while True:
            payload, peer = udp.recvfrom(65535)
            udp.sendto(encode(owner(peer, 'udp')) + payload, peer)


def check():
    rows = {'gate': 'FAIL', 'scope': 'active TCP/UDP wire retention, deadline and replacement admission',
            'requested_remaining_ms': 6000, 'tcp_exchanges': [], 'udp_exchanges': []}
    drain_sent = threading.Event()
    deadline = time.monotonic() + 10
    while not (ROOT / 'active-drain-target.ready').exists():
        if time.monotonic() >= deadline:
            raise RuntimeError('target readiness deadline')
        time.sleep(.05)

    def connect():
        conn = socket.create_connection(('127.0.0.1', 15004), timeout=2)
        try:
            conn.settimeout(2)
            conn.sendall(hashlib.sha256(b'active-drain').digest())
            identity = json.loads(receive(conn, struct.unpack('!I', receive(conn, 4))[0]))
            return conn, identity
        except Exception:
            conn.close()
            raise

    def tcp_exchange(conn, sequence):
        payload = hashlib.shake_256(f'held-tcp-{sequence}'.encode()).digest(4096)
        conn.sendall(payload)
        if receive(conn, len(payload)) != payload:
            raise RuntimeError('held TCP payload mismatch')
        rows['tcp_exchanges'].append({'sequence': sequence, 'at': time.monotonic()})

    def udp_exchange(conn, sequence):
        payload = hashlib.shake_256(f'held-udp-{sequence}'.encode()).digest(512)
        conn.sendto(payload, ('127.0.0.1', 15005))
        response = conn.recvfrom(65535)[0]
        length = struct.unpack('!I', response[:4])[0]
        identity = json.loads(response[4:4 + length])
        if response[4 + length:] != payload:
            raise RuntimeError('held UDP payload mismatch')
        rows['udp_exchanges'].append({'sequence': sequence, 'at': time.monotonic(), **identity})
        return identity

    def drain(epoch):
        request = {'version': 1, 'token': 'isolated-drain-wire-token-v1',
                   'worker_id': 1, 'owner_epoch': epoch,
                   'remaining_ms': rows['requested_remaining_ms']}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
            control.settimeout(40)
            control.connect(str(CONTROL))
            rows['drain_requested_at'] = time.monotonic()
            control.sendall(json.dumps(request).encode())
            control.shutdown(socket.SHUT_WR)
            drain_sent.set()
            body = bytearray()
            while chunk := control.recv(4096):
                body.extend(chunk)
            rows['drain_receipt_at'] = time.monotonic()
            return json.loads(body)

    def rejected_control(body, finish_request):
        started = time.monotonic()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
            control.settimeout(4)
            control.connect(str(CONTROL))
            control.sendall(body)
            if finish_request:
                control.shutdown(socket.SHUT_WR)
            response = bytearray()
            while chunk := control.recv(4096):
                response.extend(chunk)
                if len(response) > 4096:
                    raise RuntimeError('unbounded control rejection response')
        return {'elapsed_seconds': time.monotonic() - started,
                'response': json.loads(response)}

    def new_admission():
        attempts = []
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            try:
                conn, identity = connect()
                with conn:
                    tcp_exchange_new = b'replacement-new-admission'
                    conn.sendall(tcp_exchange_new)
                    if receive(conn, len(tcp_exchange_new)) != tcp_exchange_new:
                        raise RuntimeError('new admission payload mismatch')
                if identity['pid'] == rows['old_tcp_owner']['pid']:
                    attempts.append({'at': time.monotonic(),
                                     'state': 'old_owner_still_accepting_before_drain',
                                     'owner': identity})
                    time.sleep(.05)
                    continue
                return {'gate': 'PASS', 'at': time.monotonic(),
                        'owner': identity, 'attempts': attempts}
            except (OSError, RuntimeError) as error:
                attempts.append({'at': time.monotonic(), 'error': str(error)})
                time.sleep(.1)
        return {'gate': 'FAIL', 'attempts': attempts}

    def new_udp_admissions():
        def first_packet(sequence, fresh):
            row = {'sequence': sequence, 'gate': 'FAIL'}
            try:
                fresh.bind(('127.0.0.1', 0))
                fresh.settimeout(3)
                local_port = fresh.getsockname()[1]
                payload = struct.pack('!HI', local_port, sequence) + hashlib.shake_256(
                    f'new-udp-first-{sequence}'.encode()).digest(506)
                row.update(local_source_port=local_port, sent_at=time.monotonic(), sends=1)
                fresh.sendto(payload, ('127.0.0.1', 15005))
                response, reply_peer = fresh.recvfrom(65535)
                length = struct.unpack('!I', response[:4])[0]
                identity = json.loads(response[4:4 + length])
                echoed = response[4 + length:]
                if echoed != payload or struct.unpack('!H', echoed[:2])[0] != local_port:
                    raise RuntimeError('new UDP first packet/source-port echo mismatch')
                if reply_peer != ('127.0.0.1', 15005):
                    raise RuntimeError(f'new UDP returned from unexpected port: {reply_peer}')
                row.update(gate='PASS', reply_at=time.monotonic(),
                           reply_peer=list(reply_peer), owner=identity)
            except (OSError, RuntimeError, ValueError, struct.error) as error:
                row['error'] = f'{type(error).__name__}: {error}'
            return row
        with ExitStack() as sockets, concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            pending = []
            for sequence in range(24):
                # Keep every local socket alive for the entire batch so the
                # kernel cannot reuse a source port and accidentally reuse a flow.
                fresh = sockets.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                pending.append(executor.submit(first_packet, sequence, fresh))
                time.sleep(.05)
            flows = [future.result(timeout=5) for future in pending]
        return {'gate': 'PASS' if all(row['gate'] == 'PASS' for row in flows) else 'FAIL',
                'flows': flows, 'generator_retransmissions': 0}

    conn = udp = None
    try:
        conn, rows['old_tcp_owner'] = connect()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(2)
        tcp_exchange(conn, 0)
        rows['old_udp_owner'] = udp_exchange(udp, 0)
        if rows['old_tcp_owner']['worker_id'] != 1 or rows['old_udp_owner']['worker_id'] != 1:
            raise RuntimeError('held flows do not belong to the selected worker')
        ready = re.findall(r'code="worker_ready".*?worker_id=1\b.*?epoch=Some\((\d+)\)',
                           (ROOT / 'master.log').read_text())
        epoch = int(ready[-1])
        rows['old_owner_epoch'] = epoch
        if (rows['old_tcp_owner']['owner_epoch'] != epoch or
                rows['old_udp_owner']['owner_epoch'] != epoch):
            raise RuntimeError('live egress owners do not match the requested worker epoch')
        metadata = CONTROL.lstat()
        rows['control_socket_mode'] = oct(stat.S_IMODE(metadata.st_mode))
        rows['control_socket_permissions_gate'] = ('PASS' if
            stat.S_ISSOCK(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600 and
            metadata.st_uid == os.getuid() else 'FAIL')
        invalid = {'version': 1, 'token': 'wrong-isolated-token', 'worker_id': 1,
                   'owner_epoch': epoch, 'remaining_ms': 6000}
        rows['wrong_token_control'] = rejected_control(json.dumps(invalid).encode(), True)
        response = rows['wrong_token_control']['response']
        tcp_exchange(conn, -1)
        if udp_exchange(udp, -1) != rows['old_udp_owner']:
            raise RuntimeError('wrong token rejection disturbed the existing UDP flow')
        rows['wrong_token_preserves_healthy_flows_gate'] = ('PASS' if
            response.get('version') == 1 and response.get('module') == 'proxy_master' and
            response.get('code') == 'drain_control_request_failed' and
            'drain_control_unauthorized' in response.get('detail', '') else 'FAIL')
        rows['partial_control'] = rejected_control(b'{"version":1,', False)
        response = rows['partial_control']['response']
        tcp_exchange(conn, -2)
        if udp_exchange(udp, -2) != rows['old_udp_owner']:
            raise RuntimeError('partial control timeout disturbed the existing UDP flow')
        rows['partial_timeout_preserves_healthy_flows_gate'] = ('PASS' if
            response.get('version') == 1 and response.get('module') == 'proxy_master' and
            response.get('code') == 'drain_control_request_failed' and
            'drain_control_read_timeout' in response.get('detail', '') and
            1.8 <= rows['partial_control']['elapsed_seconds'] <= 3.5 else 'FAIL')
        capability = None
        status_deadline = time.monotonic() + 5
        while time.monotonic() < status_deadline:
            try:
                passive = json.loads((ROOT / 'recommended/client-status.json').read_text())
                capability = passive['nodes']['gate']['passive']['features'].get('proxy_drain')
                if capability is None or (capability.get('supported') and capability.get('authorized')):
                    break
            except (FileNotFoundError, json.JSONDecodeError, KeyError):
                pass
            time.sleep(.1)
        rows['passive_proxy_drain_before'] = capability
        rows['negotiated_capability_gate'] = ('PASS' if capability and
            capability.get('supported') and capability.get('authorized') else 'FAIL')
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            drain_future = executor.submit(drain, epoch)
            if not drain_sent.wait(timeout=3):
                raise RuntimeError('drain control request was not sent')
            new_future = executor.submit(new_admission)
            new_udp_future = executor.submit(new_udp_admissions)
            try:
                for sequence in range(1, 31):
                    if ('client_notice_observed_at' not in rows and
                            'proxy_drain_received' in (ROOT / 'client.log').read_text()):
                        rows['client_notice_observed_at'] = time.monotonic()
                    tcp_exchange(conn, sequence)
                    identity = udp_exchange(udp, sequence)
                    if identity != rows['old_udp_owner']:
                        raise RuntimeError('existing UDP egress owner or source port changed')
                    time.sleep(.04)
                conn.shutdown(socket.SHUT_WR)
                tail = bytearray()
                while chunk := conn.recv(65536):
                    tail.extend(chunk)
                if tail != TAIL:
                    raise RuntimeError('held TCP final tail/FIN mismatch')
                rows['held_completed_at'] = time.monotonic()
                rows['tcp_tail_fin_gate'] = 'PASS'
                rows['udp_owner_retention_gate'] = 'PASS'
            except (OSError, RuntimeError) as error:
                rows['held_error'] = str(error)
                rows['tcp_tail_fin_gate'] = rows['udp_owner_retention_gate'] = 'FAIL'
            rows['drain_receipt'] = drain_future.result(timeout=40)
            rows['new_admission'] = new_future.result(timeout=15)
            rows['new_udp_admissions'] = new_udp_future.result(timeout=8)
        server_log = (ROOT / 'master.log').read_text()
        client_log = (ROOT / 'client.log').read_text()
        rows['server_drain_notice'] = [line for line in server_log.splitlines()
                                       if 'proxy_drain_notified' in line and
                                       f'worker_id: 1, owner_epoch: {epoch}' in line]
        rows['client_drain_notice'] = [line for line in client_log.splitlines()
                                       if 'proxy_drain_received' in line]
        rows['replacement_ready_events'] = [line for line in server_log.splitlines()
                                             if 'worker_replacement_ready' in line]
        rows['replacement_published_events'] = [line for line in client_log.splitlines()
                                                 if 'proxy_drain_replacement_published' in line]
        rows['session_open_rejections'] = [line for line in server_log.splitlines()
                                            if 'session_open_rejected' in line]
        rows['local_tcp_errors'] = [line for line in client_log.splitlines()
                                    if 'fixed proxied TCP ended' in line]
        notice_deadlines = [int(match.group(1))
                            for line in rows['server_drain_notice'] + rows['client_drain_notice']
                            if (match := re.search(r'remaining_ms=(\d+)', line))]
        rows['negotiated_notice_gate'] = ('PASS' if rows['server_drain_notice'] and
            rows['client_drain_notice'] and len(notice_deadlines) >= 2 and
            all(0 < value <= rows['requested_remaining_ms'] for value in notice_deadlines) else 'FAIL')
        observed_at = rows.get('client_notice_observed_at')
        rows['retention_after_notice_gate'] = ('PASS' if observed_at is not None and
            any(row['at'] > observed_at for row in rows['tcp_exchanges']) and
            any(row['at'] > observed_at for row in rows['udp_exchanges']) and
            rows.get('tcp_tail_fin_gate') == 'PASS' and
            rows.get('udp_owner_retention_gate') == 'PASS' else 'FAIL')
        receipt = rows['drain_receipt']
        fresh = rows['new_admission']
        rows['exact_drain_receipt_gate'] = ('PASS' if
            (receipt['worker_id'], receipt['old_owner_epoch'], receipt['old_pid']) ==
            (1, epoch, rows['old_tcp_owner']['pid']) and
            receipt['requested_remaining_ms'] == rows['requested_remaining_ms'] and
            receipt['transport_drained'] and receipt['os_reaped'] and
            receipt['replacement_ready'] else 'FAIL')
        rows['replacement_admission_gate'] = ('PASS' if fresh['gate'] == 'PASS' and
            fresh['owner']['worker_id'] == receipt['new_worker_id'] and
            fresh['owner']['owner_epoch'] == receipt['new_owner_epoch'] and
            fresh['owner']['pid'] == receipt['new_pid'] and
            fresh['owner']['pid'] != rows['old_tcp_owner']['pid'] else 'FAIL')
        rows['new_admission_no_error_gate'] = ('PASS' if fresh['gate'] == 'PASS' and
            not any('error' in attempt for attempt in fresh['attempts']) else 'FAIL')
        rows['new_udp_first_packet_gate'] = rows['new_udp_admissions']['gate']
        rows['new_udp_replacement_overlap_gate'] = ('PASS' if any(
            row['gate'] == 'PASS' and row['owner']['worker_id'] == receipt['new_worker_id'] and
            row['owner']['owner_epoch'] == receipt['new_owner_epoch'] and
            row['owner']['pid'] == receipt['new_pid'] and
            row['reply_at'] < rows.get('held_completed_at', 0)
            for row in rows['new_udp_admissions']['flows']) else 'FAIL')
        rows['overlap_admission_gate'] = ('PASS' if fresh['gate'] == 'PASS' and
            fresh['at'] < rows.get('held_completed_at', 0) else 'FAIL')
        rows['original_deadline_gate'] = ('PASS' if
            rows['drain_receipt_at'] - rows['drain_requested_at'] < 8 else 'FAIL')
        rows['listener_preserved_gate'] = ('PASS' if receipt['replacement_ready'] and
            fresh['gate'] == 'PASS' else 'FAIL')
        gates = ['negotiated_capability_gate', 'negotiated_notice_gate',
                 'control_socket_permissions_gate',
                 'wrong_token_preserves_healthy_flows_gate',
                 'partial_timeout_preserves_healthy_flows_gate',
                 'exact_drain_receipt_gate', 'retention_after_notice_gate',
                 'tcp_tail_fin_gate', 'udp_owner_retention_gate',
                 'replacement_admission_gate', 'new_admission_no_error_gate',
                 'new_udp_first_packet_gate', 'new_udp_replacement_overlap_gate',
                 'overlap_admission_gate',
                 'original_deadline_gate', 'listener_preserved_gate']
        rows['gate'] = 'PASS' if all(rows[key] == 'PASS' for key in gates) else 'FAIL'
    except Exception as error:
        rows['error'] = f'{type(error).__name__}: {error}'
    finally:
        if conn is not None:
            conn.close()
        if udp is not None:
            udp.close()
    print(json.dumps(rows))
    return 0 if rows['gate'] == 'PASS' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['target', 'check'])
    args = parser.parse_args()
    raise SystemExit(target() if args.action == 'target' else check())
