"""Embedded disposable Linux mixed-role quota and slow-consumer gate."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import threading
import time

ROOT, FIXTURE, CORE, WRAPPER = map(Path, sys.argv[1:5])
NAMESPACES = sys.argv[5:]
CHILDREN = []
PING = []
LOGS = []
RESULT = {'gate': 'FAIL', 'scope': 'real netd/TUN and Runtime Rust Proxy on one QUIC listener',
          'quota': {'global_connections': 6, 'per_proxy_principal': 2},
          'generator_retransmissions': 0}
STOP = threading.Event()
TARGET_ERRORS = []
UDP_PEERS = []
SLOW_ACCEPTED = threading.Event()


def spawn(label, command, env=None):
    output = (ROOT / f'{label}.log').open('wb')
    LOGS.append(output)
    child = subprocess.Popen(command, stdout=output, stderr=output, env=env,
                             start_new_session=True)
    CHILDREN.append(child)
    return child


def client(label, base):
    pin = next(line.split('=', 1)[1].strip().strip('"')
               for line in (FIXTURE / 'transport.toml').read_text().splitlines()
               if line.startswith('server_pin ='))
    config = {'name': label, 'selected_node': 'gate', 'nodes': [{
        'name': 'gate', 'key_id': 'alice', 'server': '10.200.0.2:18443',
        'server_name': 'peer.candy.test', 'auth': 'shared-listener-test-secret-2026',
        'pin': pin}], 'rules': ['MATCH,gate'], 'forwards': [
            {'network': network, 'local': f'127.0.0.1:{base + delta}',
             'target': f'127.0.0.1:{target}'}
            for network, delta, target in [('tcp', 0, 19190), ('udp', 1, 19192),
                                           ('tcp', 2, 19191)]]}
    path = ROOT / f'{label}.json'
    path.write_text(json.dumps(config))
    path.chmod(0o600)
    return spawn(label, ['/bin/sh', str(WRAPPER), '--config', str(path),
                         '--format', 'candy-json', '--platform', 'linux'],
                 dict(os.environ, CANDY_CORE_BIN=str(CORE), RUST_LOG='info'))


def stop(child):
    if child.poll() is None:
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=3)


def echo_connection(conn):
    with conn:
        conn.settimeout(20)
        try:
            while block := conn.recv(65536):
                conn.sendall(block)
        except OSError:
            pass


def tcp_target(port, slow=False):
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', port))
        listener.listen(32)
        listener.settimeout(.1)
        while not STOP.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            if slow:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                SLOW_ACCEPTED.set()
                # Deliberately retain but never read this accepted egress.
                STOP.wait(45)
                conn.close()
            else:
                threading.Thread(target=echo_connection, args=(conn,), daemon=True).start()


def udp_target():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(('127.0.0.1', 19192))
        udp.settimeout(.1)
        while not STOP.is_set():
            try:
                payload, peer = udp.recvfrom(65535)
                UDP_PEERS.append(peer)
                udp.sendto(payload, peer)
            except socket.timeout:
                continue


def target(function, *args):
    def run():
        try:
            function(*args)
        except Exception as error:
            TARGET_ERRORS.append(repr(error))
    threading.Thread(target=run, daemon=True).start()


def exchange(conn, marker):
    payload = marker.encode() + hashlib.shake_256(marker.encode()).digest(4096)
    conn.sendall(payload)
    result = bytearray()
    while len(result) < len(payload):
        block = conn.recv(len(payload) - len(result))
        if not block:
            raise RuntimeError('held TCP flow closed')
        result.extend(block)
    assert result == payload, 'TCP payload mismatch'


def connect(port, seconds=10):
    deadline = time.monotonic() + seconds
    while True:
        conn = None
        try:
            conn = socket.create_connection(('127.0.0.1', port), timeout=.5)
            conn.settimeout(2)
            exchange(conn, f'warmup-{port}')
            return conn
        except OSError:
            if conn:
                conn.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(.1)


def udp_exchange(udp, sequence):
    payload = sequence.to_bytes(8, 'big') + hashlib.shake_256(str(sequence).encode()).digest(4088)
    udp.sendto(payload, ('127.0.0.1', 19101))
    reply, _ = udp.recvfrom(65535)
    assert reply == payload, 'UDP payload or sequence mismatch'


def udp_owner():
    assert UDP_PEERS, 'UDP target has no egress peer'
    port = UDP_PEERS[-1][1]
    rows = [line.split() for line in Path('/proc/net/udp').read_text().splitlines()[1:]]
    rows = [row for row in rows if int(row[1].split(':')[1], 16) == port]
    assert len(rows) == 1, f'UDP egress socket not exact port={port}'
    inode = rows[0][9]
    owners = []
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            if not any(os.readlink(fd) == f'socket:[{inode}]' for fd in (proc / 'fd').iterdir()):
                continue
            environment = (proc / 'environ').read_bytes().split(b'\0')
            if any(value.startswith(b'CANDY_WORKER_MANAGER_PID=') for value in environment):
                stat = (proc / 'stat').read_text()
                owners.append({'pid': int(proc.name), 'start_ticks': int(stat[stat.rfind(')') + 2:].split()[19]),
                               'socket_inode': inode, 'source_port': port})
        except (OSError, PermissionError):
            continue
    assert len(owners) == 1, f'UDP egress has no unique Proxy worker owner: {owners}'
    return owners[0]


def healthy_phase(held, udp, start, count=20):
    for index in range(count):
        exchange(held, f'held-{start}-{index}')
        udp_exchange(udp, start + index)
        with socket.create_connection(('127.0.0.1', 19100), timeout=2) as fresh:
            fresh.settimeout(2)
            exchange(fresh, f'fresh-{start}-{index}')
        time.sleep(.05)


def ping_result(text):
    match = re.search(r'(\d+) packets transmitted, (\d+) received, (\d+)% packet loss', text)
    passed = bool(match and int(match[1]) >= 20 and match[1] == match[2] and match[3] == '0')
    return {'gate': 'PASS' if passed else 'FAIL',
            'summary': match[0] if match else 'missing summary'}


def main():
    sockets = []
    try:
        for namespace in NAMESPACES:
            output = (ROOT / f'mixed-continuous-{namespace}.log').open('wb')
            LOGS.append(output)
            ping = subprocess.Popen(['ip', 'netns', 'exec', namespace, 'ping', '-D', '-O',
                                     '-I', '10.251.1.10', '-i', '.1', '-W', '1', '10.251.2.10'],
                                    stdout=output, stderr=output, start_new_session=True)
            PING.append(ping)
        target(tcp_target, 19190)
        target(tcp_target, 19191, True)
        target(udp_target)
        primary = client('mixed-primary', 19100)
        held = connect(19100)
        sockets.append(held)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(('127.0.0.1', 0))
        udp.settimeout(3)
        sockets.append(udp)
        udp_exchange(udp, 0)
        owner_before = udp_owner()
        holder = client('mixed-holder', 19200)
        holder_flow = connect(19200)
        sockets.append(holder_flow)
        reject_log = ROOT / 'master.log'
        baseline = reject_log.stat().st_size
        rejected = client('mixed-rejected', 19300)
        deadline = time.monotonic() + 10
        while True:
            evidence = reject_log.read_text()[baseline:]
            if ('user_connection_limit_reached' in evidence
                    or ('auth_capacity' in evidence and 'reject' in evidence)):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('missing explicit principal quota rejection in master log')
            time.sleep(.1)
        RESULT['quota_rejection_observed'] = True
        healthy_phase(held, udp, 100)
        exchange(holder_flow, 'quota-holder-at-capacity')
        assert holder.poll() is None and primary.poll() is None
        stop(rejected)
        holder_flow.close()
        stop(holder)
        recovered = client('mixed-recovered', 19400)
        recovered_flow = connect(19400, 15)
        exchange(recovered_flow, 'quota-recovered')
        recovered_flow.close()
        stop(recovered)
        RESULT['quota_released_and_recovered'] = True
        healthy_phase(held, udp, 200)
        # Same authenticated Proxy connection; only one egress consumer stalls.
        stalled = socket.create_connection(('127.0.0.1', 19102), timeout=2)
        sockets.append(stalled)
        stalled.settimeout(.25)
        pressure = {'bytes': 0, 'write_timeouts': 0, 'closed': False}
        writer_stop = threading.Event()

        def writer():
            block = b'S' * 65536
            while not writer_stop.is_set() and pressure['bytes'] < 256 * 1024 * 1024:
                try:
                    pressure['bytes'] += stalled.send(block)
                except socket.timeout:
                    pressure['write_timeouts'] += 1
                except OSError as error:
                    pressure.update(closed=True, error=repr(error))
                    return

        write_thread = threading.Thread(target=writer, daemon=True)
        write_thread.start()
        assert SLOW_ACCEPTED.wait(5), 'slow target did not receive actual Proxy egress'
        deadline = time.monotonic() + 15
        while pressure['write_timeouts'] < 2:
            assert not pressure['closed'], f'stalled flow closed before bounded pressure: {pressure}'
            assert time.monotonic() < deadline, f'slow consumer did not reach socket backpressure: {pressure}'
            time.sleep(.1)
        assert pressure['bytes'] > 0, 'slow target accepted but no actual data entered the flow'
        RESULT['slow_consumer_pressure_before'] = dict(pressure)
        healthy_phase(held, udp, 300)
        assert primary.poll() is None, 'Runtime client exited under slow consumer'
        RESULT['slow_consumer_pressure_after'] = dict(pressure)
        writer_stop.set()
        write_thread.join(timeout=2)
        assert not write_thread.is_alive(), 'pressure writer did not stop within bound'
        assert udp_owner() == owner_before, 'held UDP owner/socket/source port changed'
        assert all(peer == UDP_PEERS[0] for peer in UDP_PEERS), 'held UDP egress peer changed'
        assert not TARGET_ERRORS, TARGET_ERRORS
        RESULT.update(gate='PASS', held_tcp_preserved=True, fresh_tcp_requests=60,
                      udp_exact_packets=61, held_udp_owner=owner_before,
                      slow_consumer_socket_backpressure=True)
    except Exception as error:
        RESULT['error'] = f'{type(error).__name__}: {error}'
    finally:
        STOP.set()
        for conn in sockets:
            conn.close()
        for child in reversed(CHILDREN):
            stop(child)
        for ping in PING:
            os.killpg(ping.pid, signal.SIGINT)
            ping.wait(timeout=3)
        for output in LOGS:
            output.close()
        ping_rows = []
        for namespace in NAMESPACES:
            text = (ROOT / f'mixed-continuous-{namespace}.log').read_text()
            row = ping_result(text)
            ping_rows.append({'namespace': namespace, **row})
            if row['gate'] != 'PASS':
                RESULT['gate'] = 'FAIL'
        RESULT['continuous_sdwan'] = ping_rows
        (ROOT / 'mixed-role-fault-evidence.json').write_text(json.dumps(RESULT, indent=2) + '\n')
        print(json.dumps(RESULT))
    return 0 if RESULT['gate'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
