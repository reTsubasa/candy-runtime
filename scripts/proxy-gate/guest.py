#!/usr/bin/env python3
"""Payload for disposable Proxy gate containers; never install on a router."""
import argparse
import concurrent.futures
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading
import time

ROOT = Path('/gate')
SERVER = '10.202.0.2'


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def start(label, command, env=None, blocked_stderr=False):
    if any(value in ('/gate/candy-core', '/gate/candy-client') for value in command):
        if cpus := os.environ.get('CANDY_GATE_SERVICE_CPUS'):
            command = ['taskset', '-c', cpus, *command]
    log_path = ROOT / (label + '.log')
    if log_path.exists():
        log_path.rename(ROOT / f'{label}-{time.time_ns()}.log')
    pipe_fd = None
    try:
        if blocked_stderr:
            pipe_path = ROOT / (label + '.stderr.fifo')
            os.mkfifo(pipe_path, mode=0o600)
            pipe_fd = os.open(pipe_path, os.O_RDWR | os.O_NONBLOCK)
            while True:
                try:
                    os.write(pipe_fd, b'fixture-blocked-stderr\n' * 256)
                except BlockingIOError:
                    break
            # Fill any remaining bytes, then let the child inherit a blocking sink.
            while True:
                try:
                    os.write(pipe_fd, b'x')
                except BlockingIOError:
                    break
            os.set_blocking(pipe_fd, True)
        with log_path.open('wb') as log:
            child = subprocess.Popen(command, stdout=log,
                                     stderr=pipe_fd if blocked_stderr else log,
                                     start_new_session=True, env=env)
    finally:
        if pipe_fd is not None:
            os.close(pipe_fd)
    raw = Path(f'/proc/{child.pid}/stat').read_text()
    start_ticks = int(raw[raw.rfind(')') + 2:].split()[19])
    write_json(ROOT / (label + '.process.json'),
               {'pid': child.pid, 'start_ticks': start_ticks, 'command': command})


def stop(label):
    record = json.loads((ROOT / (label + '.process.json')).read_text())
    pid = record['pid']
    # Verify the recorded leader incarnation before signaling this owned group.
    stat = Path(f'/proc/{pid}/stat')
    if stat.exists():
        raw = stat.read_text()
        fields = raw[raw.rfind(')') + 2:].split()
        if int(fields[19]) != record['start_ticks']:
            raise RuntimeError('owned process PID reused; refusing to signal')

    def live_group():
        live = []
        for entry in Path('/proc').glob('[0-9]*'):
            try:
                raw = (entry / 'stat').read_text()
                fields = raw[raw.rfind(')') + 2:].split()
                if int(fields[2]) == pid and fields[0] != 'Z':
                    live.append(int(entry.name))
            except (OSError, ValueError):
                continue
        return live

    for sig in (signal.SIGTERM, signal.SIGKILL):
        if not live_group():
            print(json.dumps({'label': label, 'process_group_empty': True}))
            return
        try:
            os.killpg(pid, sig)
        except ProcessLookupError:
            pass
        for _ in range(100):
            if not live_group():
                print(json.dumps({'label': label, 'process_group_empty': True}))
                return
            time.sleep(.05)
    raise RuntimeError(f'owned process group still alive: {live_group()}')


def echo_connection(conn):
    with conn:
        conn.settimeout(20)
        try:
            while chunk := conn.recv(65536):
                conn.sendall(chunk)
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def tcp_target():
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((SERVER, 19000))
        listener.listen(128)
        while True:
            conn, _ = listener.accept()
            threading.Thread(target=echo_connection, args=(conn,), daemon=True).start()


def health_target():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(204 if self.path == '/generate_204' else 404)
            self.send_header('Content-Length', '0')
            self.end_headers()

        def log_message(self, *_args):
            pass

    ThreadingHTTPServer((SERVER, 80), Handler).serve_forever()


def udp_target():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        udp.bind((SERVER, 19001))
        write_json(ROOT / 'udp-target-socket.json',
                   {'receive_buffer_bytes': udp.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)})
        # Keep diagnostic disk work out of the target's per-packet hot path.
        with (ROOT / 'udp-target.jsonl').open('a', buffering=65536) as log:
            flushed = time.monotonic()
            while True:
                data, peer = udp.recvfrom(65535)
                udp.sendto(data, peer)
                log.write(json.dumps({'bytes': len(data), 'prefix': data[:16].hex(),
                                      'peer': peer, 'received_at': time.monotonic()}) + '\n')
                if time.monotonic() - flushed >= .2:
                    log.flush()
                    flushed = time.monotonic()


def tcp_probe(index=0, port=15000, timeout=5, barrier=None):
    payload = hashlib.sha256(str(index).encode()).digest() * 8192
    with socket.create_connection(('127.0.0.1', port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        if barrier is not None:
            barrier.wait(timeout=timeout)
        # Exercise early request bytes and client half-close. The response must
        # remain readable until server FIN, including the final buffered bytes.
        conn.sendall(payload)
        conn.shutdown(socket.SHUT_WR)
        response = bytearray()
        while chunk := conn.recv(65536):
            response.extend(chunk)
        if bytes(response) != payload:
            raise RuntimeError(f'TCP data/FIN mismatch: {len(response)} of {len(payload)}')
    return len(payload)


def probes(profile):
    before = time.monotonic()
    barrier = threading.Barrier(32)
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        tcp_bytes = sum(pool.map(lambda index: tcp_probe(index, barrier=barrier), range(32)))
    udp_rows = []
    for size in ((64, 512, 1200, 4096) if profile == 'recommended' else (64, 512, 1200)):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(3)
            for sequence in range(50):
                prefix = sequence.to_bytes(8, 'big')
                payload = prefix + hashlib.shake_256(prefix).digest(size - 8)
                udp.sendto(payload, ('127.0.0.1', 15001))
                try:
                    data, _ = udp.recvfrom(65535)
                except TimeoutError as error:
                    raise RuntimeError(f'UDP reply timeout profile={profile} size={size} seq={sequence}') from error
                if data != payload:
                    raise RuntimeError(f'UDP sequence/integrity mismatch size={size} seq={sequence}')
        udp_rows.append({'payload': size, 'packets': 50, 'integrity': 'PASS'})
    print(json.dumps({'gate': 'PASS', 'tcp_sessions': 32, 'tcp_payload_bytes': tcp_bytes,
                      'tcp_half_close': 'PASS', 'udp': udp_rows,
                      'seconds': time.monotonic() - before}))


def configure(workers, profile):
    directory = ROOT / profile
    directory.mkdir(mode=0o700, exist_ok=True)
    cert, key = directory / 'cert.pem', directory / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '1',
                    '-subj', '/CN=proxy-gate.test', '-addext', 'subjectAltName=DNS:proxy-gate.test'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    der = subprocess.check_output(['openssl', 'x509', '-in', str(cert), '-outform', 'DER'])
    pin = 'sha256:' + hashlib.sha256(der).hexdigest()
    features = {'recommended': ['recommended'],
                'stream_udp_fallback': ['stream_udp_fallback']}[profile]
    server = (f'listen = "{SERVER}:18443"\ncert_pem = "{cert}"\nkey_pem = "{key}"\n'
              'transport_memory_budget_mib = 2048\n'
              '[[users]]\nkey_id = "gate"\nsecret = "isolated-runtime-proxy-gate"\n'
              f'features = {json.dumps(features)}\n'
              '[admission]\nmax_connections = 8\nmax_connections_per_user = 8\n'
              '[security]\nauth_failure_delay_ms = 0\n'
              '[transport]\nprofile = "server-wan-bounded"\ncongestion = "candy-bbr"\ncandy_bbr_preset = "bbr-v1"\n'
              'keep_alive_seconds = 1\nidle_timeout_seconds = 4\n')
    (directory / 'server.toml').write_text(server)
    os.chmod(directory / 'server.toml', 0o600)
    (directory / 'baseline-server.toml').write_text(server.replace(':18443"', ':18444"', 1))
    os.chmod(directory / 'baseline-server.toml', 0o600)
    forwards = [{'network': n, 'local': f'127.0.0.1:{local}',
                 'target': f'{SERVER}:{remote}'}
                for n, local, remote in [('tcp', 15000, 19000), ('udp', 15001, 19001),
                                         ('tcp', 15201, 5201), ('tcp', 15303, 19003)]]
    config = {'name': 'runtime-rust-proxy-gate', 'selected_node': 'gate',
              'nodes': [{'name': 'gate', 'key_id': 'gate', 'server': f'{SERVER}:18443',
                         'server_name': 'proxy-gate.test', 'auth': 'isolated-runtime-proxy-gate',
                         'pin': pin}], 'rules': ['MATCH,gate'], 'forwards': forwards}
    write_json(directory / 'client.json', config)
    baseline = json.loads(json.dumps(config))
    baseline['name'] = 'runtime-rust-in-process-baseline'
    baseline['nodes'][0]['server'] = f'{SERVER}:18444'
    for forward in baseline['forwards']:
        host, port = forward['local'].rsplit(':', 1)
        forward['local'] = f'{host}:{int(port) + 4000}'
    write_json(directory / 'baseline.json', baseline)
    for label in ('bad_auth', 'bad_pin'):
        bad = json.loads(json.dumps(config))
        bad['nodes'][0]['auth' if label == 'bad_auth' else 'pin'] = (
            'isolated-gate-incorrect-auth-entropy-72e03f19' if label == 'bad_auth' else
            'sha256:' + hashlib.sha256(b'isolated-gate-incorrect-certificate').hexdigest())
        for forward in bad['forwards']:
            host, port = forward['local'].rsplit(':', 1)
            forward['local'] = f'{host}:{int(port) + 1000}'
        write_json(directory / (label + '.json'), bad)
    print(json.dumps({'profile': profile, 'workers': workers, 'pin': pin}))


def client(profile, label):
    config = 'client' if label == 'client' else label
    for suffix in ('.ready', '-status.json'):
        (ROOT / profile / (label + suffix)).unlink(missing_ok=True)
    env = dict(os.environ, CANDY_CORE_BIN='/gate/candy-core',
               CANDY_READY_FILE=f'/gate/{profile}/{label}.ready',
               TOKIO_WORKER_THREADS='2', RUST_LOG='info')
    start(label, ['/bin/sh', '/gate/candy-client', '--config',
                  f'/gate/{profile}/{config}.json', '--format', 'candy-json',
                  '--platform', 'linux', '--congestion', 'candy-bbr',
                  '--candy-bbr-preset', 'bbr-v1', '--passive-status-path',
                  f'/gate/{profile}/{label}-status.json'], env)


def server(profile, workers, blocked_stderr=False):
    (ROOT / profile / 'master').mkdir(mode=0o700, exist_ok=True)
    env = dict(os.environ, TOKIO_WORKER_THREADS='2', RUST_LOG='info')
    start('master', ['/gate/candy-core', 'server', 'proxy-master', '--config',
                     f'/gate/{profile}/server.toml', '--directory',
                     f'/gate/{profile}/master', '--workers', str(workers)], env,
          blocked_stderr=blocked_stderr)


def baseline_server(profile):
    env = dict(os.environ, TOKIO_WORKER_THREADS='2', RUST_LOG='info')
    start('baseline-master', ['/gate/candy-core', 'server', '--config',
                             f'/gate/{profile}/baseline-server.toml'], env)


def kill_worker():
    master = json.loads((ROOT / 'master.process.json').read_text())['pid']
    children = []
    for entry in Path('/proc').glob('[0-9]*'):
        try:
            status = (entry / 'status').read_text()
            argv = (entry / 'cmdline').read_bytes().split(b'\0')
            parent = int(next(line.split()[1] for line in status.splitlines()
                              if line.startswith('PPid:')))
            if parent == master and argv[:3] == [b'/gate/candy-core', b'server', b'proxy-worker']:
                children.append(int(entry.name))
        except (OSError, ValueError, StopIteration):
            continue
    if not children:
        raise RuntimeError('no owned worker found; fault was not injected')
    for pid in children:
        os.kill(pid, signal.SIGKILL)
    print(json.dumps({'killed_owned_worker_pids': children, 'master_pid': master}))


def snapshot(label):
    record = json.loads((ROOT / (label + '.process.json')).read_text())
    parent = record['pid']
    entries = {}
    for entry in Path('/proc').glob('[0-9]*'):
        try:
            raw = (entry / 'stat').read_text()
            fields = raw[raw.rfind(')') + 2:].split()
            entries[int(entry.name)] = (int(fields[1]), fields)
        except (OSError, ValueError):
            continue
    selected = {parent}
    if parent not in entries or int(entries[parent][1][19]) != record['start_ticks']:
        raise RuntimeError('recorded service incarnation is no longer running')
    for _ in range(8):
        children = {pid for pid, (ppid, _) in entries.items() if ppid in selected}
        if children <= selected:
            break
        selected |= children
    processes = []
    for pid in sorted(selected):
        if pid not in entries:
            raise RuntimeError('measured service process disappeared')
        fields = entries[pid][1]
        processes.append({'pid': pid, 'start_ticks': int(fields[19]),
                          'cpu_ticks': int(fields[11]) + int(fields[12]),
                          'rss_bytes': int(fields[21]) * os.sysconf('SC_PAGE_SIZE'),
                          'fd_count': len(list(Path(f'/proc/{pid}/fd').iterdir())),
                          'threads': int(fields[17]),
                          'allowed_cpus': next(line.split(':', 1)[1].strip() for line in
                                               Path(f'/proc/{pid}/status').read_text().splitlines()
                                               if line.startswith('Cpus_allowed_list:')),
                          'command': Path(f'/proc/{pid}/cmdline').read_bytes().decode().split('\0')[:-1]})
    cgroup = {}
    for name in ('cpu.stat', 'cpu.max', 'memory.current', 'memory.peak', 'memory.events'):
        path = Path('/sys/fs/cgroup') / name
        if path.exists():
            cgroup[name] = path.read_text()
    queues = subprocess.run(['tc', '-s', '-d', 'qdisc', 'show'],
                            capture_output=True, text=True, check=True).stdout
    print(json.dumps({'monotonic': time.monotonic(), 'clock_ticks': os.sysconf('SC_CLK_TCK'),
                      'processes': processes, 'cgroup': cgroup, 'qdisc': queues,
                      'network_namespace_counters': {
                          name: (Path('/proc/net') / name).read_text()
                          for name in ('snmp', 'netstat', 'udp', 'udp6')}}))


def latency(seconds, direct):
    started = time.monotonic()
    samples = []
    errors = 0
    while time.monotonic() - started < seconds:
        before = time.monotonic()
        try:
            address = (SERVER, 19000) if direct else ('127.0.0.1', 15000)
            with socket.create_connection(address, timeout=2) as conn:
                conn.settimeout(2)
                payload = hashlib.sha256(str(len(samples)).encode()).digest()
                conn.sendall(payload)
                data = bytearray()
                while len(data) < len(payload):
                    chunk = conn.recv(len(payload) - len(data))
                    if not chunk:
                        raise RuntimeError('latency probe truncated')
                    data.extend(chunk)
                if bytes(data) != payload:
                    raise RuntimeError('latency probe corrupted')
                samples.append((time.monotonic() - before) * 1000)
        except (OSError, RuntimeError):
            errors += 1
        time.sleep(.01)
    samples.sort()
    print(json.dumps({'samples': len(samples), 'errors': errors,
                      'p50_ms': samples[(len(samples) - 1) // 2] if samples else None,
                      'p99_ms': samples[min(len(samples) - 1, int(len(samples) * .99))] if samples else None}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['targets', 'configure', 'server', 'server-log-blocked', 'baseline-server', 'client',
                                          'stop', 'probe', 'probes', 'kill-workers',
                                          'snapshot', 'latency', 'timing'])
    parser.add_argument('--profile', default='recommended')
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--label', default='client')
    parser.add_argument('--seconds', type=int, default=10)
    parser.add_argument('--direct', action='store_true')
    parser.add_argument('--port', type=int)
    args = parser.parse_args()
    if args.action == 'targets':
        import load
        threading.Thread(target=load.target, daemon=True).start()
        threading.Thread(target=tcp_target, daemon=True).start()
        threading.Thread(target=health_target, daemon=True).start()
        udp_target()
    elif args.action == 'configure':
        configure(args.workers, args.profile)
    elif args.action == 'server':
        server(args.profile, args.workers)
    elif args.action == 'server-log-blocked':
        server(args.profile, args.workers, blocked_stderr=True)
    elif args.action == 'baseline-server':
        baseline_server(args.profile)
    elif args.action == 'client':
        client(args.profile, args.label)
    elif args.action == 'stop':
        stop(args.label)
    elif args.action == 'probe':
        print(json.dumps({'gate': 'PASS', 'bytes': tcp_probe(port=args.port or (16000 if args.label != 'client' else 15000))}))
    elif args.action == 'probes':
        probes(args.profile)
    elif args.action == 'kill-workers':
        kill_worker()
    elif args.action == 'snapshot':
        snapshot(args.label)
    elif args.action == 'latency':
        latency(args.seconds, args.direct)
    elif args.action == 'timing':
        start('timing-' + args.label, ['python3', '/gate/timing.py'])


if __name__ == '__main__':
    main()
