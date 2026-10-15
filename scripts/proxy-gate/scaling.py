#!/usr/bin/env python3
"""Prove real worker ownership using independent Runtime clients in a live fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
import time


ROOT = Path('/gate')
PROFILE = 'recommended'
TARGET = ('10.202.0.2', 19002)


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def receive(conn, length):
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise RuntimeError('persistent integrity stream closed early')
        data.extend(chunk)
    return bytes(data)


def target(token):
    lock = threading.Lock()
    log = ROOT / f'{token}-target.jsonl'
    log.write_text('')

    def echo(conn, peer):
        try:
            with conn:
                conn.settimeout(40)
                marker = receive(conn, 64).decode().rstrip()
                if not re.fullmatch(re.escape(token) + r'-[0-9]+', marker):
                    raise RuntimeError('unexpected client identity at owned target')
                with lock, log.open('a') as out:
                    out.write(json.dumps({'marker': marker, 'peer': peer,
                                          'local': conn.getsockname()}) + '\n')
                conn.sendall(marker.encode().ljust(64))
                while chunk := conn.recv(65536):
                    conn.sendall(chunk)
        except (OSError, RuntimeError) as error:
            print(f'{type(error).__name__}: {error}', file=sys.stderr, flush=True)

    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(TARGET)
        listener.listen(32)
        (ROOT / f'{token}-target.ready').write_text('ready\n')
        listener.settimeout(45)
        while True:
            conn, peer = listener.accept()
            threading.Thread(target=echo, args=(conn, peer), daemon=True).start()


def hold(token, connections, seconds):
    rows, opened = [], []
    try:
        for index in range(connections):
            marker = f'{token}-{index}'
            deadline = time.monotonic() + 20
            while True:
                try:
                    conn = socket.create_connection(('127.0.0.1', 17000 + index), timeout=1)
                    conn.settimeout(3)
                    conn.sendall(marker.encode().ljust(64))
                    if receive(conn, 64) != marker.encode().ljust(64):
                        raise RuntimeError('worker identity handshake corrupted')
                    break
                except OSError:
                    if 'conn' in locals():
                        conn.close()
                    if time.monotonic() >= deadline:
                        raise RuntimeError(f'{marker}: data-plane readiness deadline')
                    time.sleep(.1)
            opened.append(conn)
            rows.append({'marker': marker, 'bytes': 0, 'packets': 0})
        save(ROOT / f'{token}-hold.ready.json', {'connections': rows})
        deadline = time.monotonic() + seconds + 10
        sequence = 0
        while time.monotonic() < deadline:
            for conn, row in zip(opened, rows):
                payload = hashlib.shake_256(f'{row["marker"]}:{sequence}'.encode()).digest(4096)
                conn.sendall(payload)
                if receive(conn, len(payload)) != payload:
                    raise RuntimeError(f'{row["marker"]}: payload digest mismatch')
                row['bytes'] += len(payload)
                row['packets'] += 1
            save(ROOT / f'{token}-integrity.json', {'gate': 'PASS', 'connections': rows,
                                                   'monotonic': time.monotonic()})
            sequence += 1
            time.sleep(.03)
    except Exception as error:
        save(ROOT / f'{token}-integrity.json', {'gate': 'FAIL', 'error': str(error)})
        raise
    finally:
        for conn in opened:
            conn.close()


def process(pid):
    path = Path('/proc') / str(pid)
    raw = (path / 'stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    sockets = []
    for fd in (path / 'fd').iterdir():
        try:
            target = os.readlink(fd)
            if target.startswith('socket:['):
                sockets.append(target[8:-1])
        except OSError:
            pass
    return {'pid': pid, 'start_ticks': int(fields[19]), 'parent_pid': int(fields[1]),
            'command': (path / 'cmdline').read_bytes().decode().split('\0')[:-1],
            'sockets': sockets}


def sample(token):
    record = json.loads((ROOT / 'master.process.json').read_text())
    master = process(record['pid'])
    if master['start_ticks'] != record['start_ticks']:
        raise RuntimeError('master incarnation changed')
    unix = {}
    for line in Path('/proc/net/unix').read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 8:
            unix[fields[6]] = {'path': fields[7], 'flags': fields[3], 'type': fields[4], 'state': fields[5]}
    workers = []
    for entry in Path('/proc').glob('[0-9]*'):
        try:
            item = process(int(entry.name))
            if (item['parent_pid'] != master['pid'] or
                    item['command'][:3] != ['/gate/candy-core', 'server', 'proxy-worker']):
                continue
            environment = dict(part.split(b'=', 1) for part in
                               (entry / 'environ').read_bytes().split(b'\0') if b'=' in part)
            worker_id = int(environment[b'CANDY_WORKER_ID'])
            # Tokio may duplicate an FD for one socket. Count listening inodes,
            # bind the endpoint to this child's launch directory and worker ID,
            # and require the kernel's SO_ACCEPTCON flag (not connected peers).
            command = item['command']
            directory = Path(command[command.index('--directory') + 1])
            dispatch = [{'inode': inode, **unix[inode]}
                        for inode in set(item['sockets']) if inode in unix and
                        int(unix[inode]['flags'], 16) & 0x10000 and
                        unix[inode]['type'] == '0001' and
                        Path(unix[inode]['path']).parent == directory and
                        re.fullmatch(rf'driver-{worker_id}-[0-9]+\.sock',
                                     Path(unix[inode]['path']).name)]
            if len(dispatch) != 1:
                owned = {inode: unix[inode] for inode in set(item['sockets']) if inode in unix}
                raise RuntimeError(f'worker {worker_id}: expected one owned dispatch listener; '
                                   f'command={command!r} sockets={owned!r}')
            item.update(worker_id=worker_id, dispatch_socket=dispatch[0]['path'],
                        dispatch_inode=dispatch[0]['inode'])
            workers.append(item)
        except (FileNotFoundError, ProcessLookupError):
            continue

    def address(raw):
        host, port = raw.split(':')
        return [socket.inet_ntoa(bytes.fromhex(host)[::-1]), int(port, 16)]

    tcp = []
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        fields = line.split()
        local, remote = address(fields[1]), address(fields[2])
        if fields[3] == '01' and remote == list(TARGET):
            tcp.append({'local': local, 'remote': remote, 'inode': fields[9]})
    targets = [json.loads(line) for line in (ROOT / f'{token}-target.jsonl').read_text().splitlines()]
    flows = []
    # Readiness attempts can reach the target then close before the successful
    # hold. Preserve those receipts, but prove ownership of current live flows.
    for marker in sorted({row['marker'] for row in targets}):
        live = [(row, item) for row in targets if row['marker'] == marker
                for item in tcp if item['local'] == row['peer'] and item['remote'] == row['local']]
        candidates = [item for _, item in live]
        if len(candidates) != 1:
            raise RuntimeError(f'{marker}: expected exactly one live egress socket')
        row = live[0][0]
        connection = candidates[0]
        owners = [item for item in workers if connection['inode'] in item['sockets']]
        if len(owners) != 1:
            raise RuntimeError(f'{row["marker"]}: expected exactly one worker owner')
        owner = owners[0]
        flows.append(dict(row, **connection, owner={key: owner[key] for key in
                          ('pid', 'start_ticks', 'worker_id', 'dispatch_socket')}))
    print(json.dumps({'monotonic': time.monotonic(), 'master': master,
                      'workers': workers, 'flows': flows, 'target_attempts': targets}))


def run_gate(args):
    root, evidence = args.gate_root.resolve(), args.evidence.resolve()
    evidence.mkdir(parents=True, mode=0o700, exist_ok=False)
    token = 'scale-' + hashlib.sha256(str(evidence).encode()).hexdigest()[:10]
    script = root / f'{token}.py'
    script.write_bytes(Path(__file__).read_bytes())
    connections = args.connections or args.workers
    labels, snapshots = [], []
    result = {'gate': 'FAIL', 'workers_requested': args.workers, 'connections': connections,
              'scope': 'live isolated recommended fixture; distinct Runtime process per QUIC owner',
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}

    def execute(container, argv, timeout=15):
        done = subprocess.run(['docker', 'exec', container, *argv], text=True,
                              capture_output=True, timeout=timeout)
        with (evidence / 'commands.jsonl').open('a') as out:
            out.write(json.dumps({'container': container, 'argv': argv,
                                  'exit_code': done.returncode, 'stderr': done.stderr}) + '\n')
        if done.returncode:
            raise RuntimeError(f'{argv}: {done.stderr[-2000:]} {done.stdout[-2000:]}')
        return done.stdout

    def spawn(container, label, command):
        expression = 'import sys;sys.path.insert(0,"/gate");import guest;guest.start(' + repr(label) + ',' + repr(command) + ')'
        execute(container, ['python3', '-c', expression])
        labels.append((container, label))

    def wait_file(path, timeout=25):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return
            failure = root / f'{token}-integrity.json'
            if failure.exists() and json.loads(failure.read_text())['gate'] == 'FAIL':
                raise RuntimeError(failure.read_text())
            time.sleep(.1)
        raise RuntimeError(f'{path.name}: readiness deadline')

    try:
        if not 1 <= args.workers <= connections <= 7 or not 1 <= args.seconds <= 20:
            raise RuntimeError('require 1 <= workers <= connections <= 7 and seconds 1..20; one fixture admission is reserved')
        # Container names must belong to the fixture whose mounted root we use.
        for container in (args.client_container, args.server_container):
            info = json.loads(subprocess.check_output(['docker', 'inspect', container], text=True))[0]
            if info['Config']['Labels'].get('candy.proxy.gate') != str(root):
                raise RuntimeError('container does not belong to requested isolated gate root')
        spawn(args.server_container, token + '-target', ['python3', f'/gate/{token}.py',
                                                        'target', '--token', token])
        wait_file(root / f'{token}-target.ready')
        config = json.loads((root / PROFILE / 'client.json').read_text())
        for index in range(connections):
            label = f'{token}-{index}'
            settings = json.loads(json.dumps(config))
            settings['name'] = label
            settings['forwards'] = [{'network': 'tcp', 'local': f'127.0.0.1:{17000 + index}',
                                     'target': f'{TARGET[0]}:{TARGET[1]}'}]
            save(root / PROFILE / (label + '.json'), settings)
            execute(args.client_container, ['python3', '/gate/guest.py', 'client',
                                            '--profile', PROFILE, '--label', label])
            labels.append((args.client_container, label))
        spawn(args.client_container, token + '-hold', ['python3', f'/gate/{token}.py',
              'hold', '--token', token, '--connections', str(connections), '--seconds', str(args.seconds)])
        wait_file(root / f'{token}-hold.ready.json')
        deadline = time.monotonic() + args.seconds
        first = None
        while first is None or time.monotonic() < deadline:
            row = json.loads(execute(args.server_container, ['python3', f'/gate/{token}.py',
                                                            'sample', '--token', token]))
            snapshots.append(row)
            if len(row['workers']) != args.workers or len(row['flows']) != connections:
                raise RuntimeError('worker or live flow count mismatch')
            markers = {flow['marker'] for flow in row['flows']}
            if markers != {f'{token}-{i}' for i in range(connections)}:
                raise RuntimeError('persistent client identities missing or duplicated')
            identities = {(flow['owner']['pid'], flow['owner']['start_ticks']) for flow in row['flows']}
            if len(identities) != args.workers:
                raise RuntimeError('not every configured worker carries an actual egress flow')
            stable = {'master': [row['master']['pid'], row['master']['start_ticks']],
                      'flows': sorted(row['flows'], key=lambda flow: flow['marker'])}
            if first is None:
                first = stable
            elif stable != first:
                raise RuntimeError('business socket, worker identity or master incarnation changed during hold')
            time.sleep(.15)
        integrity = json.loads((root / f'{token}-integrity.json').read_text())
        if (integrity['gate'] != 'PASS' or len(integrity['connections']) != connections or
                any(row['packets'] < 2 for row in integrity['connections'])):
            raise RuntimeError('persistent payload integrity evidence incomplete')
        result.update(gate='PASS', integrity=integrity, samples=len(snapshots),
                      elapsed_seconds=snapshots[-1]['monotonic'] - snapshots[0]['monotonic'])
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        result['cleanup'] = []
        for container, label in reversed(labels):
            try:
                output = execute(container, ['python3', '/gate/guest.py', 'stop', '--label', label], timeout=15)
                result['cleanup'].append({'label': label, 'gate': 'PASS', 'detail': output.strip()})
            except Exception as error:
                result['gate'] = 'FAIL'
                result['cleanup'].append({'label': label, 'gate': 'FAIL', 'error': str(error)})
        for path in root.glob(token + '*'):
            if path.is_file():
                (evidence / path.name).write_bytes(path.read_bytes())
        for path in (root / PROFILE).glob(token + '*'):
            if path.is_file():
                (evidence / path.name).write_bytes(path.read_bytes())
        save(evidence / 'ownership.json', snapshots)
        save(evidence / 'result.json', result)
    print(json.dumps(result))
    return 0 if result['gate'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='run', choices=['run', 'target', 'hold', 'sample'])
    parser.add_argument('--token')
    parser.add_argument('--client-container')
    parser.add_argument('--server-container')
    parser.add_argument('--gate-root', type=Path)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--connections', type=int)
    parser.add_argument('--seconds', type=int, default=3)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    if args.action == 'run':
        if not all((args.client_container, args.server_container, args.gate_root, args.evidence)):
            parser.error('run requires --client-container --server-container --gate-root --evidence')
        return run_gate(args)
    if not args.token or not re.fullmatch(r'scale-[0-9a-f]{10}', args.token):
        parser.error('guest actions require an owned scale token')
    if args.action == 'target':
        target(args.token)
    elif args.action == 'hold':
        hold(args.token, args.connections, args.seconds)
    else:
        sample(args.token)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
