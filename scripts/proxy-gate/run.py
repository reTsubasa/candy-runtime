#!/usr/bin/env python3
"""Black-box Runtime Rust client gate in two isolated Linux containers."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
RUNTIME = HERE.parents[1]


class ActiveDrainComplete(Exception):
    """Exit the full matrix after a focused gate while retaining cleanup gates."""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--performance', action='store_true')
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--warmup', type=int, default=10)
    parser.add_argument('--workers', type=int, nargs='+', choices=(1, 2, 4), default=[1, 2, 4])
    parser.add_argument('--directions', nargs='+', choices=('upload', 'download', 'bidirectional'), default=['upload', 'download', 'bidirectional'])
    parser.add_argument('--flows', type=int, nargs='+', choices=(1, 4, 16), default=[1, 4, 16])
    parser.add_argument('--connections', type=int, choices=(1, 4), default=1,
                        help='independent Runtime clients; run both 1 and 4 connection matrices for acceptance')
    parser.add_argument('--scaling-attempts', type=int, choices=range(1, 13), default=12)
    parser.add_argument('--image', default='candy-proxy-netem-runner:20261015')
    parser.add_argument('--pin-cpus', action='store_true',
                        help='require 8 VM CPUs; reserve 3 per service and 1 per namespace generator')
    parser.add_argument('--drain-wire', action='store_true',
                        help='run the opt-in local Unix per-worker negotiated drain smoke gate')
    parser.add_argument('--active-drain-only', action='store_true',
                        help='only run held TCP/UDP negotiated drain and replacement admission gate')
    parser.add_argument('--udp-only', action='store_true',
                        help='only run bounded UDP rate, overload and recovery diagnostics')
    parser.add_argument('--active-drain-dns-burst', action='store_true',
                        help='use dense DNS contention stress in the focused drain gate')
    args = parser.parse_args()
    if args.udp_only and (args.active_drain_only or args.performance):
        parser.error('--udp-only cannot be combined with drain-only or performance')
    if not 1 <= args.seconds <= 120 or not 1 <= args.rounds <= 10 or not 1 <= args.warmup <= 30:
        parser.error('seconds must be 1..120 and rounds 1..10')
    root = args.evidence.resolve()
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    binary = args.binary.resolve()
    if binary.read_bytes()[:4] != b'\x7fELF':
        parser.error('the gate requires the actual Linux Rust Core ELF')
    shutil.copy2(binary, root / 'candy-core')
    shutil.copy2(HERE / 'guest.py', root / 'guest.py')
    shutil.copy2(HERE / 'load.py', root / 'load.py')
    shutil.copy2(HERE / 'udp.py', root / 'udp.py')
    shutil.copy2(HERE / 'admission.py', root / 'admission.py')
    shutil.copy2(HERE / 'timing.py', root / 'timing.py')
    shutil.copy2(HERE / 'log_fault.py', root / 'log_fault.py')
    shutil.copy2(HERE / 'scaling.py', root / 'scaling.py')
    shutil.copy2(HERE / 'active_drain.py', root / 'active_drain.py')
    shutil.copy2(Path(__file__), root / 'run.py')
    wrapper = RUNTIME / 'openwrt/client/packages/candy-client/candy-client'
    shutil.copy2(wrapper, root / 'candy-client')
    suffix = hashlib.sha256(str(root).encode()).hexdigest()[:12]
    client, server = f'candy-pgate-c-{suffix}', f'candy-pgate-s-{suffix}'
    owned = []
    control_volume = None
    observers = []
    baseline_owned = False
    extra_clients = []
    performance_started = False
    rows, perf = [], []
    result = {'schema_version': 1, 'gate': 'FAIL', 'client': 'Runtime candy-client -> Rust candy-core client',
              'scope': 'isolated aarch64 Linux containers with 1 Gbps veth; no physical-platform acceptance',
              'deprecated_profiles': ['legacy_datagram_only_without_fragmentation_or_stream_fallback'],
              'requested_matrix': {'workers': args.workers, 'directions': args.directions,
                                   'independent_connections': args.connections,
                                   'flows': args.flows, 'rounds': args.rounds,
                                   'seconds': args.seconds, 'warmup_seconds': args.warmup},
              'release_acceptance': 'INCOMPLETE',
              'performance_gate': 'INCOMPLETE' if args.performance else 'NOT_RUN',
              'cpu_isolation': ({'client_service': '0-2', 'server_service': '3-5',
                                 'client_generator': '6', 'server_generator': '7',
                                 'cfs_quota': 'none; disjoint cpusets bound execution'}
                                if args.pin_cpus else {'cfs_quota_cpus_per_namespace': 3}),
              'remaining_gates': ['released-artifact B0 comparison', 'simultaneous bidirectional traffic',
                                  'independent connection aggregate throughput', 'mixed SD-WAN traffic',
                                  'two-hour stability and renewal', 'physical platform installation and rollback'],
              'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'wrapper_sha256': hashlib.sha256(wrapper.read_bytes()).hexdigest(),
              'guest_sha256': hashlib.sha256((HERE / 'guest.py').read_bytes()).hexdigest(),
              'load_sha256': hashlib.sha256((HERE / 'load.py').read_bytes()).hexdigest(),
              'udp_sha256': hashlib.sha256((HERE / 'udp.py').read_bytes()).hexdigest(),
              'admission_sha256': hashlib.sha256((HERE / 'admission.py').read_bytes()).hexdigest(),
              'timing_sha256': hashlib.sha256((HERE / 'timing.py').read_bytes()).hexdigest(),
              'log_fault_sha256': hashlib.sha256((HERE / 'log_fault.py').read_bytes()).hexdigest(),
              'scaling_sha256': hashlib.sha256((HERE / 'scaling.py').read_bytes()).hexdigest(),
              'active_drain_sha256': hashlib.sha256((HERE / 'active_drain.py').read_bytes()).hexdigest(),
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'compatibility': rows, 'performance': perf}

    def write(name, value):
        (root / name).write_text(json.dumps(value, indent=2) + '\n')

    def run(argv, *, timeout=30, check=True):
        done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=timeout)
        with (root / 'commands.jsonl').open('a') as out:
            out.write(json.dumps({'argv': argv, 'exit_code': done.returncode,
                                  'stderr': done.stderr[-4096:]}) + '\n')
        if check and done.returncode:
            raise RuntimeError(f'command failed {argv}: {done.stderr[-4096:]} {done.stdout[-4096:]}')
        return done

    def dex(name, *argv, **kwargs):
        if args.pin_cpus:
            argv = ('taskset', '-c', '6' if name == client else '7', *argv)
        return run(['docker', 'exec', name, *argv], **kwargs)

    def guest(name, action, **kwargs):
        argv = ['python3', '/gate/guest.py', action]
        for key, value in kwargs.items():
            argv.extend(['--' + key.replace('_', '-'), str(value)])
        return dex(name, *argv)

    def ready(label, timeout=30, port=15000, process_labels=('master', 'client')):
        started = time.monotonic()
        while time.monotonic() - started < timeout:
            for process_label in process_labels:
                log = root / (process_label + '.log')
                if log.exists() and '\nError:' in log.read_text():
                    raise RuntimeError(f'{label}: {process_label} exited: {log.read_text()[-2048:]}')
            probe = dex(client, 'python3', '/gate/guest.py', 'probe', '--port', str(port), check=False, timeout=8)
            if probe.returncode == 0:
                return time.monotonic() - started
            time.sleep(.1)
        raise RuntimeError(f'{label}: actual TCP data-plane readiness deadline')

    def start(profile, workers, blocked_stderr=False):
        guest(server, 'configure', profile=profile, workers=workers,
              proxy_drain=int(profile == 'recommended' and
                              (args.drain_wire or args.active_drain_only)))
        if args.active_drain_only:
            config_path = root / profile / 'client.json'
            config = json.loads(config_path.read_text())
            config['forwards'].extend([
                {'network': network, 'local': f'127.0.0.1:{port}',
                 'target': f'10.202.0.2:{port + 4000}'}
                for network, port in [('tcp', 15004), ('udp', 15005)]])
            config['forwards'].append({'network': 'udp', 'local': '127.0.0.1:15353',
                                       'target': '10.202.0.2:53'})
            config['dns'] = {'cache': {'enabled': False}, 'split': {
                'answer_geo_validate': False, 'egress_resolver': '10.202.0.2:19053',
                'rules': [{'type': 'domain-suffix', 'domain': 'drain-gate.example',
                           'target': {'node': 'gate'}}]}}
            config_path.write_text(json.dumps(config))
        server_action = 'server-log-blocked' if blocked_stderr else 'server'
        server_kwargs = {'profile': profile, 'workers': workers}
        if (args.drain_wire or args.active_drain_only) and profile == 'recommended' and not blocked_stderr:
            token_path = root / profile / 'drain.token'
            token_path.write_text('isolated-drain-wire-token-v1\n')
            token_path.chmod(0o600)
            server_kwargs.update(drain_control='/control/drain.sock',
                                 drain_token=f'/gate/{profile}/drain.token')
        guest(server, server_action, **server_kwargs)
        guest(client, 'client', profile=profile)
        return ready(f'{profile} workers={workers}')

    def stop():
        nonlocal baseline_owned
        for label in reversed(extra_clients):
            guest(client, 'stop', label=label)
        extra_clients.clear()
        if baseline_owned:
            guest(client, 'stop', label='baseline')
            guest(server, 'stop', label='baseline-master')
            baseline_owned = False
        for label in ('bad_auth', 'bad_pin'):
            if (root / (label + '.process.json')).exists():
                guest(client, 'stop', label=label)
        guest(client, 'stop')
        guest(server, 'stop', label='master')

    def service_snapshot(name, label):
        snapshot = json.loads(guest(name, 'snapshot', label=label).stdout)
        if name == client:
            kind = 'baseline' if label == 'baseline' else 'proxy'
            for index in range(1, args.connections):
                extra = json.loads(guest(name, 'snapshot', label=f'bench-{kind}-{index}').stdout)
                snapshot['processes'].extend(extra['processes'])
            identities = [(row['pid'], row['start_ticks']) for row in snapshot['processes']]
            if len(identities) != len(set(identities)):
                raise RuntimeError('independent client resource snapshots overlap')
        return snapshot

    def scaling(workers, case):
        for attempt in range(args.scaling_attempts):
            evidence = root / f'worker-scaling-{case}-w{workers}-a{attempt}'
            done = run([sys.executable, str(root / 'scaling.py'),
                        '--client-container', client, '--server-container', server,
                        '--gate-root', str(root), '--workers', str(workers),
                        '--connections', str(6 if workers > 1 else 1), '--seconds', '3',
                        '--evidence', str(evidence)], timeout=100, check=False)
            outcome = json.loads((evidence / 'result.json').read_text())
            rows.append({'case': 'independent_client_worker_distribution',
                         'workers': workers, 'stage': case, 'attempt': attempt,
                         'gate': 'PASS' if outcome['gate'] == 'PASS' else 'INCOMPLETE',
                         'attempt_result': outcome['gate'],
                         'evidence': str(evidence)})
            if not done.returncode and outcome['gate'] == 'PASS':
                return
            if (outcome.get('error') != 'RuntimeError: not every configured worker carries an actual egress flow'
                    or any(row['gate'] != 'PASS' for row in outcome['cleanup'])):
                raise RuntimeError(str(outcome))
        raise RuntimeError('distribution coverage incomplete after bounded connection batches')

    def status(profile, label='client'):
        path = root / profile / f'{label}-status.json'
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                value = json.loads(path.read_text())
                node = value['nodes']['gate']
                if node['state'] in ('ready', 'connected') and node['passive']['applied_transport']['congestion']:
                    applied = node['passive']['applied_transport']
                    if applied['congestion'] != 'candy-bbr' or applied['candy_bbr_preset'] != 'bbr-v1':
                        raise RuntimeError(f'applied congestion mismatch: {applied}')
                    features = node['passive']['features']
                    if features['early_data']['authorized'] != (profile == 'recommended'):
                        raise RuntimeError(f'early data negotiation mismatch: {features}')
                    if not features['stream_udp_fallback']['authorized']:
                        raise RuntimeError(f'fallback negotiation mismatch: {features}')
                    if features['fragmented_datagram']['authorized'] != (profile == 'recommended'):
                        raise RuntimeError(f'fragmentation negotiation mismatch: {features}')
                    return value
            except (FileNotFoundError, json.JSONDecodeError, KeyError):
                pass
            time.sleep(.1)
        raise RuntimeError('passive status did not confirm applied settings and negotiated features')

    def current_worker_epoch(worker_id):
        """Read the active master's worker_ready receipt after replacement.

        The negotiated drain protocol deliberately requires an exact owner
        epoch.  The crash-recovery portion of this gate replaces workers before
        the drain probe, so a fixed epoch would test stale-request rejection
        rather than the live control path.
        """
        log = root / 'master.log'
        pattern = re.compile(
            rf'code="worker_ready".*?worker_id={worker_id}\b.*?epoch=Some\((\d+)\)')
        for line in reversed(log.read_text().splitlines() if log.exists() else []):
            match = pattern.search(line)
            if match:
                return int(match.group(1))
        raise RuntimeError(f'worker {worker_id} has no current ready epoch')

    def listener_socket_identity():
        code = """import json, os
from pathlib import Path
pid = json.loads(Path('/gate/master.process.json').read_text())['pid']
bound = {line.split()[9] for line in Path('/proc/net/udp').read_text().splitlines()[1:]
         if line.split()[1].split(':')[1] == '480B'}
owned = set()
for fd in Path(f'/proc/{pid}/fd').iterdir():
    try:
        link = os.readlink(fd)
        if link.startswith('socket:['):
            owned.add(link[8:-1])
    except OSError:
        continue
print(json.dumps(sorted(bound & owned)))
"""
        identity = json.loads(dex(server, 'python3', '-c', code).stdout)
        if len(identity) != 1:
            raise RuntimeError(f'expected one master-owned listener inode: {identity}')
        return identity

    try:
        image = json.loads(run(['docker', 'image', 'inspect', args.image]).stdout)[0]
        result['image_id'] = image['Id']
        result['image_architecture'] = image['Architecture']
        if args.pin_cpus and int(run(['docker', 'info', '--format', '{{.NCPU}}']).stdout) < 8:
            raise RuntimeError('--pin-cpus requires at least eight Docker VM CPUs')
        if args.drain_wire or args.active_drain_only:
            control_volume = f'candy-pgate-control-{suffix}'
            run(['docker', 'volume', 'create', '--label', f'candy.proxy.gate={root}', control_volume])
        for name in (client, server):
            resources = (['--cpuset-cpus', '0-2,6' if name == client else '3-5,7',
                          '-e', 'CANDY_GATE_SERVICE_CPUS=' + ('0-2' if name == client else '3-5')]
                         if args.pin_cpus else ['--cpus', '3'])
            run(['docker', 'run', '-d', '--name', name, '--label', f'candy.proxy.gate={root}',
                 '--network', 'none', '--privileged', *resources, '--memory', '3g',
                 '--add-host', 'www.gstatic.com:10.202.0.2',
                 '--pids-limit', '256', *(['--pid', 'host'] if name == server else []),
                 *(['--mount', f'type=volume,src={control_volume},dst=/control'] if control_volume else []),
                 '-v', f'{root}:/gate', args.image, 'sleep', 'infinity'])
            owned.append(name)
        if control_volume:
            dex(server, 'chmod', '700', '/control')
        client_pid = run(['docker', 'inspect', '-f', '{{.State.Pid}}', client]).stdout.strip()
        dex(server, 'ip', 'link', 'add', 'cpg-s', 'type', 'veth', 'peer', 'name', 'cpg-c')
        dex(server, 'ip', 'link', 'set', 'cpg-c', 'netns', client_pid)
        for name, iface, addr in ((client, 'cpg-c', '10.202.0.1/24'),
                                  (server, 'cpg-s', '10.202.0.2/24')):
            dex(name, 'ip', 'link', 'set', 'lo', 'up')
            dex(name, 'ip', 'addr', 'add', addr, 'dev', iface)
            dex(name, 'ip', 'link', 'set', iface, 'up')
            # Shape actual MTU-sized packets, not deferred 64 KiB GSO skbs.
            before_offload = dex(name, 'ethtool', '-k', iface).stdout
            dex(name, 'ethtool', '-K', iface, 'tso', 'off', 'gso', 'off', 'gro', 'off',
                'tx-udp-segmentation', 'off')
            write(f'{iface}-offload.json', {'before': before_offload,
                                          'after': dex(name, 'ethtool', '-k', iface).stdout})
            dex(name, 'tc', 'qdisc', 'add', 'dev', iface, 'root', 'netem',
                'delay', '5ms', 'rate', '1gbit', 'limit', '4096')
        for name, side in ((client, 'client'), (server, 'server')):
            guest(name, 'timing', label=side)
            observers.append((name, 'timing-' + side))
        dex(server, 'python3', '-c',
            "import subprocess; f=open('/gate/targets.log','ab'); "
            "subprocess.Popen(['python3','/gate/guest.py','targets'],stdout=f,stderr=f,start_new_session=True)")
        dex(server, 'iperf3', '-s', '-D', '-p', '5201', '--logfile', '/gate/iperf-server.log')
        if args.udp_only:
            start('recommended', 2)
            write('recommended-verified-status.json', status('recommended'))
            def udp_kernel_snapshot(name):
                return {'udp': dex(name, 'cat', '/proc/net/snmp').stdout,
                        'sockets': dex(name, 'ss', '-u', '-a', '-n', '-m').stdout,
                        'qdisc': dex(name, 'tc', '-s', 'qdisc', 'show').stdout,
                        'links': dex(name, 'ip', '-s', 'link').stdout}
            before = {side: udp_kernel_snapshot(name)
                      for side, name in [('client', client), ('server', server)]}
            identities = {side: json.loads(guest(name, 'snapshot', label=label).stdout)
                          for side, name, label in [('client', client, 'client'),
                                                    ('server', server, 'master')]}
            measured = dex(client, 'python3', '/gate/udp.py', timeout=40, check=False)
            udp = json.loads(measured.stdout)
            udp['kernel_before'] = before
            udp['kernel_after'] = {side: udp_kernel_snapshot(name)
                                   for side, name in [('client', client), ('server', server)]}
            udp['client_status_after'] = status('recommended')
            udp['target_socket'] = json.loads((root / 'udp-target-socket.json').read_text())
            udp['service_before'] = identities
            udp['service_after'] = {side: json.loads(guest(name, 'snapshot', label=label).stdout)
                                    for side, name, label in [('client', client, 'client'),
                                                              ('server', server, 'master')]}
            identity = lambda snapshot: {(p['pid'], p['start_ticks']) for p in snapshot['processes']}
            udp['service_incarnation_gate'] = ('PASS' if all(
                identity(identities[side]) == identity(udp['service_after'][side])
                for side in identities) else 'FAIL')
            if udp['service_incarnation_gate'] != 'PASS':
                udp['gate'] = 'FAIL'
            write('udp-rate-overload-recovery.json', udp)
            rows.append({'case': 'udp_rate_overload_recovery', 'gate': udp['gate']})
            result['compatibility_gate'] = udp['gate']
            result['gate'] = udp['gate']
            result['scope'] = 'isolated Linux UDP short diagnostic only; no full compatibility or release acceptance'
            stop()
            raise ActiveDrainComplete()
        if args.active_drain_only:
            start('recommended', 1)
            before_drain = json.loads(guest(server, 'snapshot', label='master').stdout)
            listener_before = listener_socket_identity()
            dex(server, 'python3', '-c',
                "import sys; sys.path.insert(0,'/gate'); import guest; guest.start('active-drain-target', "
                "['python3','/gate/active_drain.py','target'])")
            measured = dex(client, 'python3', '/gate/active_drain.py', 'check',
                           *(['--dns-burst'] if args.active_drain_dns_burst else []),
                           timeout=50, check=False)
            active = json.loads(measured.stdout)
            after_drain = json.loads(guest(server, 'snapshot', label='master').stdout)
            active['service_before'] = before_drain
            active['service_after'] = after_drain
            active['listener_inode_before'] = listener_before
            active['listener_inode_after'] = listener_socket_identity()
            active['listener_socket_identity_gate'] = ('PASS' if
                active['listener_inode_before'] == active['listener_inode_after'] else 'FAIL')
            master_before = before_drain['processes'][0]
            master_after = after_drain['processes'][0]
            active['master_incarnation_gate'] = ('PASS' if all(
                master_before[key] == master_after[key]
                for key in ('pid', 'start_ticks')) else 'FAIL')
            if (active['master_incarnation_gate'] != 'PASS' or
                    active['listener_socket_identity_gate'] != 'PASS'):
                active['gate'] = 'FAIL'
            write('active-session-drain.json', active)
            rows.append({'case': 'active_session_negotiated_proxy_drain', **active})
            result['compatibility_gate'] = active['gate']
            result['gate'] = active['gate']
            result['scope'] = 'isolated Linux active-session drain only; no full release acceptance'
            guest(server, 'stop', label='active-drain-target')
            stop()
            raise ActiveDrainComplete()
        for profile in ('recommended', 'stream_udp_fallback'):
            try:
                recovery = start(profile, 2)
                write(profile + '-verified-status.json', status(profile))
                for label in ('bad_auth', 'bad_pin'):
                    guest(client, 'client', profile=profile, label=label)
                    reason = 'authentication rejected' if label == 'bad_auth' else 'pin mismatch'
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        if reason in (root / (label + '.log')).read_text().lower():
                            break
                        time.sleep(.1)
                    else:
                        raise RuntimeError(f'{profile}: {label} never reached expected rejection: {reason}')
                    # Negative probes must fail while the positive connection works.
                    rejected = dex(client, 'python3', '/gate/guest.py', 'probe', '--label', label,
                                   check=False, timeout=8)
                    guest(client, 'stop', label=label)
                    if rejected.returncode == 0:
                        raise RuntimeError(f'{profile}: {label} accepted')
                    ready(f'{profile}: preserve good connection after {label}')
                    rows.append({'profile': profile, 'case': label,
                                 'rejection': 'PASS', 'expected_reason': reason,
                                 'healthy_connection_preserved': 'PASS'})
                if profile == 'recommended':
                    before_fault = json.loads(guest(server, 'snapshot', label='master').stdout)
                    fault = json.loads(guest(server, 'kill-workers').stdout)
                    recovery = ready('worker crash recovery', timeout=30)
                    data = {'gate': 'PASS', 'profile': profile, 'tcp_recovery': 'PASS'}
                    after_fault = json.loads(guest(server, 'snapshot', label='master').stdout)
                    leader_before = next(p for p in before_fault['processes'] if p['pid'] == fault['master_pid'])
                    leader_after = next(p for p in after_fault['processes'] if p['pid'] == fault['master_pid'])
                    if any(leader_before[key] != leader_after[key] for key in ('pid', 'start_ticks')):
                        raise RuntimeError('master incarnation changed after worker fault')
                    replacements = [p for p in after_fault['processes'] if p['command'][:3] ==
                                    ['/gate/candy-core', 'server', 'proxy-worker']]
                    if len(replacements) != 2 or any(p['pid'] in fault['killed_owned_worker_pids'] for p in replacements):
                        raise RuntimeError('worker pool did not restore two fresh children')
                    data.update(case='worker_crash_recovery', recovery_seconds=recovery, fault=fault)
                    data['master_preserved'] = 'PASS'
                    rows.append(data)
                data = json.loads(guest(client, 'probes', profile=profile).stdout)
                data.update(profile=profile)
                rows.append(data)
                if args.drain_wire and profile == 'recommended':
                    owner_epoch = current_worker_epoch(1)
                    receipt = dex(
                        client,
                        'python3', '/gate/guest.py', 'drain-control',
                        '--drain-control', '/control/drain.sock',
                        '--drain-token', 'isolated-drain-wire-token-v1',
                        '--worker-id', '1', '--owner-epoch', str(owner_epoch),
                        '--remaining-ms', '1200', timeout=45, check=False,
                    )
                    drain_result = json.loads(receipt.stdout or '{}')
                    drain_result['exit_code'] = receipt.returncode
                    write('negotiated-drain-wire.json', drain_result)
                    rows.append({'case': 'negotiated_proxy_drain_wire',
                                 'gate': 'PASS' if receipt.returncode == 0 and
                                 drain_result.get('transport_drained') and
                                 drain_result.get('os_reaped') and
                                 drain_result.get('replacement_ready') else 'FAIL',
                                 'receipt': drain_result})
                    if receipt.returncode or rows[-1]['gate'] != 'PASS':
                        raise RuntimeError(f'negotiated drain receipt failed: {drain_result}')
                    ready('replacement after negotiated drain')
                if profile == 'recommended':
                    udp_before = {side: json.loads(guest(name, 'snapshot', label=label).stdout)
                                  for side, name, label in [('client', client, 'client'), ('server', server, 'master')]}
                    udp = dex(client, 'python3', '/gate/udp.py', timeout=40, check=False)
                    udp_result = json.loads(udp.stdout)
                    udp_result['service_before'] = udp_before
                    udp_result['service_after'] = {
                        side: json.loads(guest(name, 'snapshot', label=label).stdout)
                        for side, name, label in [('client', client, 'client'), ('server', server, 'master')]}
                    udp_result['target_socket'] = json.loads((root / 'udp-target-socket.json').read_text())
                    write('udp-rate-overload-recovery.json', udp_result)
                    rows.append({'case': 'udp_rate_overload_recovery', 'gate': udp_result['gate']})
                    scaling(2, 'compatibility')
                    # Wait for the previous owners' bounded QUIC close before
                    # deliberately consuming the effective transport budget.
                    time.sleep(5)
                    admission_before = json.loads(guest(server, 'snapshot', label='master').stdout)
                    admission = dex(client, 'python3', '/gate/admission.py', timeout=100, check=False)
                    admission_result = json.loads(admission.stdout)
                    admission_after = json.loads(guest(server, 'snapshot', label='master').stdout)
                    admission_result['service_before'] = admission_before
                    admission_result['service_after'] = admission_after
                    if ({(p['pid'], p['start_ticks']) for p in admission_before['processes']} !=
                            {(p['pid'], p['start_ticks']) for p in admission_after['processes']}):
                        admission_result.update(gate='FAIL', error='service incarnation changed during admission exhaustion')
                    write('admission-exhaustion-recovery.json', admission_result)
                    rows.append({'case': 'admission_exhaustion_recovery', 'gate': admission_result['gate']})
            except Exception as error:
                rows.append({'profile': profile, 'gate': 'FAIL', 'error': str(error)})
            finally:
                stop()
        try:
            start('recommended', 2, blocked_stderr=True)
            blocked = {'case': 'platform_log_backpressure', 'gate': 'FAIL'}
            for action, name in [('state', server), ('traffic', client), ('state', server), ('drain', server)]:
                observation = json.loads(dex(name, 'python3', '/gate/log_fault.py', action,
                                             timeout=35, check=False).stdout)
                blocked.setdefault(action, []).append(observation)
                write('platform-log-backpressure.json', blocked)
                if observation['gate'] != 'PASS':
                    raise RuntimeError(f'platform log fault {action}: {observation}')
            if blocked['state'][0]['processes'] != blocked['state'][1]['processes']:
                raise RuntimeError('master/worker incarnation changed during blocked logging')
            ready('healthy traffic after platform log recovery')
            blocked['gate'] = 'PASS'
            write('platform-log-backpressure.json', blocked)
            rows.append({'case': 'platform_log_backpressure', 'gate': 'PASS'})
        except Exception as error:
            rows.append({'case': 'platform_log_backpressure', 'gate': 'FAIL', 'error': str(error)})
        finally:
            stop()
        result['compatibility_gate'] = 'FAIL' if any(x.get('gate') == 'FAIL' for x in rows) else 'PASS'
        if args.performance:
            performance_started = True
            for workers in args.workers:
                # Never reuse a private worker generation across master runs.
                dex(server, 'python3', '-c',
                    "from pathlib import Path; import shutil; "
                    "p=Path('/gate/recommended/master'); shutil.rmtree(p) if p.exists() else None")
                start('recommended', workers)
                pool = json.loads(guest(server, 'snapshot', label='master').stdout)
                active_workers = [p for p in pool['processes'] if p['command'][:3] ==
                                  ['/gate/candy-core', 'server', 'proxy-worker']]
                if len(active_workers) != workers:
                    raise RuntimeError(f'configured {workers} workers, found {len(active_workers)}')
                scaling(workers, 'performance')
                guest(server, 'baseline-server', profile='recommended')
                baseline_owned = True
                guest(client, 'client', profile='recommended', label='baseline')
                ready('in-process baseline', port=19000, process_labels=('baseline-master', 'baseline'))
                write(f'baseline-w{workers}-verified-status.json', status('recommended', 'baseline'))
                baseline_tree = json.loads(guest(server, 'snapshot', label='baseline-master').stdout)
                if len(baseline_tree['processes']) != 1:
                    raise RuntimeError('in-process baseline spawned unexpected child processes')
                for kind in ('proxy', 'baseline'):
                    for index in range(1, args.connections):
                        extra_label = f'bench-{kind}-{index}'
                        guest(client, 'client', profile='recommended', label=extra_label)
                        extra_clients.append(extra_label)
                        ready(extra_label, port=(19000 if kind == 'baseline' else 15000) + index * 100,
                              process_labels=(extra_label,))
                        write(f'{extra_label}-w{workers}-verified-status.json', status('recommended', extra_label))
                for direction in args.directions:
                    for flows in args.flows:
                        for round_id in range(args.rounds):
                            for kind in (('direct', 'baseline', 'proxy') if round_id % 2 == 0 else ('proxy', 'baseline', 'direct')):
                                label = f'{kind}-w{workers}-{direction}-p{flows}-c{args.connections}-r{round_id}'
                                process_labels = [('client', client, 'baseline' if kind == 'baseline' else 'client'),
                                                  ('server', server, 'baseline-master' if kind == 'baseline' else 'master')]
                                before = {side: service_snapshot(name, process_label)
                                          for side, name, process_label in process_labels}
                                status_path = root / 'recommended' / ('baseline-status.json' if kind == 'baseline' else 'client-status.json')
                                status_before = json.loads(status_path.read_text())
                                measured = dex(client, 'python3', '/gate/load.py', 'round',
                                               '--kind', kind, '--direction', direction,
                                               '--flows', str(flows), '--seconds', str(args.seconds),
                                               '--connections', str(args.connections),
                                               '--case', label, '--warmup', str(args.warmup), timeout=args.seconds + args.warmup + 40,
                                               check=False)
                                raw = json.loads(measured.stdout)
                                raw['client_status_before'] = status_before
                                raw['service_before'] = before
                                raw['service_after'] = {
                                    side: service_snapshot(name, process_label)
                                    for side, name, process_label in process_labels}
                                if args.pin_cpus:
                                    for side, cpus in [('client', '0-2'), ('server', '3-5')]:
                                        if any(process['allowed_cpus'] != cpus for phase in ('service_before', 'service_after')
                                               for process in raw[phase][side]['processes']):
                                            raw.update(gate='FAIL', error=f'{side} service affinity mismatch')
                                    if raw.get('generator_cpu_affinity') != [6]:
                                        raw.update(gate='FAIL', error='client load generator affinity mismatch')
                                if status_path.exists():
                                    raw['client_status_after'] = json.loads(status_path.read_text())
                                write(label + '.json', raw)
                                if measured.returncode or raw['gate'] != 'PASS':
                                    raise RuntimeError(f'{label}: {raw.get("error", raw)}')
                                latency = raw['loaded_latency']
                                if latency['errors'] or latency['samples'] != args.seconds * 20:
                                    raise RuntimeError(f'{label}: loaded latency integrity failure {latency}')
                                mbps = raw['receiver_mbps']
                                resource = {}
                                for side, name, process_label in process_labels:
                                    if kind == 'direct':
                                        continue
                                    after = raw['service_after'][side]
                                    initial = {p['pid']: p for p in before[side]['processes']}
                                    final = {p['pid']: p for p in after['processes']}
                                    if initial.keys() != final.keys() or any(
                                            initial[pid]['start_ticks'] != final[pid]['start_ticks']
                                            for pid in initial):
                                        raise RuntimeError(f'{label}: service process changed during measurement')
                                    ticks = sum(final[pid]['cpu_ticks'] - initial[pid]['cpu_ticks']
                                                for pid in initial)
                                    delivered_gib = raw['measured_payload_bytes'] / (1024 ** 3)
                                    resource[side] = {'before': before[side], 'after': after,
                                                      'cpu_seconds_per_measured_gib_including_warmup_and_probes':
                                                          ticks / after['clock_ticks'] / delivered_gib}
                                perf.append({'kind': kind, 'workers': workers, 'direction': direction,
                                             'flows': flows, 'round': round_id, 'receiver_mbps': mbps,
                                             'independent_connections': args.connections,
                                             'receiver_mbps_by_direction': raw['receiver_mbps_by_direction'],
                                             'loaded_latency': latency, 'payload_integrity': 'PASS',
                                             'measurement_window': [raw['start'], raw['end']],
                                             'service_resources': resource})
                                write('performance-progress.json', perf)
                stop()
            from statistics import median
            groups = []
            for workers in args.workers:
                for direction in args.directions:
                    for flows in args.flows:
                        sample = [x for x in perf if x['workers'] == workers and
                                  x['direction'] == direction and x['flows'] == flows]
                        direct = median(x['receiver_mbps'] for x in sample if x['kind'] == 'direct')
                        proxy = median(x['receiver_mbps'] for x in sample if x['kind'] == 'proxy')
                        baseline = median(x['receiver_mbps'] for x in sample if x['kind'] == 'baseline')
                        direct_p99 = median(x['loaded_latency']['p99_ms'] for x in sample if x['kind'] == 'direct')
                        proxy_p99 = median(x['loaded_latency']['p99_ms'] for x in sample if x['kind'] == 'proxy')
                        baseline_p99 = median(x['loaded_latency']['p99_ms'] for x in sample if x['kind'] == 'baseline')
                        cpu = lambda row: sum(side['cpu_seconds_per_measured_gib_including_warmup_and_probes']
                                              for side in row['service_resources'].values())
                        baseline_cpu = median(cpu(x) for x in sample if x['kind'] == 'baseline')
                        proxy_cpu = median(cpu(x) for x in sample if x['kind'] == 'proxy')
                        latency_pass = all(x['loaded_latency']['p99_ms'] <= max(1.2 * baseline_p99, baseline_p99 + 2)
                                           for x in sample if x['kind'] == 'proxy')
                        axes = ('upload', 'download') if direction == 'bidirectional' else (direction,)
                        per_direction = {
                            axis: {kind: median(x['receiver_mbps_by_direction'][axis]
                                                for x in sample if x['kind'] == kind)
                                   for kind in ('direct', 'baseline', 'proxy')}
                            for axis in axes}
                        groups.append({'workers': workers, 'direction': direction, 'flows': flows,
                                       'independent_connections': args.connections,
                                       'direction_median_mbps': per_direction,
                                       'direct_median_mbps': direct, 'proxy_median_mbps': proxy,
                                       'baseline_median_mbps': baseline,
                                       'direct_p99_ms': direct_p99, 'proxy_p99_ms': proxy_p99,
                                       'baseline_p99_ms': baseline_p99,
                                       'baseline_cpu_seconds_per_measured_gib': baseline_cpu,
                                       'proxy_cpu_seconds_per_measured_gib': proxy_cpu,
                                       'architecture_goodput_gate': 'PASS' if all(x['proxy'] >= x['baseline'] * .95 for x in per_direction.values()) else 'FAIL',
                                       'cpu_gate': 'PASS' if proxy_cpu <= baseline_cpu * 1.2 else 'FAIL',
                                       'latency_gate': 'PASS' if latency_pass else 'FAIL',
                                       'goodput_gate': 'PASS' if all(x['direct'] >= 900 and x['proxy'] >= 800 for x in per_direction.values()) else 'FAIL'})
            result['goodput'] = groups
            result['performance_observed_gate'] = 'PASS' if all(
                all(x[key] == 'PASS' for key in ('goodput_gate', 'latency_gate', 'architecture_goodput_gate', 'cpu_gate'))
                for x in groups) else 'FAIL'
            result['performance_gate'] = result['performance_observed_gate']
            result['measurement_duration_standard_met'] = args.seconds >= 60 and args.rounds >= 5 and args.warmup >= 10
            result['requested_matrix_complete'] = (set(args.workers) == {1, 2, 4}
                and set(args.directions) == {'upload', 'download', 'bidirectional'}
                and set(args.flows) == {1, 4, 16})
            result['connection_matrix'] = 'separate evidence required for both --connections 1 and 4'
            if (not result['measurement_duration_standard_met'] or not result['requested_matrix_complete']) and result['performance_gate'] == 'PASS':
                result['performance_gate'] = 'INCOMPLETE'
        else:
            result['performance_gate'] = 'NOT_RUN'
        result['gate'] = 'PASS' if (result['compatibility_gate'] == 'PASS' and result['performance_gate'] in ('PASS', 'NOT_RUN')) else 'FAIL'
    except ActiveDrainComplete:
        pass
    except Exception as error:
        result['error'] = str(error)
        if performance_started:
            result['performance_gate'] = 'FAIL'
    finally:
        result['cleanup'] = []
        result['timing_observers'] = {}
        for name, label in reversed(observers):
            try:
                guest(name, 'stop', label=label)
                result['timing_observers'][label] = json.loads((root / (label + '.log')).read_text())
            except Exception as error:
                result['gate'] = 'FAIL'
                result['cleanup'].append({'observer': label, 'error': str(error)})
        for name in reversed(owned):
            try:
                done = run(['docker', 'rm', '-f', name], check=False, timeout=15)
                result['cleanup'].append({'container': name, 'exit_code': done.returncode})
                if done.returncode:
                    result['gate'] = 'FAIL'
            except Exception as error:
                result['cleanup'].append({'container': name, 'error': str(error)})
                result['gate'] = 'FAIL'
        if control_volume:
            done = run(['docker', 'volume', 'rm', control_volume], check=False, timeout=15)
            result['cleanup'].append({'control_volume': control_volume, 'exit_code': done.returncode})
            if done.returncode:
                result['gate'] = 'FAIL'
        write('result.json', result)
        print(json.dumps(result, indent=2))
    return 0 if result['gate'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
