import json
from pathlib import Path
import subprocess
import sys
import time

runtime = Path('/Users/hyc/Documents/candy/candy-runtime')
version = sys.argv[1]
base = runtime / 'docs/artifacts/sdwan-20261016'
build = base / f'registered-mbb-release-{version}'
source = build / 'frozen/candy-runtime'
tasks = [
    ('domain-evidence-socket', 'signed_cli_shared_domain_evidence_socket_gate'),
    ('mixed-role-fault', 'signed_cli_mixed_role_quota_and_slow_consumer_isolation'),
    ('shared-pool-negotiated-final', 'signed_cli_shared_pool_scales_and_isolates_four_domains'),
    ('successor-server-restart', 'signed_cli_successor_server_restart_preserves_authorization'),
    ('bilateral-mbb-final', 'signed_cli_bilateral_candidate_reload_preserves_traffic'),
]
for name, test in tasks:
    if len(sys.argv) > 2 and sys.argv[2] == 'skip-domain' and name == 'domain-evidence-socket':
        continue
    evidence = base / f'{name}-{version}'
    command = ['python3', str(source/'scripts/shared_pool_gate.py'), str(evidence), test,
               '--build', str(build), '--pin-cpus']
    with (base/f'{name}-{version}-runner.log').open('x') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=330)
    print(json.dumps({'name': name, 'exit_code': result.returncode, 'result': json.loads((evidence/'result.json').read_text())['gate']}), flush=True)
    if result.returncode:
        raise SystemExit(result.returncode)
for name, option in [('active-drain', '--active-drain-only'), ('udp', '--udp-only')]:
    evidence = base/f'proxy-release-{version}-{name}-v1'
    command = ['python3', str(source/'scripts/proxy-gate/run.py'), '--binary', str(build/'binaries/candy-core'),
               '--evidence', str(evidence), option, '--pin-cpus']
    with (base/f'proxy-release-{version}-{name}-runner.log').open('x') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    print(json.dumps({'name': name, 'exit_code': result.returncode}), flush=True)
    if result.returncode:
        raise SystemExit(result.returncode)
