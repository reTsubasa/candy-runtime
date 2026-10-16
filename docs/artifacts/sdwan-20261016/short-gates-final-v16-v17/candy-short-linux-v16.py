import json
from pathlib import Path
import subprocess
import time

runtime = Path('/Users/hyc/Documents/candy/candy-runtime')
build = runtime / 'docs/artifacts/sdwan-20261016/registered-mbb-release-v16'
evidence = runtime / 'docs/artifacts/sdwan-20261016/short-linux-regression-v16'
evidence.mkdir(exist_ok=False)
freeze = json.loads((build / 'source-freeze.json').read_text())
rows = []
tasks = [
    ('core-app', 'core', ['test', '-p', 'candy-core-process', '--lib', '--', '--test-threads=1']),
    ('wire-compile', 'core', ['test', '-p', 'candy-carrier-server', '--lib', '--no-run', '--message-format=json']),
    ('core-clippy', 'core', ['clippy', '-p', 'candy-core-process', '-p', 'candy-carrier-runtime', '-p', 'candy-carrier-transport', '-p', 'candy-carrier-server', '--all-targets', '--', '-D', 'warnings']),
    ('tunio-clippy', 'tunio', ['clippy', '--all-targets', '--', '-D', 'warnings']),
]
for name, kind, args in tasks:
    root = '/workspace/candy-core' if kind == 'core' else '/workspace/candy-runtime'
    manifest = root + ('/linux/common/apps/candy-tunio/Cargo.toml' if kind == 'tunio' else '/Cargo.toml')
    cache = runtime.parent / 'candy-core/target-linux-shared' if kind == 'core' else runtime / 'target-linux-netd-v2'
    command = ['docker', 'run', '--rm', '--network', 'none', '--cpus', '2', '--memory', '3g',
               '-v', f'{build}/frozen:/workspace:ro', '-v', f'{cache}:/build',
               '-v', f'{Path.home()}/.cargo/registry:/usr/local/cargo/registry:ro',
               '-w', '/tmp', '-e', 'CARGO_TARGET_DIR=/build', '-e', 'CARGO_BUILD_JOBS=2',
               'candy-short-gates-clippy:20261016', 'cargo', args[0],
               '--manifest-path', manifest, '--locked', '--offline', *args[1:]]
    started = time.monotonic()
    with (evidence/f'{name}.log').open('w') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=900)
    row = {'name': name, 'exit_code': result.returncode, 'seconds': time.monotonic()-started, 'command': command, 'log': f'{name}.log'}
    rows.append(row)
    (evidence/'result.json').write_text(json.dumps({'source': freeze, 'checks': rows}, indent=2)+'\n')
    print(json.dumps({k:v for k,v in row.items() if k != 'command'}), flush=True)
    if result.returncode:
        raise SystemExit(result.returncode)
