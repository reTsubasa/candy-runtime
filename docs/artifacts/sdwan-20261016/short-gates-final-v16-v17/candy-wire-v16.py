import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time

runtime = Path('/Users/hyc/Documents/candy/candy-runtime')
base = runtime/'docs/artifacts/sdwan-20261016'
reg = base/'short-linux-regression-v16'
evidence = base/'control-reserve-wire-v16'
evidence.mkdir(exist_ok=False)
artifacts=[]
for line in (reg/'wire-compile.log').read_text().splitlines():
    if line.startswith('{'):
        row=json.loads(line)
        if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')=='candy_carrier_server' and row.get('executable'):
            artifacts.append(row['executable'])
assert len(artifacts)==1, artifacts
source=runtime.parent/'candy-core/target-linux-shared'/Path(artifacts[0]).relative_to('/build')
binary=evidence/'wire-server-tests'
shutil.copy2(source,binary)
command=['docker','run','--rm','--network','none','--cpuset-cpus','0-2','--memory','3g','--pids-limit','512',
         '-v',f'{evidence}:/wire:ro','candy-sdwan-perf-runner:20261013','timeout','120',
         '/wire/wire-server-tests','control_reserve_wire','--include-ignored','--test-threads=1','--nocapture']
started=time.monotonic()
with (evidence/'test.log').open('w') as log:
    done=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=150)
log=(evidence/'test.log').read_text()
summary=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',log)
passed=done.returncode==0 and summary==[('4','0','0')]
result={'gate':'PASS' if passed else 'FAIL','exit_code':done.returncode,'seconds':time.monotonic()-started,
        'summary':summary,'command':command,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
        'source':json.loads((reg/'result.json').read_text())['source'],
        'scope':'actual QUIC and Unix IPC control-pressure protocol fixture, not Runtime client or throughput acceptance'}
(evidence/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:result[k] for k in ('gate','exit_code','seconds','summary','binary_sha256')}),flush=True)
raise SystemExit(0 if passed else 1)
