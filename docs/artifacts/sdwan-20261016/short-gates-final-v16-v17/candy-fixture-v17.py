import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

runtime=Path('/Users/hyc/Documents/candy/candy-runtime')
base=runtime/'docs/artifacts/sdwan-20261016'
old=base/'registered-mbb-release-v16'
new=base/'registered-mbb-release-v17'
subprocess.run(['python3',str(runtime/'scripts/freeze_build_six.py'),str(new),'--freeze-only'],check=True)
before={row['path']:row['sha256'] for row in json.loads((old/'source-manifest.json').read_text())}
after={row['path']:row['sha256'] for row in json.loads((new/'source-manifest.json').read_text())}
changed=sorted(path for path in before.keys()|after.keys() if before.get(path)!=after.get(path))
assert changed==['candy-runtime/linux/common/apps/candy-tunio/tests/fixtures/shared_domain_evidence.rs'], changed
cache=runtime/'target-linux-release-freeze'
mounts=['-v',f'{new}/frozen:/workspace:ro','-v',f'{cache}:/build',
        '-v',f'{Path.home()}/.cargo/registry:/usr/local/cargo/registry:ro']
command=['docker','run','--rm','--network','none','--cpus','2','--memory','4g',*mounts,
         'candy-sdwan-perf-runner:20261013','cargo','test','--manifest-path',
         '/workspace/candy-runtime/linux/common/apps/candy-tunio/Cargo.toml','--target-dir','/build',
         '--release','--locked','--offline','--test','signed_cli','--no-run','--message-format=json']
with (new/'build-signed-cli-helper.log').open('w') as log:
    result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=600)
assert result.returncode==0, result.returncode
executables=[]
for line in (new/'build-signed-cli-helper.log').read_text().splitlines():
    if line.startswith('{'):
        row=json.loads(line)
        if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')=='signed_cli' and row.get('executable'):
            executables.append(row['executable'])
assert len(executables)==1,executables
binaries=new/'binaries'
binaries.mkdir()
artifacts={}
for label,expected in json.loads((old/'binary-hashes.json').read_text()).items():
    source=old/'binaries'/label
    inherited=True
    if label=='signed_cli_helper':
        source=cache/Path(executables[0]).relative_to('/build')
        inherited=False
    else:
        assert hashlib.sha256(source.read_bytes()).hexdigest()==expected
    target=binaries/label
    shutil.copy2(source,target)
    artifacts[label]={'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'bytes':target.stat().st_size,
                      'inherited_from':str(old) if inherited else None}
clippy=['docker','run','--rm','--network','none','--cpus','2','--memory','3g',
        '-v',f'{new}/frozen:/workspace:ro','-v',f'{runtime}/target-linux-netd-v2:/build',
        '-v',f'{Path.home()}/.cargo/registry:/usr/local/cargo/registry:ro','-w','/tmp',
        '-e','CARGO_TARGET_DIR=/build','candy-short-gates-clippy:20261016','cargo','clippy',
        '--manifest-path','/workspace/candy-runtime/linux/common/apps/candy-tunio/Cargo.toml',
        '--locked','--offline','--all-targets','--','-D','warnings']
with (new/'tunio-clippy.log').open('w') as log:
    result=subprocess.run(clippy,stdout=log,stderr=subprocess.STDOUT,timeout=600)
assert result.returncode==0,result.returncode
hashes={label:row['sha256'] for label,row in artifacts.items()}
(new/'binary-hashes.json').write_text(json.dumps(hashes,indent=2)+'\n')
freeze=json.loads((new/'source-freeze.json').read_text())
provenance={'kind':'fixture-only rebuild; five unchanged production artifacts inherited from verified v16',
            'changed_source_paths':changed,'source':freeze,'artifacts':artifacts,'binary_hashes':hashes,
            'helper_build_command':command,'strict_clippy_command':clippy,
            'inherited_provenance_sha256':hashlib.sha256((old/'build-provenance.json').read_bytes()).hexdigest()}
(new/'build-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
(new/'result.json').write_text(json.dumps({'gate':'BUILD_PASS','scope':provenance['kind'],
    'manifest_sha256':freeze['manifest_sha256'],'strict_tunio_clippy':'PASS','performance':'NOT_RUN'},indent=2)+'\n')
print(json.dumps({'gate':'BUILD_PASS','changed_source_paths':changed,'manifest_sha256':freeze['manifest_sha256']}),flush=True)
