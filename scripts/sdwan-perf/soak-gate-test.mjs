import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const root=fs.mkdtempSync(path.join(os.tmpdir(),'candy-soak-gate-'));
const write=(file,value)=>fs.writeFileSync(path.join(root,file),JSON.stringify(value));
const summary=fileURLToPath(new URL('./summarize-supplemental-perf.mjs',import.meta.url));
const state={pid:1,dataplane_phase:'data_plane_active',failed_prefixes:[],reconnects:2,counters:{stream_read_errors:3,stream_write_errors:4}};
const snapshot=()=>({status:JSON.stringify(state),resources:'pid=1 executable=/bench/binaries/candy-core fd_count=20 status=VmRSS: 102400 kB,',memory:200e6,peak:200e6});
const filename=(round,stage)=>`soak-p4-${round%2?'upload':'download'}-r${round}-${stage}.json`;
const run=label=>{
  const result=spawnSync(process.execPath,[summary,'soak',root,path.join(root,`${label}.json`)],{encoding:'utf8'});
  assert.equal(result.error,undefined);
  return {status:result.status,...JSON.parse(fs.readFileSync(path.join(root,`${label}.json`)))};
};
const change=(round,stage,mutate)=>{
  const file=filename(round,stage),data=JSON.parse(fs.readFileSync(path.join(root,file)));
  const actual=JSON.parse(data.client.status);
  mutate(actual);
  data.client.status=JSON.stringify(actual);
  write(file,data);
};
try{
  for(let round=1;round<=120;round++){
    write(`soak-p4-${round%2?'upload':'download'}-r${round}.json`,{end:{sum_received:{seconds:60,bits_per_second:750e6}}});
    for(const stage of ['before','after'])write(filename(round,stage),{client:snapshot(),server:snapshot()});
  }
  assert.equal(run('valid').gate,'PASS');
  for(const [label,round,stage,mutate,issue] of [
    ['early-stream',1,'after',s=>s.counters.stream_read_errors++,'increased_stream_read_errors'],
    ['middle-stream',60,'after',s=>s.counters.stream_write_errors++,'increased_stream_write_errors'],
    ['final-stream',120,'after',s=>s.counters.stream_read_errors++,'increased_stream_read_errors'],
    ['reconnect',2,'after',s=>s.reconnects++,'increased_reconnects'],
    ['reset',60,'after',s=>s.counters.stream_write_errors=0,'non_monotonic_stream_write_errors'],
    ['pre-error',1,'before',s=>s.counters.stream_read_errors--,'increased_stream_read_errors'],
    ['missing-reconnect',60,'after',s=>delete s.reconnects,'missing_reconnects'],
  ]){
    change(round,stage,mutate);
    const result=run(label);
    assert.equal(result.gate,'FAIL',label);
    assert.notEqual(result.status,0,label);
    assert(result.sides[0].counter_issues.includes(issue),label);
    const data=JSON.parse(fs.readFileSync(path.join(root,filename(round,stage))));
    data.client=snapshot();write(filename(round,stage),data);
  }
  assert.equal(run('restored').gate,'PASS');
  console.log('PASS: initial nonzero counters accepted; all 120 samples reject early/mid/final stream errors, reconnects, counter resets and missing evidence');
}finally{
  fs.rmSync(root,{recursive:true,force:true});
}
