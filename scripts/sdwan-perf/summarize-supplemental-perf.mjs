import fs from 'node:fs';
import path from 'node:path';

const [mode,directory,output]=process.argv.slice(2);
if(!['udp','soak'].includes(mode)||!directory||!output)throw new Error('usage: node summarize-supplemental-perf.mjs udp|soak <run> <new output.json>');
if(fs.existsSync(output))throw new Error('refusing to replace prior supplemental evidence');
const root=path.resolve(directory),read=file=>JSON.parse(fs.readFileSync(path.join(root,file)));
const median=values=>{const sorted=[...values].sort((a,b)=>a-b);return sorted.length%2?sorted[Math.floor(sorted.length/2)]:(sorted[sorted.length/2-1]+sorted[sorted.length/2])/2;};
const snmp=text=>{
  const lines=text.trim().split('\n'),values={};
  for(let i=0;i+1<lines.length;i+=2){
    const keys=lines[i].trim().split(/\s+/),counts=lines[i+1].trim().split(/\s+/);
    for(let j=1;j<keys.length;j++)values[`${keys[0]}${keys[j]}`]=Number(counts[j]);
  }
  return values;
};
let result;
if(mode==='udp'){
  const integrity=[];
  for(const payload of [64,512,1200])for(const direction of ['upload','download'])for(const stage of ['before','after']){
    const name=`formal-udp-validated-${payload}-${direction}-${stage}`,data=read(`${name}.json`);
    const snapshots=['before','after'].map(suffix=>read(`${name}-${suffix}.json`));
    const fragments=Object.fromEntries(['client','server'].map(side=>[side,snmp(snapshots[1][side].snmp)['Ip:FragCreates']-snmp(snapshots[0][side].snmp)['Ip:FragCreates']]));
    const valid=data.sent_packets===10000&&['lost_packets','send_errors','corrupt_packets','duplicate_packets'].every(key=>data[key]===0);
    const fragmentVerified=payload!==1200||Object.values(fragments).every(value=>Number.isFinite(value)&&value>0);
    integrity.push({payload,direction,stage,...data,ipv4_fragment_creates:fragments,fragmentation_gate:fragmentVerified?'PASS':'FAIL',gate:valid&&fragmentVerified?'PASS':'FAIL'});
  }
  const groups=[64,512,1200].flatMap(payload=>['upload','download'].map(direction=>{
    const samples=[];
    for(let round=1;round<=5;round++){
      const data=read(`formal-udp-iperf-${payload}-${direction}-r${round}.json`);
      if(data.error)throw new Error(data.error);
      const receiver=data.end?.sum_received||(direction==='upload'?data.server_output_json?.end?.sum:data.end?.sum);
      if(!receiver||!['bits_per_second','lost_packets','packets','lost_percent'].every(key=>Number.isFinite(receiver[key])))throw new Error('missing actual UDP receiver counters');
      samples.push({round,receiver_mbps:receiver.bits_per_second/1e6,received_payload_bytes:receiver.bytes,lost_packets:receiver.lost_packets,packets:receiver.packets,lost_percent:receiver.lost_percent,jitter_ms:receiver.jitter_ms,out_of_order:receiver.out_of_order??null});
    }
    return {payload,direction,n:samples.length,offered_payload_mbps:800,median_receiver_mbps:median(samples.map(sample=>sample.receiver_mbps)),median_lost_percent:median(samples.map(sample=>sample.lost_percent)),samples};
  }));
  result={schema_version:1,mode,scope:'SD-WAN IPv4 UDP payload sizes; 1200-byte payload explicitly validates IP fragmentation with inner MTU 1180. High-rate 64-byte offered payload can exceed wire capacity; raw loss is reported, not silently treated as corruption.',gate:integrity.every(row=>row.gate==='PASS')?'PASS':'FAIL',integrity,groups,high_rate_relative_gate:'PAIR_REQUIRED'};
}else{
  const samples=[];
  for(let round=1;round<=120;round++){
    const direction=round%2?'upload':'download',name=`soak-p4-${direction}-r${round}`;
    const data=read(`${name}.json`),beforeSnapshot=read(`${name}-before.json`),snapshot=read(`${name}-after.json`);
    if(data.error)throw new Error(data.error);
    const stateFrom=(sideSnapshot)=>sideSnapshot.status.split('\n').filter(Boolean).map(line=>JSON.parse(line)).find(row=>row.counters);
    const sides=Object.fromEntries(['client','server'].map(side=>{
      const beforeState=stateFrom(beforeSnapshot[side]),state=stateFrom(snapshot[side]);
      if(!state)throw new Error('missing actual Core status in soak snapshot');
      if(!beforeState)throw new Error('missing pre-sample Core status in soak snapshot');
      let rss=0,fds=0;
      for(const resource of snapshot[side].resources.split('\n')){
        if(!resource.includes('/bench/binaries/'))continue;
        const count=resource.match(/fd_count=(\d+)/),memory=resource.match(/VmRSS:\s*(\d+)/);
        if(count)fds+=Number(count[1]);
        if(memory)rss+=Number(memory[1])*1024;
      }
      return [side,{rss_bytes:rss,fd_count:fds,memory_bytes:Number(snapshot[side].memory),memory_peak_bytes:Number(snapshot[side].peak),pid:state.pid,phase:state.dataplane_phase,failed_prefixes:state.failed_prefixes,counters:state.counters,reconnects:state.reconnects,before:{pid:beforeState.pid,counters:beforeState.counters,reconnects:beforeState.reconnects}}];
    }));
    samples.push({round,direction,measured_seconds:data.end.sum_received.seconds,receiver_mbps:data.end.sum_received.bits_per_second/1e6,...sides});
  }
  const sides=['client','server'].map(side=>{
    const values=samples.slice(10).map(row=>row[side]);
    const first=values.slice(0,15),last=values.slice(-15);
    const initialRss=median(first.map(row=>row.rss_bytes)),finalRss=median(last.map(row=>row.rss_bytes));
    const initialFds=median(first.map(row=>row.fd_count)),finalFds=median(last.map(row=>row.fd_count));
    const allowance=Math.max(16*1024*1024,initialRss*0.05);
    const meanX=(values.length-1)/2,meanY=values.reduce((sum,row)=>sum+row.rss_bytes,0)/values.length;
    const slope=values.reduce((sum,row,index)=>sum+(index-meanX)*(row.rss_bytes-meanY),0)/values.reduce((sum,_,index)=>sum+(index-meanX)**2,0);
    const identity=samples[0][side].pid;
    const healthy=samples.every(row=>row[side].pid===identity&&row[side].phase==='data_plane_active'&&Array.isArray(row[side].failed_prefixes)&&row[side].failed_prefixes.length===0);
    const withinBudget=values.every(row=>row.memory_peak_bytes<=2147483648&&row.rss_bytes>0&&row.fd_count>0);
    const monotonicCounters=['stream_read_errors','stream_write_errors','reconnects'];
    const initial=samples[0][side].before;
    const counterIssues=[];
    if(!initial||!Number.isFinite(initial.pid))counterIssues.push('missing_initial_state');
    else if(initial.pid!==identity)counterIssues.push('initial_core_identity_changed');
    else for(const key of monotonicCounters){
      const baseline=key==='reconnects'?initial.reconnects:initial.counters?.[key];
      if(!Number.isFinite(baseline))counterIssues.push(`missing_initial_${key}`);
      for(const sample of samples){
        const row=sample[side],before=row.before,after=key==='reconnects'?row.reconnects:row.counters?.[key];
        const prior=key==='reconnects'?before?.reconnects:before?.counters?.[key];
        if(!Number.isFinite(prior)||!Number.isFinite(after)){counterIssues.push(`missing_${key}`);continue;}
        if(prior<baseline||after<prior)counterIssues.push(`non_monotonic_${key}`);
        if(prior!==baseline||after!==baseline)counterIssues.push(`increased_${key}`);
      }
    }
    const noErrors=counterIssues.length===0;
    const passed=healthy&&withinBudget&&noErrors&&finalRss-initialRss<=allowance&&slope*values.length<=allowance&&finalFds-initialFds<=16;
    return {side,initial_rss_bytes:initialRss,final_rss_bytes:finalRss,rss_allowance_bytes:allowance,rss_trend_bytes_per_minute:slope,initial_fd_count:initialFds,final_fd_count:finalFds,healthy,within_budget:withinBudget,no_stream_errors:noErrors,counter_issues:counterIssues,gate:passed?'PASS':'FAIL'};
  });
  const seconds=samples.reduce((sum,row)=>sum+row.measured_seconds,0);
  result={schema_version:1,mode,scope:'Two-hour static signed-Grant SD-WAN IPC stability; does not replace a real Cloud renewal cycle or mixed-role/production listener test',criteria:{minimum_measured_seconds:7200,aggregate_timer_tolerance_seconds:1,offered_mbps:750,warm_samples_excluded:10,comparison_window_samples:15,rss_growth_allowance:'max(16 MiB, 5% initial service RSS), both median growth and fitted trend',fd_growth_allowance:16,cgroup_memory_budget_bytes:2147483648},measured_seconds:seconds,sides,samples,gate:seconds>=7199&&samples.every(row=>row.receiver_mbps>=712.5)&&sides.every(row=>row.gate==='PASS')?'PASS':'FAIL'};
}
fs.writeFileSync(output,JSON.stringify(result,null,2),{mode:0o600});
console.log(`${mode} ${result.gate}`);
if(result.gate!=='PASS')process.exitCode=1;
