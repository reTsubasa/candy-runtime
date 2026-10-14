import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const [phase, directory, baselineGate] = process.argv.slice(2);
if (!['setup', 'smoke', 'smoke-cpu', 'formal-cpu', 'formal-direct', 'formal-tunnel', 'formal-udp', 'smoke-udp', 'soak', 'cleanup'].includes(phase) || !directory) throw new Error('usage: node run-two-docker-perf.mjs setup|smoke|smoke-cpu|formal-cpu|formal-direct|formal-tunnel|formal-udp|smoke-udp|soak|cleanup <run-directory> [baseline-gate-json]');
const root = path.resolve(directory);
const topology = process.env.CANDY_PERF_TOPOLOGY || 'ipc';
if (!['ipc', 'in-process'].includes(topology)) throw new Error(`unsupported topology: ${topology}`);
const cpuTargetMbps = Number(process.env.CANDY_PERF_CPU_TARGET_MBPS || 750);
const transactions = process.env.CANDY_PERF_TRANSACTIONS === '1';
const grantTtlSecs = Number(process.env.CANDY_PERF_GRANT_TTL_SECS || 3600);
const selectedSample=process.env.CANDY_PERF_SAMPLE?process.env.CANDY_PERF_SAMPLE.split('/'):undefined;
if(selectedSample&&!/^([1-5])\/(1|4|16)\/(upload|download)$/.test(process.env.CANDY_PERF_SAMPLE))throw new Error('sample selection must be round/parallel/direction');
const selectedUdp=process.env.CANDY_PERF_UDP_SAMPLE?process.env.CANDY_PERF_UDP_SAMPLE.split('/'):undefined;
if(selectedUdp&&!/^(64|512|1200)\/(upload|download)\/[1-5]$/.test(process.env.CANDY_PERF_UDP_SAMPLE))throw new Error('UDP selection must be payload/direction/round');
if (!Number.isInteger(grantTtlSecs) || grantTtlSecs < 60 || grantTtlSecs > 86400) throw new Error('test Grant TTL must be between 60 and 86400 seconds');
if (!Number.isFinite(cpuTargetMbps) || cpuTargetMbps <= 0 || cpuTargetMbps > 800) throw new Error('matched CPU target must be within (0, 800] Mbps');
const runId = crypto.createHash('sha256').update(root).digest('hex').slice(0, 12);
const client = `candy-perf-client-${runId}`;
const server = `candy-perf-server-${runId}`;
const image = 'candy-sdwan-perf-runner:20261013';
const run = (args, options = {}) => {
  const result = spawnSync('docker', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...options });
  if (result.status !== 0) throw new Error(`${args.slice(0, 3).join(' ')} failed: ${result.stderr || result.stdout}`);
  return result.stdout;
};
const exec = (name, args) => run(['exec', name, ...args]);
const write = (name, data) => fs.writeFileSync(path.join(root, name), typeof data === 'string' ? data : JSON.stringify(data, null, 2), { mode: 0o600 });
const pause = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
const launch = (name, label, args, env = []) => {
  const quote = value => `'${String(value).replaceAll("'", "'\\''")}'`;
  run(['exec', '-d', ...env.flatMap(value => ['-e', value]), name, 'sh', '-c', `exec ${args.map(quote).join(' ')} > /bench/${label}.log 2>&1`]);
};
const wait = (name, file) => {
  for (let i = 0; i < 300; i++) {
    try { exec(name, ['test', '-e', file.startsWith('/') ? file : `/bench/${file}`]); return; } catch { pause(100); }
  }
  throw new Error(`timeout waiting ${name} ${file}`);
};
const snapshot = name => JSON.parse(exec(name, ['sh', '-c', `
resources() {
  for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$exe" in /bench/binaries/*|/usr/bin/iperf3) ;; *) continue ;; esac
    [ "$(cat "$p/cgroup" 2>/dev/null)" = "$(cat /proc/self/cgroup)" ] || continue
    printf 'pid=%s executable=%s fd_count=%s stat=%s status=%s\\n' "$(basename "$p")" "$exe" "$(ls -U "$p/fd" 2>/dev/null | wc -l)" "$(cat "$p/stat" 2>/dev/null)" "$(sed -n '/^VmRSS:/p; /^VmHWM:/p; /^Threads:/p' "$p/status" 2>/dev/null | tr '\\n' ',')"
  done
}
state() {
  for file in /run/candy-perf/*status.json; do
    [ -f "$file" ] || continue
    jq -c 'walk(if type == "object" then del(.readiness_token) else . end)' "$file"
  done
}
jq -n --arg cpu "$(cat /sys/fs/cgroup/cpu.stat)" --arg vm_cpu "$(sed -n '1p' /proc/stat)" --arg ticks_per_second "$(getconf CLK_TCK)" --arg vm_softirq "$(cat /proc/softirqs)" --arg memory "$(cat /sys/fs/cgroup/memory.current)" --arg peak "$(cat /sys/fs/cgroup/memory.peak)" --arg quota "$(cat /sys/fs/cgroup/cpu.max)" --arg links "$(ip -s -j link show)" --arg routes "$(ip -j route show table all)" --arg qdisc "$(tc -s -j qdisc show)" --arg snmp "$(cat /proc/net/snmp)" --arg resources "$(resources)" --arg status "$(state)" '{cpu:$cpu,vm_cpu:$vm_cpu,ticks_per_second:$ticks_per_second,vm_softirq:$vm_softirq,memory:$memory,peak:$peak,quota:$quota,links:$links,routes:$routes,qdisc:$qdisc,snmp:$snmp,resources:$resources,status:$status}'`]));
const cleanup = () => {
  for (const name of [client, server]) {
    const inspected = spawnSync('docker', ['inspect', name], { encoding: 'utf8' });
    if (inspected.status === 0) {
      const item = JSON.parse(inspected.stdout)[0];
      if (item.Config.Labels?.['candy.perf.run'] !== root) throw new Error(`refusing cleanup of foreign ${name}`);
      run(['rm', '-f', name]);
    }
  }
};
if (phase === 'cleanup') { cleanup(); process.exit(0); }
if (phase === 'setup') {
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  if (fs.existsSync(path.join(root, 'fixture'))) throw new Error('setup needs a new run directory without a fixture; preserve prior evidence and choose a new directory');
  if (fs.existsSync(path.join(root, 'run-identity.json'))) throw new Error('setup refuses to overwrite a prior run; choose a new run directory');
  const binaries = ['candy-core', 'candy-netd', 'candy-tunio', 'candy-agent', 'sdwan_signed_cli_fixture', 'signed_cli_helper'];
  const hashes = Object.fromEntries(binaries.map(name => [name, crypto.createHash('sha256').update(fs.readFileSync(path.join(root, 'binaries', name))).digest('hex')]));
  if (fs.existsSync(path.join(root, 'binary-hashes.json'))) {
    const expected = JSON.parse(fs.readFileSync(path.join(root, 'binary-hashes.json')));
    if (Object.keys(expected).length !== binaries.length || binaries.some(name => hashes[name] !== expected[name])) throw new Error('build binary identity mismatch');
  } else {
    write('binary-hashes.json', hashes);
  }
  write('docker-info.json', JSON.parse(run(['info', '--format', '{{json .}}'])));
  const probe = path.resolve(new URL('./candy-perf-probe.py', import.meta.url).pathname);
  fs.copyFileSync(probe,path.join(root,'candy-perf-probe.py'));
  write('run-identity.json', {run_id:runId,root,client,server,image,topology,cpu_target_mbps:cpuTargetMbps,runner_sha256:crypto.createHash('sha256').update(fs.readFileSync(new URL(import.meta.url))).digest('hex'),probe_sha256:crypto.createHash('sha256').update(fs.readFileSync(probe)).digest('hex'),parameters:{cpu_quota:3,memory_bytes:2147483648,link_bps:1000000000,grant_bps:2000000000,grant_ttl_secs:grantTtlSecs,transactions,window_mib:64,mtu:1180,formal_warm_seconds:10,formal_measure_seconds:60,formal_rounds:5},started_at:new Date().toISOString()});
  for (const name of [client, server]) {
    run(['run', '-d', '--name', name, '--label', `candy.perf.run=${root}`, '--label', `candy.perf.run_id=${runId}`, '--network', 'none', ...(name === server ? ['--pid', 'host'] : []), '--privileged', '--cpus', '3', '--memory', '2g', '--memory-swap', '2g', '--pids-limit', '256', '-v', `${root}:/bench`, image, 'sleep', 'infinity']);
  }
  const runIdentity=JSON.parse(fs.readFileSync(path.join(root,'run-identity.json')));
  runIdentity.image_id=JSON.parse(run(['inspect',client]))[0].Image;
  write('run-identity.json',runIdentity);
  const clientPid = run(['inspect', '-f', '{{.State.Pid}}', client]).trim();
  exec(server, ['ip', 'link', 'add', 'candy-perf-s', 'type', 'veth', 'peer', 'name', 'candy-perf-c']);
  exec(server, ['ip', 'link', 'set', 'candy-perf-c', 'netns', clientPid]);
  for (const [name, iface, address, lan] of [[client, 'candy-perf-c', '10.200.0.1/24', '10.251.1.10/24'], [server, 'candy-perf-s', '10.200.0.2/24', '10.251.2.10/24']]) {
    exec(name, ['mkdir', '-m', '700', '/run/candy-perf']);
    exec(name, ['ln', '-s', '/bench/fixture', '/run/candy-perf/fixture']);
    exec(name, ['ip', 'link', 'set', 'lo', 'up']);
    exec(name, ['ip', 'addr', 'add', address, 'dev', iface]);
    exec(name, ['ip', 'link', 'set', iface, 'up']);
    exec(name, ['tc', 'qdisc', 'add', 'dev', iface, 'root', 'handle', '1:', 'htb', 'default', '10']);
    exec(name, ['tc', 'class', 'add', 'dev', iface, 'parent', '1:', 'classid', '1:10', 'htb', 'rate', '1gbit', 'ceil', '1gbit', 'burst', '128k', 'cburst', '128k']);
    exec(name, ['ip', 'link', 'add', 'candy-test-lan', 'type', 'dummy']);
    exec(name, ['ip', 'addr', 'add', lan, 'dev', 'candy-test-lan']);
    exec(name, ['ip', 'link', 'set', 'candy-test-lan', 'up']);
  }
  exec(server, ['env', 'CANDY_SIGNED_FIXTURE_ENDPOINT=10.200.0.2:18443', `CANDY_SIGNED_FIXTURE_GRANT_TTL_SECS=${grantTtlSecs}`, ...(process.env.CANDY_SIGNED_FIXTURE_POLICY_TTL_SECS ? [`CANDY_SIGNED_FIXTURE_POLICY_TTL_SECS=${process.env.CANDY_SIGNED_FIXTURE_POLICY_TTL_SECS}`] : []), 'CANDY_SIGNED_FIXTURE_RATE_BPS=2000000000', 'CANDY_SIGNED_FIXTURE_WINDOW_MIB=64', '/bench/binaries/sdwan_signed_cli_fixture', '/bench/fixture']);
  const compiled = JSON.parse(exec(client, ['/bench/binaries/candy-core', 'client', 'sdwan', 'compile-control', '--config', '/bench/fixture/client.toml']));
  write('compiled-control.json', compiled);
  for (const [name, socket, journal] of [[client, 'netd.sock', 'infra.journal'], [server, 'server-netd.sock', 'server-infra.journal']]) {
    launch(name, name === client ? 'client-netd' : 'server-netd', ['/bench/binaries/candy-netd', '--protocol-v2', '--socket', `/run/candy-perf/${socket}`, '--allowed-uid', '0', '--allowed-gid', '0', '--infrastructure-journal', `/run/candy-perf/${journal}`]);
    wait(name, `/run/candy-perf/${socket}`);
  }
  launch(server, 'server-core', ['/bench/binaries/signed_cli_helper', '--exact', 'signed_server_helper', '--ignored', '--nocapture'], ['CANDY_SIGNED_TEST_ROOT=/run/candy-perf', 'CANDY_SIGNED_SERVER_EPOCH=1', 'CANDY_CORE_TEST_BINARY=/bench/binaries/candy-core']);
  const [device, inode] = exec(client, ['stat', '-Lc', '%d %i', '/proc/self/ns/net']).trim().split(' ').map(Number);
  const prefix = (network, prefix_len) => ({ network, prefix_len });
  write('plan.json', {schema_version:1, netd_socket:'/bench/netd.sock', tunio:'/bench/binaries/candy-tunio', core:'/bench/binaries/candy-core', core_config:'/bench/fixture/client.toml', core_status:'/bench/client-status.json', binding_file:'/bench/binding.json', instance_id:Array(16).fill(1), infrastructure:{infra_id:Array(16).fill(3),generation:1,netns_device:device,netns_inode:inode,overlay_router_ipv4:[100,64,0,1],mtu:1180}, domain_id:Array(16).fill(2),io_epoch:1,worker_epoch:1,fencing_token:1,signed_generation:1,auth_deadline_unix:compiled.authorization_expires_at_unix,declaration:{table_id:compiled.netd.table_id,overlay_router_ipv4:[100,64,0,1],effective_mtu:1180,routes:[{prefix:prefix([10,251,1,0],24),kind:'Local'},{prefix:prefix([10,251,2,0],24),kind:'Remote'}],exclusions:[{prefix:prefix([10,200,0,2],32),kind:'HubEndpoint'}],firewall:{allow_forward:true,clamp_tcp_mss:true,require_ipv4_forwarding:true,manage_rp_filter:true}},independent_supervision:{control_socket:'/bench/io-control.sock',status:'/bench/io-status.json',process_record:'/bench/io-process.json'},independent_worker:{control_socket:'/bench/worker-control.sock',process_record:'/bench/worker-process.json'}});
  const plan = JSON.parse(fs.readFileSync(path.join(root,'plan.json')));
  plan.netd_socket = '/run/candy-perf/netd.sock';
  plan.core_status = '/run/candy-perf/client-status.json';
  plan.binding_file = '/run/candy-perf/binding.json';
  for (const entry of [plan.independent_supervision,plan.independent_worker]) for (const key of Object.keys(entry)) entry[key]=entry[key].replace('/bench/','/run/candy-perf/');
  write('plan.json', plan);
  if (topology === 'ipc') {
    if (process.env.CANDY_PERF_RUNTIME_AGENT === '1') {
      write('runtime-agent.json', {schema_version:1,status:'/run/candy-perf/runtime-agent-status.json',budgets:{max_domain_supervisors:1,max_managed_threads:2,thread_stack_bytes:1048576,max_managed_stack_bytes:2097152,event_capacity:1,cloud_iteration_deadline_ms:1000,shutdown_timeout_ms:5000},cloud:{state_dir:'/run/candy-perf/cloud-state',run_dir:'/run/candy-perf',interval_ms:1000,retry_initial_ms:100,retry_max_ms:1000},domain_plans:['/bench/plan.json']});
      launch(client, 'client-agent', ['/bench/binaries/candy-agent', 'experimental-runtime-agent', '--experimental-packet-port-ipc', '--config', '/bench/runtime-agent.json']);
    } else {
      launch(client, 'client-agent', ['/bench/binaries/candy-agent', 'experimental-packet-port-run', '--experimental-packet-port-ipc', '--plan', '/bench/plan.json']);
    }
  } else {
    launch(client, 'client-b0', ['/bench/binaries/signed_cli_helper', '--exact', 'signed_b0_client_helper', '--ignored', '--nocapture'], ['CANDY_SIGNED_TEST_ROOT=/run/candy-perf', 'CANDY_CORE_TEST_BINARY=/bench/binaries/candy-core']);
  }
  wait(client, '/run/candy-perf/client-status.json');
  wait(server, '/run/candy-perf/server-status.json');
  write('ready-client.json', snapshot(client)); write('ready-server.json', snapshot(server));
  exec(client, ['ping', '-c', '3', '-W', '3', '-I', '10.251.1.10', '10.251.2.10']);
  launch(server, 'iperf-server', ['iperf3', '-s', '-p', '5201']);
  for (const [name, address, side] of [[client,'10.251.1.10','client'],[server,'10.251.2.10','server']]) {
    launch(name,`${side}-probe-server`,['python3','/bench/candy-perf-probe.py','server','--address',address,'--output',`/bench/${side}-probe-ready.json`]);
    wait(name,`${side}-probe-ready.json`);
  }
  console.log(`setup PASS; topology=${topology}, two independent netns, real signed TLS QUIC, real TUN${topology === 'ipc' ? ', managed TUNIO' : ', single-process Core B0'}`);
  process.exit(0);
}
const expectedHashes = JSON.parse(fs.readFileSync(path.join(root,'binary-hashes.json')));
const identity = JSON.parse(fs.readFileSync(path.join(root,'run-identity.json')));
if (identity.topology !== topology || identity.cpu_target_mbps !== cpuTargetMbps) throw new Error('topology or matched CPU target changed after setup');
if (identity.parameters.transactions !== transactions || identity.parameters.grant_ttl_secs !== grantTtlSecs) throw new Error('transaction mode or Grant TTL changed after setup');
if (crypto.createHash('sha256').update(fs.readFileSync(path.join(root,'candy-perf-probe.py'))).digest('hex') !== identity.probe_sha256) throw new Error('probe changed after setup');
for (const [name,expected] of Object.entries(expectedHashes)) {
  const actual = crypto.createHash('sha256').update(fs.readFileSync(path.join(root,'binaries',name))).digest('hex');
  if (actual !== expected) throw new Error(`fixed binary changed: ${name}`);
}
if (['formal-udp','smoke-udp'].includes(phase)) {
  if (!selectedUdp&&fs.readdirSync(root).some(file=>file.startsWith(`${phase}-`))) throw new Error('UDP phase already has evidence; use a new run directory');
  const formalUdp=phase==='formal-udp';
  for (const payload of [64,512,1200]) for (const direction of ['upload','download']) {
    if(selectedUdp&&(Number(selectedUdp[0])!==payload||selectedUdp[1]!==direction))continue;
    const sender=direction==='upload'?client:server;
    const target=direction==='upload'?'10.251.2.10':'10.251.1.10';
    const validate=stage=>{
      const label=`${phase}-validated-${payload}-${direction}-${stage}`;
      if(['.json','-before.json','-after.json'].some(suffix=>fs.existsSync(path.join(root,`${label}${suffix}`))))throw new Error(`refusing to overwrite prior UDP validation ${label}`);
      write(`${label}-before.json`,{client:snapshot(client),server:snapshot(server)});
      exec(sender,['python3','/bench/candy-perf-probe.py','udp-client','--address',target,'--bind',direction==='upload'?'10.251.1.10':'10.251.2.10','--size',String(payload),'--seconds','5','--output',`/bench/${label}.json`]);
      write(`${label}-after.json`,{client:snapshot(client),server:snapshot(server)});
      const integrity=JSON.parse(fs.readFileSync(path.join(root,`${label}.json`)));
      if (['lost_packets','send_errors','corrupt_packets','duplicate_packets'].some(key=>integrity[key]!==0)) throw new Error(`${label}: validated sequence/payload gate failed`);
    };
    if(!selectedUdp||selectedUdp[2]==='1')validate('before');
    for (let round=1;round<=(formalUdp?5:1);round++) {
      if(selectedUdp&&Number(selectedUdp[2])!==round)continue;
      const name=`${phase}-iperf-${payload}-${direction}-r${round}`;
      if(['.json','-before.json','-after.json'].some(suffix=>fs.existsSync(path.join(root,`${name}${suffix}`))))throw new Error(`refusing to overwrite prior UDP sample ${name}`);
      write(`${name}-before.json`,{client:snapshot(client),server:snapshot(server)});
      const output=exec(client,['iperf3','-c','10.251.2.10','-B','10.251.1.10','-p','5201','-u','--udp-counters-64bit','--get-server-output','-b','800M','-l',String(payload),'-O',formalUdp?'10':'1','-t',formalUdp?'60':'5','-J',...(direction==='download'?['-R']:[])]);
      write(`${name}.json`,output);
      write(`${name}-after.json`,{client:snapshot(client),server:snapshot(server)});
      if (JSON.parse(output).error) throw new Error(`${name}: iperf UDP error`);
      console.log(`${name} complete at=${new Date().toISOString()}`);
    }
    if(!selectedUdp||selectedUdp[2]==='5')validate('after');
  }
  process.exit(0);
}
if (phase==='soak') {
  if (fs.readdirSync(root).some(file=>file.startsWith('soak-'))) throw new Error('soak phase already has evidence; use a new run directory');
  if (grantTtlSecs<10800) throw new Error('two-hour static-Grant soak needs an explicit test TTL >=10800; this does not replace Cloud renewal gates');
  for (let round=1;round<=120;round++) {
    const direction=round%2?'upload':'download',name=`soak-p4-${direction}-r${round}`;
    write(`${name}-before.json`,{client:snapshot(client),server:snapshot(server)});
    const output=exec(client,['iperf3','-c','10.251.2.10','-B','10.251.1.10','-p','5201','-P','4','-b','187500000','-t','60','-J',...(direction==='download'?['-R']:[])]);
    write(`${name}.json`,output);
    write(`${name}-after.json`,{client:snapshot(client),server:snapshot(server)});
    if (JSON.parse(output).error) throw new Error(`${name}: iperf soak error`);
    console.log(`${name} complete at=${new Date().toISOString()}`);
  }
  process.exit(0);
}
const formal = phase.startsWith('formal-');
if (phase === 'formal-tunnel') {
  const gate = baselineGate && JSON.parse(fs.readFileSync(baselineGate));
  if (gate?.gate !== 'PASS') throw new Error('formal tunnel requires independently preserved direct >=900 Mbps gate');
  write('accepted-direct-baseline-gate.json', gate);
}
const seconds = formal ? 60 : 5;
const warm = formal ? 10 : 1;
const rounds = formal ? 5 : 1;
const direct = [];
const matchedCpu = phase.endsWith('-cpu');
for (const kind of (phase === 'formal-direct' ? ['direct'] : phase === 'formal-tunnel' || matchedCpu ? ['tunnel'] : ['direct', 'tunnel'])) {
  for (let round = 1; round <= rounds; round++) {
    if(selectedSample&&Number(selectedSample[0])!==round)continue;
    for (const parallel of [1, 4, 16]) {
      for (const direction of ['upload', 'download']) {
        if(selectedSample&&(Number(selectedSample[1])!==parallel||selectedSample[2]!==direction))continue;
        const name = `${phase}-${kind}-p${parallel}-${direction}-r${round}`;
        if (['.json','-before.json','-after.json','-latency.json'].some(suffix=>fs.existsSync(path.join(root,`${name}${suffix}`)))) throw new Error(`refusing to overwrite prior sample ${name}`);
        write(`${name}-before.json`, {client:snapshot(client),server:snapshot(server)});
        if (transactions && kind==='tunnel') launch(client,`${name}-latency`,['python3','/bench/candy-perf-probe.py','tcp-client','--address','10.251.2.10','--bind','10.251.1.10','--seconds',String(warm+seconds),'--warm',String(warm),'--output',`/bench/${name}-latency.json`]);
        const output = exec(client, ['iperf3', '-c', kind === 'direct' ? '10.200.0.2' : '10.251.2.10', '-B', kind === 'direct' ? '10.200.0.1' : '10.251.1.10', '-p', '5201', '-P', String(parallel), '-O', String(warm), '-t', String(seconds), '-J', ...(matchedCpu ? ['-b', String(cpuTargetMbps * 1e6 / parallel)] : []), ...(direction === 'download' ? ['-R'] : [])]);
        write(`${name}.json`, output);
        const result = JSON.parse(output);
        if (result.error) throw new Error(`${name} ${result.error}`);
        write(`${name}-after.json`, {client:snapshot(client),server:snapshot(server)});
        if (transactions && kind==='tunnel') wait(client,`${name}-latency.json`);
        const mbps = result.end.sum_received.bits_per_second / 1e6;
        console.log(`${name} receiver_mbps=${mbps.toFixed(2)}`);
        if (kind === 'direct') direct.push({parallel,direction,mbps});
      }
    }
    console.log(`${phase} ${kind} round=${round}/${rounds} completed_at=${new Date().toISOString()}`);
  }
  if (kind === 'direct' && formal) {
    const medians = [1,4,16].flatMap(parallel => ['upload','download'].map(direction => {
      const samples = direct.filter(x=>x.parallel===parallel&&x.direction===direction).map(x=>x.mbps).sort((a,b)=>a-b);
      return {parallel,direction,median_mbps:samples[2]};
    }));
    write('direct-baseline-gate.json',{medians,gate:medians.every(x=>x.median_mbps>=900)?'PASS':'BLOCKED'});
    if (medians.some(x=>x.median_mbps<900)) throw new Error('direct baseline below 900 Mbps; absolute tunnel 800 Mbps gate BLOCKED');
  }
}
console.log(`${phase} complete; final result requires report review`);
