import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync, execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {observeHost} from './host-observer.mjs';

const [buildDirectory, destination, mode = 'renewal-smoke'] = process.argv.slice(2);
if (!buildDirectory || !destination || !['renewal-smoke', 'comparison', 'diagnostic', 'stability-20m', 'renewal-20m', 'soak'].includes(mode)) {
  throw new Error('usage: node run-renewing-soak.mjs <frozen build> <new evidence directory> [renewal-smoke|comparison|diagnostic|stability-20m|renewal-20m|soak]');
}
const root = path.resolve(destination), build = path.resolve(buildDirectory);
const workspace = path.resolve(new URL('../../..', import.meta.url).pathname);
const runner = path.resolve(new URL('./run-two-docker-perf.mjs', import.meta.url).pathname);
const smoke = mode === 'renewal-smoke';
const continuousRenewal = mode === 'renewal-20m';
const stability = mode === 'stability-20m';
const ttl = smoke ? 180 : continuousRenewal ? 90 : 1800;
const renewalInterval = stability ? null : smoke ? 15 : continuousRenewal ? 45 : 900;
const rounds = smoke || mode === 'comparison' ? 4 : mode === 'diagnostic' ? 12 : continuousRenewal || stability ? 20 : 120;
const seconds = smoke ? 20 : 60;
const policyTtl = 10800;
const requireOutputs = process.env.CANDY_PERF_REQUIRE_OUTPUT_DIAGNOSTICS === '1' || continuousRenewal || stability;
if (fs.existsSync(root)) throw new Error('new evidence directory required');
fs.mkdirSync(root, {recursive: true, mode: 0o700});
const write = (name, value) => fs.writeFileSync(path.join(root, name), JSON.stringify(value, null, 2), {mode: 0o600});
const event = (name, value = {}) => fs.appendFileSync(path.join(root, 'renewal-events.jsonl'), `${JSON.stringify({at: new Date().toISOString(), event: name, ...value})}\n`, {mode: 0o600});
const read = name => JSON.parse(fs.readFileSync(path.join(root, name)));
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const env = {...process.env, CANDY_PERF_TOPOLOGY: 'ipc', CANDY_PERF_RUNTIME_AGENT: '1', CANDY_PERF_TRANSACTIONS: '0', CANDY_PERF_GRANT_TTL_SECS: String(ttl), CANDY_SIGNED_FIXTURE_POLICY_TTL_SECS: String(policyTtl)};
const phase = name => {
  const result = spawnSync(process.execPath, [runner, name, root], {cwd: workspace, env, stdio: 'inherit'});
  if (result.status !== 0) throw new Error(`${name} failed (${result.status})`);
};
const execAsync = promisify(execFile);
const docker = async (...args) => (await execAsync('docker', args, {encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 120000})).stdout;
const inClient = async (...args) => docker('exec', identity.client, ...args);
const readPrivate = async filename => JSON.parse(await inClient('cat', filename));
let identity, stop = false, renewalError, renewalCount = 0, renewalTask, stopHostObserver;
const status = async () => {
  for (let attempt = 0; attempt < 20; attempt++) {
    try {
      const record = await readPrivate('/run/candy-perf/worker-process.json');
      const core = await readPrivate(record.status_path);
      const current = await readPrivate('/run/candy-perf/worker-process.json');
      if (JSON.stringify(record) !== JSON.stringify(current)) { await delay(100); continue; }
      if (core.pid !== record.pid) throw new Error('worker status PID differs from stable process record');
      const io = await readPrivate('/run/candy-perf/io-process.json');
      let outputs;
      try {
        outputs = await readPrivate('/run/candy-perf/io-status.outputs.json');
        const monotonic = Number(await inClient('python3', '-c', 'import time; print(time.clock_gettime(time.CLOCK_MONOTONIC) * 1000)'));
        if (!Number.isFinite(monotonic) || outputs.schema_version !== 1 || outputs.pid !== io.pid || outputs.process_start_ticks !== io.process_start_ticks || !Number.isFinite(outputs.report_monotonic_millis) || monotonic - outputs.report_monotonic_millis > 5000 || outputs.report_monotonic_millis > monotonic + 50) throw new Error('TUNIO output sidecar identity/clock differs from running process');
      } catch (error) {
        if (requireOutputs || !String(error.stderr || '').includes('No such file or directory')) throw error;
      }
      return {record, core, io, io_status: await readPrivate('/run/candy-perf/io-status.json'), outputs, link: JSON.parse(await inClient('ip', '-j', 'link', 'show', 'candy0'))};
    } catch (error) {
      const transientPublication = String(error.stderr || '').includes('No such file or directory') || error instanceof SyntaxError;
      if (!transientPublication || attempt === 19) throw error;
      await delay(100);
    }
  }
  throw new Error('worker record did not stabilize during publication');
};
const sameInfrastructure = (before, after) => before.io.pid === after.io.pid && before.io.process_start_ticks === after.io.process_start_ticks && before.link[0].ifindex === after.link[0].ifindex;
const renew = async () => {
  event('renewal_started');
  const before = await status();
  event('renewal_before_status', {pid: before.record.pid, worker_epoch: before.record.worker_epoch, auth_deadline_unix: before.record.auth_deadline_unix});
  const stdout = await inClient('env', 'CANDY_SIGNED_FIXTURE_RENEW_ROOT=/bench/fixture', `CANDY_SIGNED_FIXTURE_GRANT_TTL_SECS=${ttl}`, '/bench/binaries/sdwan_signed_cli_fixture');
  event('renewal_fixture_signed');
  const compiled = JSON.parse(await inClient('/bench/binaries/candy-core', 'client', 'sdwan', 'compile-control', '--config', '/bench/fixture/client.toml'));
  event('renewal_control_compiled', {authorization_expires_at_unix: compiled.authorization_expires_at_unix});
  const plan = read('plan.json');
  plan.auth_deadline_unix = compiled.authorization_expires_at_unix;
  const temporary = path.join(root, '.plan-renewal.json');
  fs.writeFileSync(temporary, JSON.stringify(plan), {mode: 0o600});
  fs.renameSync(temporary, path.join(root, 'plan.json'));
  const limit = Date.now() + 25000;
  while (Date.now() < limit) {
    const after = await status();
    if (after.record.pid !== before.record.pid && after.core.worker_authority_sha256 === compiled.authorization_snapshot_sha256 && after.io_status.auth_deadline_unix === compiled.authorization_expires_at_unix && after.core.dataplane_phase === 'data_plane_active') {
      if (!sameInfrastructure(before, after) || after.record.worker_epoch <= before.record.worker_epoch || after.record.auth_deadline_unix <= before.record.auth_deadline_unix) throw new Error('renewal changed infrastructure or failed monotonic authorization checks');
      write(`renewal-${++renewalCount}.json`, {at: new Date().toISOString(), stdout, compiled, before, after, source: 'isolated signed fixture; real Agent/IO/netd authority transaction; no Cloud mTLS'});
      event('renewal_committed', {pid: after.record.pid, worker_epoch: after.record.worker_epoch, auth_deadline_unix: after.record.auth_deadline_unix});
      console.log(`renewal ${renewalCount} PASS epoch=${after.record.worker_epoch}`);
      return;
    }
    await delay(250);
  }
  throw new Error('signed renewal commit/readiness timeout');
};
const snapshot = async name => {
  const raw = await docker('exec', name, 'sh', '-c', `jq -n --arg cpu "$(cat /sys/fs/cgroup/cpu.stat)" --arg vm_cpu "$(sed -n '1p' /proc/stat)" --arg vm_softirq "$(cat /proc/softirqs)" --arg memory "$(cat /sys/fs/cgroup/memory.current)" --arg peak "$(cat /sys/fs/cgroup/memory.peak)" --arg qdisc "$(tc -s -j qdisc show)" --arg links "$(ip -s -j link show)" --arg snmp "$(cat /proc/net/snmp)" '{cpu:$cpu,vm_cpu:$vm_cpu,vm_softirq:$vm_softirq,memory:$memory,peak:$peak,qdisc:$qdisc,links:$links,snmp:$snmp}'`);
  const value = JSON.parse(raw);
  if (name === identity.client) value.active = await status();
  else value.core = JSON.parse(await docker('exec', name, 'cat', '/run/candy-perf/server-status.json'));
  value.processes = await docker('exec', name, 'sh', '-c', 'for p in /proc/[0-9]*; do exe=$(readlink "$p/exe" 2>/dev/null) || continue; case "$exe" in /bench/binaries/*) ;; *) continue ;; esac; [ "$(cat "$p/cgroup" 2>/dev/null)" = "$(cat /proc/self/cgroup)" ] || continue; printf "pid=%s exe=%s fd=%s stat=%s status=%s\\n" "${p##*/}" "$exe" "$(ls -U "$p/fd" 2>/dev/null | wc -l)" "$(cat "$p/stat" 2>/dev/null)" "$(sed -n "/^VmRSS:/p; /^VmHWM:/p; /^Threads:/p" "$p/status" 2>/dev/null | tr "\\n" ",")"; done');
  return value;
};
try {
  fs.cpSync(path.join(build, 'binaries'), path.join(root, 'binaries'), {recursive: true});
  for (const name of ['binary-hashes.json', 'source-freeze.json', 'build-provenance.json']) fs.copyFileSync(path.join(build, name), path.join(root, name));
  write('renewal-run.json', {mode, require_output_diagnostics: requireOutputs || continuousRenewal, executor_diagnostics: process.env.CANDY_PERF_EXECUTOR_DIAGNOSTICS === '1', ttl_seconds: ttl, policy_ttl_seconds: policyTtl, renewal_interval_seconds: renewalInterval, rounds, seconds, target_duration_seconds: continuousRenewal ? 1200 : mode === 'soak' ? 7200 : rounds * seconds, runner_sha256: crypto.createHash('sha256').update(fs.readFileSync(new URL(import.meta.url))).digest('hex'), scope: 'isolated aarch64 Docker signed-renewal stability; not physical-link acceptance'});
  phase('setup');
  identity = read('run-identity.json');
  stopHostObserver = observeHost(path.join(root, 'scheduler-host.jsonl'));
  write('host-observer.json', {sha256: crypto.createHash('sha256').update(fs.readFileSync(new URL('./host-observer.mjs', import.meta.url))).digest('hex'), interval_seconds: 1, event_loop_resolution_millis: 10, scope: 'host aggregate CPU and event-loop delay; no process arguments or credentials'});
  const initial = await status();
  if (initial.record.auth_deadline_unix - Math.floor(Date.now() / 1000) < ttl - 15) throw new Error('initial verified authorization cannot support renewal interval');
  renewalTask = (async () => {
    let next = renewalInterval === null ? Infinity : Date.now() + renewalInterval * 1000;
    while (!stop && renewalInterval !== null) {
      await delay(250);
      if (Date.now() >= next && !stop) {
        try {
          await renew();
        } catch (error) {
          event('renewal_failed', {error: String(error)});
          throw error;
        }
        next = Date.now() + renewalInterval * 1000;
      }
    }
  })().catch(error => { renewalError = error; });
  const samples = [];
  for (let round = 1; round <= rounds; round++) {
    if (renewalError) throw renewalError;
    const direction = round % 2 ? 'upload' : 'download', label = `sample-p4-${direction}-r${round}`;
    write(`${label}-before.json`, {client: await snapshot(identity.client), server: await snapshot(identity.server)});
    let data;
    try {
      data = JSON.parse(await inClient('iperf3', '-c', '10.251.2.10', '-B', '10.251.1.10', '-p', '5201', '-P', '4', '-b', '187500000', '-t', String(seconds), '-J', ...(direction === 'download' ? ['-R'] : [])));
    } catch (error) {
      event('iperf_result_invalid', {round, direction, error: String(error), stderr: error.stderr});
      throw error;
    }
    write(`${label}.json`, data);
    write(`${label}-after.json`, {client: await snapshot(identity.client), server: await snapshot(identity.server)});
    if (data.error) throw new Error(data.error);
    samples.push({round, direction, measured_seconds: data.end.sum_received.seconds, receiver_mbps: data.end.sum_received.bits_per_second / 1e6});
    write('progress.json', {renewals: renewalCount, samples});
    console.log(`${label} receiver_mbps=${samples.at(-1).receiver_mbps.toFixed(2)}`);
  }
  stop = true;
  await renewalTask;
  if (renewalError) throw renewalError;
  const measuredDuration = samples.reduce((sum, row) => sum + row.measured_seconds, 0);
  const sufficient = measuredDuration >= (continuousRenewal || stability ? 1199 : mode === 'soak' ? 7199 : 0);
  write('completion.json', {mode, renewals: renewalCount, measured_duration_seconds: measuredDuration, sufficient_duration: sufficient, samples, throughput_gate: samples.every(row => row.receiver_mbps >= 712.5) ? 'PASS' : 'FAIL', gate: 'REVIEW_REQUIRED', note: 'requires signed renewal, counter/resource integrity review; throughput alone cannot pass stability'});
} catch (error) {
  event('run_failed', {error: String(error)});
  write('failure.json', {error: String(error), at: new Date().toISOString(), renewals: renewalCount, stdout: error.stdout, stderr: error.stderr});
  if (identity) {
    try {
      const diagnostic = await inClient('sh', '-c', 'for f in /run/candy-perf/*.json; do [ -f "$f" ] || continue; printf "%s\\n" "$f"; jq -c "walk(if type == \"object\" then del(.readiness_token) else . end)" "$f"; done');
      write('failure-status.json', {diagnostic});
    } catch (inspectionError) {
      write('failure-inspection.json', {error: String(inspectionError)});
    }
  }
  process.exitCode = 1;
} finally {
  stop = true;
  if (renewalTask) await renewalTask;
  if (stopHostObserver) write('host-observer-result.json', stopHostObserver());
  phase('cleanup');
}
