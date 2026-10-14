import fs from 'node:fs';
import path from 'node:path';

const [directory, output] = process.argv.slice(2);
if (!directory || !output) throw new Error('usage: node summarize-renewing-run.mjs <run> <new output.json>');
if (fs.existsSync(output)) throw new Error('new output required');
const root = path.resolve(directory), read = name => JSON.parse(fs.readFileSync(path.join(root, name)));
const run = read('renewal-run.json');
const completion = fs.existsSync(path.join(root, 'completion.json')) ? read('completion.json') : undefined;
const cpu = text => Object.fromEntries(text.trim().split('\n').map(row => row.split(/\s+/)).map(([key, value]) => [key, Number(value)]));
const core = (snapshot, side) => side === 'client' ? snapshot.active.core : snapshot.core;
const difference = (before, after) => {
  const values = {};
  for (const key of new Set([...Object.keys(before), ...Object.keys(after)])) {
    const a = before[key] ?? 0, b = after[key] ?? 0;
    if (!Number.isFinite(a) || !Number.isFinite(b) || b < a) throw new Error(`counter missing/invalid/regressed: ${key}`);
    values[key] = b - a;
  }
  return values;
};
const samples = [];
for (let round = 1; round <= run.rounds; round++) {
  const direction = round % 2 ? 'upload' : 'download', label = `sample-p4-${direction}-r${round}`;
  if (!fs.existsSync(path.join(root, `${label}-after.json`))) break;
  const data = read(`${label}.json`), before = read(`${label}-before.json`), after = read(`${label}-after.json`);
  if (data.error || !Number.isFinite(data.end?.sum_received?.bits_per_second)) throw new Error(`invalid iperf sample ${label}`);
  const seconds = data.end.sum_received.seconds;
  const sides = {};
  for (const side of ['client', 'server']) {
    const a = core(before[side], side), b = core(after[side], side);
    if (!a || !b || !a.counters || !b.counters) throw new Error(`missing actual Core status ${side}`);
    const same = a.pid === b.pid;
    const reasons = same ? difference(a.counters.drop_reasons, b.counters.drop_reasons) : null;
    const counters = same ? difference(Object.fromEntries(['drops', 'stream_read_errors', 'stream_write_errors', 'tun_output_write_blocked_events'].map(key => [key, a.counters[key]])), Object.fromEntries(['drops', 'stream_read_errors', 'stream_write_errors', 'tun_output_write_blocked_events'].map(key => [key, b.counters[key]]))) : null;
    const cpuDelta = difference(cpu(before[side].cpu), cpu(after[side].cpu));
    const qdiscBefore = JSON.parse(before[side].qdisc), qdiscAfter = JSON.parse(after[side].qdisc);
    const qdisc = qdiscAfter.map(row => {
      const previous = qdiscBefore.find(item => item.dev === row.dev && item.kind === row.kind && item.handle === row.handle);
      if (!previous) throw new Error('qdisc identity changed');
      return {dev: row.dev, kind: row.kind, counters: difference(Object.fromEntries(['drops', 'overlimits', 'requeues'].map(key => [key, previous[key]])), Object.fromEntries(['drops', 'overlimits', 'requeues'].map(key => [key, row[key]]))), backlog: row.backlog, qlen: row.qlen};
    });
    sides[side] = {before_pid: a.pid, after_pid: b.pid, process_generation_changed: !same, phase: b.dataplane_phase, lifecycle: b.lifecycle, failed_prefixes: b.failed_prefixes, counter_delta: counters, drop_reason_delta: reasons, output_queue_depth: b.counters.tun_output_queue_depth, output_queue_high_watermark: b.counters.tun_output_queue_high_watermark, cgroup_cpu_delta: cpuDelta, average_cgroup_cpu_cores: cpuDelta.usage_usec / 1e6 / seconds, memory_bytes: Number(after[side].memory), memory_peak_bytes: Number(after[side].peak), qdisc};
  }
  samples.push({round, direction, receiver_mbps: data.end.sum_received.bits_per_second / 1e6, measured_seconds: seconds, ...sides});
}
const reasonTotals = Object.fromEntries(['client', 'server'].map(side => {
  const totals = {};
  for (const sample of samples) for (const [key, value] of Object.entries(sample[side].drop_reason_delta || {})) totals[key] = (totals[key] || 0) + value;
  return [side, totals];
}));
const throughput = samples.length === run.rounds && samples.every(row => row.receiver_mbps >= 712.5);
const integrity = samples.length === run.rounds && samples.every(row => ['client', 'server'].every(side => {
  const state = row[side];
  return !state.process_generation_changed && state.lifecycle === 'active' && state.phase === 'data_plane_active' && state.failed_prefixes?.length === 0 && state.counter_delta?.drops === 0 && state.counter_delta?.stream_read_errors === 0 && state.counter_delta?.stream_write_errors === 0 && state.memory_peak_bytes <= 2147483648;
}));
const result = {schema_version: 1, scope: 'aarch64 Docker diagnostic; no physical-link or full stability acceptance', mode: run.mode, complete: Boolean(completion) && samples.length === run.rounds, throughput_gate: throughput ? 'PASS' : 'FAIL', steady_sample_integrity: integrity ? 'PASS' : 'FAIL', full_gate: 'NOT_EVALUATED', note: 'Changed process generations require transaction and retired-worker counter review; no reset is treated as zero. Queue subtype counters may overlap aggregate reasons in historical builds.', reason_totals: reasonTotals, samples};
fs.writeFileSync(output, JSON.stringify(result, null, 2), {mode: 0o600});
console.log(JSON.stringify({samples: samples.length, throughput: result.throughput_gate, integrity: result.steady_sample_integrity, reasons: reasonTotals}));
