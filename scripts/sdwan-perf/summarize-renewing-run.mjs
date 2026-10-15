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
const outputFailureCounters = ['queue_slot_exhausted', 'queue_byte_exhausted', 'queue_channel_full', 'backpressure_drops', 'deadline_drops', 'stale_drops'];
const outputTimingCounters = ['tun_output_queued_write_attempts', 'tun_output_queue_wait_micros', 'tun_output_send_elapsed_micros'];
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
    const timings = same && outputTimingCounters.every(key => Number.isFinite(a.counters[key]) && Number.isFinite(b.counters[key])) ? difference(Object.fromEntries(outputTimingCounters.map(key => [key, a.counters[key]])), Object.fromEntries(outputTimingCounters.map(key => [key, b.counters[key]]))) : null;
    const cpuDelta = difference(cpu(before[side].cpu), cpu(after[side].cpu));
    let outputs = null;
    if (side === 'client') {
      const first = before.client.active.outputs, last = after.client.active.outputs;
      if (first && last) {
        if (first.pid !== last.pid || first.process_start_ticks !== last.process_start_ticks || first.pid !== before.client.active.io.pid || last.pid !== after.client.active.io.pid) throw new Error('TUNIO diagnostic process identity changed');
        const deltas = {};
        for (const direction of ['to_worker', 'to_tun']) {
          const a = {...first.bridge_outputs[direction]}, b = {...last.bridge_outputs[direction]};
          if (outputFailureCounters.some(key => !Number.isFinite(a[key]) || !Number.isFinite(b[key]))) throw new Error(`missing TUNIO output failure counter: ${direction}`);
          for (const key of ['queue_depth','queue_high_watermark','queue_wait_max_micros','send_elapsed_max_micros']) { delete a[key]; delete b[key]; }
          deltas[direction] = difference(a, b);
          if (outputFailureCounters.some(key => !Number.isFinite(deltas[direction][key]))) throw new Error(`missing TUNIO output failure counter: ${direction}`);
        }
        outputs = {delta: deltas, current: last.bridge_outputs};
      }
      if (run.require_output_diagnostics && !outputs) throw new Error('required TUNIO direction diagnostics absent');
    }
    const qdiscBefore = JSON.parse(before[side].qdisc), qdiscAfter = JSON.parse(after[side].qdisc);
    const qdisc = qdiscAfter.map(row => {
      const previous = qdiscBefore.find(item => item.dev === row.dev && item.kind === row.kind && item.handle === row.handle);
      if (!previous) throw new Error('qdisc identity changed');
      return {dev: row.dev, kind: row.kind, counters: difference(Object.fromEntries(['drops', 'overlimits', 'requeues'].map(key => [key, previous[key]])), Object.fromEntries(['drops', 'overlimits', 'requeues'].map(key => [key, row[key]]))), backlog: row.backlog, qlen: row.qlen};
    });
    sides[side] = {before_pid: a.pid, after_pid: b.pid, process_generation_changed: !same, phase: b.dataplane_phase, lifecycle: b.lifecycle, failed_prefixes: b.failed_prefixes, counter_delta: counters, output_timing_delta: timings, output_timing_max_micros: {queue_wait: b.counters.tun_output_queue_wait_max_micros ?? null, send_elapsed: b.counters.tun_output_send_elapsed_max_micros ?? null}, drop_reason_delta: reasons, output_queue_depth: b.counters.tun_output_queue_depth, output_queue_high_watermark: b.counters.tun_output_queue_high_watermark, tunio_outputs: outputs, cgroup_cpu_delta: cpuDelta, average_cgroup_cpu_cores: cpuDelta.usage_usec / 1e6 / seconds, memory_bytes: Number(after[side].memory), memory_peak_bytes: Number(after[side].peak), qdisc};
  }
  samples.push({round, direction, receiver_mbps: data.end.sum_received.bits_per_second / 1e6, measured_seconds: seconds, ...sides});
}
const reasonTotals = Object.fromEntries(['client', 'server'].map(side => {
  const totals = {};
  for (const sample of samples) for (const [key, value] of Object.entries(sample[side].drop_reason_delta || {})) totals[key] = (totals[key] || 0) + value;
  return [side, totals];
}));
const tunioFailureTotals = Object.fromEntries(['to_worker', 'to_tun'].map(direction => [direction,
  Object.fromEntries(outputFailureCounters.map(key => [key,
    samples.reduce((total, sample) => total + (sample.client.tunio_outputs?.delta[direction][key] ?? 0), 0),
  ])),
]));
const throughput = samples.length === run.rounds && samples.every(row => row.receiver_mbps >= 712.5);
const integrity = samples.length === run.rounds && samples.every(row => ['client', 'server'].every(side => {
  const state = row[side];
  const outputIntegrity = side !== 'client' || (state.tunio_outputs ? ['to_worker', 'to_tun'].every(direction => outputFailureCounters.every(key => state.tunio_outputs.delta[direction][key] === 0)) : !run.require_output_diagnostics);
  const timingEvidence = !run.require_output_diagnostics || (state.output_timing_delta && state.output_timing_max_micros.queue_wait !== null && state.output_timing_max_micros.send_elapsed !== null);
  return outputIntegrity && timingEvidence && !state.process_generation_changed && state.lifecycle === 'active' && state.phase === 'data_plane_active' && state.failed_prefixes?.length === 0 && state.counter_delta?.drops === 0 && state.counter_delta?.stream_read_errors === 0 && state.counter_delta?.stream_write_errors === 0 && state.memory_peak_bytes <= 2147483648;
}));
const result = {schema_version: 1, scope: 'aarch64 Docker diagnostic; no physical-link or full stability acceptance', mode: run.mode, complete: Boolean(completion) && samples.length === run.rounds, throughput_gate: throughput ? 'PASS' : 'FAIL', steady_sample_integrity: integrity ? 'PASS' : 'FAIL', full_gate: 'NOT_EVALUATED', note: 'Changed process generations require transaction and retired-worker counter review; no reset is treated as zero. Queue subtype counters may overlap aggregate reasons in historical builds.', reason_totals: reasonTotals, tunio_failure_totals: tunioFailureTotals, samples};
fs.writeFileSync(output, JSON.stringify(result, null, 2), {mode: 0o600});
console.log(JSON.stringify({samples: samples.length, throughput: result.throughput_gate, integrity: result.steady_sample_integrity, reasons: reasonTotals, tunio_failures: tunioFailureTotals}));
