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
const renewalRecords = fs.readdirSync(root).filter(name => /^renewal-\d+\.json$/.test(name)).sort((a, b) => Number(a.match(/\d+/)[0]) - Number(b.match(/\d+/)[0])).map(name => read(name));
const integrityCounterKeys = ['drops', 'stream_read_errors', 'stream_write_errors', 'tun_output_write_blocked_events'];
const outputTimingCounters = ['tun_output_queued_write_attempts', 'tun_output_queue_wait_micros', 'tun_output_send_elapsed_micros'];
const coreCounters = value => Object.fromEntries(integrityCounterKeys.map(key => [key, value?.counters?.[key]]));
const reasonDifference = (before, after) => {
  const result = {};
  for (const key of new Set([...Object.keys(before || {}), ...Object.keys(after || {})])) {
    const a = before?.[key], b = after?.[key];
    if (!Number.isFinite(a) || !Number.isFinite(b) || b < a) throw new Error(`drop reason missing/invalid/regressed: ${key}`);
    result[key] = b - a;
  }
  return result;
};
const sameTunIdentity = (a, b) => a?.io?.pid === b?.io?.pid && a?.io?.process_start_ticks === b?.io?.process_start_ticks && a?.link?.[0]?.ifindex === b?.link?.[0]?.ifindex;
const authorizedClientTransition = (start, end) => {
  const first = start.active, last = end.active;
  if (!first?.record || !last?.record || !sameTunIdentity(first, last)) return null;
  let pid = first.core.pid, epoch = first.record.worker_epoch, authDeadline = first.record.auth_deadline_unix;
  let priorCounters = coreCounters(first.core);
  let priorReasons = first.core.counters?.drop_reasons;
  let priorTiming = Object.fromEntries(outputTimingCounters.map(key => [key, first.core.counters?.[key]]));
  const transitions = [], total = Object.fromEntries(integrityCounterKeys.map(key => [key, 0]));
  const timingTotal = Object.fromEntries(outputTimingCounters.map(key => [key, 0]));
  total.drop_reasons = {};
  while (pid !== last.core.pid || epoch !== last.record.worker_epoch) {
    const evidence = renewalRecords.find(row => row.before?.record?.pid === pid && row.before?.record?.worker_epoch === epoch && row.after?.record?.worker_epoch > epoch);
    if (!evidence || evidence.source !== 'isolated signed fixture; real Agent/IO/netd authority transaction; no Cloud mTLS' || !evidence.compiled?.authorization_snapshot_sha256 || !evidence.before?.core || !evidence.after?.core) return null;
    if (evidence.before.core.pid !== pid || evidence.after.core.pid !== evidence.after.record.pid || evidence.after.core.lifecycle !== 'active' || evidence.after.core.dataplane_phase !== 'data_plane_active') return null;
    if (evidence.before.record.auth_deadline_unix < authDeadline || evidence.after.record.auth_deadline_unix <= evidence.before.record.auth_deadline_unix || evidence.after.core.worker_authority_sha256 !== evidence.compiled.authorization_snapshot_sha256) return null;
    if (!sameTunIdentity(evidence.before, evidence.after) || !sameTunIdentity(first, evidence.after)) return null;
    try {
      const delta = difference(priorCounters, coreCounters(evidence.before.core));
      for (const key of integrityCounterKeys) total[key] += delta[key];
      for (const [key, value] of Object.entries(reasonDifference(priorReasons, evidence.before.core.counters?.drop_reasons))) total.drop_reasons[key] = (total.drop_reasons[key] || 0) + value;
      const timingDelta = difference(priorTiming, Object.fromEntries(outputTimingCounters.map(key => [key, evidence.before.core.counters?.[key]])));
      for (const key of outputTimingCounters) timingTotal[key] += timingDelta[key];
    } catch { return null; }
    transitions.push({from_pid: pid, to_pid: evidence.after.core.pid, from_epoch: epoch, to_epoch: evidence.after.record.worker_epoch, authorization_snapshot_sha256: evidence.compiled.authorization_snapshot_sha256});
    pid = evidence.after.core.pid;
    epoch = evidence.after.record.worker_epoch;
    authDeadline = evidence.after.record.auth_deadline_unix;
    priorCounters = coreCounters(evidence.after.core);
    priorReasons = evidence.after.core.counters?.drop_reasons;
    priorTiming = Object.fromEntries(outputTimingCounters.map(key => [key, evidence.after.core.counters?.[key]]));
    if (transitions.length > renewalRecords.length) return null;
  }
  if (!transitions.length || last.record.auth_deadline_unix < authDeadline) return null;
  try {
    const delta = difference(priorCounters, coreCounters(last.core));
    for (const key of integrityCounterKeys) total[key] += delta[key];
    for (const [key, value] of Object.entries(reasonDifference(priorReasons, last.core.counters?.drop_reasons))) total.drop_reasons[key] = (total.drop_reasons[key] || 0) + value;
    const timingDelta = difference(priorTiming, Object.fromEntries(outputTimingCounters.map(key => [key, last.core.counters?.[key]])));
    for (const key of outputTimingCounters) timingTotal[key] += timingDelta[key];
  } catch { return null; }
  return {transitions, counter_delta: total, output_timing_delta: timingTotal};
};
const samples = [];
const outputFailureCounters = ['queue_slot_exhausted', 'queue_byte_exhausted', 'queue_channel_full', 'backpressure_drops', 'deadline_drops', 'stale_drops'];
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
    const renewal = !same && side === 'client' ? authorizedClientTransition(before.client, after.client) : null;
    const reasons = same ? difference(a.counters.drop_reasons, b.counters.drop_reasons) : renewal?.counter_delta.drop_reasons ?? null;
    const counters = same ? difference(Object.fromEntries(integrityCounterKeys.map(key => [key, a.counters[key]])), Object.fromEntries(integrityCounterKeys.map(key => [key, b.counters[key]]))) : renewal?.counter_delta ?? null;
    const timings = same && outputTimingCounters.every(key => Number.isFinite(a.counters[key]) && Number.isFinite(b.counters[key])) ? difference(Object.fromEntries(outputTimingCounters.map(key => [key, a.counters[key]])), Object.fromEntries(outputTimingCounters.map(key => [key, b.counters[key]]))) : renewal?.output_timing_delta ?? null;
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
    sides[side] = {before_pid: a.pid, after_pid: b.pid, process_generation_changed: !same, authorized_renewal_transitions: renewal?.transitions ?? [], phase: b.dataplane_phase, lifecycle: b.lifecycle, failed_prefixes: b.failed_prefixes, counter_delta: counters, output_timing_delta: timings, output_timing_max_micros: {queue_wait: b.counters.tun_output_queue_wait_max_micros ?? null, send_elapsed: b.counters.tun_output_send_elapsed_max_micros ?? null}, drop_reason_delta: reasons, output_queue_depth: b.counters.tun_output_queue_depth, output_queue_high_watermark: b.counters.tun_output_queue_high_watermark, tunio_outputs: outputs, cgroup_cpu_delta: cpuDelta, average_cgroup_cpu_cores: cpuDelta.usage_usec / 1e6 / seconds, memory_bytes: Number(after[side].memory), memory_peak_bytes: Number(after[side].peak), qdisc};
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
  const generationEvidence = !state.process_generation_changed || (side === 'client' && state.authorized_renewal_transitions.length > 0);
  const reasonIntegrity = state.drop_reason_delta !== null && Object.values(state.drop_reason_delta || {}).every(value => value === 0);
  const qdiscIntegrity = state.qdisc.every(device => device.counters.drops === 0);
  return outputIntegrity && timingEvidence && generationEvidence && reasonIntegrity && qdiscIntegrity && state.counter_delta !== null && state.lifecycle === 'active' && state.phase === 'data_plane_active' && state.failed_prefixes?.length === 0 && state.counter_delta?.drops === 0 && state.counter_delta?.stream_read_errors === 0 && state.counter_delta?.stream_write_errors === 0 && state.memory_peak_bytes <= 2147483648;
}));
const requiredSeconds = run.target_duration_seconds ?? run.rounds * run.seconds;
const durationGate = Boolean(completion?.sufficient_duration) && Number(completion?.measured_duration_seconds) >= requiredSeconds - 1;
const renewalRequired = run.mode === 'renewal-20m' || run.mode === 'soak';
const renewalGate = !renewalRequired || (renewalRecords.length >= Math.floor(requiredSeconds / run.renewal_interval_seconds) - 1 && renewalRecords.every(row => row.source === 'isolated signed fixture; real Agent/IO/netd authority transaction; no Cloud mTLS' && row.compiled?.authorization_snapshot_sha256 && row.after?.core?.worker_authority_sha256 === row.compiled.authorization_snapshot_sha256));
const complete = Boolean(completion) && samples.length === run.rounds && durationGate && renewalGate;
const result = {schema_version: 2, scope: 'isolated aarch64 Docker stability; not physical-link or full 2-hour acceptance', mode: run.mode, complete, duration_gate: durationGate ? 'PASS' : 'FAIL', signed_renewal_gate: renewalRequired ? (renewalGate ? 'PASS' : 'FAIL') : 'NOT_RUN', worker_replacement_gate: 'NOT_RUN', throughput_gate: throughput ? 'PASS' : 'FAIL', steady_sample_integrity: integrity ? 'PASS' : 'FAIL', full_gate: 'NOT_EVALUATED', note: 'A stability run without a renewal interval does not exercise signed renewal or worker replacement. Worker generation changes require linked signed renewal evidence, monotonic authorization and worker epochs, stable TUN/TUNIO identity, and counter continuity. No physical-link acceptance is implied.', reason_totals: reasonTotals, tunio_failure_totals: tunioFailureTotals, samples};
fs.writeFileSync(output, JSON.stringify(result, null, 2), {mode: 0o600});
console.log(JSON.stringify({samples: samples.length, throughput: result.throughput_gate, integrity: result.steady_sample_integrity, reasons: reasonTotals, tunio_failures: tunioFailureTotals}));
