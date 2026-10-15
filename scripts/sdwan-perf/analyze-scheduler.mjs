import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

// All values are offline observations; schedstat wait is cumulative runnable wait,
// not the longest individual scheduling delay.
const counters = raw => Object.fromEntries(String(raw || '').split('\n').filter(Boolean)
  .map(line => line.trim().split(/\s+/)).map(([key, value]) => [key, Number(value)]));
const delta = (before, after) => Object.fromEntries(Object.entries(after)
  .filter(([key, value]) => Number.isFinite(value) && Number.isFinite(before[key]))
  .map(([key, value]) => [key, value - before[key]]));
const percentile = (values, fraction) => values.length ? [...values].sort((a, b) => a - b)[Math.ceil(values.length * fraction) - 1] : null;
function taskMap(row) {
  const tasks = new Map();
  for (const process of row.processes || []) {
    // /proc/<pid>/stat comm may include spaces or parentheses.
    const fields = String(process.stat || '').slice(String(process.stat || '').lastIndexOf(')') + 2).split(/\s+/);
    const generation = fields[19] || 'unknown'; // starttime, stat field 22
    for (const task of process.tasks || []) {
      const [runtime_ns, runqueue_wait_ns, timeslices] = task.schedstat.split(/\s+/).map(Number);
      tasks.set(`${process.pid}/${generation}/${task.tid}`, {pid: process.pid, generation, tid: task.tid,
        executable: path.basename(process.executable), runtime_ns, runqueue_wait_ns, timeslices});
    }
  }
  return tasks;
}
function interval(before, after) {
  const elapsed_s = (after.monotonic_ns - before.monotonic_ns) / 1e9;
  if (!(elapsed_s > 0)) throw new Error('scheduler monotonic clock did not advance');
  const previous = taskMap(before);
  const threads = [];
  for (const [key, task] of taskMap(after)) {
    const old = previous.get(key);
    if (!old) continue;
    const change = delta(old, task);
    if (['runtime_ns', 'runqueue_wait_ns', 'timeslices'].some(field => change[field] < 0)) continue;
    threads.push({pid: task.pid, generation: task.generation, tid: task.tid, executable: task.executable,
      runtime_ms: change.runtime_ns / 1e6, runqueue_wait_ms: change.runqueue_wait_ns / 1e6,
      timeslices: change.timeslices});
  }
  const vm = row => String(Array.isArray(row.vm_cpu) ? row.vm_cpu[0] : row.vm_cpu).trim().split(/\s+/).slice(1).map(Number);
  const vm_before = vm(before), vm_after = vm(after);
  const ticks = vm_after.slice(0, 8).map((value, index) => value - vm_before[index]);
  const total = ticks.reduce((sum, value) => sum + value, 0);
  const pressure = row => Object.fromEntries(String(row.cpu_pressure || '').split('\n').filter(Boolean)
    .map(line => [line.split(' ')[0], Number(line.match(/total=(\d+)/)?.[1])]));
  return {start_unix_ms: before.unix_ns / 1e6, end_unix_ms: after.unix_ns / 1e6, elapsed_s,
    cgroup: delta(counters(before.cpu_stat), counters(after.cpu_stat)),
    cpu_pressure_usec: delta(pressure(before), pressure(after)),
    independent_heartbeat: after.heartbeat ? {
      probes: after.heartbeat.probes,
      late_50ms_probes: after.heartbeat.late_50ms_probes,
      max_lateness_ms: after.heartbeat.max_lateness_ns / 1e6,
      snapshot_elapsed_ms: after.heartbeat.snapshot_elapsed_ns / 1e6,
    } : null,
    vm_busy_percent: total > 0 ? 100 * (total - ticks[3] - ticks[4]) / total : null,
    vm_total_ticks: total,
    vm_cpu_count: String(after.vm_softirq || '').split('\n')[0].match(/CPU\d+/g)?.length ?? null,
    vm_steal_ticks: ticks[7], threads};
}
function readScheduler(root, side) {
  const filename = path.join(root, `scheduler-${side}.jsonl`);
  if (!fs.existsSync(filename)) return {available: false, intervals: []};
  const lines = fs.readFileSync(filename, 'utf8').trimEnd().split('\n');
  const rows = [];
  let partial_final_line = false;
  for (let index = 0; index < lines.length; index++) {
    try { rows.push(JSON.parse(lines[index])); }
    catch (error) {
      if (index !== lines.length - 1) throw error;
      partial_final_line = true;
    }
  }
  return {available: true, partial_final_line, sample_count: rows.length,
    intervals: rows.slice(1).map((row, index) => interval(rows[index], row))};
}
function deadlineLogs(root) {
  const events = [];
  for (const filename of fs.readdirSync(root).filter(name => name.endsWith('.log'))) {
    for (const line of fs.readFileSync(path.join(root, filename), 'utf8').split('\n')) {
      if (!line.includes('code="tun_write_deadline"')) continue;
      const timestamp = line.match(/\d{4}-\d\d-\d\dT[\d:.]+Z/)?.[0];
      const fields = Object.fromEntries([...line.matchAll(/([a-z_]+)=(?:"([^"]*)"|(\S+))/g)]
        .map(([, key, quoted, raw]) => [key, quoted ?? raw]));
      events.push({file: filename, timestamp, unix_ms: Date.parse(timestamp), ...fields});
    }
  }
  return events;
}
function summarizeIntervals(intervals) {
  const sums = {};
  const threads = new Map();
  for (const item of intervals) {
    for (const [key, value] of Object.entries(item.cgroup)) sums[key] = (sums[key] || 0) + value;
    for (const task of item.threads) {
      const key = `${task.pid}/${task.generation}/${task.tid}/${task.executable}`;
      const total = threads.get(key) || {...task, runtime_ms: 0, runqueue_wait_ms: 0, timeslices: 0, max_interval_runqueue_wait_ms: 0};
      for (const field of ['runtime_ms', 'runqueue_wait_ms', 'timeslices']) total[field] += task[field];
      total.max_interval_runqueue_wait_ms = Math.max(total.max_interval_runqueue_wait_ms, task.runqueue_wait_ms);
      threads.set(key, total);
    }
  }
  return {interval_count: intervals.length, observed_seconds: intervals.reduce((sum, row) => sum + row.elapsed_s, 0),
    independent_heartbeat: {
      intervals_available: intervals.filter(row => row.independent_heartbeat).length,
      probes: intervals.reduce((sum, row) => sum + (row.independent_heartbeat?.probes ?? 0), 0),
      late_50ms_probes: intervals.reduce((sum, row) => sum + (row.independent_heartbeat?.late_50ms_probes ?? 0), 0),
      max_lateness_ms: intervals.some(row => row.independent_heartbeat)
        ? Math.max(...intervals.map(row => row.independent_heartbeat?.max_lateness_ms ?? 0)) : null,
    },
    max_observer_interval_seconds: intervals.length ? Math.max(...intervals.map(row => row.elapsed_s)) : null,
    cgroup: sums, vm_busy_percent_p95: percentile(intervals.map(row => row.vm_busy_percent).filter(Number.isFinite), 0.95),
    threads: [...threads.values()].sort((a, b) => b.runqueue_wait_ms - a.runqueue_wait_ms)};
}
function readHost(root) {
  const filename = path.join(root, 'scheduler-host.jsonl');
  if (!fs.existsSync(filename)) return {available: false, intervals: []};
  const rows = fs.readFileSync(filename, 'utf8').trimEnd().split('\n').map(line => JSON.parse(line));
  const intervals = rows.slice(1).map((row, index) => ({
    start_unix_ms: rows[index].unix_millis,
    end_unix_ms: row.unix_millis,
    elapsed_ms: Number(BigInt(row.monotonic_ns) - BigInt(rows[index].monotonic_ns)) / 1e6,
    event_loop_samples: row.event_loop_samples,
    event_loop_max_ms: row.event_loop_max_millis,
    event_loop_p99_ms: row.event_loop_p99_millis,
  }));
  return {available: true, sample_count: rows.length, intervals};
}
function analyze(root) {
  const scheduler = Object.fromEntries(['client', 'server'].map(side => [side, readScheduler(root, side)]));
  const host = readHost(root);
  const events = deadlineLogs(root);
  const samples = [];
  for (const filename of fs.readdirSync(root).filter(name => /^sample-.*\.json$/.test(name) && !/-(before|after)\.json$/.test(name)).sort()) {
    const test = JSON.parse(fs.readFileSync(path.join(root, filename)));
    if (!test.start?.timestamp?.timesecs) continue;
    const start_ms = test.start.timestamp.timesecs * 1000;
    const end_ms = start_ms + (test.end?.sum_received?.seconds ?? test.end?.sum_sent?.seconds ?? test.start.test_start.duration) * 1000;
    samples.push({file: filename, start_ms, end_ms,
      receiver_mbps: test.end?.sum_received?.bits_per_second / 1e6,
      scheduler: Object.fromEntries(Object.entries(scheduler).map(([side, data]) => [side,
        summarizeIntervals(data.intervals.filter(row => row.end_unix_ms > start_ms && row.start_unix_ms < end_ms))]))});
  }
  return {schema_version: 1, root, scope: 'offline scheduling diagnostics; not a performance acceptance gate',
    limitations: [
      'Scheduler intervals are about one second; they cannot prove the cause or maximum duration of a single 100 ms stall.',
      'Thread runqueue wait sums repeated runnable waits; a sum over 100 ms is not proof of one 100 ms deschedule.',
      'No per-thread names or Tokio task IDs are captured; TID cannot identify the PacketOutput executor task.',
      'iperf timestamps have one-second resolution; sample boundary alignment is approximate.',
      'Deadline logs are sampled; do not sum dropped_packets fields. Status counter deltas establish exact totals.',
      'VM CPU is shared by both containers; CPU quota throttling and scheduler contention are distinct observations.',
      'Independent guest heartbeat lateness and host event-loop delay show observation windows, not exact packet-event causation or a same-executor heartbeat.',
    ], scheduler: Object.fromEntries(Object.entries(scheduler).map(([side, data]) => [side,
      {...data, intervals: undefined, summary: summarizeIntervals(data.intervals)}])), samples,
    host,
    deadline_log_records: events.map(event => ({...event,
      nearby_host: host.intervals.filter(row => row.end_unix_ms >= event.unix_ms - 1000 && row.start_unix_ms <= event.unix_ms + 1000),
      nearby_scheduler: Object.fromEntries(Object.entries(scheduler).map(([side, data]) => [side,
        data.intervals.filter(row => row.end_unix_ms >= event.unix_ms - 1000 && row.start_unix_ms <= event.unix_ms + 1000)]))}))};
}

if (process.argv[2] === '--self-check') {
  const row = (time, runtime, wait, throttle) => ({monotonic_ns: time * 1e9, unix_ns: time * 1e9,
    cpu_stat: `nr_throttled ${throttle}\nusage_usec ${time * 100}`, vm_cpu: [`cpu ${time * 20} 0 0 ${time * 80} 0 0 0 0 0 0`],
    processes: [{pid: 1, executable: '/bench/binaries/candy-core', stat: '1 (comm has ) parens) R 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 42',
      tasks: [{tid: 1, schedstat: `${runtime} ${wait} ${time}`}]}]});
  const result = interval(row(1, 100, 200, 0), row(2, 10000100, 20000200, 2));
  assert.equal(result.threads[0].runtime_ms, 10);
  assert.equal(result.threads[0].runqueue_wait_ms, 20);
  assert.equal(result.cgroup.nr_throttled, 2);
  assert.equal(result.vm_busy_percent, 20);
  const heartbeating = {...row(2, 10000100, 20000200, 2), heartbeat: {
    probes: 90, late_50ms_probes: 1, max_lateness_ns: 125000000, snapshot_elapsed_ns: 2000000,
  }};
  const observed = interval(row(1, 100, 200, 0), heartbeating);
  assert.equal(observed.independent_heartbeat.max_lateness_ms, 125);
  assert.equal(summarizeIntervals([observed]).independent_heartbeat.late_50ms_probes, 1);
  assert.equal(summarizeIntervals([result]).independent_heartbeat.max_lateness_ms, null);
  assert.equal(percentile([1, 3, 2], 0.95), 3);
  console.log(JSON.stringify({self_check: 'PASS'}));
} else {
  const [directory, output] = process.argv.slice(2);
  if (!directory) throw new Error('usage: node analyze-scheduler.mjs <evidence-directory> [new-output.json] | --self-check');
  const result = JSON.stringify(analyze(path.resolve(directory)), null, 2) + '\n';
  if (output) fs.writeFileSync(output, result, {flag: 'wx', mode: 0o600});
  else process.stdout.write(result);
}
