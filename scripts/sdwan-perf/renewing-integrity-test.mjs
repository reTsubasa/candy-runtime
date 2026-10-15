import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'candy-renewing-integrity-'));
const summarize = fileURLToPath(new URL('./summarize-renewing-run.mjs', import.meta.url));
const write = (name, value) => fs.writeFileSync(path.join(root, name), JSON.stringify(value));
const outputCounters = () => Object.fromEntries(['sent_packets', 'sent_bytes', 'queue_slot_exhausted', 'queue_byte_exhausted', 'queue_channel_full', 'backpressure_drops', 'deadline_drops', 'stale_drops', 'queue_depth', 'queue_high_watermark', 'write_blocked_events', 'queued_write_attempts', 'queue_wait_micros', 'queue_wait_max_micros', 'send_elapsed_micros', 'send_elapsed_max_micros'].map(key => [key, 10]));
const snapshot = () => {
  const core = {pid: 11, lifecycle: 'active', dataplane_phase: 'data_plane_active', failed_prefixes: [], counters: {drops: 5, stream_read_errors: 3, stream_write_errors: 4, tun_output_write_blocked_events: 7, drop_reasons: {}, tun_output_queued_write_attempts: 8, tun_output_queue_wait_micros: 9, tun_output_send_elapsed_micros: 10, tun_output_queue_wait_max_micros: 4, tun_output_send_elapsed_max_micros: 5}};
  const resource = {cpu: 'usage_usec 100\nnr_throttled 0', memory: '100', peak: '100', qdisc: '[]'};
  return {client: {...resource, active: {core, io: {pid: 12}, outputs: {pid: 12, process_start_ticks: 42, bridge_outputs: {to_worker: outputCounters(), to_tun: outputCounters()}}}}, server: {...resource, core: structuredClone(core)}};
};
let sequence = 0;
const execute = (before, after, expected, requireOutputs = true, expectedFailures) => {
  write('renewal-run.json', {rounds: 1, mode: 'test', require_output_diagnostics: requireOutputs});
  write('completion.json', {});
  write('sample-p4-upload-r1.json', {end: {sum_received: {seconds: 60, bits_per_second: 750e6}}});
  write('sample-p4-upload-r1-before.json', before);
  write('sample-p4-upload-r1-after.json', after);
  const output = path.join(root, `result-${++sequence}.json`);
  const result = spawnSync(process.execPath, [summarize, root, output], {encoding: 'utf8'});
  if (expected === 'REJECT') assert.notEqual(result.status, 0);
  else {
    assert.equal(result.status, 0, result.stderr);
    const summary = JSON.parse(fs.readFileSync(output));
    assert.equal(summary.steady_sample_integrity, expected);
    if (expectedFailures) assert.equal(summary.tunio_failure_totals[expectedFailures.direction][expectedFailures.key], expectedFailures.value);
  }
};
try {
  execute(snapshot(), snapshot(), 'PASS');
  for (const direction of ['to_worker', 'to_tun']) for (const key of ['queue_slot_exhausted', 'queue_byte_exhausted', 'queue_channel_full', 'backpressure_drops', 'deadline_drops', 'stale_drops']) {
    const after = snapshot();
    after.client.active.outputs.bridge_outputs[direction][key]++;
    execute(snapshot(), after, 'FAIL', true, {direction, key, value: 1});
  }
  const missing = snapshot();
  delete missing.client.active.outputs;
  execute(missing, missing, 'REJECT');
  execute(missing, missing, 'PASS', false);
  const incomplete = snapshot();
  delete incomplete.client.active.outputs.bridge_outputs.to_tun.deadline_drops;
  execute(incomplete, incomplete, 'REJECT');
  const reset = snapshot();
  reset.client.active.outputs.bridge_outputs.to_tun.sent_packets = 0;
  execute(snapshot(), reset, 'REJECT');
  const replaced = snapshot();
  replaced.client.active.outputs.process_start_ticks++;
  execute(snapshot(), replaced, 'REJECT');
  const timing = snapshot();
  delete timing.server.core.counters.tun_output_queue_wait_micros;
  execute(timing, timing, 'FAIL');
  console.log('PASS: both TUNIO directions reject admission/deadline/backpressure/stale failures; missing evidence, counter reset, identity replacement and missing Core timing cannot pass');
} finally {
  fs.rmSync(root, {recursive: true, force: true});
}
