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
  return {client: {...resource, active: {core, record: {pid: 11, worker_epoch: 1, auth_deadline_unix: 1000}, io: {pid: 12, process_start_ticks: 42}, link: [{ifindex: 7}], outputs: {pid: 12, process_start_ticks: 42, bridge_outputs: {to_worker: outputCounters(), to_tun: outputCounters()}}}}, server: {...resource, core: structuredClone(core)}};
};
let sequence = 0;
const execute = (before, after, expected, requireOutputs = true, expectedFailures, renewals = []) => {
  write('renewal-run.json', {rounds: 1, mode: 'test', require_output_diagnostics: requireOutputs});
  write('completion.json', {});
  write('sample-p4-upload-r1.json', {end: {sum_received: {seconds: 60, bits_per_second: 750e6}}});
  write('sample-p4-upload-r1-before.json', before);
  write('sample-p4-upload-r1-after.json', after);
  for (const name of fs.readdirSync(root).filter(name => /^renewal-\d+\.json$/.test(name))) fs.unlinkSync(path.join(root, name));
  renewals.forEach((row, index) => write(`renewal-${index + 1}.json`, row));
  const output = path.join(root, `result-${++sequence}.json`);
  const result = spawnSync(process.execPath, [summarize, root, output], {encoding: 'utf8'});
  if (expected === 'REJECT') assert.notEqual(result.status, 0);
  else {
    assert.equal(result.status, 0, result.stderr);
    const summary = JSON.parse(fs.readFileSync(output));
    assert.equal(summary.steady_sample_integrity, expected, `${result.stdout}\n${result.stderr}\n${JSON.stringify(summary.samples?.[0]?.client)}`);
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
  const reason = snapshot();
  reason.server.core.counters.drop_reasons.route_has_no_active_peer = 1;
  execute(snapshot(), reason, 'FAIL');
  const renewedBefore = snapshot(), renewedAfter = snapshot();
  renewedBefore.client.active.core.pid = 11;
  renewedAfter.client.active.core.pid = 21;
  renewedAfter.client.active.record = {pid: 21, worker_epoch: 2, auth_deadline_unix: 2000};
  renewedAfter.client.active.core.pid = 21;
  renewedAfter.client.active.core.worker_authority_sha256 = 'signed-sha256';
  const transitionBefore = structuredClone(renewedBefore.client.active);
  const transitionAfter = structuredClone(renewedAfter.client.active);
  transitionBefore.core.counters = structuredClone(renewedBefore.client.active.core.counters);
  transitionAfter.core.counters = structuredClone(renewedAfter.client.active.core.counters);
  transitionAfter.record = {pid: 21, worker_epoch: 2, auth_deadline_unix: 2000};
  const signed = {source: 'isolated signed fixture; real Agent/IO/netd authority transaction; no Cloud mTLS', compiled: {authorization_snapshot_sha256: 'signed-sha256'}, before: {...transitionBefore, record: {pid: 11, worker_epoch: 1, auth_deadline_unix: 1000}}, after: transitionAfter};
  execute(renewedBefore, renewedAfter, 'PASS', true, undefined, [signed]);
  const droppedRenewal = structuredClone(signed);
  droppedRenewal.before.core.counters.drops++;
  execute(renewedBefore, renewedAfter, 'FAIL', true, undefined, [droppedRenewal]);
  const unstableInfra = structuredClone(signed);
  unstableInfra.after.link[0].ifindex++;
  execute(renewedBefore, renewedAfter, 'FAIL', true, undefined, [unstableInfra]);
  execute(renewedBefore, renewedAfter, 'FAIL');
  console.log('PASS: TUNIO failures, missing evidence, counter reset, identity replacement and timing gaps reject; signed renewal requires stable TUN/TUNIO identity, monotonic epoch and zero generation-spanning errors');
} finally {
  fs.rmSync(root, {recursive: true, force: true});
}
