import fs from 'node:fs';
import os from 'node:os';
import {monitorEventLoopDelay} from 'node:perf_hooks';

// Host measurements complement guest schedstat; neither proves why a VM vCPU stalled.
export function observeHost(filename) {
  const fd = fs.openSync(filename, 'wx', 0o600);
  const delay = monitorEventLoopDelay({resolution: 10});
  delay.enable();
  let error;
  const sample = () => {
    try {
      const row = {
        schema_version: 1,
        unix_millis: Date.now(),
        monotonic_ns: process.hrtime.bigint().toString(),
        platform: process.platform,
        arch: process.arch,
        cpu_times_millis: os.cpus().map(cpu => cpu.times),
        load_average: os.loadavg(),
        free_memory_bytes: os.freemem(),
        total_memory_bytes: os.totalmem(),
        event_loop_samples: delay.count,
        event_loop_max_millis: delay.count ? delay.max / 1e6 : null,
        event_loop_p99_millis: delay.count ? delay.percentile(99) / 1e6 : null,
      };
      fs.writeSync(fd, JSON.stringify(row) + '\n');
      delay.reset();
    } catch (failure) {
      error = String(failure);
    }
  };
  sample();
  const timer = setInterval(sample, 1000);
  timer.unref();
  return () => {
    clearInterval(timer);
    sample();
    delay.disable();
    fs.closeSync(fd);
    return {error: error ?? null};
  };
}
