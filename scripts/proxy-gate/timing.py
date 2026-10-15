#!/usr/bin/env python3
"""Independent bounded scheduling witness; emit evidence only on shutdown."""
from collections import deque
import json
import os
import signal
import time


def main():
    stopped = False

    def stop(_signal, _frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    started = previous = time.monotonic()
    events = deque(maxlen=4096)
    count, samples, maximum = 0, 0, 0
    while not stopped and time.monotonic() - started < 86400:
        time.sleep(.01)
        now = time.monotonic()
        lag = max(0, now - previous - .01)
        samples += 1
        maximum = max(maximum, lag)
        if lag > .02:
            count += 1
            events.append({'previous_at': previous, 'resumed_at': now, 'lag_ms': lag * 1000})
        previous = now
    print(json.dumps({'scope': 'independent process scheduling witness, not a packet latency measurement',
                      'cpu_affinity': sorted(os.sched_getaffinity(0)),
                      'started_at': started, 'ended_at': time.monotonic(), 'samples': samples,
                      'max_lag_ms': maximum * 1000, 'late_intervals': count,
                      'events': list(events), 'omitted_old_events': max(0, count - len(events))}))


if __name__ == '__main__':
    main()
