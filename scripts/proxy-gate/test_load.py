#!/usr/bin/env python3
"""Acceptance metrics must retain delayed, failed and missing observations."""
import unittest

from load import summarize_latency


class LatencyCohortTest(unittest.TestCase):
    @staticmethod
    def rows():
        return [{'scheduled_at': 10 + index * .05, 'started_at': 10 + index * .05,
                 'finished_at': 10.01 + index * .05, 'ms': 10,
                 'schedule_lag_ms': 0, 'error': None} for index in range(20)]

    def test_delayed_tail_after_window_remains_in_p99(self):
        rows = self.rows()
        rows[-1].update(finished_at=13, ms=2050)
        result = summarize_latency(rows, 10, 11)
        self.assertEqual(result['samples'], 20)
        self.assertEqual(result['p99_ms'], 2050)

    def test_error_after_window_is_counted_without_success_sample(self):
        rows = self.rows()
        rows[-1].update(finished_at=13, ms=2050, error='timed out')
        result = summarize_latency(rows, 10, 11)
        self.assertEqual(result['offered'], 20)
        self.assertEqual(result['samples'], 19)
        self.assertEqual(result['errors'], 1)

    def test_late_start_is_preserved_in_generator_quality(self):
        rows = self.rows()
        rows[-1].update(started_at=11.1, finished_at=11.11, schedule_lag_ms=150)
        self.assertEqual(summarize_latency(rows, 10, 11)['generator_max_lag_ms'], 150)

    def test_missing_duplicate_and_out_of_window_probes_reject(self):
        missing = self.rows()[:-1]
        duplicate = self.rows()
        duplicate[-1] = dict(duplicate[0])
        outside = self.rows()
        outside[-1]['scheduled_at'] = 11
        for rows in (missing, duplicate, outside):
            with self.subTest(rows=rows), self.assertRaisesRegex(RuntimeError, 'offered sequence'):
                summarize_latency(rows, 10, 11)


if __name__ == '__main__':
    unittest.main()
