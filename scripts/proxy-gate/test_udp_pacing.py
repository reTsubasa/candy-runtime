#!/usr/bin/env python3
"""Deterministic generator timing checks, independent of Docker scheduling."""
import unittest

from udp import RatePacer


class Clock:
    def __init__(self):
        self.now = 0.0
        self.oversleep = 0.0

    def read(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds + self.oversleep
        self.oversleep = 0.0


class PacingTests(unittest.TestCase):
    def test_normal_schedule(self):
        clock = Clock()
        pacer = RatePacer(.1, 100, clock.read, clock.sleep)
        for sequence in range(300):
            nominal, target, actual = pacer.wait(sequence)
            self.assertAlmostEqual(actual, nominal)
            self.assertAlmostEqual(target, nominal)

    def test_pause_does_not_catch_up_or_erase_nominal_lateness(self):
        clock = Clock()
        pacer = RatePacer(.1, 100, clock.read, clock.sleep)
        pacer.wait(0)
        clock.now += .3
        first = pacer.wait(1)
        second = pacer.wait(2)
        self.assertGreater(first[2] - first[0], .02)
        self.assertGreater(second[2] - second[0], .02)
        self.assertGreaterEqual(second[2] - first[2], .01 - 1e-9)

    def test_oversleep_and_short_pause_never_burst(self):
        clock = Clock()
        pacer = RatePacer(.1, 100, clock.read, clock.sleep)
        clock.oversleep = .3
        previous = pacer.wait(0)[2]
        for sequence in range(1, 30):
            clock.now += .015 if sequence == 5 else 0
            now = pacer.wait(sequence)[2]
            self.assertGreaterEqual(now - previous, .01 - 1e-9)
            previous = now


if __name__ == '__main__':
    unittest.main()
