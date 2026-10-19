"""Local result-parser checks; these do not replace the privileged gate."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


def load_gate():
    path = Path(__file__).with_name('mixed_role_faults.py')
    spec = importlib.util.spec_from_file_location('mixed_role_faults', path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, 'argv', [str(path), '/tmp/root', '/tmp/fixture', '/tmp/core', '/tmp/wrapper']):
        spec.loader.exec_module(module)
    return module


class PingEvidenceTests(unittest.TestCase):
    def test_full_exact_cohort(self):
        gate = load_gate()
        self.assertEqual(gate.ping_result('40 packets transmitted, 40 received, 0% packet loss')['gate'], 'PASS')

    def test_rounded_zero_loss_cannot_hide_missing_packet(self):
        gate = load_gate()
        self.assertEqual(gate.ping_result('1000 packets transmitted, 999 received, 0% packet loss')['gate'], 'FAIL')

    def test_missing_or_short_cohort_fails(self):
        gate = load_gate()
        for text in ('', '19 packets transmitted, 19 received, 0% packet loss',
                     '40 packets transmitted, 0 received, 100% packet loss'):
            self.assertEqual(gate.ping_result(text)['gate'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
