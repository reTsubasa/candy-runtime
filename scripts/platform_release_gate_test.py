#!/usr/bin/env python3
"""Offline architecture-gate regressions; no cross compiler or device required."""

from pathlib import Path
import struct
import tempfile
import unittest

from platform_release_gate import elf_identity


class ElfGateTest(unittest.TestCase):
    def identity(self, bits=1, machine=40, flags=0x05000400, program_type=1, profile="ipq40xx"):
        header, entry = (52, 32) if bits == 1 else (64, 56)
        data = bytearray(header + entry)
        data[:7] = b"\x7fELF" + bytes([bits, 1, 1])
        struct.pack_into("<HH", data, 16, 2, machine)
        if bits == 1:
            struct.pack_into("<I", data, 28, header)
            struct.pack_into("<I", data, 36, flags)
            struct.pack_into("<HH", data, 42, entry, 1)
        else:
            struct.pack_into("<Q", data, 32, header)
            struct.pack_into("<HH", data, 54, entry, 1)
        struct.pack_into("<I", data, header, program_type)
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "core"
            artifact.write_bytes(data)
            return elf_identity(artifact, profile)

    def test_accepts_armv7_hardfloat_header_at_52(self):
        self.assertEqual(self.identity()["class"], 32)

    def test_accepts_static_x86_64(self):
        self.assertEqual(self.identity(bits=2, machine=62, profile="x86_64")["class"], 64)

    def test_rejects_softfloat(self):
        with self.assertRaisesRegex(ValueError, "hard-float"):
            self.identity(flags=0x05000200)

    def test_rejects_wrong_machine(self):
        with self.assertRaisesRegex(ValueError, "class/machine"):
            self.identity(machine=183)

    def test_rejects_dynamic_interpreter(self):
        with self.assertRaisesRegex(ValueError, "dynamic interpreter"):
            self.identity(program_type=3)


if __name__ == "__main__":
    unittest.main()
