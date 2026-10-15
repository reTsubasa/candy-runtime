#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("gate", Path(__file__).with_name("openwrt_vm_gate.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class GateInputs(unittest.TestCase):
    def test_exact_manifest_entry(self):
        digest = "a" * 64
        self.assertEqual(gate.manifest_digest(f"{digest}  image.gz\n", "image.gz"), digest)
        self.assertEqual(gate.manifest_digest(f"{digest} *image.gz\n", "image.gz"), digest)

    def test_manifest_missing_or_duplicate_rejected(self):
        entry = "a" * 64 + "  image.gz\n"
        for text in (entry.replace("image.gz", "other.gz"), entry * 2, "x" * 64 + "  image.gz\n"):
            with self.assertRaises(ValueError):
                gate.manifest_digest(text, "image.gz")

    def test_reject_wrong_architecture_before_vm(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "netd"
            path.write_bytes(b"#!/bin/sh\n")
            with self.assertRaises(ValueError):
                gate.static_x86_elf(path)

    def test_static_elf_and_interpreter_rejection(self):
        raw = bytearray(120)
        raw[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", raw, 18, 62)
        struct.pack_into("<Q", raw, 32, 64)
        struct.pack_into("<HH", raw, 54, 56, 1)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "netd"
            path.write_bytes(raw)
            gate.static_x86_elf(path)
            struct.pack_into("<I", raw, 64, 3)
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                gate.static_x86_elf(path)


if __name__ == "__main__":
    unittest.main()
