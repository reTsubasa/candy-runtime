#!/usr/bin/env python3
"""Negative gates for the independently consumable public source package."""
import copy
import json
from pathlib import Path
import shutil
import tempfile

import packet_port_package as package


def rejected():
    try:
        package.verify()
    except (ValueError, KeyError):
        return
    raise AssertionError("invalid public package was accepted")


source = package.PACKAGE
with tempfile.TemporaryDirectory(prefix="candy-public-package-") as temporary:
    root = Path(temporary)
    for scenario in ("changed", "added", "missing", "symlink", "private_dependency"):
        package.PACKAGE = root / scenario
        shutil.copytree(source, package.PACKAGE)
        original = json.loads((package.PACKAGE / "provenance.json").read_text())
        if scenario == "changed":
            path = package.PACKAGE / "src/lib.rs"
            path.write_bytes(path.read_bytes() + b"\n// altered\n")
        elif scenario == "added":
            (package.PACKAGE / "src/extra.rs").write_text("// untracked implementation\n")
        elif scenario == "missing":
            (package.PACKAGE / "src/fd.rs").unlink()
        elif scenario == "symlink":
            (package.PACKAGE / "src/alias.rs").symlink_to("lib.rs")
        else:
            # Even an internally self-consistent package may not smuggle a
            # private implementation dependency past the layout boundary.
            path = package.PACKAGE / "Cargo.toml"
            path.write_bytes(path.read_bytes().replace(b"[dependencies]", b'[dependencies]\ncandy-tun = "1"'))
            files = {p.relative_to(package.PACKAGE).as_posix(): p.read_bytes() for p in package.PACKAGE.rglob("*") if p.is_file() and p.name != "provenance.json"}
            record = copy.deepcopy(original)
            record["files"] = {name: package.digest(data) for name, data in files.items()}
            record["package_content_sha256"] = package.tree_digest(files)
            (package.PACKAGE / "provenance.json").write_text(json.dumps(record))
        rejected()
package.PACKAGE = source
package.verify()
print("Public PacketPort negative gates passed: 5/5")
