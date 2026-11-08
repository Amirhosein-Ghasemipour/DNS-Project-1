"""Small toolchain/sandbox smoke check; does not run an unsafe program."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchcheck.sandbox import Sandbox

root = Path(__file__).resolve().parents[1]
work = root / "artifacts" / "sandbox-probe"
work.mkdir(parents=True, exist_ok=True)
request = {"argv": ["/usr/bin/cc", "--version"], "limits": {
    "wall_seconds": 5, "cpu_seconds": 3, "memory_mb": 512, "output_bytes": 1048576,
    "file_bytes": 16777216, "pids": 128, "build_seconds": 60}}
print(json.dumps(Sandbox("namespace").execute(work, request), indent=2))

