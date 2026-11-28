"""Small toolchain/sandbox smoke check; does not run an unsafe program.

Uses the default backend resolution: the namespace pipeline is probed and, when
the host denies it (container seccomp, disabled unprivileged user namespaces),
the resolved mode and the reason are reported instead of an abort.
"""

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
sandbox = Sandbox("auto")
result = sandbox.execute(work, request)
print(json.dumps({"resolved_mode": sandbox.mode, "identity": sandbox.identity,
                  "probe_result": result}, indent=2))
if sandbox.mode == "restricted":
    print("warning: sandbox resolved to the restricted fallback; "
          "user namespaces and Docker were unavailable on this host", file=sys.stderr)
