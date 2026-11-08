"""Small Linux supervisor executed INSIDE the sandbox, never on the host.

The child sees a clean environment. stdout/stderr are captured as bytes, with
wall/CPU/output/file/process limits and sampled aggregate resident-memory limits.
Docker additionally provides cgroup memory, CPU and process limits.
"""

import base64
import json
import math
import os
import resource
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path


def group_usage(group):
    """Sample aggregate RSS and process count for one process group.

    Monitoring is best-effort and must never abort a validation run. Processes
    exit while ``/proc`` is being walked -- especially inside a fresh PID
    namespace, where low PIDs are recycled constantly -- so an entry can vanish
    between listing and reading, and the directory iterator itself can fail
    mid-walk. Both are absorbed here: a missed sample understates memory use for
    one interval, whereas an escaping exception aborted the entire run as
    BUILD_OR_CONFIG_ERROR and misreported a sandbox limitation as a tool error.
    """
    rss, count = 0, 0
    try:
        for path in Path("/proc").glob("[0-9]*/stat"):
            try:
                fields = path.read_text().rsplit(")", 1)[1].split()
                # fields begin at proc stat field 3; pgrp=5, rss=24.
                if int(fields[2]) == group:
                    count += 1
                    rss += int(fields[21]) * os.sysconf("SC_PAGE_SIZE")
            except (OSError, ValueError, IndexError):
                continue
    except OSError:
        # The /proc walk itself failed; report what was sampled so far.
        return rss, count
    return rss, count


def execute(request):
    limits = request["limits"]
    building = request.get("build", False)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (limits["file_bytes"], limits["file_bytes"]))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    cpu = math.ceil(limits["build_seconds"] if building else limits["cpu_seconds"])
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
    data = base64.b64decode(request.get("input_base64", ""), validate=True)
    input_file = Path("/tmp/patchcheck-input")
    input_file.write_bytes(data)
    interface = request.get("interface", "stdin")
    substitutions = {"{binary}": request.get("binary", ""), "{input}": str(input_file)}
    if interface == "argv":
        substitutions["{input_text}"] = data.decode("utf-8")
    argv = request["argv"][:]
    for index, value in enumerate(argv):
        for token, replacement in substitutions.items():
            value = value.replace(token, replacement)
        argv[index] = value
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "HOME": "/tmp", "TMPDIR": "/tmp"}
    env.update(request.get("env", {}))
    started = time.monotonic()
    child = subprocess.Popen(argv, cwd="/work", env=env, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ, "stdout")
    selector.register(child.stderr, selectors.EVENT_READ, "stderr")
    pending = memoryview(data if interface == "stdin" else b"")
    if pending:
        os.set_blocking(child.stdin.fileno(), False)
        selector.register(child.stdin, selectors.EVENT_WRITE, "stdin")
    else:
        child.stdin.close()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limit_reason = None
    wall = limits["build_seconds"] if building else limits["wall_seconds"]
    peak_rss = 0
    while selector.get_map() or child.poll() is None:
        rss, processes = group_usage(child.pid)
        peak_rss = max(peak_rss, rss)
        reason = ("wall_time" if time.monotonic() - started > wall else
                  "memory" if rss > limits["memory_mb"] * 1024 * 1024 else
                  "processes" if processes > limits["pids"] else None)
        if reason or limit_reason:
            limit_reason = limit_reason or reason
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for key, _ in selector.select(0.02):
            if key.data == "stdin":
                try:
                    size = os.write(key.fd, pending[:65536])
                    pending = pending[size:]
                except BrokenPipeError:
                    pending = memoryview(b"")
                if not pending:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
            else:
                try:
                    chunk = os.read(key.fd, 65536)
                except OSError:
                    # The child died or the pipe was torn down between the
                    # selector event and the read; treat it as end of stream.
                    chunk = b""
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                else:
                    total = sum(len(value) for value in buffers.values())
                    remaining = max(0, limits["output_bytes"] - total)
                    buffers[key.data].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        limit_reason = "output"
    code = child.wait()
    # Kill lingering descendants even when the direct child exited normally.
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    sig = signal.Signals(-code).name if code < 0 else None
    if sig in {"SIGXCPU", "SIGXFSZ"}:
        limit_reason = "cpu_time" if sig == "SIGXCPU" else "file_size"
    result = {"argv": argv, "environment": env, "returncode": code,
              "exit_code": code if code >= 0 else None, "signal": sig,
              "resource_limit": limit_reason, "duration_seconds": round(time.monotonic() - started, 6),
              "peak_rss_bytes": peak_rss}
    for key, value in buffers.items():
        result[key] = bytes(value).decode("utf-8", "replace")
        result[key + "_base64"] = base64.b64encode(value).decode()
    return result


if __name__ == "__main__":
    try:
        result = execute(json.load(sys.stdin))
    except Exception as exc:
        result = {"worker_error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(result, sort_keys=True))

