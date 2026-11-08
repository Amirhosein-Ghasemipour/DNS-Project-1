"""Container/namespace backends. There is deliberately no host-execution mode."""

import json
import os
import platform
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from .config import ConfigError


class Sandbox:
    def __init__(self, backend="docker", image="patchcheck-toolchain:1"):
        self.backend, self.image = backend, image
        self.directory = Path(__file__).resolve().parent
        if backend == "namespace":
            if sys.platform != "linux" or platform.machine() != "x86_64":
                raise ConfigError("namespace backend requires Linux x86_64; use WSL on Windows")
            self.identity = {"backend": backend, "kernel": platform.release(),
                             "memory_enforcement": "sampled aggregate RSS (20ms); CPU/file/output/process limits",
                             "toolchain": self._toolchain()}
        elif backend == "docker":
            result = self._host(["docker", "image", "inspect", image], timeout=30)
            if result.returncode:
                raise ConfigError("Docker image unavailable; build docker/Dockerfile first: " + result.stderr)
            info = json.loads(result.stdout)[0]
            if info.get("Architecture") != "amd64" or info.get("Os") != "linux":
                raise ConfigError("toolchain image must target linux/amd64")
            self.image = info["Id"]
            self.identity = {"backend": backend, "image_id": self.image,
                             "repo_digests": info.get("RepoDigests", []), "memory_enforcement": "Docker cgroup"}
        else:
            raise ConfigError("unknown sandbox backend")

    @staticmethod
    def _host(argv, **kwargs):
        return subprocess.run(argv, capture_output=True, text=True, **kwargs)

    def _toolchain(self):
        info = {}
        for binary in ("cc", "readelf", "python3", "git"):
            result = self._host([binary, "--version"], timeout=10)
            info[binary] = result.stdout.splitlines()[0] if result.returncode == 0 else result.stderr
        return info

    def execute(self, work, request):
        timeout = request["limits"]["build_seconds" if request.get("build") else "wall_seconds"] + 30
        if self.backend == "namespace":
            with tempfile.TemporaryDirectory(prefix="patchcheck-root-") as root:
                argv = ["unshare", "--user", "--map-root-user", "--mount", "--net", "--pid", "--fork", "--kill-child",
                        sys.executable, "-I", str(self.directory / "namespace.py"), root, str(work.resolve()),
                        str(self.directory / "worker.py"), "1" if request.get("build") else "0"]
                result = self._host(argv, input=json.dumps(request), timeout=timeout)
        else:
            name = "patchcheck-" + uuid.uuid4().hex
            limits = request["limits"]
            argv = ["docker", "run", "--name", name, "--pull=never", "--platform=linux/amd64", "--network=none",
                    "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--user=1000:1000",
                    "--memory", f"{limits['memory_mb']}m", "--memory-swap", f"{limits['memory_mb']}m",
                    "--cpus=1", "--pids-limit", str(limits["pids"]), "--ulimit=core=0:0",
                    "--tmpfs=/tmp:rw,nosuid,nodev,size=256m", "--workdir=/work",
                    "--mount", f"type=bind,source={work.resolve()},target=/work" + ("" if request.get("build") else ",readonly"),
                    "--mount", f"type=bind,source={self.directory / 'worker.py'},target=/validator/worker.py,readonly",
                    "--interactive", self.image, "python3", "-I", "/validator/worker.py"]
            try:
                result = self._host(argv, input=json.dumps(request), timeout=timeout)
                state = self._host(["docker", "inspect", "--format={{json .State}}", name], timeout=10)
                if state.returncode == 0 and json.loads(state.stdout).get("OOMKilled"):
                    return {"argv": request["argv"], "returncode": None, "exit_code": None, "signal": None,
                            "resource_limit": "container_memory", "stdout": "", "stderr": result.stderr,
                            "stdout_base64": "", "stderr_base64": "", "environment": request.get("env", {})}
            finally:
                self._host(["docker", "rm", "--force", name], timeout=15)
        try:
            output = json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            raise ConfigError(f"sandbox failed ({result.returncode}): {result.stderr[:4000]}") from exc
        if result.returncode or "worker_error" in output:
            raise ConfigError(f"sandbox worker failed: {output.get('worker_error', result.stderr)}")
        output["sandbox"] = self.identity
        return output

