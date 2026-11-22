"""Container/namespace backends. There is deliberately no raw host-execution mode.

Every target still runs behind the in-process supervisor (``worker.py``) with
wall-clock, CPU, memory, file-size, output and process limits. Which *isolation
envelope* wraps that supervisor is resolved by capability probing, because the
strongest envelope -- rootless user namespaces -- is denied by several common
environments (container seccomp profiles that reject the ``/proc/self/uid_map``
write, kernels with ``kernel.unprivileged_userns_clone=0``, Ubuntu 24.04
AppArmor rules). Instead of aborting the whole analysis with
``sandbox failed: unshare: ... Vorgang nicht zulässig``, the backend resolves as:

    namespace (probed end-to-end) -> docker (if the toolchain image exists)
                                  -> restricted (process-level isolation only)

The restricted mode keeps every control the supervisor enforces and drops all
capabilities via ``setpriv``, but it cannot provide a chroot, a network
namespace or a private /proc. Whatever mode actually ran is recorded in
``report["sandbox"]``, echoed in ``summary.txt`` and copied into every
reproducer manifest, so no evidence ever claims stronger isolation than it had.
"""

import base64
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from .config import ConfigError

BACKENDS = ("auto", "namespace", "docker", "restricted")


class Sandbox:
    """Resolve and drive the strongest sandbox the host actually permits."""

    def __init__(self, backend="auto", image="patchcheck-toolchain:1"):
        if backend not in BACKENDS:
            raise ConfigError(f"unknown sandbox backend: {backend} (choose one of {', '.join(BACKENDS)})")
        self.backend, self.image = backend, image
        self.directory = Path(__file__).resolve().parent
        self.mode = None
        self.unavailable_reason = None
        self.capability_argv = []
        self.preparation = None
        if backend == "docker":
            self._init_docker()
            return
        if sys.platform != "linux" or platform.machine() != "x86_64":
            raise ConfigError("sandbox backends require Linux x86_64; use WSL on Windows")
        if backend == "restricted":
            self.unavailable_reason = "restricted backend requested explicitly"
        elif backend in ("auto", "namespace"):
            usable, reason = self._probe_namespace()
            if usable:
                self.mode = "namespace"
                self.identity = {"backend": backend, "mode": "namespace", "kernel": platform.release(),
                                 "memory_enforcement": "sampled aggregate RSS (20ms); CPU/file/output/process limits",
                                 "toolchain": self._toolchain()}
                return
            self.unavailable_reason = reason
            if self._docker_ready():
                self._init_docker()
                return
        self._init_restricted()

    # ------------------------------------------------------------------ init

    def _init_docker(self):
        try:
            result = self._host(["docker", "image", "inspect", self.image], timeout=30)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ConfigError(f"Docker CLI unavailable: {exc}") from exc
        if result.returncode:
            raise ConfigError("Docker image unavailable; build docker/Dockerfile first: " + result.stderr)
        info = json.loads(result.stdout)[0]
        if info.get("Architecture") != "amd64" or info.get("Os") != "linux":
            raise ConfigError("toolchain image must target linux/amd64")
        self.mode = "docker"
        self.image = info["Id"]
        uid, gid = os.getuid(), os.getgid()
        self.identity = {"backend": self.backend, "mode": "docker", "image_id": self.image,
                         "repo_digests": info.get("RepoDigests", []), "memory_enforcement": "Docker cgroup",
                         "container_user": ("1000:1000 (image default; the host runs patchcheck as root"
                                            " and each build directory is chowned to the container"
                                            " user before its build)"
                                            if uid == 0 else f"{uid}:{gid} (invoking host user)")}
        if self.unavailable_reason:
            self.identity["namespace_unavailable"] = self.unavailable_reason

    def _init_restricted(self):
        self.mode = "restricted"
        self.capability_argv = self._setpriv_argv()
        drop = bool(self.capability_argv)
        self.identity = {
            "backend": self.backend, "mode": "restricted",
            "namespace_unavailable": self.unavailable_reason or "user namespaces unavailable",
            "memory_enforcement": "sampled aggregate RSS (20ms) kill; CPU/file/output/process rlimits",
            "capability_drop": ("setpriv --bounding-set=-all --no-new-privs" if drop
                                else "unavailable on this host; rlimits and session kill only"),
            "isolation": ["rlimits: CPU time, file size, open files, core dumps",
                          "wall-clock supervision with process-group kill",
                          "sampled aggregate resident-memory kill",
                          "output-volume and process-count caps",
                          "clean environment and private temporary directory",
                          "capability drop and no-new-privs via setpriv" if drop
                          else "no capability drop available"],
            "not_provided": ["user namespace", "chroot filesystem view",
                             "network namespace", "private /proc"],
            "toolchain": self._toolchain(),
        }

    def _setpriv_argv(self):
        """Return the setpriv prefix, probed once, or [] when it does not work.

        setpriv itself needs prctl and can be denied by the same sandbox
        policies that deny user namespaces (observed as ``setpriv: apply
        bounding set: Operation not permitted``); a prefix that cannot run
        must never be inserted into every execution.
        """
        if shutil.which("setpriv") is None:
            return []
        test = self._host(["setpriv", "--bounding-set=-all", "--inh-caps=-all",
                           "--ambient-caps=-all", "--no-new-privs", "true"], timeout=10)
        if test.returncode != 0:
            return []
        return ["setpriv", "--bounding-set=-all", "--inh-caps=-all",
                "--ambient-caps=-all", "--no-new-privs"]

    def _docker_ready(self):
        try:
            probe = self._host(["docker", "image", "inspect", self.image], timeout=30)
        except (OSError, subprocess.SubprocessError):
            return False
        return probe.returncode == 0

    @staticmethod
    def _host(argv, **kwargs):
        return subprocess.run(argv, capture_output=True, text=True, **kwargs)

    def _toolchain(self):
        info = {}
        for binary in ("cc", "readelf", "python3", "git"):
            result = self._host([binary, "--version"], timeout=10)
            info[binary] = result.stdout.splitlines()[0] if result.returncode == 0 else result.stderr
        return info

    # ----------------------------------------------------------------- probe

    def _namespace_argv(self, work, build, root):
        return ["unshare", "--user", "--map-root-user", "--mount", "--net", "--pid", "--fork", "--kill-child",
                sys.executable, "-I", str(self.directory / "namespace.py"), str(root), str(Path(work).resolve()),
                str(self.directory / "worker.py"), "1" if build else "0"]

    def _probe_namespace(self):
        """Run the complete namespace pipeline once with a harmless command.

        The probe replays the exact production chain -- unshare with user/mount/
        net/pid namespaces, the mount table, the chroot, the setpriv exec and
        the worker -- because each stage can be denied independently: a kernel
        without unprivileged user namespaces denies the unshare itself, a
        container seccomp profile denies the ``/proc/self/uid_map`` write, and
        AppArmor rules deny mounts or the chroot. Checking one stage in
        isolation would miss precisely the denials that abort a real run.
        """
        if shutil.which("unshare") is None:
            return False, "the unshare utility (util-linux) is not installed"
        limits = {"wall_seconds": 15, "cpu_seconds": 10, "memory_mb": 256, "output_bytes": 65536,
                  "file_bytes": 1048576, "pids": 32, "build_seconds": 15}
        request = {"argv": ["/usr/bin/true"], "limits": limits}
        try:
            with tempfile.TemporaryDirectory(prefix="patchcheck-probe-") as directory:
                work = Path(directory) / "work"
                work.mkdir()
                root = Path(directory) / "root"
                root.mkdir()  # namespace.py mounts a tmpfs on it, so it must exist
                argv = self._namespace_argv(work, False, root)
                result = self._host(argv, input=json.dumps(request), timeout=120)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            return False, f"{type(exc).__name__}: {exc}"
        if result.returncode == 0:
            try:
                output = json.loads(result.stdout)
            except (ValueError, TypeError):
                return False, (result.stderr or "namespace probe returned unparsable output").strip()[:400]
            if "worker_error" in output:
                return False, str(output["worker_error"])[:400]
            return True, None
        detail = (result.stderr or result.stdout or "").strip()
        reason = detail.splitlines()[-1] if detail else f"namespace pipeline exited with {result.returncode}"
        return False, reason[:400]

    # --------------------------------------------------------------- execute

    def execute(self, work, request):
        timeout = request["limits"]["build_seconds" if request.get("build") else "wall_seconds"] + 30
        self.preparation = None
        if self.mode == "namespace":
            with tempfile.TemporaryDirectory(prefix="patchcheck-root-") as root:
                argv = self._namespace_argv(work, request.get("build"), root)
                result = self._host(argv, input=json.dumps(request), timeout=timeout)
        elif self.mode == "docker":
            result = self._execute_docker(work, request, timeout)
        else:
            result = self._execute_restricted(work, request, timeout)
        if isinstance(result, dict):
            # The docker backend synthesizes a result for container-level OOM
            # kills; there is no worker JSON to parse in that case.
            output, returncode, stderr = dict(result), None, ""
        else:
            try:
                output = json.loads(result.stdout)
            except (ValueError, TypeError) as exc:
                raise ConfigError(f"sandbox failed ({result.returncode}): {result.stderr[:4000]}") from exc
            returncode, stderr = result.returncode, result.stderr
        if returncode or "worker_error" in output:
            raise ConfigError(f"sandbox worker failed: {output.get('worker_error', stderr)}")
        if self.mode == "restricted":
            self._normalize_paths(output, work)
        output["sandbox"] = self.identity
        if self.preparation:
            output["sandbox_preparation"] = self.preparation
        return output

    @staticmethod
    def _hand_build_tree_to_container(work):
        """Give the container user (1000:1000) write access to a root-owned tree.

        Root callers create the per-run build directories as root, and the
        docker backend deliberately keeps the container non-root, so the tree
        is handed to uid/gid 1000 instead of running the build as root. The
        handover is returned and recorded next to the sandbox identity, so
        the evidence never hides that the host-side chown happened.
        """
        entries = 0
        try:
            for base, dirs, files in os.walk(work):
                os.lchown(base, 1000, 1000)
                entries += 1
                for name in dirs:
                    os.lchown(os.path.join(base, name), 1000, 1000)
                    entries += 1
                for name in files:
                    os.lchown(os.path.join(base, name), 1000, 1000)
                    entries += 1
        except OSError as exc:
            raise ConfigError(
                "the host runs patchcheck as root, so each build directory must be "
                f"handed to the container user (chown 1000:1000 on {work}): {exc}") from exc
        return {"step": "chown", "uid": 1000, "gid": 1000, "entries": entries,
                "path": str(Path(work).resolve()),
                "reason": "root host callers create build directories as root; the "
                          "non-root container user needs write access to build"}

    def _execute_docker(self, work, request, timeout):
        name = "patchcheck-" + uuid.uuid4().hex
        limits = request["limits"]
        # The container writes into the bind-mounted build directory, so its
        # uid must own that directory. Hardcoding 1000:1000 fails instantly
        # ("permission denied" from cmake/gcc) whenever the invoking host
        # user has a different uid; mapping the invoking user keeps every
        # execution non-root while making the mount writable. Root callers
        # keep the image's 1000:1000 so a root host user never widens the
        # container's privileges -- their root-owned build directories are
        # chowned to 1000:1000 instead (see _hand_build_tree_to_container);
        # without that handover every "cc -o target" dies with
        # "ld: cannot open output file target: Permission denied".
        uid, gid = os.getuid(), os.getgid()
        user_flag = "--user=1000:1000" if uid == 0 else f"--user={uid}:{gid}"
        if uid == 0 and request.get("build"):
            self.preparation = self._hand_build_tree_to_container(work)
        argv = ["docker", "run", "--name", name, "--pull=never", "--platform=linux/amd64", "--network=none",
                "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", user_flag,
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
        return result

    def _execute_restricted(self, work, request, timeout):
        """Best-available isolation without user namespaces or Docker.

        The target still never runs unsupervised: the worker enforces rlimits,
        wall-clock, sampled memory, output and process caps, starts the target
        in a fresh session it can kill wholesale, and hands it a clean
        environment plus a private temporary directory. ``setpriv`` empties the
        capability bounding set and sets no-new-privs so a setuid bit cannot
        escalate. What this mode cannot give is a private filesystem view,
        network isolation or /proc; the sandbox identity says so explicitly.
        """
        work = Path(work).resolve()
        request = dict(request, cwd=str(work))
        argv = self.capability_argv + [sys.executable, "-I", str(self.directory / "worker.py")]
        with tempfile.TemporaryDirectory(prefix="patchcheck-tmp-") as private:
            request["tmp"] = private
            result = self._host(argv, input=json.dumps(request), timeout=timeout)
        return result

    @staticmethod
    def _normalize_paths(result, work):
        """Rewrite the real build-directory prefix to the canonical /work view.

        With a chroot, source paths inside sanitizer stacks and tool output are
        literally ``/work/...``. Without one they carry the host path, and
        ``evidence.LOCATION`` would match nothing, silently downgrading every
        sanitizer finding to an unconfirmed observation. Normalizing the prefix
        gives all modes one location encoding; the rewrite is recorded in the
        result rather than passed off as chroot output, and the ``argv`` field
        keeps the command exactly as it was executed.
        """
        real = str(work)
        raw = real.encode()
        changed = False
        for key in ("stdout_base64", "stderr_base64"):
            data = base64.b64decode(result.get(key) or "")
            if raw in data:
                data = data.replace(raw, b"/work")
                changed = True
            result[key] = base64.b64encode(data).decode()
        for key in ("stdout", "stderr"):
            value = result.get(key) or ""
            if real in value:
                value = value.replace(real, "/work")
                changed = True
            result[key] = value
        if changed:
            result["path_normalization"] = {"from": real, "to": "/work",
                                            "reason": "restricted mode has no chroot; "
                                                      "host build-directory prefix mapped to /work"}
