"""Rootless Linux namespace setup. Called only through unshare by the backend.

Only the toolchain, selected source/build directory and worker are exposed.
Mount capabilities are dropped before the worker and target start.
"""

import os
import subprocess
import sys
from pathlib import Path


def run(*argv):
    subprocess.run(argv, check=True, stdout=subprocess.DEVNULL)


def main():
    root, work, worker, writable = sys.argv[1:]
    root = Path(root)
    run("mount", "--make-rprivate", "/")
    run("mount", "-t", "tmpfs", "-o", "size=32m,nosuid,nodev", "tmpfs", str(root))
    for path in ("usr", "bin", "sbin", "lib", "lib64"):
        source = Path("/") / path
        if source.exists():
            destination = root / path
            destination.mkdir()
            run("mount", "--rbind", str(source), str(destination))
            mounts = [line.split()[4].replace("\\040", " ") for line in Path("/proc/self/mountinfo").read_text().splitlines()]
            for mountpoint in sorted((p for p in mounts if p == str(destination) or p.startswith(str(destination) + "/")), reverse=True):
                run("mount", "-o", "remount,bind,ro,nosuid,nodev", mountpoint)
    for path in ("work", "validator", "tmp", "proc", "dev", "etc"):
        (root / path).mkdir()
    alternatives = Path("/etc/alternatives")
    if alternatives.exists():
        (root / "etc/alternatives").mkdir()
        run("mount", "--bind", str(alternatives), str(root / "etc/alternatives"))
        run("mount", "-o", "remount,bind,ro,nosuid,nodev", str(root / "etc/alternatives"))
    for name in ("null", "zero", "urandom", "random"):
        destination = root / "dev" / name
        destination.touch()
        run("mount", "--bind", "/dev/" + name, str(destination))
    cache = Path("/etc/ld.so.cache")
    if cache.exists():
        (root / "etc/ld.so.cache").touch()
        run("mount", "--bind", str(cache), str(root / "etc/ld.so.cache"))
        run("mount", "-o", "remount,bind,ro", str(root / "etc/ld.so.cache"))
    run("mount", "--bind", work, str(root / "work"))
    run("mount", "-o", "remount,bind," + ("rw" if writable == "1" else "ro") + ",nosuid,nodev", str(root / "work"))
    (root / "validator/worker.py").touch()
    run("mount", "--bind", worker, str(root / "validator/worker.py"))
    run("mount", "-o", "remount,bind,ro", str(root / "validator/worker.py"))
    run("mount", "-t", "tmpfs", "-o", "size=256m,nosuid,nodev", "tmpfs", str(root / "tmp"))
    run("mount", "-t", "proc", "-o", "ro,nosuid,nodev,noexec", "proc", str(root / "proc"))
    run("mount", "-o", "remount,bind,ro,nosuid,nodev", str(root))
    os.chroot(root)
    os.chdir("/work")
    os.execv("/usr/bin/setpriv", ["setpriv", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                                "--no-new-privs", "/usr/bin/python3", "-I", "/validator/worker.py"])


if __name__ == "__main__":
    main()

