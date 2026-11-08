"""Export exact local Git revisions, apply supplied diffs, and fingerprint source."""

import hashlib
import io
import subprocess
import tarfile
from pathlib import Path

from .config import ConfigError, inside


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git(repository, *args):
    command = ["git", "-c", f"safe.directory={repository.as_posix()}", "-C", str(repository), *args]
    result = subprocess.run(command, capture_output=True, timeout=60)
    if result.returncode:
        raise ConfigError(result.stderr.decode("utf-8", "replace"))
    return result.stdout


def materialize(root, version, destination):
    repository = inside(root, version["repository"])
    commit = git(repository, "rev-parse", "--verify", version["revision"] + "^{commit}").decode().strip()
    archive = git(repository, "archive", "--format=tar", commit)
    destination.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
        for member in stream.getmembers():
            target = (destination / member.name).resolve()
            if not target.is_relative_to(destination.resolve()) or not (member.isfile() or member.isdir()):
                raise ConfigError(f"unsafe source archive entry: {member.name}; symlinks/submodules are unsupported")
        # Members above are restricted to ordinary files/directories; extraction
        # cannot create links, devices or paths outside this new directory.
        stream.extractall(destination)
    patches = []
    for name in version.get("patches", []):
        data = inside(root, name).read_bytes()
        if b"120000" in data or b"160000" in data:
            raise ConfigError("symlink and submodule patches are unsupported")
        result = subprocess.run(["git", "apply", "--whitespace=nowarn", "-"],
                                cwd=destination, input=data, capture_output=True, timeout=30)
        if result.returncode:
            raise ConfigError(f"patch {name}: {result.stderr.decode('utf-8', 'replace')}")
        if any(file.is_symlink() for file in destination.rglob("*")):
            raise ConfigError("patched source must not contain symlinks")
        patches.append({"path": name, "sha256": sha256(data)})
    overlays = []
    for target, name in version.get("overlays", {}).items():
        data = inside(root, name).read_bytes()
        output = inside(destination, target)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
        overlays.append({"path": target, "source": name, "sha256": sha256(data)})
    digest = hashlib.sha256()
    for file in sorted(destination.rglob("*")):
        if file.is_file():
            name = file.relative_to(destination).as_posix().encode()
            data = file.read_bytes()
            digest.update(len(name).to_bytes(8, "big") + name + len(data).to_bytes(8, "big") + data)
    return {"repository": str(repository), "commit": commit, "patches": patches,
            "overlays": overlays, "source_sha256": digest.hexdigest()}


def diff_sources(before, after):
    result = subprocess.run(["git", "diff", "--no-index", "--no-ext-diff", "--no-renames", "--unified=0",
                             str(before), str(after)], capture_output=True, timeout=60)
    if result.returncode not in (0, 1):
        raise ConfigError(result.stderr.decode("utf-8", "replace"))
    text = result.stdout.decode("utf-8", "replace")
    # Normalize generated paths for relocation and precise runtime file matching.
    for source in (before, after):
        prefix = source.as_posix() + "/"
        text = text.replace("a/" + prefix, "a/").replace("b/" + prefix, "b/")
        # Git on Windows may omit the slash between a/b and an absolute drive.
        text = text.replace("a" + prefix, "a/").replace("b" + prefix, "b/")
    return text

