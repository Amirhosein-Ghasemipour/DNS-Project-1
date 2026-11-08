"""Reconstruct the nested target Git repositories in a clean checkout.

A checkout of the parent repository contains the target *files* but not the
nested ``.git`` databases the pinned configuration revisions need. This script
rebuilds each repository from the checked-in bundle in ``targets/bundles/`` and
verifies that every pinned commit resolves afterwards.

It is safe to run repeatedly and is a no-op for a repository whose pinned
revisions already resolve.

Usage:
    python scripts/restore_sources.py            # restore what is missing
    python scripts/restore_sources.py --check    # fail if anything is missing
"""

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ROOT = ROOT / "targets/bundles"


def git(repository, *args, check=True):
    command = ["git", "-c", f"safe.directory={Path(repository).as_posix()}", "-C", str(repository), *args]
    result = subprocess.run(command, capture_output=True)
    if check and result.returncode:
        raise SystemExit(f"git {' '.join(args)} failed in {repository}: "
                         f"{result.stderr.decode('utf-8', 'replace').strip()}")
    return result


def resolves(repository, commit):
    if not (Path(repository) / ".git").exists():
        return False
    return git(repository, "cat-file", "-e", f"{commit}^{{commit}}", check=False).returncode == 0


def restore(repository, bundle, entry):
    """Materialize the bundle at ``repository`` and check out its recorded HEAD.

    Cloning is used rather than fetching: the supplied upstream histories are
    shallow, and a shallow bundle cannot be fetched into a repository with no
    matching shallow boundary. The clone is staged beside the target so that
    existing tracked source files are restored in place rather than deleted.
    """
    repository = Path(repository)
    repository.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="patchcheck-restore-") as directory:
        staged = Path(directory) / "clone"
        clone = subprocess.run(["git", "clone", "--quiet", str(bundle), str(staged)], capture_output=True)
        if clone.returncode:
            raise SystemExit(f"cannot clone {bundle.name}: {clone.stderr.decode('utf-8', 'replace').strip()}")
        checkout = subprocess.run(["git", "-C", str(staged), "checkout", "--quiet", entry["head"]],
                                  capture_output=True)
        if checkout.returncode:
            raise SystemExit(f"cannot check out {entry['head']} in {bundle.name}: "
                             f"{checkout.stderr.decode('utf-8', 'replace').strip()}")
        if repository.exists() and any(repository.iterdir()):
            # Source files are normally present in a parent-repository checkout.
            # Move only the Git database and let Git restore tracked content, so
            # untracked developer files are left untouched.
            shutil.move(str(staged / ".git"), str(repository / ".git"))
            restore_files = subprocess.run(
                ["git", "-c", f"safe.directory={repository.as_posix()}", "-C", str(repository),
                 "checkout", "--force", "--quiet", "--detach", entry["head"]], capture_output=True)
            if restore_files.returncode:
                raise SystemExit(f"cannot restore tracked files in {repository}: "
                                 f"{restore_files.stderr.decode('utf-8', 'replace').strip()}")
        else:
            if repository.exists():
                repository.rmdir()
            shutil.copytree(staged, repository)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report missing prerequisites, change nothing")
    parser.add_argument("--root", type=Path, default=ROOT,
                        help="checkout to restore (defaults to the project containing this script)")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    manifest_path = root / "targets/bundles/manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(f"missing {manifest_path.relative_to(root)}; run scripts/package_sources.py")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    problems = 0
    for relative, entry in sorted(manifest["repositories"].items()):
        repository = root / relative
        pinned = entry.get("pinned", [])
        if all(resolves(repository, commit) for commit in pinned):
            print(f"{relative}: all pinned revisions present")
            continue
        if args.check:
            problems += 1
            missing = [commit for commit in pinned if not resolves(repository, commit)]
            print(f"{relative}: MISSING pinned revisions {missing}")
            continue
        bundle = root / entry["bundle"]
        if not bundle.is_file():
            raise SystemExit(f"missing bundle: {entry['bundle']}")
        restore(repository, bundle, entry)
        missing = [commit for commit in pinned if not resolves(repository, commit)]
        if missing:
            raise SystemExit(f"{relative}: pinned revisions still missing after restore: {missing}")
        print(f"{relative}: restored {len(pinned)} pinned revisions from {entry['bundle']}")
    if problems:
        raise SystemExit(f"{problems} repositories need restoration; run scripts/restore_sources.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
