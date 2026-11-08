"""Package the nested target Git histories into checked-in bundles.

A Git checkout of the parent repository does not carry nested ``.git``
databases, so ``source.materialize`` cannot resolve pinned commits on a clean
runner. This script writes one Git bundle per target repository under
``targets/bundles/`` together with a manifest of the exact refs and the commit
hashes the configurations pin. ``scripts/restore_sources.py`` consumes them.

Usage:
    python scripts/package_sources.py            # create/update bundles
    python scripts/package_sources.py --check    # verify bundles match the repos
"""

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ROOT = ROOT / "targets/bundles"

# repository path (relative to the project root) -> bundle file stem
REPOSITORIES = {
    "targets/cjson/upstream": "cjson-upstream",
    "targets/jq/upstream": "jq-upstream",
    "targets/record_reader/repository": "record_reader-repository",
}


def git(repository, *args, check=True):
    command = ["git", "-c", f"safe.directory={Path(repository).as_posix()}", "-C", str(repository), *args]
    result = subprocess.run(command, capture_output=True)
    if check and result.returncode:
        raise SystemExit(f"git {' '.join(args)} failed in {repository}: "
                         f"{result.stderr.decode('utf-8', 'replace').strip()}")
    return result


def pinned_revisions():
    """Every commit hash the supplied configurations depend on, per repository."""
    pinned = {}
    for path in sorted((ROOT / "configs").glob("*.json")):
        config = json.loads(path.read_text(encoding="utf-8"))
        for role in ("baseline", "patched"):
            version = config["versions"][role]
            repository = version["repository"].replace("\\", "/")
            pinned.setdefault(repository, set()).add(version["revision"].lower())
    return pinned


def describe(repository):
    """Describe one repository: HEAD, all refs, and whether it is shallow."""
    head = git(repository, "rev-parse", "HEAD").stdout.decode().strip()
    refs = git(repository, "for-each-ref", "--format=%(refname) %(objectname)").stdout.decode().strip().splitlines()
    shallow = (Path(repository) / ".git/shallow").exists()
    detached = git(repository, "symbolic-ref", "-q", "HEAD", check=False).returncode != 0
    return {"head": head, "refs": [line.split() for line in refs if line], "shallow": shallow,
            "detached": detached}


def bundle_contains(bundle, commits):
    """Clone a bundle into a temporary directory and check every commit resolves.

    Verification is a real clone: a shallow bundle can be header-valid yet still
    be uncloneable, so inspecting the header proves nothing.
    """
    with tempfile.TemporaryDirectory(prefix="patchcheck-bundle-check-") as directory:
        clone_path = Path(directory) / "clone"
        clone = subprocess.run(["git", "clone", "--quiet", "--no-checkout", str(bundle), str(clone_path)],
                               capture_output=True)
        if clone.returncode:
            return False
        return all(subprocess.run(["git", "-C", str(clone_path), "cat-file", "-e", f"{commit}^{{commit}}"],
                                  capture_output=True).returncode == 0
                   for commit in commits)


def write_bundle(repository, destination, commits):
    """Bundle the history needed to resolve ``commits`` without any remote.

    A shallow repository (both supplied upstreams are) makes ``--all`` produce a
    bundle whose prerequisite lines refer to the shallow boundary, which cannot
    be cloned. Bundling ``HEAD`` alone works there, so the simple form is tried
    first and the result is proved by cloning it. Only when a pinned commit is
    unreachable from ``HEAD`` are explicit temporary refs added.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    attempts = [["HEAD"]]
    if commits:
        refs = [f"{commit}:refs/patchcheck/{index}" for index, commit in enumerate(sorted(commits))]
        attempts.append(["HEAD", *refs] if commits else refs)
    problems = []
    for refs in attempts:
        destination.unlink(missing_ok=True)
        result = subprocess.run(["git", "-c", f"safe.directory={Path(repository).as_posix()}", "-C",
                                 str(repository), "bundle", "create", str(destination), *refs],
                                capture_output=True)
        if result.returncode:
            problems.append(result.stderr.decode("utf-8", "replace").strip())
            continue
        if bundle_contains(destination, commits):
            return
        problems.append(f"bundle with refs {refs} does not contain every pinned commit")
    destination.unlink(missing_ok=True)
    raise SystemExit(f"cannot bundle {repository}: " + "; ".join(problems))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify existing bundles instead of rewriting them")
    args = parser.parse_args(argv)
    pinned = pinned_revisions()
    manifest = {"schema_version": 1, "generated_by": "scripts/package_sources.py", "repositories": {}}
    for relative, stem in REPOSITORIES.items():
        repository = ROOT / relative
        if not (repository / ".git").exists():
            raise SystemExit(f"missing Git repository: {relative}; recreate it before packaging")
        bundle = BUNDLE_ROOT / f"{stem}.bundle"
        if args.check:
            if not bundle.is_file():
                raise SystemExit(f"missing bundle: {bundle.relative_to(ROOT)}; run scripts/package_sources.py")
            if not bundle_contains(bundle, pinned.get(relative, set())):
                raise SystemExit(f"{bundle.name} cannot resolve every pinned commit; "
                                 f"run scripts/package_sources.py")
        else:
            write_bundle(repository, bundle, pinned.get(relative, set()))
        info = describe(repository)
        missing = sorted(commit for commit in pinned.get(relative, set())
                         if git(repository, "cat-file", "-e", f"{commit}^{{commit}}", check=False).returncode)
        if missing:
            raise SystemExit(f"{relative}: pinned revisions are not present in the repository: {missing}")
        manifest["repositories"][relative] = {
            "bundle": bundle.relative_to(ROOT).as_posix(),
            "bundle_sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
            "head": info["head"], "shallow": info["shallow"], "detached": info["detached"],
            "pinned": sorted(pinned.get(relative, set())),
            "refs": [{"name": name, "commit": commit} for name, commit in info["refs"]]}
    destination = BUNDLE_ROOT / "manifest.json"
    if args.check:
        existing = json.loads(destination.read_text(encoding="utf-8"))
        for relative, entry in manifest["repositories"].items():
            if existing["repositories"].get(relative, {}).get("bundle_sha256") != entry["bundle_sha256"]:
                raise SystemExit(f"{relative}: bundle changed; run scripts/package_sources.py and commit the result")
        print(f"Bundles verified for {len(manifest['repositories'])} repositories.")
        return 0
    destination.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    total = sum((BUNDLE_ROOT / f"{stem}.bundle").stat().st_size for stem in REPOSITORIES.values())
    print(f"Packaged {len(REPOSITORIES)} repositories into targets/bundles ({total} bytes).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
