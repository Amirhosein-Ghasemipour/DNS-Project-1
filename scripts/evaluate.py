"""Run the real evaluation matrix; expected codes are assertions, never verdicts.

All verdicts come from patchcheck executing targets in its selected sandbox.
This script exits 1 if any actual result disagrees with the scenario contract,
and 2 if the host or the checkout cannot support an evaluation at all.

Generated regressions are persisted into ``--suite-root`` (``.patchcheck-suites``
by default) rather than inside the evidence directory. That directory is the
durable store a later CI execution restores before evaluating, so a minimized
reproducer produced by one run is genuinely re-checked by the next one. The
evidence directory also receives ``evaluation.html`` -- a self-contained,
browser-readable report listing every scenario that ran, its expected and
actual exit codes, recorded errors and its full console log.

A fresh checkout -- or the distributed archive -- carries the target source
files but not the nested ``.git`` databases the pinned revisions live in, so
this script prepares itself first: ``scripts/restore_sources.py`` rebuilds the
nested histories from ``targets/bundles`` and ``scripts/prepare_examples.py``
regenerates the pinned patches, inputs and configurations. Both steps are
idempotent, and ``--skip-setup`` opts out for CI jobs that restore sources
themselves. Skipping them used to turn every scenario into
``BUILD_OR_CONFIG_ERROR`` (exit 30) with the bare message ``fatal: not a git
repository``; now the run either prepares itself or stops with an actionable
message before any scenario executes.
"""
import argparse
import json
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluation_html import write_report  # noqa: E402  (scripts/ sibling module)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUITE_ROOT = ROOT / ".patchcheck-suites"


def fail(message):
    print(f"evaluation setup failed: {message}", file=sys.stderr)
    raise SystemExit(2)


def preflight(root):
    """Name every missing host prerequisite before any scenario runs."""
    problems = []
    if sys.version_info < (3, 10):
        problems.append(f"Python 3.10+ is required, found {platform.python_version()}")
    for tool, package in (("git", "git"), ("cc", "build-essential"), ("readelf", "binutils")):
        if shutil.which(tool) is None:
            problems.append(f"'{tool}' is not on PATH; Debian/Ubuntu: sudo apt install {package}")
    if not (root / "targets/bundles/manifest.json").is_file():
        problems.append("targets/bundles/manifest.json is missing; the pinned target "
                        "histories cannot be rebuilt from this checkout")
    if problems:
        fail(" | ".join(problems))


def setup_sources(root):
    """Restore the nested git histories, then regenerate the pinned artifacts."""
    for script in ("scripts/restore_sources.py", "scripts/prepare_examples.py"):
        run = subprocess.run([sys.executable, script], cwd=root, capture_output=True, text=True)
        output = (run.stdout + run.stderr).strip()
        if output:
            print(output, flush=True)
        if run.returncode:
            fail(f"{script} exited with {run.returncode}; a pinned revision or fixture could "
                 "not be rebuilt (see its output above)")


def summarize_failure(output, name, report):
    """Print the recorded error lines so a failure is diagnosable in place."""
    for message in (report.get("errors") or [])[:3]:
        print(f"    error: {' '.join(str(message).split())}", flush=True)
    print(f"    evidence: {output / (name + '.log')} and {(output / name) / 'report.json'}",
          flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("auto", "namespace", "docker", "restricted"), default="auto",
                        help="sandbox backend; auto probes the namespace pipeline and falls back to "
                             "docker, then to the restricted mode (default: auto)")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--targets", nargs="+", default=["cjson", "jq", "record-reader"])
    parser.add_argument("--only", nargs="+", help="limit to named scenarios, e.g. record-reader-correct")
    parser.add_argument("--suite-root", type=Path, default=DEFAULT_SUITE_ROOT,
                        help="durable regression suite root, scoped per scenario; restored by CI before a run")
    parser.add_argument("--fresh-suites", action="store_true",
                        help="do not read or write durable suites; every scenario starts with no persisted regressions")
    parser.add_argument("--skip-setup", action="store_true",
                        help="skip the automatic restore/prepare preflight (for CI jobs that restore sources themselves)")
    args = parser.parse_args()
    output = args.output.resolve()
    started = time.time()
    preflight(ROOT)
    if output.exists():
        fail(f"output directory already exists: {output} (evidence is never overwritten; "
             "choose a new name or remove the old directory)")
    output.mkdir(parents=True)
    if not args.skip_setup:
        setup_sources(ROOT)
    rows = []
    scenarios = [f"{target}-{variant}" for target in args.targets for variant in ("correct", "incomplete", "regression")]
    if args.only:
        scenarios = [name for name in scenarios if name in set(args.only)]
    for name in scenarios:
        expected = {"correct": 0, "incomplete": 10, "regression": 20}[name.rsplit("-", 1)[1]]
        destination = output / name
        # Scenario scoping keeps one target's reproducer out of another version
        # pair; entries also carry the scenario name, so a shared root is safe.
        command = [sys.executable, "-m", "patchcheck", "run", str(ROOT / "configs" / f"{name}.json"),
                   "--output", str(destination), "--backend", args.backend]
        if args.fresh_suites:
            command.append("--no-regressions")
        else:
            command += ["--suite-root", str((args.suite_root / name).resolve())]
        print(f"Evaluating {name} (expected {expected})", flush=True)
        run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        (output / f"{name}.log").write_text(run.stdout + run.stderr, encoding="utf-8")
        report = json.loads((destination / "report.json").read_text()) if (destination / "report.json").exists() else {}
        imported = sum(1 for item in report.get("executions", []) if item.get("generated"))
        rows.append({"scenario": name, "expected_exit": expected, "actual_exit": run.returncode,
                     "passed": run.returncode == expected and report.get("exit_code") == expected,
                     "generated_executions": imported,
                     "persisted_regressions": len(report.get("persisted_regressions", [])),
                     "report": f"{name}/report.json"})
        print(f"  actual {run.returncode}: {'OK' if rows[-1]['passed'] else 'FAILED'}"
              f" (generated re-executions: {imported})", flush=True)
        if not rows[-1]["passed"]:
            summarize_failure(output, name, report)
    (output / "evaluation.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    meta = {
        "Backend": args.backend,
        "Project root": str(ROOT),
        "Regression suites": "disabled (--fresh-suites)" if args.fresh_suites else str(args.suite_root.resolve()),
        "Python": platform.python_version(),
        "Host": platform.platform(),
        "Wall time": f"{time.time() - started:.1f}s",
    }
    report_path = write_report(output, rows, meta)
    print(f"HTML report: {report_path}", flush=True)
    return 0 if all(row["passed"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
