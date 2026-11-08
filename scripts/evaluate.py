"""Run the real evaluation matrix; expected codes are assertions, never verdicts.

All verdicts come from patchcheck executing targets in its selected sandbox.
This script exits 1 if any actual result disagrees with the scenario contract.

Generated regressions are persisted into ``--suite-root`` (``.patchcheck-suites``
by default) rather than inside the evidence directory. That directory is the
durable store a later CI execution restores before evaluating, so a minimized
reproducer produced by one run is genuinely re-checked by the next one.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUITE_ROOT = ROOT / ".patchcheck-suites"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("docker", "namespace"), default="docker")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--targets", nargs="+", default=["cjson", "jq", "record-reader"])
    parser.add_argument("--only", nargs="+", help="limit to named scenarios, e.g. record-reader-correct")
    parser.add_argument("--suite-root", type=Path, default=DEFAULT_SUITE_ROOT,
                        help="durable regression suite root, scoped per scenario; restored by CI before a run")
    parser.add_argument("--fresh-suites", action="store_true",
                        help="do not read or write durable suites; every scenario starts with no persisted regressions")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
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
    (output / "evaluation.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    return 0 if all(row["passed"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
