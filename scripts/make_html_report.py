"""Regenerate ``evaluation.html`` from an existing evidence directory.

Useful when the artifacts were produced before the HTML report existed, or by
CI: nothing is re-run, the report is rebuilt purely from ``evaluation.json``,
the per-scenario ``report.json``/``summary.txt`` files and the console logs
that are already on disk.

    python3 scripts/make_html_report.py --output artifacts/evaluation-20251111-143005
    python3 scripts/make_html_report.py --output artifacts/evaluation-... --force
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluation_html import write_report  # noqa: E402  (scripts/ sibling module)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path,
                        help="evidence directory produced by scripts/evaluate.py "
                             "(the one holding evaluation.json and <scenario>/report.json)")
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing evaluation.html")
    args = parser.parse_args()
    output = args.output.resolve()
    evaluation = output / "evaluation.json"
    if not evaluation.is_file():
        print(f"error: {evaluation} not found; pass the evidence directory that "
              "scripts/evaluate.py created (it must contain evaluation.json)", file=sys.stderr)
        return 2
    rows = json.loads(evaluation.read_text(encoding="utf-8"))
    destination = output / "evaluation.html"
    if destination.exists() and not args.force:
        print(f"error: {destination} already exists (use --force to overwrite)", file=sys.stderr)
        return 2
    meta = {
        "Evidence directory": str(output),
        "Source": "regenerated from existing evidence; the scenarios ran earlier",
        "Scenarios": str(len(rows)),
        "Generated at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    write_report(output, rows, meta)
    print(f"HTML report: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
