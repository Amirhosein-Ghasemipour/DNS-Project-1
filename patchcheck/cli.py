"""Public CLI. JSON and a readable report are persisted even on tool failure."""

import argparse
import base64
import json
import subprocess
import sys
import traceback
from pathlib import Path

from . import __version__
from .config import ConfigError, load
from .decision import decide
from .evidence import analyze, matches_expected, reproduces
from .runner import Runner, Testbed, write_json
from .sandbox import Sandbox
from .source import sha256


def summary(report):
    lines = [f"Patchcheck: {report.get('name', 'configuration')} — {report['status']} (exit {report['exit_code']})", ""]
    for key, value in report["independent_statuses"].items():
        lines.append(f"{key}: {value}")
    for finding in report.get("findings", []):
        lines.append(f"[{finding['profile']}] {finding['test_id']}: {finding['status']} | correlation: {finding['correlation']['status']}")
    for change in report.get("hardening", {}).get("warnings", []):
        lines.append(f"Hardening warning: {change['protection']}: {change['baseline']} -> {change['patched']}")
    for message in report.get("errors", []):
        lines.append("Error: " + message)
    for message in report.get("inconclusive", []):
        lines.append("Inconclusive: " + message)
    lines += ["", "Conclusions are limited to the recorded inputs, builds, references and execution limits.",
              "Absence of an observed error is not proof that all vulnerabilities have been eliminated.",
              "New observations and stack/diff overlap do not by themselves prove patch causation."]
    return "\n".join(lines) + "\n"


def replay(args):
    manifest_path = Path(args.manifest).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    # manifest is output/reproducers/profile/test/manifest.json
    output = manifest_path.parents[3]
    profile = manifest["profile"]
    sandbox = Sandbox(args.backend, args.image)
    config = json.loads((output / "effective-config.json").read_text(encoding="utf-8"))
    data = (manifest_path.parent / "original.bin").read_bytes()
    if sha256(data) != manifest["original_sha256"]:
        raise ConfigError("original reproducer input hash mismatch")
    # Same request construction and analysis the Runner uses, so a manual
    # replay cannot drift from what the automated run actually did.
    tests = Testbed(config, profile, output / "builds" / profile, sandbox)
    for role in ("baseline", "patched"):
        tests.verify_binary(role, manifest["builds"][role])
    results = [tests.pair(manifest["test"], data) for _ in range(3)]
    write_json(manifest_path.parent / "manual-replays.json", results)
    stable = all(all((reproduces(pair[role], manifest["initial"][role]["error"]["fingerprint"])
                         if manifest["initial"][role]["error"]["confirmed"] else
                         matches_expected(pair[role], manifest["test"]["expected"]))
                        for role in pair) for pair in results)
    print(f"Recorded 3 paired replays in {manifest_path.parent / 'manual-replays.json'}")
    return 0 if stable else 40


def main(argv=None):
    parser = argparse.ArgumentParser(description="Isolated, evidence-based C/C++ patch validation")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="build and compare the configured versions")
    run.add_argument("config")
    run.add_argument("--output", required=True, help="new artifact directory; existing evidence is never overwritten")
    run.add_argument("--regressions", action="append", default=[],
                     help="additional directory of generated regression JSON files; the project suite is always included")
    run.add_argument("--no-regressions", action="store_true", help="skip the persisted project regression suite")
    run.add_argument("--suite-root",
                     help="directory used to persist and re-import generated regressions; defaults to the "
                          "configured project suite. Evaluation uses a per-scenario root so results cannot "
                          "depend on the order scenarios ran in.")
    check = sub.add_parser("check-config", help="validate configuration without compiling or executing targets")
    check.add_argument("config")
    rep = sub.add_parser("replay", help="record three additional paired executions from a reproducer bundle")
    rep.add_argument("manifest")
    for command in (run, rep):
        command.add_argument("--backend", choices=("docker", "namespace"), default="docker")
        command.add_argument("--image", default="patchcheck-toolchain:1")
    args = parser.parse_args(argv)
    if args.command != "run":
        try:
            if args.command == "check-config":
                config, _ = load(args.config)
                print(f"Configuration valid: {config['name']}")
                return 0
            return replay(args)
        except (ConfigError, OSError, ValueError, subprocess.SubprocessError) as exc:
            print(str(exc), file=sys.stderr)
            return 30
    output = Path(args.output).resolve()
    if output.exists():
        print(f"Output already exists; choose a new evidence directory: {output}", file=sys.stderr)
        return 30
    output.mkdir(parents=True)
    report = {"schema_version": 1, "tool_version": __version__, "findings": [], "executions": [],
              "errors": [], "inconclusive": [], "functional_complete": False}
    try:
        config, root = load(args.config)
        report["name"] = config["name"]
        write_json(output / "effective-config.json", config)
        sandbox = Sandbox(args.backend, args.image)
        report["sandbox"] = sandbox.identity
        suite = Path(args.suite_root).resolve() if args.suite_root else Path(root) / config["regression_suite"]
        runner = Runner(config, root, output, sandbox, report,
                        regression_root=None if args.no_regressions else suite)
        runner.build()
        runner.test()
        directories = list(args.regressions)
        if suite.is_dir() and not args.no_regressions:
            directories.append(suite)
        if directories:
            runner.import_regressions(directories)
    except Exception as exc:
        report["errors"].append(f"{type(exc).__name__}: {exc}")
        try:
            output.mkdir(parents=True, exist_ok=True)
            (output / "tool-error.txt").write_text(traceback.format_exc(), encoding="utf-8")
        except OSError as secondary:
            print(f"cannot persist tool error evidence in {output}: {secondary}", file=sys.stderr)
            print(traceback.format_exc(), file=sys.stderr)
    code = decide(report)
    write_json(output / "report.json", report)
    text = summary(report)
    (output / "summary.txt").write_text(text, encoding="utf-8")
    print(text, end="")
    return code

