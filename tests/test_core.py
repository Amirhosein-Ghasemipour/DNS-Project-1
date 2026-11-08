import base64
import copy
import json
import shutil
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from patchcheck.config import ConfigError, load
from patchcheck.correlation import correlate, equivalent, parse_diff
from patchcheck.decision import decide
from patchcheck.evidence import analyze, matches_expected, observation_key
from patchcheck.hardening import assess, warnings
from patchcheck.minimize import ddmin

ROOT = Path(__file__).resolve().parents[1]


def result(stderr="", stdout="", code=0, signal=None, resource=None):
    return analyze({"stderr": stderr, "stdout": stdout, "returncode": code,
                    "exit_code": code if code >= 0 else None, "signal": signal,
                    "resource_limit": resource,
                    "stdout_base64": base64.b64encode(stdout.encode()).decode(),
                    "stderr_base64": base64.b64encode(stderr.encode()).decode()})


def memory_error(line=10, function="copy_record", kind="heap-buffer-overflow"):
    return result(f"ERROR: AddressSanitizer: {kind}\n    #0 0x123 in {function} /work/reader.c:{line}:2\n", code=1)


class EvidenceTests(unittest.TestCase):
    def test_signal_alone_is_not_a_confirmed_vulnerability(self):
        error = result(code=-11, signal="SIGSEGV")["error"]
        self.assertEqual(error["type"], "unclassified-crash")
        self.assertFalse(error["confirmed"])

    def test_sanitizer_needs_relevant_location(self):
        self.assertFalse(result("ERROR: AddressSanitizer: heap-buffer-overflow")["error"]["confirmed"])
        self.assertTrue(memory_error()["error"]["confirmed"])

    def test_asan_multiword_diagnosis_keeps_canonical_name(self):
        # Regression: the regex used to stop at the space, yielding "attempting".
        stderr = ("==7==ERROR: AddressSanitizer: attempting double-free on 0x502000000010 in thread T0:\n"
                  "    #1 0x1 in main /work/reader.c:10:5\n"
                  "0x502000000010 is located 0 bytes inside of 16-byte region [0x502000000010,0x502000000020)\n"
                  "SUMMARY: AddressSanitizer: double-free\n")
        error = result(stderr, code=1)["error"]
        self.assertEqual(error["type"], "double-free")
        self.assertTrue(error["confirmed"])

    def test_asan_unknown_crash_is_recovered_from_access_direction(self):
        # Regression: bulk copies surface as "unknown-crash", which was unconfirmed,
        # so a real baseline overflow could never confirm the original vulnerability.
        stderr = ("==7==ERROR: AddressSanitizer: unknown-crash on address 0x502000000010\n"
                  "WRITE of size 64 at 0x502000000010 thread T0\n"
                  "    #1 0x1 in main /work/reader.c:16:5\n"
                  "0x502000000020 is located 0 bytes to the right of 16-byte region\n")
        error = result(stderr, code=1)["error"]
        self.assertEqual(error["type"], "heap-buffer-overflow")
        self.assertTrue(error["confirmed"])

    def test_unknown_crash_without_direction_stays_unconfirmed(self):
        stderr = ("==7==ERROR: AddressSanitizer: unknown-crash on address 0x99\n"
                  "    #1 0x1 in main /work/a.c:9:5\n")
        error = result(stderr, code=1)["error"]
        self.assertEqual(error["type"], "unknown-crash")
        self.assertFalse(error["confirmed"])

    def test_fortify_abort_is_reported_not_silently_ignored(self):
        # Regression: -O2 + _FORTIFY_SOURCE aborts with this text, not "stack smashing".
        stderr = "*** buffer overflow detected ***: terminated\n/work/reader.c:16:5\n"
        error = result(stderr, code=-6, signal="SIGABRT")["error"]
        self.assertEqual(error["type"], "fortify-abort")
        self.assertIn("FORTIFY", error["mechanism"])

    def test_ubsan_report_cannot_overwrite_asan_memory_error(self):
        # Regression: a UBSan line in the same stderr clobbered the ASan type,
        # corrupting both the report and the fix-equivalence fingerprint.
        stderr = ("ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
                  "    #0 0x1 in main /work/a.c:10:2\n"
                  "/work/a.c:20:5: runtime error: signed integer overflow: 1 + 1\n")
        error = result(stderr, code=1)["error"]
        self.assertEqual(error["type"], "heap-buffer-overflow")
        self.assertEqual(error["mechanism"], "ASan+UBSan")
        self.assertEqual([x["type"] for x in error["secondary"]], ["signed-integer-overflow"])

    def test_ubsan_location_and_error_type(self):
        error = result("/work/parser.c:42:9: runtime error: load of null pointer of type 'char'", code=1)["error"]
        self.assertTrue(error["confirmed"])
        self.assertEqual(error["type"], "null-pointer-dereference")
        self.assertEqual(error["mechanism"], "UBSan")

    def test_resource_limit_cannot_confirm_vulnerability(self):
        observation = memory_error()
        observation["resource_limit"] = "output"
        self.assertFalse(analyze(observation)["error"]["confirmed"])

    def test_exact_reference_includes_binary_output_and_stderr(self):
        expected = {"exit_code": 2, "stdout": "invalid\n", "stderr": ""}
        self.assertTrue(matches_expected(result(stdout="invalid\n", code=2), expected))
        self.assertFalse(matches_expected(result(stdout="invalid\n", stderr="warning", code=2), expected))
        self.assertFalse(matches_expected(result(stdout="invalid", code=2), expected))

    def test_replay_key_ignores_addresses_but_not_location(self):
        first = memory_error()
        second = copy.deepcopy(first)
        second["stderr"] = second["stderr"].replace("0x123", "0x456")
        self.assertEqual(observation_key(first), observation_key(second))
        self.assertNotEqual(observation_key(first), observation_key(memory_error(11)))


class DiffTests(unittest.TestCase):
    def test_insertion_does_not_move_the_line_before_it(self):
        diff = parse_diff("--- a/reader.c\n+++ b/reader.c\n@@ -10,0 +11 @@\n+guard();\n")
        self.assertTrue(equivalent(memory_error(10), memory_error(10), diff))
        self.assertTrue(equivalent(memory_error(11), memory_error(12), diff))

    def test_unrelated_file_is_not_the_same_finding(self):
        changed = memory_error()
        changed["error"]["fingerprint"]["location"]["file"] = "other.c"
        self.assertFalse(equivalent(memory_error(), changed, {}))

    def test_dynamic_frame_can_associate_changed_caller_function(self):
        diff = parse_diff("--- a/reader.c\n+++ b/reader.c\n@@ -4,0 +5 @@ static int copy_record(void)\n+guard();\n")
        correlation = correlate({"baseline": memory_error(10)}, diff)
        self.assertNotEqual(correlation["status"], "Undetermined")
        self.assertEqual(correlation["caused_by_patch"], "Undetermined")

    def test_no_dynamic_evidence_is_undetermined(self):
        self.assertEqual(correlate({"patched": result()}, {})["status"], "Undetermined")


class MinimizerTests(unittest.TestCase):
    def test_preserves_predicate_and_reduces_bytes(self):
        minimum, stats = ddmin(b"prefix-FAIL-suffix", lambda data: b"FAIL" in data)
        self.assertEqual(minimum, b"FAIL")
        self.assertLess(stats["minimized_bytes"], stats["original_bytes"])

    def test_budget_is_bounded_and_original_preserved_when_no_reduction(self):
        original = b"abcdef"
        calls = []
        minimum, stats = ddmin(original, lambda data: calls.append(data) or False, budget=2)
        self.assertEqual(minimum, original)
        self.assertEqual(len(calls), 2)
        self.assertTrue(stats["budget_exhausted"])


class DecisionTests(unittest.TestCase):
    def test_priority_and_independent_results(self):
        report = {"findings": [{"status": "New Issue"}, {"status": "Functional Regression"}],
                  "errors": ["build failed"], "inconclusive": ["unstable"]}
        self.assertEqual(decide(report), 30)
        self.assertEqual(report["independent_statuses"]["security"], "Confirmed patched error")
        self.assertEqual(report["independent_statuses"]["functionality"], "Functional Regression")
        report["errors"] = []
        self.assertEqual(decide(report), 10)
        report["findings"].pop(0)
        self.assertEqual(decide(report), 20)
        report["findings"] = []
        self.assertEqual(decide(report), 40)

    def test_no_evidence_cannot_pass(self):
        self.assertEqual(decide({"findings": [], "errors": [], "inconclusive": []}), 40)


def observation(stderr="", stdout="", code=0, signal=None, expected=None):
    observation = result(stderr, stdout, code, signal)
    observation["expected_match"] = matches_expected(observation, expected or {"exit_code": code,
                                                                              "stdout": stdout, "stderr": ""})
    return observation


class ClassificationTests(unittest.TestCase):
    """Exit codes are decided from evidence, never from which profile saw it."""

    def runner(self):
        from patchcheck.runner import Runner
        runner = Runner.__new__(Runner)
        runner.report = {"findings": [], "inconclusive": [], "executions": [], "reproducers": []}
        runner.diff, runner.seen_errors, runner.regression_root = {}, set(), None
        runner.discovery_queue, runner.bundle_depth, runner.discoveries = [], 0, 0
        return runner

    def exit_code(self, runner):
        return decide(runner.report)

    def test_confirmed_patched_error_is_exit_10_with_unclassified_baseline(self):
        # Regression: a confirmed patched error returned 40 whenever the baseline
        # crash could not be named. Security confirmation must not depend on it.
        runner = self.runner()
        baseline = observation(code=-6, signal="SIGABRT")
        baseline["error"] = {"type": "unclassified-crash", "mechanism": "OS-signal", "confirmed": False,
                             "locations": [], "fingerprint": {"error_type": "unclassified-crash", "location": None},
                             "secondary": [], "root_cause": "Undetermined", "exploitability": "Not assessed"}
        patched = observation("ERROR: AddressSanitizer: heap-use-after-free\n    #1 0x1 in main /work/a.c:16:5\n", code=1)
        test = {"id": "t", "category": "invalid", "expected": {"exit_code": 2, "stdout": "", "stderr": ""}}
        runner.classify(test, "sanitized", {"baseline": baseline, "patched": patched},
                        {"baseline": True, "patched": True})
        self.assertEqual([f["status"] for f in runner.report["findings"]], ["New Issue"])
        self.assertEqual(self.exit_code(runner), 10)
        self.assertIn("undetermined", runner.report["findings"][0]["reason"])

    def test_boundary_regression_is_exit_20_not_40(self):
        # Regression: only category "valid" produced Functional Regression, so a
        # boundary case breaking a documented reference was merely inconclusive.
        expected = {"exit_code": 0, "stdout": "", "stderr": ""}
        runner = self.runner()
        runner.classify({"id": "b", "category": "boundary", "expected": expected}, "release",
                        {"baseline": observation(expected=expected),
                         "patched": observation("rejected\n", code=2, expected=expected)},
                        {"baseline": True, "patched": True})
        self.assertEqual([f["status"] for f in runner.report["findings"]], ["Functional Regression"])
        self.assertEqual(runner.report["inconclusive"], [])
        self.assertEqual(self.exit_code(runner), 20)

    def test_boundary_regression_with_crashing_patched_side_is_still_20(self):
        expected = {"exit_code": 0, "stdout": "\n", "stderr": ""}
        runner = self.runner()
        runner.classify({"id": "b", "category": "boundary", "expected": expected}, "sanitized",
                        {"baseline": observation(stdout="\n", expected=expected),
                         "patched": observation(code=-6, signal="SIGABRT", expected=expected)},
                        {"baseline": True, "patched": True})
        self.assertEqual([f["status"] for f in runner.report["findings"]], ["Functional Regression"])
        self.assertEqual(self.exit_code(runner), 20)

    def test_valid_regression_unchanged(self):
        expected = {"exit_code": 0, "stdout": "ok\n", "stderr": ""}
        runner = self.runner()
        runner.classify({"id": "v", "category": "valid", "expected": expected}, "release",
                        {"baseline": observation(stdout="ok\n", expected=expected),
                         "patched": observation(stdout="no\n", code=2, expected=expected)},
                        {"baseline": True, "patched": True})
        self.assertEqual(self.exit_code(runner), 20)

    def test_release_crash_explained_by_companion_sanitizer_run(self):
        # FORTIFY/canary aborts carry no source location. The matching sanitized
        # run at the same input explains them instead of being "unexplained".
        expected = {"exit_code": 2, "stdout": "too long\n", "stderr": ""}
        runner = self.runner()
        release_abort = observation(code=-6, signal="SIGABRT", expected=expected)
        release_abort["error"] = {"type": "fortify-abort", "mechanism": "FORTIFY (glibc __chk_fail)",
                                  "confirmed": False, "locations": [], "secondary": [],
                                  "fingerprint": {"error_type": "fortify-abort", "location": None},
                                  "root_cause": "Undetermined", "exploitability": "Not assessed"}
        sanitized = observation("ERROR: AddressSanitizer: heap-buffer-overflow\n"
                                "    #1 0x1 in main /work/reader.c:16:5\n", code=1, expected=expected)
        companion = {"results": {"baseline": sanitized, "patched": sanitized}, "stable": {"baseline": True, "patched": True}}
        self.assertTrue(runner.explained(companion, "baseline"))
        self.assertFalse(runner.explained(None, "baseline"))
        unconfirmed = {"results": {"baseline": observation(code=-11, signal="SIGSEGV"), "patched": sanitized}}
        self.assertFalse(runner.explained(unconfirmed, "baseline"))

    def test_explained_release_failure_does_not_suppress_real_regression(self):
        expected = {"exit_code": 0, "stdout": "", "stderr": ""}
        runner = self.runner()
        runner.classify({"id": "b", "category": "boundary", "expected": expected}, "release",
                        {"baseline": observation(expected=expected),
                         "patched": observation("rejected\n", code=2, expected=expected)},
                        {"baseline": True, "patched": True},
                        companion={"results": {"baseline": observation(), "patched": observation()}})
        self.assertEqual(self.exit_code(runner), 20)


class DiscoveryIdentityTests(unittest.TestCase):
    """Defects found in review: verdicts must survive per-role discovery."""

    def runner(self):
        from patchcheck.runner import Runner
        runner = Runner.__new__(Runner)
        runner.report = {"findings": [], "inconclusive": [], "executions": [], "reproducers": []}
        runner.diff, runner.seen_errors, runner.regression_root = {}, set(), None
        runner.discovery_queue, runner.bundle_depth, runner.discoveries = [], 0, 0
        return runner

    def test_same_fingerprint_is_new_per_version(self):
        # Regression: deduplication ignored the version role, so a patched error
        # matching an already recorded baseline fingerprint was never confirmed,
        # classified or bundled and the run could still report PASS.
        runner = self.runner()
        self.assertTrue(runner.record_error("sanitized", "baseline", memory_error()))
        self.assertTrue(runner.record_error("sanitized", "patched", memory_error()))
        self.assertFalse(runner.record_error("sanitized", "patched", memory_error()))

    def test_unconfirmed_observation_is_not_a_discovery(self):
        runner = self.runner()
        self.assertFalse(runner.record_error("sanitized", "patched", result(code=-11, signal="SIGSEGV")))

    def test_discovered_patched_error_during_baseline_reduction_is_exit_10(self):
        # The review fixture: minimization of a baseline reproducer reaches the
        # same defect in the patched version for the first time. That observation
        # must be classified, bundled, and force exit 10 even though a later
        # reduction no longer triggers it.
        runner = self.runner()
        reference = {"exit_code": 2, "stdout": "too long\n", "stderr": "", "reference": "fixture contract"}
        test = {"id": "original", "category": "invalid", "expected": reference,
                "minimized_expected": reference}
        pair = {"baseline": memory_error(16), "patched": memory_error(16)}
        runner.replay = lambda *args: ([pair] * 3, {"baseline": True, "patched": True})
        bundled = []
        runner.bundle = lambda *args, **kwargs: bundled.append(kwargs)
        # The patched error was already recorded for the baseline role only.
        runner.record_error("sanitized", "baseline", pair["baseline"])
        runner.discover("sanitized", test, b"A" * 32, pair)
        self.assertEqual([f["status"] for f in runner.report["findings"]], ["Incomplete Fix"])
        self.assertEqual(decide(runner.report), 10)
        self.assertEqual(bundled, [], "discovery must not nest a bundle inside minimization")
        self.assertEqual(len(runner.discovery_queue), 1)
        runner.drain_discoveries()
        self.assertEqual(len(bundled), 1, "the discovery must be bundled")
        self.assertEqual(bundled[0]["roles"], ["patched"],
                         "only the newly discovered patched error needs its own reduction")
        self.assertEqual(runner.discovery_queue, [])


class CompletenessTests(unittest.TestCase):
    """Unconfirmed observations and unstable roles must not be silently dropped."""

    def runner(self):
        from patchcheck.runner import Runner
        runner = Runner.__new__(Runner)
        runner.report = {"findings": [], "inconclusive": [], "executions": [], "reproducers": []}
        runner.diff, runner.seen_errors, runner.regression_root = {}, set(), None
        runner.discovery_queue, runner.bundle_depth, runner.discoveries = [], 0, 0
        return runner

    def test_unclassified_baseline_failure_prevents_pass(self):
        # Regression: only two exact names counted as "unclassified", so an ASan
        # unknown-crash on a non-target test could be dropped entirely and the
        # run still reported PASS.
        runner = self.runner()
        runner.report["findings"].append({"status": "Fixed", "test_id": "original"})
        before = observation("ERROR: AddressSanitizer: unknown-crash\n    #0 0x1 in parse /work/a.c:10:1\n", code=1)
        runner.classify({"id": "extra", "category": "invalid",
                         "expected": {"exit_code": 2, "stdout": "invalid\n", "stderr": ""}},
                        "sanitized", {"baseline": before, "patched": observation(stdout="invalid\n", code=2)},
                        {"baseline": True, "patched": True})
        self.assertEqual(decide(runner.report), 40)
        self.assertTrue(any("unconfirmed baseline" in message for message in runner.report["inconclusive"]))

    def test_unconfirmed_asan_segv_is_not_dropped(self):
        runner = self.runner()
        before = observation("ERROR: AddressSanitizer: SEGV on unknown address 0x0\n"
                             "    #0 0x1 in f /work/a.c:10:1\n", code=1)
        self.assertFalse(before["error"]["confirmed"])
        runner.classify({"id": "extra", "category": "invalid",
                         "expected": {"exit_code": 2, "stdout": "invalid\n", "stderr": ""}},
                        "sanitized", {"baseline": before, "patched": observation(stdout="invalid\n", code=2)},
                        {"baseline": True, "patched": True})
        self.assertEqual(decide(runner.report), 40)

    def test_stable_patched_error_with_unstable_baseline_stays_exit_10(self):
        # Regression: returning early for either unstable role discarded a
        # patched error confirmed in every replay, reporting 40 instead of 10.
        runner = self.runner()
        runner.report["findings"].append({"status": "Fixed", "test_id": "original"})
        patched = memory_error()
        runner.classify({"id": "extra", "category": "invalid",
                         "expected": {"exit_code": 2, "stdout": "", "stderr": ""}},
                        "sanitized", {"baseline": observation(stdout="invalid\n", code=2), "patched": patched},
                        {"baseline": False, "patched": True})
        self.assertIn("New Issue", [finding["status"] for finding in runner.report["findings"]])
        self.assertEqual(decide(runner.report), 10)
        self.assertTrue(any("unstable baseline" in message for message in runner.report["inconclusive"]))

    def test_unstable_patched_observation_remains_inconclusive(self):
        runner = self.runner()
        runner.classify({"id": "extra", "category": "invalid",
                         "expected": {"exit_code": 2, "stdout": "", "stderr": ""}},
                        "sanitized", {"baseline": observation(code=2), "patched": memory_error()},
                        {"baseline": True, "patched": False})
        self.assertEqual([finding["status"] for finding in runner.report["findings"]], ["Inconclusive"])
        self.assertEqual(decide(runner.report), 40)


class ReuseTests(unittest.TestCase):
    """Imported regressions must be reused, not regenerated, yet still yield evidence."""

    def runner(self, directory):
        from patchcheck.runner import Runner
        runner = Runner.__new__(Runner)
        runner.report = {"findings": [], "inconclusive": [], "executions": [], "reproducers": [], "versions": []}
        runner.diff, runner.seen_errors, runner.regression_root = {}, set(), None
        runner.discovery_queue, runner.bundle_depth, runner.discoveries = [], 0, 0
        runner.output = directory / "output"
        runner.output.mkdir()
        runner.config = {"target": "review-target", "name": "review/target", "builds": {"sanitized": {}}}
        runner.builds = {"sanitized": {"baseline": {"record": {}}, "patched": {"record": {}}}}
        runner.sandbox = type("Sandbox", (), {"identity": {}})()
        return runner

    def write_entry(self, directory, baseline, **overrides):
        from patchcheck.source import sha256
        (directory / "input.bin").write_bytes(b"recorded-input")
        entry = {"schema_version": 1, "id": "stored-test", "target": "review-target",
                 "scenario": "review/target", "profile": "sanitized", "input": "input.bin", "args": [],
                 "expected": {"exit_code": 2, "stdout": "", "stderr": "", "reference": "fixture"},
                 "input_sha256": sha256(b"recorded-input"),
                 "baseline_fingerprint": baseline["error"]["fingerprint"],
                 "observed_fingerprint": baseline["error"]["fingerprint"], "observed_version": "baseline"}
        entry.update(overrides)
        (directory / "entry.json").write_text(json.dumps(entry))
        return entry

    def test_unchanged_regression_is_not_rebundled(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            baseline = memory_error()
            self.write_entry(root, baseline)
            runner = self.runner(root)
            runner.pair = lambda profile, test, data: {"baseline": baseline, "patched": baseline}
            runner.replay = lambda *args: ([], {"baseline": True, "patched": True})
            calls = []
            runner.bundle = lambda *args, **kwargs: calls.append(args)
            runner.import_regressions([root])
            self.assertEqual(calls, [], "an already minimized unchanged entry must not be reduced again")
            self.assertEqual(decide(runner.report), 10)
            self.assertEqual(len(runner.report["executions"]), 1)

    def test_new_error_in_imported_regression_gets_its_own_bundle(self):
        # Regression: the import path classified new errors but never bundled
        # them, so the earlier input stayed the only reproducer even though it
        # had been minimized for a different fingerprint.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            baseline = memory_error(16, "copy_record", "heap-buffer-overflow")
            self.write_entry(root, baseline)
            runner = self.runner(root)
            patched = memory_error(41, "drain", "heap-use-after-free")
            pair = {"baseline": baseline, "patched": patched}
            runner.pair = lambda profile, test, data: pair
            runner.replay = lambda *args: ([pair] * 3, {"baseline": True, "patched": True})
            bundled = []
            runner.bundle = lambda *args, **kwargs: bundled.append(kwargs)
            runner.import_regressions([root])
            self.assertEqual(len(bundled), 1, "a newly observed patched error needs fresh evidence")
            self.assertEqual(bundled[0]["roles"], ["patched"])
            self.assertEqual(decide(runner.report), 10)
            self.assertIn("source_regression", runner.report["executions"][0]["test"])

    def test_regression_from_another_scenario_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            baseline = memory_error()
            self.write_entry(root, baseline, scenario="some/other-variant")
            runner = self.runner(root)
            runner.pair = lambda *args: self.fail("a foreign scenario's input must not execute here")
            runner.import_regressions([root])
            self.assertEqual(runner.report["executions"], [])


class SourceRestorationTests(unittest.TestCase):
    """A clean checkout must be able to rebuild the pinned target revisions."""

    def test_bundles_cover_every_pinned_revision(self):
        import subprocess
        for path in (ROOT / "configs").glob("*.json"):
            config = json.loads(path.read_text(encoding="utf-8"))
            for version in config["versions"].values():
                relative = version["repository"]
                self.assertTrue((ROOT / relative / ".git").is_dir() or (ROOT / "targets/bundles").is_dir(),
                                f"no recoverable history for {relative}")
        manifest = json.loads((ROOT / "targets/bundles/manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(set(manifest["repositories"]),
                         {"targets/cjson/upstream", "targets/jq/upstream", "targets/record_reader/repository"})
        for relative, entry in manifest["repositories"].items():
            bundle = ROOT / entry["bundle"]
            with self.subTest(repository=relative):
                self.assertTrue(bundle.is_file(), f"missing bundle for {relative}")
                self.assertTrue(entry["pinned"], "no pinned revision recorded")
                with tempfile.TemporaryDirectory() as directory:
                    clone = subprocess.run(["git", "clone", "--quiet", "--no-checkout", str(bundle),
                                            str(Path(directory) / "clone")], capture_output=True)
                    self.assertEqual(clone.returncode, 0, clone.stderr.decode("utf-8", "replace"))
                    for commit in entry["pinned"]:
                        resolved = subprocess.run(["git", "-C", str(Path(directory) / "clone"), "cat-file", "-e",
                                                   f"{commit}^{{commit}}"], capture_output=True)
                        self.assertEqual(resolved.returncode, 0, f"{relative} bundle cannot resolve {commit}")

    def test_restore_reports_missing_history_without_changing_anything(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            shutil.copytree(ROOT / "targets/bundles", checkout / "targets/bundles")
            manifest = json.loads((checkout / "targets/bundles/manifest.json").read_text(encoding="utf-8"))
            for relative in manifest["repositories"]:
                (checkout / relative).mkdir(parents=True)
            script = str(ROOT / "scripts/restore_sources.py")
            # --check must fail, not silently rebuild, when history is absent.
            result = subprocess.run([sys.executable, script, "--check", "--root", str(checkout)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("MISSING pinned revisions", result.stdout)

    def test_restore_rebuilds_a_checkout_with_sources_but_no_history(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            # Model a real parent-repository checkout: tracked source files are
            # present, nested .git directories are not.
            shutil.copytree(ROOT / "targets/bundles", checkout / "targets/bundles")
            manifest = json.loads((checkout / "targets/bundles/manifest.json").read_text(encoding="utf-8"))
            for relative, entry in manifest["repositories"].items():
                (checkout / relative).mkdir(parents=True)
                (checkout / relative / "placeholder.c").write_text("/* tracked file */\n")
            script = str(ROOT / "scripts/restore_sources.py")
            restored = subprocess.run([sys.executable, script, "--root", str(checkout)],
                                      capture_output=True, text=True)
            self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
            verified = subprocess.run([sys.executable, script, "--check", "--root", str(checkout)],
                                      capture_output=True, text=True)
            self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
            for relative, entry in manifest["repositories"].items():
                for commit in entry["pinned"]:
                    resolved = subprocess.run(["git", "-C", str(checkout / relative), "cat-file", "-e",
                                               f"{commit}^{{commit}}"], capture_output=True)
                    self.assertEqual(resolved.returncode, 0, f"{relative} cannot resolve {commit}")
    def test_all_supplied_configurations_validate(self):
        for path in (ROOT / "configs").glob("*.json"):
            with self.subTest(path=path.name):
                config, root = load(path)
                self.assertTrue(root.is_dir())
                self.assertEqual(set(config["builds"]), {"release", "sanitized"})

    def test_malformed_objects_always_raise_config_error(self):
        original = json.loads((ROOT / "configs/record-reader-correct.json").read_text())
        original["root"] = str(ROOT)
        variants = [{"tests": [None]}, {"builds": {"release": None, "sanitized": None}},
                    {"execution": None}, {"limits": []}, {"versions": None}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for changes in variants:
                with self.subTest(changes=changes):
                    path.write_text(json.dumps({**original, **changes}))
                    with self.assertRaises(ConfigError):
                        load(path)


class SupervisorRobustnessTests(unittest.TestCase):
    """Monitoring must never abort a run when /proc changes underneath it."""

    def test_vanishing_process_is_skipped_not_raised(self):
        # Regression: a process exiting between the /proc listing and the read
        # raised ProcessLookupError out of the sampling helper and aborted the
        # whole run as BUILD_OR_CONFIG_ERROR (observed as exit 30 on a valid
        # configuration during a repeated matrix run).
        import os
        import patchcheck.worker as worker
        vanished = Path("/proc/self") / "definitely-not-a-pid" / "stat"
        original_glob = Path.glob

        def glob(self, pattern):
            if pattern == "[0-9]*/stat":
                yield vanished
                yield from (Path("/proc") / str(os.getpid()) / "stat",)
            else:
                yield from original_glob(self, pattern)

        with unittest.mock.patch.object(Path, "glob", glob), \
                unittest.mock.patch.object(Path, "read_text", side_effect=ProcessLookupError(3, "No such process")):
            rss, count = worker.group_usage(os.getpid())
        self.assertEqual((rss, count), (0, 0), "a vanished entry must be skipped")

    def test_failing_proc_walk_returns_partial_sample(self):
        import os
        import patchcheck.worker as worker

        def broken_glob(self, pattern):
            raise ProcessLookupError(3, "No such process")
            yield  # pragma: no cover - generator marker

        with unittest.mock.patch.object(Path, "glob", broken_glob):
            self.assertEqual(worker.group_usage(os.getpid()), (0, 0))


class HardeningTests(unittest.TestCase):
    def evidence(self, stack="RW", relro=True, now=True, pie=True, canary=True):
        return "\n".join(["Class: ELF64", "Machine: Advanced Micro Devices X86-64",
            "Type: DYN" if pie else "Type: EXEC", f"GNU_STACK 0 0 0 0 0 {stack} 0x10",
            "GNU_RELRO 0 0" if relro else "", "(FLAGS) BIND_NOW" if now else "",
            "(FLAGS_1) Flags: NOW PIE" if pie else "", "UND __stack_chk_fail@GLIBC_2.4" if canary else ""])

    def test_all_relro_levels_and_nx(self):
        self.assertEqual(assess(self.evidence())["RELRO"]["status"], "Full RELRO")
        self.assertEqual(assess(self.evidence(now=False, pie=False))["RELRO"]["status"], "Partial RELRO")
        self.assertEqual(assess(self.evidence(relro=False))["RELRO"]["status"], "No RELRO")
        self.assertEqual(assess(self.evidence(stack="RWE"))["NX"]["status"], "Disabled")

    def test_removed_protections_warn(self):
        changes = warnings(assess(self.evidence()), assess(self.evidence(pie=False, canary=False)))
        self.assertEqual({entry["protection"] for entry in changes}, {"PIE", "Stack Canary"})
        self.assertTrue(all(entry["decreased"] for entry in changes))

    def test_non_elf_is_configuration_error(self):
        with self.assertRaises(ConfigError):
            assess("not an ELF header")


if __name__ == "__main__":
    unittest.main()
