"""Build, compare, replay, minimize and persist evidence for a configured target."""

import base64
import json
import shutil
import subprocess
from pathlib import Path

from .config import ConfigError, expectation, inside
from .correlation import correlate, equivalent, parse_diff
from .evidence import analyze, matches_expected, observation_key, reproduces
from .hardening import assess, warnings
from .minimize import ddmin
from .source import diff_sources, materialize, sha256


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class Testbed:
    """Construction and execution of one profile's target binaries.

    Shared by the automated run and the manual replay command so the two can
    never drift apart in how a target is invoked or how its output is read.
    """

    def __init__(self, config, profile, work_root, sandbox):
        self.config, self.profile = config, profile
        self.work_root, self.sandbox = Path(work_root), sandbox

    def work(self, role):
        return self.work_root / role

    def request(self, test, data):
        settings = self.config["builds"][self.profile]
        return {"argv": self.config["execution"]["argv"] + test.get("args", []),
                "interface": self.config["execution"]["interface"],
                "binary": "/work/" + settings["binary"],
                "input_base64": base64.b64encode(data).decode(), "env": settings.get("env", {}),
                "limits": self.config["limits"]}

    def verify_binary(self, role, record):
        binary = self.work(role) / record["settings"]["binary"]
        if sha256(binary.read_bytes()) != record["binary_sha256"]:
            raise ConfigError(f"replay binary hash mismatch for {role}")

    def run_one(self, role, test, data):
        result = analyze(self.sandbox.execute(self.work(role), self.request(test, data)))
        result["input_sha256"] = sha256(data)
        result["expected_match"] = matches_expected(result, test["expected"])
        return result

    def pair(self, test, data):
        return {role: self.run_one(role, test, data) for role in ("baseline", "patched")}


class Runner:
    def __init__(self, config, root, output, sandbox, report, regression_root=None):
        self.config, self.root, self.output = config, root, output
        self.sandbox, self.report = sandbox, report
        self.regression_root = Path(regression_root) if regression_root else None
        self.builds = {}
        self.diff = {}
        self.seen_errors = set()
        self.discoveries = 0
        self.discovery_queue = []
        self.bundle_depth = 0
        self.testbeds = {}

    def build(self):
        versions = self.report.setdefault("versions", {})
        for role in ("baseline", "patched"):
            versions[role] = materialize(self.root, self.config["versions"][role], self.output / "sources" / role)
        text = diff_sources(self.output / "sources/baseline", self.output / "sources/patched")
        (self.output / "patch.diff").write_text(text, encoding="utf-8")
        self.diff = parse_diff(text)
        self.report["diff_sha256"] = sha256(text.encode())
        for profile, settings in self.config["builds"].items():
            self.builds[profile] = {}
            for role in ("baseline", "patched"):
                work = self.output / "builds" / profile / role
                shutil.copytree(self.output / "sources" / role, work)
                record = {"profile": profile, "version": role, "settings": settings, "steps": []}
                self.report.setdefault("builds", []).append(record)
                for argv in settings["commands"]:
                    request = {"argv": argv, "env": settings.get("env", {}), "build": True,
                               "limits": self.config["limits"]}
                    result = self.sandbox.execute(work, request)
                    record["steps"].append(result)
                    if result.get("returncode") != 0 or result.get("resource_limit"):
                        raise ConfigError(f"{profile}/{role} build failed (see build evidence)")
                binary = inside(work, settings["binary"])
                if not binary.is_file() or binary.read_bytes()[:4] != b"\x7fELF":
                    raise ConfigError(f"{profile}/{role}: configured binary is not an ELF file")
                result = self.sandbox.execute(work, {"argv": ["readelf", "-W", "-h", "-l", "-d", "-s", "{binary}"],
                    "binary": "/work/" + settings["binary"], "limits": self.config["limits"]})
                if result["returncode"] != 0 or result.get("resource_limit"):
                    raise ConfigError("ELF inspection failed or exceeded resource limits")
                protections = assess(result["stdout"])
                instrumented = "__asan_init" in result["stdout"] or "__ubsan_handle_" in result["stdout"]
                if instrumented != (profile == "sanitized"):
                    raise ConfigError(f"{profile}/{role}: instrumentation does not match build profile")
                record.update({"binary_sha256": sha256(binary.read_bytes()), "elf_inspection": result,
                               "instrumented": instrumented})
                self.builds[profile][role] = {"record": record}
                if profile == "release":
                    self.report.setdefault("hardening", {})[role] = protections
        self.report["hardening"]["warnings"] = warnings(self.report["hardening"]["baseline"], self.report["hardening"]["patched"])
        for role in ("baseline", "patched"):
            if any(value.get("status") == "Unknown" for value in self.report["hardening"][role].values() if isinstance(value, dict)):
                self.inconclusive(f"{role}: some mandatory ELF protection evidence is unavailable")

    def inconclusive(self, message):
        if message not in self.report["inconclusive"]:
            self.report["inconclusive"].append(message)

    def run_one(self, profile, role, test, data):
        return self.testbed(profile).run_one(role, test, data)

    def pair(self, profile, test, data):
        return self.testbed(profile).pair(test, data)

    def testbed(self, profile):
        if profile not in self.testbeds:
            self.testbeds[profile] = Testbed(self.config, profile, self.output / "builds" / profile, self.sandbox)
        return self.testbeds[profile]

    def replay(self, profile, test, data, original):
        replays = [self.pair(profile, test, data) for _ in range(self.config["replays"])]
        stable = {role: all(observation_key(replay[role]) == observation_key(original[role]) for replay in replays)
                  for role in ("baseline", "patched")}
        return replays, stable

    def finding(self, status, test, profile, pair, **extra):
        finding = {"id": f"{profile}-{test['id']}-{status.replace(' ', '-').lower()}", "test_id": test["id"],
                   "profile": profile, "status": status, "correlation": correlate(pair, self.diff), **extra}
        self.report["findings"].append(finding)
        return finding

    @staticmethod
    def explained(companion, role):
        """True when the instrumented run at the same input confirms an error.

        A release binary can observe that it aborted without being able to name
        the access it made: FORTIFY and stack-canary aborts carry no source
        location. The sanitized build supplies exactly that missing detail for
        the corresponding build type/role, so the release observation is
        explained rather than unexplained. It is never upgraded to "confirmed"
        and its own evidence is reported unchanged.
        """
        return bool(companion and companion["results"][role]["error"]["confirmed"])

    def unexplained_error(self, result, role, companion):
        """True when an unconfirmed error observation is not explained by its companion.

        Any unconfirmed diagnosis counts, not only the two names this tool
        happens to emit itself: ASan ``unknown-crash``, an unconfirmed ``SEGV``
        or a future sanitizer report must never be dropped silently. A release
        observation is explained only by a stable, confirmed instrumented
        observation of the same input and role; nothing is upgraded to
        "confirmed" and the release evidence itself is reported unchanged.
        """
        error = result["error"]
        if error["confirmed"] or not error["type"] or result.get("resource_limit"):
            return False
        return not (companion and companion["stable"].get(role) and self.explained(companion, role))

    def classify(self, test, profile, pair, stable, companion=None):
        """Classify one paired observation, evaluating each version independently.

        Confirmation is per role. A patched memory error that reproduces in
        every replay is exit 10 on its own evidence even when the baseline
        observation is unstable; the baseline uncertainty is then reported as
        separate incompleteness (priority 10 > 40), never as a downgrade.
        """
        before, after = pair["baseline"], pair["patched"]
        functional = test["category"] in ("valid", "boundary")
        baseline_stable, patched_stable = stable.get("baseline", True), stable.get("patched", True)
        if not patched_stable:
            self.finding("Inconclusive", test, profile, pair,
                         reason="Non-deterministic patched observation across replay executions")
            self.inconclusive(f"{profile}/{test['id']}: unstable patched replay")
        elif after["error"]["confirmed"]:
            # Security confirmation does not depend on the baseline diagnosis.
            if before["error"]["confirmed"]:
                self.finding("Incomplete Fix" if equivalent(before, after, self.diff) else "New Issue", test, profile, pair,
                             baseline_error=before["error"], patched_error=after["error"])
            else:
                self.finding("New Issue", test, profile, pair, patched_error=after["error"],
                             reason=("Newly observed confirmed error; causation is undetermined" if not before["error"]["type"]
                                     else "Confirmed patched error alongside an unclassified baseline failure; "
                                          "causation and whether it is the original defect are undetermined"))
            if not baseline_stable:
                self.inconclusive(f"{profile}/{test['id']}: unstable baseline replay; fix equivalence undetermined")
        elif before["error"]["confirmed"]:
            if not baseline_stable:
                self.finding("Inconclusive", test, profile, pair,
                             reason="Non-deterministic baseline observation across replay executions")
                self.inconclusive(f"{profile}/{test['id']}: unstable baseline replay")
            elif after.get("expected_match"):
                self.finding("Fixed", test, profile, pair, baseline_error=before["error"], scope="This input and build only")
            else:
                self.finding("Inconclusive", test, profile, pair, reason="Baseline error absent but expected patched behavior unverified")
                self.inconclusive(f"{profile}/{test['id']}: patched behavior cannot validate original fix")
        elif not baseline_stable:
            self.finding("Inconclusive", test, profile, pair,
                         reason="Non-deterministic baseline observation across replay executions")
            self.inconclusive(f"{profile}/{test['id']}: unstable baseline replay")
        if functional and before.get("expected_match") and not after.get("expected_match"):
            self.finding("Functional Regression", test, profile, pair, expected=test["expected"],
                         baseline_matches_reference=True, patched_matches_reference=False)
        if after.get("resource_limit"):
            self.inconclusive(f"{profile}/{test['id']}: patched resource limit ({after['resource_limit']})")
        if before.get("resource_limit"):
            self.inconclusive(f"{profile}/{test['id']}: baseline resource limit ({before['resource_limit']})")
        if self.unexplained_error(after, "patched", companion):
            self.inconclusive(f"{profile}/{test['id']}: unconfirmed patched error observation ({after['error']['type']})")
        if self.unexplained_error(before, "baseline", companion):
            self.inconclusive(f"{profile}/{test['id']}: unconfirmed baseline error observation ({before['error']['type']})")
        if not after.get("expected_match") and not after["error"]["confirmed"]:
            # A demonstrated valid-input regression is complete evidence for exit 20.
            if not (functional and before.get("expected_match") and not after["error"]["type"]):
                if not self.explained(companion, "patched"):
                    self.inconclusive(f"{profile}/{test['id']}: patched output/termination does not match the independent reference")
        if functional and not before.get("expected_match") and not before["error"]["type"] and not before.get("resource_limit"):
            self.inconclusive(f"{profile}/{test['id']}: baseline does not satisfy the supplied reference")

    def record_error(self, profile, role, observation):
        """Track a confirmed error fingerprint for one version, returning True if it is new.

        The version role is part of the identity: the same defect first observed
        in the patched version is a new discovery even when the baseline already
        exhibited it. Deduplicating without the role would let a confirmed
        patched error be skipped entirely.
        """
        if not observation["error"]["confirmed"]:
            return False
        key = (profile, role, json.dumps(observation["error"]["fingerprint"], sort_keys=True))
        if key in self.seen_errors:
            return False
        self.seen_errors.add(key)
        return True

    def new_errors(self, profile, observation, roles=("baseline", "patched")):
        """Return {role: observation} for confirmed errors not yet seen for that role."""
        return {role: observation[role] for role in roles
                if role in observation and self.record_error(profile, role, observation[role])}

    def bundle(self, test, profile, data, pair, replays, stable, directory=None, roles=None):
        """Persist one reproducer bundle, then minimize and register its reproducer.

        ``roles`` limits reduction to the versions whose error is the subject of
        this bundle. A discovery reached while reducing another error must gain
        evidence for *its own* fingerprint; re-reducing an already recorded error
        would only duplicate an existing suite entry.
        """
        self.new_errors(profile, pair)
        directory = directory or self.output / "reproducers" / profile / test["id"]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "original.bin").write_bytes(data)
        manifest = {"schema_version": 1, "test": test, "profile": profile, "versions": self.report["versions"],
                    "sandbox": self.sandbox.identity, "limits": self.config["limits"], "initial": pair,
                    "replays": replays, "stable": stable, "original_sha256": sha256(data),
                    "builds": {role: self.builds[profile][role]["record"] for role in pair},
                    "reproduction": "Use patchcheck replay MANIFEST --backend BACKEND; retain the enclosing artifact directory."}
        # Preserve unstable evidence, but do not reduce it or pretend it is confirmed.
        if all(stable.values()):
            for role in roles or ("baseline", "patched"):
                if pair[role]["error"]["confirmed"]:
                    self.minimize_role(test, profile, data, role, directory, manifest,
                                       pair[role]["error"]["fingerprint"])
        write_json(directory / "manifest.json", manifest)
        relative = str(directory.relative_to(self.output) / "manifest.json")
        if relative not in self.report.setdefault("reproducers", []):
            self.report["reproducers"].append(relative)
        return directory

    def minimize_role(self, test, profile, data, role, directory, manifest, fingerprint):
        """Reduce one role's reproducer, verify it, and register the regression."""
        trials = []

        def predicate(candidate):
            observation = self.pair(profile, test, candidate)
            trials.append({"input_sha256": sha256(candidate), "input_base64": base64.b64encode(candidate).decode(),
                           "results": observation})
            self.discover(profile, test, candidate, observation)
            return reproduces(observation[role], fingerprint)

        minimum, stats = ddmin(data, predicate, self.config["minimize_budget"])
        minimized_pair = self.pair(profile, test, minimum)
        minimized_replays, minimized_stable = self.replay(profile, test, minimum, minimized_pair)
        stable_minimum = all(minimized_stable.values()) and reproduces(minimized_pair[role], fingerprint)
        (directory / f"minimized-{role}.bin").write_bytes(minimum)
        write_json(directory / f"minimization-{role}.json", trials)
        manifest.setdefault("minimizations", {})[role] = {**stats, "sha256": sha256(minimum), "stable": stable_minimum,
            "results": minimized_pair, "replays": minimized_replays, "fingerprint": fingerprint}
        if not stable_minimum:
            self.inconclusive(f"{profile}/{test['id']}/{role}: minimized reproducer is unstable")
            return
        self.register_regression(test, profile, role, data, minimum, minimized_pair,
                                 minimized_replays, minimized_stable, fingerprint)

    def discover(self, profile, test, candidate, observation, id_prefix="discovery", roles=None):
        """Classify an error first seen during minimization.

        Minimization is dynamic testing too: an error it exposes must affect the
        verdict even if a later reduction no longer reproduces it. The version
        role is part of the identity, so a patched error first reached during
        baseline reduction is a real discovery rather than an already-known one.

        ``roles`` restricts which versions are being discovered. A reused
        regression supplies it, because its baseline fingerprint is already
        documented and only the patched side may be new.

        Bundles are queued, never created here: a bundle re-enters minimization,
        and reducing inside reduction would nest unboundedly.
        """
        candidates = roles or ("baseline", "patched")
        found = [role for role in candidates
                 if role in observation and self.record_error(profile, role, observation[role])]
        if not found:
            return []
        self.discoveries += 1
        reference = test.get("minimized_expected")
        discovered = {**test, "id": f"{id_prefix}-{self.discoveries}",
                      "category": "invalid", "expected": reference or test["expected"],
                      "discovered_roles": found}
        if reference is None:
            self.inconclusive(f"{profile}/{discovered['id']}: discovered input lacks an independent reference")
        for value in observation.values():
            value["expected_match"] = matches_expected(value, discovered["expected"])
        replayed, consistent = self.replay(profile, discovered, candidate, observation)
        self.report["executions"].append({"test": discovered, "profile": profile,
            "results": observation, "replays": replayed, "stable": consistent, "generated": True})
        self.classify(discovered, profile, observation, consistent)
        self.discovery_queue.append((discovered, profile, candidate, observation, replayed, consistent))
        return found

    def drain_discoveries(self):
        """Bundle every queued discovery, in order, without recursive minimization.

        A queued discovery is bundled exactly once even when its input later fails
        to reproduce: it was observed and confirmed during a real execution, so
        it must leave a reproducible record and affect the verdict.
        """
        while self.discovery_queue:
            test, profile, data, pair, replays, stable = self.discovery_queue.pop(0)
            roles = [role for role in test.get("discovered_roles", ("baseline", "patched"))
                     if pair[role]["error"]["confirmed"]]
            self.bundle(test, profile, data, pair, replays, stable, roles=roles)

    def register_regression(self, test, profile, role, data, minimum, minimized_pair,
                            minimized_replays, minimized_stable, fingerprint):
        """Turn a verified minimized reproducer into a persisted regression test."""
        expected = test["expected"] if minimum == data else test.get("minimized_expected")
        if expected is None:
            self.inconclusive(f"{profile}/{test['id']}: minimized input needs an independent expected result")
        else:
            expectation(expected)
            minimized_test = {**test, "id": test["id"] + "-minimized-" + role, "expected": expected}
            for observation in minimized_pair.values():
                observation["expected_match"] = matches_expected(observation, expected)
            self.report["executions"].append({"test": minimized_test, "profile": profile,
                "results": minimized_pair, "replays": minimized_replays, "stable": minimized_stable,
                "generated": True})
            self.classify(minimized_test, profile, minimized_pair, minimized_stable)
        regression = {"schema_version": 1, "id": f"{profile}-{test['id']}-{role}", "profile": profile,
                      "target": self.config["target"], "scenario": self.config["name"],
                      "input": f"../../reproducers/{profile}/{test['id']}/minimized-{role}.bin",
                      "input_sha256": sha256(minimum), "args": test.get("args", []),
                      "expected": expected, "baseline_fingerprint": minimized_pair["baseline"]["error"]["fingerprint"],
                      "observed_version": role, "observed_fingerprint": fingerprint,
                      "state": "active" if expected else "pending-independent-reference",
                      "reference_note": "Only explicitly configured independent expectations are used."}
        write_json(self.output / "regressions" / profile / f"{test['id']}-{role}.json", regression)
        if expected:
            self.persist_regression(regression, minimum)
            if (not matches_expected(minimized_pair["patched"], expected)
                    and not minimized_pair["patched"]["error"]["confirmed"]):
                self.inconclusive(f"{profile}/{test['id']}: minimized regression does not satisfy its reference")

    def persist_regression(self, regression, minimum):
        """Copy an active generated regression into the project-level suite.

        Artifact-relative paths cannot be reused by later runs, so the minimized
        input is copied beside the entry and the path rewritten. Entries record
        both the target and the scenario (configuration name) that produced them:
        one durable suite can then hold regressions for many targets and variants
        without ever replaying a reproducer against the wrong version pair.

        A regression check always executes the input against both versions, so
        one entry per distinct minimized input already satisfies all three
        obligations of spec 3.3; the second role's entry is not written again.
        """
        if not self.regression_root:
            self.inconclusive(f"{regression['id']}: no project regression suite configured")
            return
        destination = self.regression_root / f"{regression['id']}.json"
        if destination.exists():
            existing = json.loads(destination.read_text(encoding="utf-8"))
            if (existing.get("input_sha256") == regression["input_sha256"]
                    and existing.get("observed_fingerprint") == regression["observed_fingerprint"]
                    and existing.get("scenario") == regression["scenario"]):
                return
            # Never silently replace a previously recorded expectation.
            self.inconclusive(f"{regression['id']}: project regression already exists with different evidence")
            return
        for sibling in self.regression_root.glob("*.json"):
            other = json.loads(sibling.read_text(encoding="utf-8"))
            if (other.get("scenario") == regression["scenario"]
                    and other.get("profile") == regression["profile"]
                    and other.get("input_sha256") == regression["input_sha256"]):
                return
        inputs = self.regression_root / "inputs"
        inputs.mkdir(parents=True, exist_ok=True)
        filename = f"{regression['id']}-{regression['input_sha256'][:16]}.bin"
        (inputs / filename).write_bytes(minimum)
        stored = {**regression, "input": f"inputs/{filename}"}
        write_json(destination, stored)
        self.report.setdefault("persisted_regressions", []).append(str(destination))

    def test(self):
        observations, inputs = {}, {}
        for profile in self.config["builds"]:
            for test in self.config["tests"]:
                data = inside(self.root, test["input"]).read_bytes()
                pair = self.pair(profile, test, data)
                needs_replay = any(result["error"]["type"] or result.get("resource_limit")
                                   or not result["expected_match"] for result in pair.values())
                replays, stable = self.replay(profile, test, data, pair) if needs_replay else ([], {role: True for role in pair})
                record = {"test": test, "profile": profile, "results": pair, "replays": replays, "stable": stable}
                self.report["executions"].append(record)
                observations[(profile, test["id"])] = record
                inputs[(profile, test["id"])] = data
        # Classify only after every observation exists: the release profile is
        # explained by the sanitized run of the same input, and that run may be
        # produced later in the loop order.
        for (profile, test_id), record in observations.items():
            companion = observations.get(("sanitized", test_id)) if profile == "release" else None
            self.classify(record["test"], profile, record["results"], record["stable"], companion)
        for key, record in observations.items():
            if any(result["error"]["type"] for result in record["results"].values()):
                self.bundle(record["test"], key[0], inputs.pop(key), record["results"],
                            record["replays"], record["stable"])
        self.drain_discoveries()
        for test_id in self.config["target_tests"]:
            record = observations[("sanitized", test_id)]
            if not (record["results"]["baseline"]["error"]["confirmed"] and record["stable"]["baseline"]):
                self.inconclusive(f"target {test_id}: original baseline memory/security error not reproducibly confirmed")
        self.report["functional_complete"] = all(
            record["results"]["baseline"]["expected_match"] and record["results"]["patched"]["expected_match"]
            and all(record["stable"].values())
            for record in self.report["executions"] if record["test"]["category"] in ("valid", "boundary"))
        self.report["mandatory_checks_complete"] = True

    def import_regressions(self, directories):
        """Re-execute persisted minimized tests in subsequent CI runs, including both versions.

        Directories may be supplied explicitly; otherwise the project-level
        suite is discovered from the configuration root so re-use does not
        depend on an operator remembering a flag (spec 3.3).

        An imported input is already minimal for the fingerprint recorded with
        it, so an unchanged entry is executed, checked and never re-bundled: that
        would grow a new generation of the suite on every run. If the same input
        reveals a *different* error, that error has never been minimized, so it
        is confirmed by replay, classified, bundled and reduced under its own
        fingerprint, exactly like a newly discovered error.
        """
        found, seen = [], set()
        for directory in directories:
            for path in sorted(Path(directory).resolve().rglob("*.json")):
                resolved = path.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    found.append(resolved)
        for path in found:
            entry = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(entry, dict) or entry.get("schema_version") != 1 or "observed_fingerprint" not in entry:
                raise ConfigError(f"not a generated regression: {path}")
            if entry.get("profile") not in self.config["builds"]:
                raise ConfigError(f"invalid generated regression profile: {path}")
            if entry.get("target") != self.config["target"]:
                # A suite shared by several targets must not run another
                # target's reproducer against this binary.
                continue
            if entry.get("scenario") and entry["scenario"] != self.config["name"]:
                # A durable suite can hold many scenarios of the same target.
                # A regression records the exact version pair it was minimized
                # against, so replaying it under a different pair would compare
                # it to the wrong baseline.
                continue
            import re
            if not isinstance(entry.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9_-]+", entry["id"]):
                raise ConfigError(f"invalid generated regression id: {path}")
            if entry.get("expected") is None:
                self.inconclusive(f"regression {entry['id']} lacks an independent reference")
                continue
            input_path = (path.parent / entry["input"]).resolve()
            data = input_path.read_bytes()
            if sha256(data) != entry["input_sha256"]:
                raise ConfigError(f"regression input hash mismatch: {path}")
            test = {"id": entry["id"], "category": "invalid", "expected": expectation(entry["expected"]),
                    "args": entry["args"], "input_sha256": entry["input_sha256"],
                    "source_regression": str(path)}
            pair = self.pair(entry["profile"], test, data)
            # An imported entry is judged against its own recorded independent
            # reference exactly like a configured test, so classification never
            # has to guess what the expected behavior was.
            for observation in pair.values():
                observation["expected_match"] = matches_expected(observation, test["expected"])
            replays, stable = self.replay(entry["profile"], test, data, pair)
            self.report["executions"].append({"test": test, "profile": entry["profile"], "results": pair,
                                              "replays": replays, "stable": stable, "generated": True})
            self.classify(test, entry["profile"], pair, stable)
            self.reuse_evidence(entry, path, test, data, pair, replays, stable)
        self.drain_discoveries()

    def reuse_evidence(self, entry, path, test, data, pair, replays, stable):
        """Preserve a reused regression's recorded evidence and bundle genuinely new errors."""
        recorded = {"baseline": entry.get("baseline_fingerprint"),
                    "patched": entry.get("observed_fingerprint") if entry.get("observed_version") == "patched" else None}
        if not entry.get("baseline_fingerprint"):
            self.inconclusive(f"regression {entry['id']}: no expected baseline error was recorded")
        elif not reproduces(pair["baseline"], entry["baseline_fingerprint"]):
            self.inconclusive(f"regression {entry['id']}: expected baseline error no longer reproduced")
        # A different confirmed error on this input is a new observation. The
        # stored input was minimized for the previous fingerprint, so it cannot
        # serve as the reproduction package for this one: confirm by replay,
        # then reduce and persist evidence for the new fingerprint. Only roles
        # whose recorded fingerprint does not match can be discoveries, so the
        # entry's already documented evidence is never re-classified as new.
        new = [role for role in ("baseline", "patched")
               if pair[role]["error"]["confirmed"] and stable.get(role)
               and not any(pair[role]["error"]["fingerprint"] == value
                           for value in recorded.values() if value)]
        if new:
            self.discover(entry["profile"], test, data, pair,
                          id_prefix=f"reimport-{'-'.join(new)}", roles=new)

