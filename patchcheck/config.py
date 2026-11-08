"""Strict configuration validation before any build or target execution."""

import json
import math
import re
from pathlib import Path


class ConfigError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ConfigError(message)


def inside(base, value):
    require(isinstance(value, str) and value, "paths must be nonempty strings")
    path = (base / value).resolve()
    require(path.is_relative_to(base.resolve()), f"path escapes configuration root: {value}")
    return path


def vector(value, label):
    require(isinstance(value, list) and value and all(isinstance(x, str) and "\0" not in x for x in value),
            f"{label} must be a nonempty array of arguments, without NUL bytes")


def expectation(value):
    require(isinstance(value, dict), "every test needs an independent expected result")
    require(isinstance(value.get("exit_code"), int) and not isinstance(value["exit_code"], bool)
            and 0 <= value["exit_code"] <= 255, "expected.exit_code must be 0..255")
    require(isinstance(value.get("stdout"), str) and isinstance(value.get("stderr"), str),
            "expected.stdout and expected.stderr must be exact UTF-8 strings")
    require(isinstance(value.get("reference"), str) and bool(value["reference"].strip()),
            "expected.reference must document an independent correctness source")
    return value


def load(path):
    path = Path(path).resolve()
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
        require(isinstance(config, dict), "configuration must be an object")
        require(isinstance(config.get("root", "."), str), "root must be a path string")
        root = (path.parent / config.get("root", ".")).resolve()
        require(root.is_dir(), "configuration root must be an existing directory")
        require(config.get("schema_version") == 1, "schema_version must be 1")
        require(isinstance(config.get("name"), str) and bool(config["name"]), "name is required")
        require(isinstance(config.get("target"), str) and re.fullmatch(r"[A-Za-z0-9_-]+", config["target"]),
                "target must be a short identifier; it scopes persisted regression tests")
        suite = config.setdefault("regression_suite", "regressions")
        require(isinstance(suite, str) and suite and not Path(suite).is_absolute()
                and ".." not in Path(suite).parts, "regression_suite must be a relative directory inside root")
        require(config.get("authorized") is True, "authorized: true must attest permission to test these local sources")
        require(isinstance(config.get("versions"), dict), "versions must be an object")
        for role in ("baseline", "patched"):
            version = config["versions"][role]
            require(isinstance(version, dict), f"versions.{role} must be an object")
            require(inside(root, version["repository"]).is_dir(), f"missing {role} repository")
            require(re.fullmatch(r"[0-9a-fA-F]{40}", version["revision"]) is not None,
                    "versions must pin full 40-character Git commit hashes")
            require(isinstance(version.get("patches", []), list), "patches must be an array")
            require(isinstance(version.get("overlays", {}), dict), "overlays must be an object")
            for patch in version.get("patches", []):
                require(inside(root, patch).is_file(), f"missing patch: {patch}")
            for destination, source in version.get("overlays", {}).items():
                require(not Path(destination).is_absolute() and ".." not in Path(destination).parts,
                        "overlay destinations must be relative paths")
                require(inside(root, source).is_file(), f"missing overlay: {source}")
        profiles = config["builds"]
        require(isinstance(profiles, dict), "builds must be an object")
        require(set(profiles) == {"release", "sanitized"}, "both release and sanitized builds are mandatory")
        for name, build in profiles.items():
            require(isinstance(build, dict), f"builds.{name} must be an object")
            require(isinstance(build.get("commands"), list) and bool(build["commands"]), "build commands are required")
            for command in build["commands"]:
                vector(command, f"builds.{name}.commands")
            binary = build["binary"]
            require(isinstance(binary, str) and binary and not Path(binary).is_absolute()
                    and ".." not in Path(binary).parts, "binary must be relative to the build directory")
            env = build.get("env", {})
            require(isinstance(env, dict) and all(isinstance(k, str) and isinstance(v, str)
                    and "\0" not in k + v and "=" not in k for k, v in env.items()), "invalid build environment")
        require(isinstance(config.get("execution"), dict), "execution must be an object")
        vector(config["execution"]["argv"], "execution.argv")
        interface = config["execution"]["interface"]
        require(interface in {"stdin", "file", "argv"}, "input interface must be stdin, file, or argv")
        joined = " ".join(config["execution"]["argv"])
        require("{binary}" in joined, "execution.argv must contain {binary}")
        if interface != "stdin":
            require(("{input}" if interface == "file" else "{input_text}") in joined,
                    "file/argv interfaces must contain the corresponding input placeholder")
        limits = config.setdefault("limits", {})
        require(isinstance(limits, dict), "limits must be an object")
        for name, default in {"wall_seconds": 3, "cpu_seconds": 2, "memory_mb": 512,
                              "output_bytes": 1048576, "file_bytes": 16777216,
                              "pids": 128, "build_seconds": 180}.items():
            value = limits.setdefault(name, default)
            require(isinstance(value, (float, int)) and not isinstance(value, bool)
                    and math.isfinite(value) and value > 0, f"limits.{name} must be positive and finite")
            if name not in {"wall_seconds", "build_seconds"}:
                require(isinstance(value, int), f"limits.{name} must be an integer")
        require(isinstance(config.setdefault("replays", 3), int) and config["replays"] >= 3,
                "at least three replay executions are mandatory")
        require(isinstance(config.setdefault("minimize_budget", 100), int) and config["minimize_budget"] > 0,
                "minimize_budget must be positive")
        tests = config["tests"]
        require(isinstance(tests, list) and tests, "test suite is required")
        ids = set()
        for test in tests:
            require(isinstance(test, dict), "every test must be an object")
            require(isinstance(test.get("id"), str) and re.fullmatch(r"[A-Za-z0-9_-]+", test["id"]), "invalid test id")
            require(test["id"] not in ids, "duplicate test id")
            ids.add(test["id"])
            require(test.get("category") in {"valid", "boundary", "invalid"}, "invalid test category")
            require(inside(root, test["input"]).is_file(), f"missing test input: {test['input']}")
            require(inside(root, test["input"]).stat().st_size <= limits["file_bytes"], "input exceeds file limit")
            if interface == "argv":
                try:
                    text = inside(root, test["input"]).read_bytes().decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ConfigError("argv inputs must be valid UTF-8") from exc
                require("\0" not in text, "argv inputs cannot contain NUL bytes")
            expectation(test.get("expected"))
            if "minimized_expected" in test:
                expectation(test["minimized_expected"])
            if "args" in test:
                require(isinstance(test["args"], list) and all(isinstance(x, str) and "\0" not in x
                        for x in test["args"]), "test args must be an array of strings")
        require({x["category"] for x in tests} == {"valid", "boundary", "invalid"},
                "valid, boundary and invalid tests are all mandatory")
        targets = config["target_tests"]
        require(isinstance(targets, list) and targets and all(x in ids for x in targets),
                "target_tests must identify original baseline reproducer tests")
        return config, root
    except (OSError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(f"invalid configuration: {exc}") from exc

