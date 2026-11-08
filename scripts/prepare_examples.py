"""Prepare local, pinned evaluation versions; never changes upstream checkouts.

The fixture Git repository is derived from fully preserved source files. cJSON
uses its supplied upstream commit plus transparent patches and a fixed driver.
No target is built or executed by this script.
"""

import difflib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CJSON_COMMIT = "87d8f0961a01bf09bef98ff89bae9fdec42181ee"
JQ_COMMIT = "11c528d04d76c9b9553781aa76b073e4f40da008"


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def git(repository, *args, env=None):
    result = subprocess.run(["git", "-c", f"safe.directory={repository.as_posix()}", "-C", str(repository), *args],
                            capture_output=True, check=True, env=env)
    return result.stdout.decode().strip()


def patch(path, old, new, name):
    content = "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        fromfile="a/" + name, tofile="b/" + name))
    write(path, content)


def expected(stdout, code=0, reference="targets/CONTRACTS.md: independent record/API contract"):
    return {"exit_code": code, "stdout": stdout, "stderr": "", "reference": reference}


def configurations(name, versions, sources, tests, interface="stdin"):
    release = ["cc", "-std=c11", "-g", "-O2", "-fstack-protector-strong", "-fPIE", "-pie",
               "-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack", *sources, "-o", "target"]
    sanitized = ["cc", "-std=c11", "-g", "-O1", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
                 "-fsanitize=address,undefined", "-fno-sanitize-recover=all", *sources, "-o", "target"]
    for variant in ("correct", "incomplete", "regression"):
        config = {"schema_version": 1, "name": f"{name}/{variant}", "target": name.replace("-", "_"),
                  "root": "..", "authorized": True,
                  "versions": {"baseline": versions["base"], "patched": versions[variant]},
                  "builds": {"release": {"commands": [release], "binary": "target"},
                             "sanitized": {"commands": [sanitized], "binary": "target", "env": {
                                 "ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1:symbolize=1:allow_addr2line=1",
                                 "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"}}},
                  "execution": {"interface": interface, "argv": ["{binary}"] + (["{input}"] if interface == "file" else [])}, "tests": tests,
                  "target_tests": ["original"], "replays": 3, "minimize_budget": 40,
                  "limits": {"wall_seconds": 3, "cpu_seconds": 2, "memory_mb": 512,
                             "output_bytes": 1048576, "file_bytes": 67108864, "pids": 128, "build_seconds": 180}}
        write(ROOT / "configs" / f"{name}-{variant}.json", json.dumps(config, indent=2) + "\n")


def main():
    upstream = ROOT / "targets/cjson/upstream"
    cjson_commit = CJSON_COMMIT
    fixed = subprocess.run(["git", "-c", f"safe.directory={upstream.as_posix()}", "-C", str(upstream),
                            "show", f"{cjson_commit}:cJSON.c"], capture_output=True, check=True).stdout.decode()
    guard = "    /* return NULL if the object is corrupted */\n    if (object->valuestring == NULL)\n    {\n        return NULL;\n    }\n"
    if fixed.count(guard) != 1:
        raise RuntimeError("supplied cJSON revision does not contain the expected public guard; inspect provenance")
    base = fixed.replace(guard, "")
    incomplete = fixed.replace("if (object->valuestring == NULL)",
                               'if (object->valuestring == NULL && strcmp(valuestring, "original") == 0)', 1)
    regression = fixed.replace(guard, guard + "    if (valuestring[0] != '\\0') { return NULL; }\n")
    versions = {}
    for name, content in {"base": base, "correct": fixed, "incomplete": incomplete, "regression": regression}.items():
        version = {"repository": "targets/cjson/upstream", "revision": cjson_commit,
                   "overlays": {"harness.c": "targets/cjson/harness.c"}}
        if content != fixed:
            name_path = f"targets/cjson/patches/{name}.patch"
            patch(ROOT / name_path, fixed, content, "cJSON.c")
            version["patches"] = [name_path]
        versions[name] = version
    cases = [("valid", "valid", b"=hello", expected("hello\n")),
             ("valid-longer", "valid", b"=university", expected("university\n")),
             ("empty-string", "boundary", b"=", expected("\n")),
             ("invalid-interface", "invalid", b"?", expected("invalid\n", 2)),
             ("original", "invalid", b"!original", expected("invalid\n", 2)),
             ("alternative", "invalid", b"!alternate", expected("invalid\n", 2))]
    tests = []
    for name, category, data, oracle in cases:
        relative = f"targets/cjson/inputs/{name}.bin"
        (ROOT / relative).parent.mkdir(parents=True, exist_ok=True)
        (ROOT / relative).write_bytes(data)
        test = {"id": name, "category": category, "input": relative, "expected": oracle}
        if name in {"original", "alternative"}:
            test["minimized_expected"] = expected("invalid\n", 2,
                "targets/CONTRACTS.md: every corrupted-object (!) case is rejected, independent of replacement bytes")
        tests.append(test)
    configurations("cjson", versions, ["/work/cJSON.c", "/work/harness.c", "-lm"], tests)

    upstream = ROOT / "targets/jq/upstream"
    jq_commit = JQ_COMMIT
    fixed = git(upstream, "show", f"{jq_commit}:src/jv_unicode.c") + "\n"
    guard = "  } else if (in + length > end) {\n    /* String ends before UTF8 sequence ends */\n    length = end - in;\n"
    if fixed.count(guard) != 1:
        raise RuntimeError("jq UTF-8 bounds guard changed; inspect pinned source")
    variants = {"base": fixed.replace(guard, ""), "correct": fixed,
                "incomplete": fixed.replace("in + length > end", "in + length > end && first == 0xe2"),
                "regression": fixed.replace("codepoint = first;", "codepoint = -1;")}
    versions = {}
    for name, content in variants.items():
        version = {"repository": "targets/jq/upstream", "revision": jq_commit,
                   "overlays": {"harness.c": "targets/jq/harness.c"}}
        if content != fixed:
            relative = f"targets/jq/patches/{name}.patch"
            patch(ROOT / relative, fixed, content, "src/jv_unicode.c")
            version["patches"] = [relative]
        versions[name] = version
    tests = []
    cases = [("ascii", "valid", b"hello", True), ("unicode", "valid", bytes.fromhex("e282ac"), True),
             ("empty", "boundary", b"", True), ("maximum", "boundary", bytes.fromhex("f48fbfbf"), True),
             ("surrogate", "invalid", bytes.fromhex("eda080"), False),
             ("original", "invalid", bytes.fromhex("e2"), False),
             ("alternative", "invalid", bytes.fromhex("f0"), False)]
    for name, category, data, valid in cases:
        relative = f"targets/jq/inputs/{name}.bin"
        (ROOT / relative).parent.mkdir(parents=True, exist_ok=True)
        (ROOT / relative).write_bytes(data)
        tests.append({"id": name, "category": category, "input": relative,
                      "expected": expected("valid\n" if valid else "invalid\n", 0 if valid else 2,
                          "targets/CONTRACTS.md: RFC 3629 section 4 UTF-8 grammar")})
    configurations("jq", versions, ["/work/src/jv_unicode.c", "/work/harness.c"], tests, interface="file")

    fixture = ROOT / "targets/record_reader"
    base = (fixture / "base.c").read_text(encoding="utf-8")
    marker = "    /* The baseline deliberately lacks the record-length check. */"
    proper = '    if (length > 16) { puts("too long"); return 2; }'
    variants = {"base": base, "correct": base.replace(marker, proper),
                "incomplete": base.replace(marker, '    if (length == 64) { puts("too long"); return 2; }'),
                "regression": base.replace(marker, proper + '\n    if (length > 8) { puts("too long"); return 2; }')}
    repository = fixture / "repository"
    # Build once. Never reset or overwrite an existing user repository.
    if not repository.exists():
        repository.mkdir()
        git(repository, "init", "--quiet")
        env = dict(os.environ, GIT_AUTHOR_NAME="Patchcheck teaching fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                   GIT_COMMITTER_NAME="Patchcheck teaching fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid",
                   GIT_AUTHOR_DATE="2024-01-01T00:00:00+0000", GIT_COMMITTER_DATE="2024-01-01T00:00:00+0000")
        for name, content in variants.items():
            write(repository / "reader.c", content)
            git(repository, "add", "reader.c")
            git(repository, "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", name, env=env)
            git(repository, "tag", name)
    versions = {}
    for name, content in variants.items():
        write(fixture / "versions" / f"{name}.c", content)
        commit = git(repository, "rev-parse", f"refs/tags/{name}")
        if git(repository, "show", f"{commit}:reader.c") != content.strip():
            raise RuntimeError("existing teaching repository differs from preserved source; inspect it before regenerating")
        versions[name] = {"repository": "targets/record_reader/repository", "revision": commit}
    tests = []
    for name, category, data in [("valid", "valid", b"hello"), ("valid-wide", "valid", b"123456789012"),
                                 ("boundary", "boundary", b"1234567890123456"), ("empty", "boundary", b""),
                                 ("original", "invalid", b"A" * 64), ("alternative", "invalid", b"B" * 48)]:
        relative = f"targets/record_reader/inputs/{name}.bin"
        (ROOT / relative).parent.mkdir(parents=True, exist_ok=True)
        (ROOT / relative).write_bytes(data)
        oracle = expected(data.decode() if len(data) <= 16 else "too long\n", 0 if len(data) <= 16 else 2)
        test = {"id": name, "category": category, "input": relative, "expected": oracle}
        if len(data) > 16:
            test["minimized_expected"] = expected("too long\n", 2,
                "targets/CONTRACTS.md: every record that overflows the baseline 16-byte heap allocation has length >16 and must be rejected")
        tests.append(test)
    configurations("record-reader", versions, ["/work/reader.c"], tests)
    print("Prepared nine configurations, source patches, exact local revisions, and independent test inputs.")


if __name__ == "__main__":
    main()

