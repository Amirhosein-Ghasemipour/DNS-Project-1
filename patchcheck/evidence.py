"""Interpret runtime evidence conservatively; crashes are not vulnerability proofs."""

import base64
import re

ASAN_TYPES = {"heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
              "heap-use-after-free", "stack-use-after-return", "stack-use-after-scope",
              "double-free", "bad-free", "alloc-dealloc-mismatch", "new-delete-type-mismatch",
              "use-after-poison"}
# ASan prefixes some diagnoses with a verb. The canonical name is the tail.
ASAN_ALIASES = {"attempting double-free": "double-free",
                "attempting free on address which was not malloc()-ed": "bad-free"}
LOCATION = re.compile(r"(?P<file>/work/[^\s():]+\.(?:c|cc|cpp|cxx|h|hpp)):(?P<line>\d+)(?::\d+)?")


def _derive_unknown_crash(stderr):
    """Recover the access class ASan failed to name, without guessing.

    ASan reports bulk copies through intercepted libc/FORTIFY paths as
    ``unknown-crash`` even though the report still states the access direction
    and the region kind. Only a report that states both is re-classified.
    """
    if not re.search(r"\b(?:READ|WRITE) of size \d+", stderr):
        return None
    if re.search(r"is located in stack of thread|is located in stack of", stderr):
        return "stack-buffer-overflow"
    if "global variable" in stderr:
        return "global-buffer-overflow"
    if re.search(r"allocated by thread|-byte region", stderr):
        return "heap-buffer-overflow"
    return None


def _asan_type(phrase, stderr):
    text = phrase.strip()
    for alias, canonical in ASAN_ALIASES.items():
        if text.startswith(alias):
            return canonical
    words = text.split()
    kind = words[0].rstrip(":,") if words else ""
    if kind == "unknown-crash":
        return _derive_unknown_crash(stderr) or kind
    return kind


UBSAN_CHECKS = (
    (r"(?:load of|store to|member access within|null pointer passed).*null pointer|"
     r"null pointer passed as argument|applying (?:non-zero|zero) offset.*null pointer", "null-pointer-dereference"),
    (r"division by zero", "division-by-zero"),
    (r"index .* out of bounds|insufficient space for an object", "out-of-bounds"),
    (r"signed integer overflow", "signed-integer-overflow"),
    (r"misaligned address", "misaligned-access"))


def _ubsan_type(stderr):
    for expression, kind in UBSAN_CHECKS:
        if re.search(expression, stderr):
            return kind
    return None


def analyze(result):
    stderr = result.get("stderr", "")
    locations = []
    for line in stderr.splitlines():
        match = LOCATION.search(line)
        if match:
            function = re.search(r"\bin (\S+)\s+", line)
            location = {"file": match["file"][len("/work/"):], "line": int(match["line"]),
                        "function": function[1] if function else None}
            if location not in locations:
                locations.append(location)
    error_type, mechanism, confirmed, secondary = None, None, False, []
    match = re.search(r"ERROR: AddressSanitizer: ([^\n]+)", stderr)
    if match:
        error_type = _asan_type(match[1], stderr)
        mechanism = "ASan"
        confirmed = error_type in ASAN_TYPES and bool(locations)
    if "runtime error:" in stderr:
        mechanism = "UBSan" if not mechanism else "ASan+UBSan"
        kind = _ubsan_type(stderr)
        if error_type is None:
            # An undefined-behavior report we cannot name stays unconfirmed.
            error_type = kind or "unclassified-undefined-behavior"
            confirmed = bool(locations) if kind else False
        elif kind and kind != error_type:
            # A sanitizer report must never overwrite a memory-safety diagnosis:
            # the fingerprint drives fix-equivalence, not just labelling.
            secondary.append({"type": kind, "mechanism": "UBSan"})
    if "stack smashing detected" in stderr and error_type is None:
        error_type, mechanism = "stack-canary-failure", "stack-canary"
        # Without a relevant location this alone is insufficient for a confirmed vulnerability.
        confirmed = bool(locations)
    if "buffer overflow detected" in stderr and error_type is None:
        # glibc _FORTIFY_SOURCE abort (__chk_fail); distinct from stack canary.
        error_type, mechanism = "fortify-abort", "FORTIFY (glibc __chk_fail)"
        confirmed = bool(locations)
    if result.get("resource_limit"):
        confirmed = False
    if result.get("signal") and error_type is None:
        error_type, mechanism = "unclassified-crash", "OS-signal"
    if "AddressSanitizer:DEADLYSIGNAL" in stderr and error_type is None:
        error_type, mechanism = "unclassified-crash", "ASan"
    primary = locations[0] if locations else None
    fingerprint = {"error_type": error_type, "location": primary} if error_type else None
    result["error"] = {"type": error_type, "mechanism": mechanism, "confirmed": confirmed,
                       "locations": locations, "fingerprint": fingerprint, "secondary": secondary,
                       "root_cause": "Undetermined", "exploitability": "Not assessed"}
    return result


def matches_expected(result, expected):
    return (not result.get("resource_limit") and not result.get("signal")
            and not result["error"]["type"] and result.get("exit_code") == expected["exit_code"]
            and base64.b64decode(result["stdout_base64"]) == expected["stdout"].encode("utf-8")
            and base64.b64decode(result["stderr_base64"]) == expected["stderr"].encode("utf-8"))


def observation_key(result):
    """Compare observable behavior, excluding timing, ASLR addresses and PIDs."""
    error = result["error"]
    if error["type"]:
        return (error["confirmed"], str(error["fingerprint"]), result.get("resource_limit"))
    return (result.get("returncode"), result.get("resource_limit"), result.get("stdout_base64"),
            result.get("stderr_base64"))


def reproduces(result, fingerprint):
    return result["error"]["confirmed"] and result["error"]["fingerprint"] == fingerprint
