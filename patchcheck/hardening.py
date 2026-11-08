"""Read readelf evidence; never infer runtime ASLR or universal canary coverage."""

import re

from .config import ConfigError


def assess(text):
    require = (re.search(r"Class:\s+ELF64", text) and re.search(r"Machine:\s+Advanced Micro Devices X86-64", text)
               and re.search(r"Type:\s+(?:EXEC|DYN)", text))
    if not require:
        raise ConfigError("target is not a Linux-compatible x86_64 ELF64 executable")
    lines = text.splitlines()
    stack = next((line.strip() for line in lines if "GNU_STACK" in line), None)
    relro = next((line.strip() for line in lines if "GNU_RELRO" in line), None)
    bind_now = [line.strip() for line in lines if "BIND_NOW" in line or ("FLAGS" in line and "NOW" in line)]
    pie = [line.strip() for line in lines if "FLAGS_1" in line and "PIE" in line]
    canary = [line.strip() for line in lines if re.search(r"\b__stack_chk_fail(?:@|\b)", line)]
    nx = "Unknown" if stack is None else "Disabled" if re.search(r"\bRWE\b|\bE\b", stack) else "Enabled"
    return {"NX": {"status": nx, "evidence": [stack] if stack else []},
            "PIE": {"status": "Enabled" if pie else "Disabled" if re.search(r"Type:\s+EXEC", text) else "Unknown",
                    "evidence": pie},
            "RELRO": {"status": "Full RELRO" if relro and bind_now else "Partial RELRO" if relro else "No RELRO",
                      "evidence": ([relro] if relro else []) + bind_now},
            "Stack Canary": {"status": "Evidence present" if canary else "No symbol evidence", "evidence": canary},
            "limitations": ["PIE does not prove runtime ASLR is enabled.",
                            "Canary symbols do not establish protection of every function.",
                            "Missing dynamic PIE flags in an ET_DYN binary are reported as Unknown."]}


def warnings(before, after):
    ranks = {"NX": {"Enabled": 1, "Disabled": 0}, "PIE": {"Enabled": 1, "Disabled": 0},
             "RELRO": {"Full RELRO": 2, "Partial RELRO": 1, "No RELRO": 0},
             "Stack Canary": {"Evidence present": 1, "No symbol evidence": 0}}
    changes = []
    for name, levels in ranks.items():
        old, new = before[name]["status"], after[name]["status"]
        if old != new:
            changes.append({"protection": name, "baseline": old, "patched": new,
                            "decreased": levels.get(new, -1) < levels.get(old, -1)})
    return changes

