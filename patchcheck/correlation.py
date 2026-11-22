"""Link runtime source locations to diff hunks without inferring causation."""

import re


def parse_diff(text):
    files, old, new = {}, None, None
    for line in text.splitlines():
        if line.startswith("--- "):
            old = line[4:].split("\t")[0].removeprefix("a/")
        elif line.startswith("+++ "):
            new = line[4:].split("\t")[0].removeprefix("b/")
        elif line.startswith("@@ "):
            match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if match:
                values = [int(match[i]) if match[i] is not None else 1 for i in range(1, 5)]
                hunk = dict(zip(("old_start", "old_count", "new_start", "new_count"), values))
                context = line[match.end():].strip()
                functions = re.findall(r"\b([A-Za-z_][A-Za-z_0-9]*)\s*\(", context)
                hunk["function"] = functions[-1] if functions else None
                files.setdefault((old, new), []).append(hunk)
    return files


def correlate(results, diff):
    matches = []
    for role, result in results.items():
        for location in result["error"]["locations"]:
            for names, hunks in diff.items():
                if location["file"] != names[0 if role == "baseline" else 1]:
                    continue
                prefix = "old" if role == "baseline" else "new"
                for hunk in hunks:
                    start, count = hunk[prefix + "_start"], hunk[prefix + "_count"]
                    if count and start <= location["line"] < start + count:
                        matches.append({"version": role, "runtime_location": location, "hunk": hunk,
                                        "association": "changed-line"})
                    elif location.get("function") and location["function"] == hunk.get("function"):
                        matches.append({"version": role, "runtime_location": location, "hunk": hunk,
                                        "association": "changed-function"})
    status = ("Runtime stack intersects changed lines" if any(x["association"] == "changed-line" for x in matches)
              else "Runtime stack includes changed function" if matches else "Undetermined")
    return {"status": status,
            "evidence": matches, "caused_by_patch": "Undetermined",
            "note": "Dynamic stack/diff overlap supports association, not root cause or causation."}


def equivalent(before, after, diff):
    a, b = before["error"], after["error"]
    if not (a["confirmed"] and b["confirmed"] and a["type"] == b["type"]):
        return False
    left, right = a["fingerprint"]["location"], b["fingerprint"]["location"]
    if left is None or right is None:
        return False
    hunks = diff.get((left["file"], right["file"]), [])
    if not hunks:
        return left["file"] == right["file"] and left["line"] == right["line"]
    shift = 0
    for hunk in hunks:
        start, count = hunk["old_start"], hunk["old_count"]
        if count and start <= left["line"] < start + count:
            return (hunk["new_count"] > 0 and hunk["new_start"] <= right["line"] < hunk["new_start"] + hunk["new_count"])
        if (count and left["line"] >= start + count) or (not count and left["line"] > start):
            shift += hunk["new_count"] - count
    return left["file"] == right["file"] and right["line"] == left["line"] + shift

