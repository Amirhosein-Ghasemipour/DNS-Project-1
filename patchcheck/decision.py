"""Exit priority is independent of reporting order and preserves every status."""

PRIORITY = (30, 10, 20, 40, 0)
NAMES = {0: "PASS", 10: "VULN_REMAINS / NEW_ISSUE", 20: "FUNC_REGRESSION",
         30: "BUILD_OR_CONFIG_ERROR", 40: "INCONCLUSIVE"}


def decide(report):
    codes = {0}
    if report.get("errors"):
        codes.add(30)
    statuses = {finding["status"] for finding in report.get("findings", [])}
    if statuses & {"Incomplete Fix", "New Issue"}:
        codes.add(10)
    if "Functional Regression" in statuses:
        codes.add(20)
    if report.get("inconclusive") or "Inconclusive" in statuses or not report.get("mandatory_checks_complete"):
        codes.add(40)
    code = next(value for value in PRIORITY if value in codes)
    report["exit_code"], report["status"] = code, NAMES[code]
    report["independent_statuses"] = {
        "security": "Confirmed patched error" if 10 in codes else "Inconclusive" if 40 in codes or 30 in codes else "No patched error observed",
        "functionality": "Functional Regression" if 20 in codes else "Expected results passed" if report.get("functional_complete") else "Inconclusive",
        "analysis_completeness": "Error" if 30 in codes else "Incomplete" if 40 in codes else "Complete"}
    return code

