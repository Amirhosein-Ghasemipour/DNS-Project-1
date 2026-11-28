"""Render evaluation evidence as a single self-contained HTML report.

Used by ``scripts/evaluate.py`` (which writes ``evaluation.html`` at the end
of every evaluation run) and by ``scripts/make_html_report.py`` (which
regenerates the report from an existing evidence directory without running
anything again).  Standard library only; the file opens offline in any
browser, and every scenario links to its raw log and JSON report next to it.
"""
import html
import json
import time
from pathlib import Path

_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font-family: "Segoe UI", system-ui, -apple-system, Arial, sans-serif;
       margin: 0; background: #f4f6f8; color: #1c2733; }
main { max-width: 1080px; margin: 0 auto; padding: 24px 20px 60px; }
header h1 { font-size: 22px; margin: 0 0 4px; }
.meta { color: #5b6b7b; font-size: 13px; margin: 4px 0; display: flex;
        flex-wrap: wrap; gap: 2px 14px; }
.meta span b::after { content: ": "; font-weight: 400; }
.banner { margin: 18px 0 22px; padding: 14px 18px; border-radius: 8px;
          font-size: 15px; font-weight: 600; border: 1px solid transparent; }
.banner.all-ok { background: #e6f6ec; border-color: #9fd8b4; color: #116632; }
.banner.has-failures { background: #fdeceb; border-color: #f3b6b0; color: #8f1d18; }
table { width: 100%; border-collapse: collapse; background: #fff;
        border: 1px solid #d7dee6; border-radius: 8px; overflow: hidden;
        font-size: 13.5px; }
th, td { padding: 8px 10px; border-bottom: 1px solid #e6ebf1; text-align: left;
         vertical-align: top; }
th { background: #eef2f6; font-weight: 600; white-space: nowrap; }
tr:last-child td { border-bottom: none; }
code, pre { font-family: ui-monospace, "Cascadia Mono", Consolas, "DejaVu Sans Mono", monospace; }
td code, .chip, .exit { font-size: 12.5px; }
a { color: #0b5cad; text-decoration: none; }
a:hover { text-decoration: underline; }
.chip { display: inline-block; padding: 2px 10px; border-radius: 999px;
        font-weight: 600; }
.chip.ok { background: #d9f2e2; color: #116632; }
.chip.fail { background: #fbdcd9; color: #8f1d18; }
.chip.sandbox { background: #fdf1d7; color: #7a5410; font-weight: 500; }
.exit { font-variant-numeric: tabular-nums; }
section.scenario { background: #fff; border: 1px solid #d7dee6; border-radius: 8px;
                   margin-top: 22px; overflow: hidden; }
section.scenario > h2 { font-size: 16px; margin: 0; padding: 12px 16px;
                        background: #eef2f6; border-bottom: 1px solid #e6ebf1;
                        display: flex; gap: 10px; align-items: center; }
.facts { display: flex; flex-wrap: wrap; gap: 6px 22px; padding: 10px 16px;
         font-size: 13px; color: #44525f; }
.facts b { color: #1c2733; font-weight: 600; }
.errors { margin: 4px 16px 12px; padding: 10px 12px; background: #fdeceb;
          border: 1px solid #f3b6b0; border-radius: 6px; }
.errors pre { margin: 2px 0; white-space: pre-wrap; word-break: break-word;
              color: #8f1d18; font-size: 12.5px; }
.summarybox { margin: 4px 16px 14px; }
.summarybox pre { background: #f7f9fb; border: 1px solid #dfe6ee; border-radius: 6px;
                  padding: 12px; white-space: pre-wrap; word-break: break-word;
                  font-size: 12.5px; line-height: 1.5; margin: 0; }
details { margin: 0 16px 16px; }
details summary { cursor: pointer; font-size: 13px; color: #0b5cad; padding: 4px 0; }
details pre { background: #10161d; color: #d7e3ee; border-radius: 6px; padding: 12px;
              white-space: pre-wrap; word-break: break-word; font-size: 12px;
              line-height: 1.45; max-height: 480px; overflow: auto; }
.note { margin-top: 8px; }
footer { margin-top: 26px; color: #5b6b7b; font-size: 12.5px; }
"""

_SCENARIO_ORDER = ("correct", "incomplete", "regression")
_EXIT_NAMES = {0: "OK", 10: "INCOMPLETE", 20: "REGRESSION", 30: "BUILD_OR_CONFIG_ERROR"}


def _exit_name(code):
    return _EXIT_NAMES.get(code, f"EXIT {code}")


def _esc(value):
    return html.escape(str(value), quote=True)


def _load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _read_text(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _scenario_section(row, output):
    name = row.get("scenario", "scenario")
    report = _load_json(output / name / "report.json")
    errors = [str(item) for item in (report.get("errors") or [])]
    inconclusive = [str(item) for item in (report.get("inconclusive") or [])]
    sandbox = (report.get("sandbox") or {})
    mode = sandbox.get("mode", "unknown")
    summary_text = _read_text(output / name / "summary.txt")
    log_text = _read_text(output / (name + ".log"))
    passed = bool(row.get("passed"))
    chip = "ok" if passed else "fail"
    verdict = "OK" if passed else "FAILED"
    parts = [f'<section class="scenario" id="{_esc(name)}">']
    parts.append(f'<h2><span class="chip {chip}">{verdict}</span> '
                 f'<code>{_esc(name)}</code></h2>')
    facts = [
        ("Expected", f'{row.get("expected_exit", "?")} ({_exit_name(row.get("expected_exit"))})'),
        ("Actual", f'{row.get("actual_exit", "?")} ({_exit_name(row.get("actual_exit"))})'),
        ("Generated re-executions", row.get("generated_executions", 0)),
        ("Persisted regressions", row.get("persisted_regressions", 0)),
        ("Sandbox mode", mode),
    ]
    if report.get("exit_code") is not None and report.get("exit_code") != row.get("actual_exit"):
        facts.append(("Patchcheck exit_code", report["exit_code"]))
    parts.append('<div class="facts">' + "".join(
        f"<span><b>{_esc(k)}:</b> {_esc(v)}</span>" for k, v in facts) + "</div>")
    if errors:
        parts.append('<div class="errors"><pre>' + "</pre><pre>".join(
            _esc(line) for line in errors) + "</pre></div>")
    if inconclusive:
        parts.append('<div class="errors" style="background:#fdf6e3;border-color:#ecd9a0">'
                     "<pre>" + "</pre><pre>".join(_esc(line) for line in inconclusive)
                     + "</pre></div>")
    if mode == "restricted":
        parts.append('<div class="errors note" style="background:#fdf1d7;border-color:#ecd9a0;color:#7a5410">'
                     "<pre>Sandbox fallback: the restricted mode ran the targets under rlimits, "
                     "capability drop and a private temp directory without a chroot or network "
                     "namespace. This is a documented degradation, not a scenario failure.</pre></div>")
    if summary_text:
        parts.append('<div class="summarybox"><pre>' + _esc(summary_text) + "</pre></div>")
    if log_text is not None:
        parts.append("<details><summary>Full console log (" + f"{len(log_text):,} bytes)</summary>"
                     "<pre>" + _esc(log_text) + "</pre></details>")
    parts.append('<div class="facts note">'
                 f'<span><b>Raw evidence:</b> <a href="{_esc(name + ".log")}">{_esc(name)}.log</a>'
                 f' · <a href="{_esc(name)}/report.json">report.json</a>'
                 f' · <a href="{_esc(name)}/summary.txt">summary.txt</a></span></div>')
    parts.append("</section>")
    return "\n".join(parts)


def render(rows, meta):
    """Build the complete HTML document string from result rows + metadata."""
    rows = list(rows)
    total = len(rows)
    passed = sum(1 for row in rows if row.get("passed"))
    failed = [str(row.get("scenario", "?")) for row in rows if not row.get("passed")]
    if failed:
        banner = (f'<div class="banner has-failures">{passed} of {total} scenarios passed — '
                  f"{len(failed)} FAILED: {_esc(', '.join(failed))}. "
                  f"Exit 30 means BUILD_OR_CONFIG_ERROR; see the red error lines below each "
                  f"failing scenario.</div>")
    else:
        banner = (f'<div class="banner all-ok">All {total} scenarios passed '
                  f"(expected exit codes matched actual exits).</div>")
    table_rows = []
    for row in rows:
        name = row.get("scenario", "?")
        chip = "ok" if row.get("passed") else "fail"
        table_rows.append(
            f'<tr><td><code>{_esc(name)}</code></td>'
            f'<td class="exit">{_esc(row.get("expected_exit", "?"))}</td>'
            f'<td class="exit">{_esc(row.get("actual_exit", "?"))}</td>'
            f'<td><span class="chip {chip}">{"OK" if row.get("passed") else "FAILED"}</span></td>'
            f'<td class="exit">{_esc(row.get("generated_executions", 0))}</td>'
            f'<td class="exit">{_esc(row.get("persisted_regressions", 0))}</td>'
            f'<td><a href="#{_esc(name)}">details</a></td></tr>')
    meta_bits = "".join(f'<span><b>{_esc(key)}</b>{_esc(value)}</span>'
                        for key, value in meta.items()
                        if value and not key.startswith("_") and key != "generated_at")
    title = "Patchcheck evaluation report"
    head = (f'<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>{_esc(title)}</title>\n<style>{_CSS}</style>\n</head>\n<body>\n<main>\n"
            f"<header><h1>{_esc(title)}</h1><div class=\"meta\">{meta_bits}</div></header>\n"
            f"{banner}\n"
            "<table><thead><tr><th>Scenario</th><th>Expected exit</th><th>Actual exit</th>"
            "<th>Result</th><th>Generated re-executions</th><th>Persisted regressions</th>"
            "<th></th></tr></thead>\n<tbody>\n" + "\n".join(table_rows) + "\n</tbody></table>\n"
            "<h2 style=\"font-size:16px;margin-top:28px\">Scenario details</h2>\n")
    body = "\n".join(_scenario_section(row, Path(meta["_output_dir"])) for row in rows)
    footer = (f'<footer>Generated {_esc(meta.get("generated_at", time.strftime("%Y-%m-%d %H:%M:%S")))} '
              f"by the patchcheck evaluation pipeline. Verdicts come from executing the pinned "
              f"baseline and patched builds in the selected sandbox; exit codes: 0 = correct build "
              f"behaves correctly, 10 = incomplete build detected, 20 = regression detected, "
              f"30 = build or configuration error.</footer>\n</main>\n</body>\n</html>\n")
    return head + body + footer


def write_report(output, rows, meta):
    """Write ``evaluation.html`` into the evidence directory ``output``."""
    output = Path(output)
    meta = dict(meta)
    meta["_output_dir"] = str(output)
    meta.setdefault("generated_at", time.strftime("%Y-%m-%d %H:%M:%S"))
    html_text = render(rows, meta)
    destination = output / "evaluation.html"
    destination.write_text(html_text, encoding="utf-8")
    return destination
