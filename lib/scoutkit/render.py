"""Markdown and self-contained HTML renderers.

The HTML output embeds its own CSS and contains no scripts and no external
references, so it renders identically offline and inside a SharePoint or
OneDrive preview sandbox.
"""

from __future__ import annotations

import html
from typing import Any

from .findings import Report, Severity

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#B4232C",
    Severity.HIGH: "#C2410C",
    Severity.MEDIUM: "#A16207",
    Severity.LOW: "#1D4ED8",
    Severity.INFO: "#4B5563",
}

_VERDICT_COLOR = {"block": "#B4232C", "review": "#A16207", "pass": "#15803D"}

_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; padding: 32px; background: #F3F4F6; color: #111827;
       font-family: "Segoe UI", system-ui, -apple-system, sans-serif; line-height: 1.55; }
main { max-width: 1080px; margin: 0 auto; }
.card { background: #FFFFFF; border: 1px solid #E5E7EB; border-radius: 10px;
        padding: 20px 24px; margin-bottom: 18px; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 17px; margin: 0 0 12px; text-transform: uppercase;
     letter-spacing: .06em; color: #4B5563; }
.sub { color: #6B7280; font-size: 13px; margin: 0; }
.verdict { display: inline-block; padding: 6px 14px; border-radius: 999px;
           color: #FFFFFF; font-weight: 600; font-size: 13px; letter-spacing: .04em; }
.pills { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.pill { border: 1px solid #E5E7EB; border-radius: 999px; padding: 4px 12px; font-size: 12px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid #E5E7EB; vertical-align: top; }
th { background: #F9FAFB; font-size: 11px; text-transform: uppercase;
     letter-spacing: .05em; color: #4B5563; }
tr:last-child td { border-bottom: none; }
.sev { font-weight: 600; white-space: nowrap; }
code, .mono { font-family: Consolas, "Cascadia Mono", monospace; font-size: 12px; }
.empty { color: #6B7280; font-style: italic; }
ul { margin: 0; padding-left: 20px; }
footer { color: #6B7280; font-size: 12px; text-align: center; margin-top: 8px; }
"""


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _md_cell(value: Any) -> str:
    """Escape pipes and newlines so a value can never break table layout."""
    return _flatten(value).replace("|", "\\|")


def _flatten(value: Any) -> str:
    return " ".join(("" if value is None else str(value)).split())


def render_markdown(report: Report, *, title: str) -> str:
    counts = report.counts()
    lines: list[str] = [
        f"# {title}",
        "",
        f"Skill: `{report.skill}`  ",
        f"Subject: {report.subject or 'n/a'}  ",
        f"Generated: {report.generated_at}  ",
        f"Verdict: **{report.verdict.upper()}**",
        "",
        "## Severity counts",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    lines += [f"| {level} | {counts[level]} |" for level in Severity.ORDER]

    if report.summary:
        lines += ["", "## Summary", "", "| Measure | Value |", "| --- | --- |"]
        lines += [f"| {_md_cell(k)} | {_md_cell(v)} |" for k, v in sorted(report.summary.items())]

    lines += ["", "## Findings", ""]
    findings = report.sorted_findings()
    if not findings:
        lines.append("No findings. Every check passed.")
    else:
        lines += ["| Severity | Code | Where | Finding | Recommended action |", "| --- | --- | --- | --- | --- |"]
        for f in findings:
            lines.append(
                f"| {f.severity} | `{f.code}` | {_md_cell(f.locator) or '—'} "
                f"| {_md_cell(f.title)}: {_md_cell(f.detail)} | {_md_cell(f.recommendation) or '—'} |"
            )

    if report.notes:
        lines += ["", "## Run notes", ""] + [f"- {_flatten(n)}" for n in report.notes]

    lines += ["", "---", "", "Deterministic offline analysis. No tenant state was read or changed."]
    return "\n".join(lines) + "\n"


def render_html(report: Report, *, title: str) -> str:
    counts = report.counts()
    verdict_color = _VERDICT_COLOR.get(report.verdict, "#4B5563")

    pills = "".join(
        f'<span class="pill"><strong style="color:{_SEVERITY_COLOR[level]}">'
        f"{counts[level]}</strong> {level}</span>"
        for level in Severity.ORDER
    )

    summary_rows = "".join(
        f"<tr><td>{_esc(key)}</td><td class='mono'>{_esc(value)}</td></tr>"
        for key, value in sorted(report.summary.items())
    )
    summary_block = (
        f"<section class='card'><h2>Summary</h2><table><thead><tr><th>Measure</th>"
        f"<th>Value</th></tr></thead><tbody>{summary_rows}</tbody></table></section>"
        if summary_rows
        else ""
    )

    findings = report.sorted_findings()
    if findings:
        rows = "".join(
            "<tr>"
            f"<td class='sev' style='color:{_SEVERITY_COLOR[f.severity]}'>{_esc(f.severity)}</td>"
            f"<td class='mono'>{_esc(f.code)}</td>"
            f"<td class='mono'>{_esc(f.locator) or '&mdash;'}</td>"
            f"<td><strong>{_esc(f.title)}</strong><br>{_esc(f.detail)}</td>"
            f"<td>{_esc(f.recommendation) or '&mdash;'}</td>"
            "</tr>"
            for f in findings
        )
        findings_block = (
            "<table><thead><tr><th>Severity</th><th>Code</th><th>Where</th>"
            f"<th>Finding</th><th>Recommended action</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    else:
        findings_block = "<p class='empty'>No findings. Every check passed.</p>"

    notes_block = (
        "<section class='card'><h2>Run notes</h2><ul>"
        + "".join(f"<li>{_esc(n)}</li>" for n in report.notes)
        + "</ul></section>"
        if report.notes
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
  <section class="card">
    <h1>{_esc(title)}</h1>
    <p class="sub">{_esc(report.skill)} &middot; {_esc(report.subject or 'n/a')}
       &middot; generated {_esc(report.generated_at)}</p>
    <p style="margin:14px 0 0">
      <span class="verdict" style="background:{verdict_color}">{_esc(report.verdict.upper())}</span>
    </p>
    <div class="pills">{pills}</div>
  </section>
  {summary_block}
  <section class="card"><h2>Findings</h2>{findings_block}</section>
  {notes_block}
  <footer>Deterministic offline analysis &middot; no tenant state read or changed</footer>
</main>
</body>
</html>
"""
