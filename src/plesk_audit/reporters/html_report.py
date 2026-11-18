"""Self-contained HTML report. All host-derived text is escaped; no scripts or remote assets."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

from plesk_audit.models import AuditRun
from plesk_audit.reporters.json_report import to_jsonable, write_private

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'none'"
_STYLE = """
body{font-family:sans-serif;margin:2rem;color:#222}
table{border-collapse:collapse;margin-bottom:1.5rem;width:100%}
th,td{border:1px solid #ccc;padding:.3rem .5rem;text-align:left;vertical-align:top}
th{background:#f0f0f0}
pre{background:#f7f7f7;padding:.5rem;overflow-x:auto;white-space:pre-wrap}
.sev-critical,.sev-high{color:#a00;font-weight:bold}.sev-medium{color:#b60}
.st-error{color:#a00}.st-partial,.st-skipped{color:#b60}
"""


def _e(value: object) -> str:
    return escape("" if value is None else str(value), quote=True)


def _row(*cells: str, header: bool = False) -> str:
    tag = "th" if header else "td"
    return "<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>"


def render_html(audit: AuditRun) -> str:
    run = to_jsonable(audit.run)
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{_e(_CSP)}">',
        '<meta name="referrer" content="no-referrer">',
        f"<title>Security audit report {_e(audit.run.run_id)}</title>",
        f"<style>{_STYLE}</style></head><body>",
        "<h1>Plesk / AlmaLinux security audit</h1>",
        (
            "<p><strong>Confidential.</strong> Contains host-specific security information. "
            "Findings are indicators that require human validation.</p>"
        ),
        "<h2>Run</h2><table>",
    ]
    parts += [_row(_e(key), _e(run[key])) for key in sorted(run)]
    parts.append("</table>")

    parts.append("<h2>Findings</h2>")
    findings = sorted(audit.findings, key=lambda f: (_SEVERITY_ORDER[f.severity], f.id))
    if findings:
        parts.append("<table>")
        parts.append(_row("ID", "Severity", "Confidence", "Status", "Finding", header=True))
        for f in findings:
            detail = (
                f"<strong>{_e(f.title)}</strong><br>{_e(f.summary)}"
                f"<br><em>Impact:</em> {_e(f.impact)}"
                f"<br><em>Recommendation:</em> {_e(f.recommendation)}"
                f"<br><em>Evidence:</em> {_e(', '.join(f.evidence_refs))}"
            )
            parts.append(
                _row(
                    _e(f.id),
                    f'<span class="sev-{_e(f.severity)}">{_e(f.severity)}</span>',
                    _e(f.confidence),
                    _e(f.status),
                    detail,
                )
            )
        parts.append("</table>")
    else:
        parts.append("<p>No findings were produced by the implemented rules.</p>")

    parts.append("<h2>Collectors</h2><table>")
    parts.append(_row("Collector", "Status", "Message", header=True))
    for c in audit.collectors:
        status = f'<span class="st-{_e(c.status)}">{_e(c.status)}</span>'
        parts.append(_row(_e(c.name), status, _e(c.message)))
    parts.append("</table>")

    parts.append("<h2>Limitations</h2><ul>")
    parts += [f"<li>{_e(item)}</li>" for item in audit.limitations]
    parts.append("</ul>")

    parts.append("<h2>Evidence</h2>")
    for c in audit.collectors:
        for ev in c.evidence:
            body = json.dumps(to_jsonable(ev.data), indent=2, sort_keys=True, ensure_ascii=False)
            parts.append(
                f'<h3 id="{_e(ev.evidence_id)}">{_e(ev.evidence_id)}</h3>'
                f"<p>Source: {_e(ev.source)} &middot; collected {_e(to_jsonable(ev.collected_at))}"
                f"</p><pre>{_e(body)}</pre>"
            )
    parts.append("</body></html>\n")
    return "\n".join(parts)


def write_html_report(audit: AuditRun, directory: Path) -> Path:
    path = directory / "report.html"
    write_private(path, render_html(audit))
    return path
