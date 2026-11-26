"""Text and JSON report rendering."""

from __future__ import annotations

import json

from .checker import Finding, Status


def summarise(findings: list[Finding]) -> dict[str, int]:
    """Count findings per status, plus the total checked."""
    summary = {status.value: 0 for status in Status}
    for finding in findings:
        summary[finding.status.value] += 1
    summary["total"] = len(findings)
    return summary


def render_text(findings: list[Finding]) -> str:
    lines: list[str] = []
    for finding in findings:
        label = finding.status.value.upper()
        line = f"{label:<18} {finding.host}"
        if finding.target:
            line += f" -> {finding.target}"
        if finding.service:
            line += f" ({finding.service})"
        if finding.reason:
            line += f": {finding.reason}"
        lines.append(line)
    summary = summarise(findings)
    lines.append(
        "Checked {total} host(s): {v} vulnerable-likely, {c} claimed, "
        "{u} unknown, {n} no-cname.".format(
            total=summary["total"],
            v=summary[Status.VULNERABLE.value],
            c=summary[Status.CLAIMED.value],
            u=summary[Status.UNKNOWN.value],
            n=summary[Status.NO_CNAME.value],
        )
    )
    return "\n".join(lines)


def render_json(findings: list[Finding], version: str = "") -> str:
    payload = {
        "tool": "subdangler",
        "version": version,
        "results": [
            {
                "host": finding.host,
                "status": finding.status.value,
                "cnames": list(finding.cnames),
                "service": finding.service,
                "target": finding.target,
                "reason": finding.reason,
            }
            for finding in findings
        ],
        "summary": summarise(findings),
    }
    return json.dumps(payload, indent=2)
