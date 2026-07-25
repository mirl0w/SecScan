from __future__ import annotations

from secscan.core.findings import AggregatedResults, Severity
from secscan.core.reporter import Reporter

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


class MarkdownReporter(Reporter):
    name = "markdown"
    file_extension = "md"

    def render(self, results: AggregatedResults) -> str:
        lines = ["# Security Scan Results", ""]

        counts = results.counts_by_severity()
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for sev in Severity:
            lines.append(f"| {_SEVERITY_EMOJI[sev]} {sev.value} | {counts[sev.value]} |")
        lines.append("")

        lines.append("## Scanner Runs")
        lines.append("")
        lines.append("| Scanner | Status | Duration | Findings |")
        lines.append("|---|---|---|---|")
        for run in results.scanner_runs:
            status = "✅ OK" if run.success else f"❌ {run.error_message or 'failed'}"
            lines.append(
                f"| {run.scanner} | {status} | {run.duration_seconds:.1f}s | {run.actionable_count} |"
            )
        lines.append("")

        actionable = sorted(
            results.actionable_findings, key=lambda f: -f.severity.rank
        )
        if actionable:
            lines.append("## Findings")
            lines.append("")
            for f in actionable:
                loc = f.file_path
                if f.line_start:
                    loc += f":{f.line_start}"
                lines.append(
                    f"### {_SEVERITY_EMOJI[f.severity]} [{f.severity.value}] {f.title}"
                )
                lines.append("")
                lines.append(f"- **Scanner:** {f.scanner}")
                lines.append(f"- **Rule:** {f.rule_id}")
                lines.append(f"- **Location:** `{loc}`")
                if f.description:
                    lines.append(f"- **Details:** {f.description}")
                lines.append("")
        else:
            lines.append("No actionable findings. ✅")
            lines.append("")

        return "\n".join(lines)
