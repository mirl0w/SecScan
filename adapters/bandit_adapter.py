from __future__ import annotations

import json
from pathlib import Path

from secscan.core.adapter import ScannerAdapter
from secscan.core.findings import Finding, Severity

# Bandit uses its own severity words; map them onto our normalized enum.
_SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class BanditAdapter(ScannerAdapter):
    name = "bandit"
    binary_name = "bandit"

    def build_command(self, target_dir: Path) -> list[str]:
        cmd = ["bandit", "-r", ".", "-f", "json"]
        exclude = self.options.get("exclude_dirs")
        if exclude:
            cmd += ["-x", ",".join(exclude)]
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        # Bandit exits non-zero when it finds issues — that's expected, not a failure.
        # Only a genuinely empty/unparsable stdout indicates something went wrong.
        if not stdout.strip():
            if returncode not in (0, 1):
                raise RuntimeError(f"bandit failed (exit {returncode}): {stderr.strip()[:500]}")
            return []

        data = json.loads(stdout)
        findings = []
        for result in data.get("results", []):
            findings.append(
                Finding(
                    scanner=self.name,
                    rule_id=result.get("test_id", "UNKNOWN"),
                    title=result.get("test_name", "Bandit finding"),
                    severity=_SEVERITY_MAP.get(result.get("issue_severity", "LOW"), Severity.LOW),
                    file_path=result.get("filename", "unknown"),
                    line_start=result.get("line_number"),
                    line_end=result.get("line_range", [None])[-1] if result.get("line_range") else None,
                    description=result.get("issue_text", ""),
                )
            )
        return findings
