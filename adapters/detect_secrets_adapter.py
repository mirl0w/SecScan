from __future__ import annotations

import json
from pathlib import Path

from secscan.core.adapter import ScannerAdapter
from secscan.core.findings import Finding, Severity


class DetectSecretsAdapter(ScannerAdapter):
    name = "detect-secrets"
    binary_name = "detect-secrets"

    # detect-secrets doesn't grade severity itself — every hit is a potential
    # hardcoded secret, so we treat all of them as HIGH by default. Some
    # plugin types (e.g. Base64HighEntropyString) are noisier and get
    # downgraded, since they trigger more false positives than credential
    # patterns like AWSKeyDetector.
    _LOWER_CONFIDENCE_TYPES = {"Base64HighEntropyString", "HexHighEntropyString"}

    def build_command(self, target_dir: Path) -> list[str]:
        cmd = ["detect-secrets", "scan"]
        exclude = self.options.get("exclude_dirs")
        if exclude:
            pattern = "|".join(exclude)
            cmd += ["--exclude-files", pattern]
        cmd.append(".")
        return cmd

    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list[Finding]:
        if not stdout.strip():
            if returncode != 0:
                raise RuntimeError(f"detect-secrets failed (exit {returncode}): {stderr.strip()[:500]}")
            return []

        data = json.loads(stdout)
        # Output shape: {"results": {"path/to/file": [{...}, {...}], ...}, ...}
        results = data.get("results", {})

        findings = []
        for file_path, hits in results.items():
            for hit in hits:
                secret_type = hit.get("type", "Unknown secret type")
                severity = (
                    Severity.MEDIUM
                    if secret_type in self._LOWER_CONFIDENCE_TYPES
                    else Severity.HIGH
                )
                findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id=secret_type,
                        title=f"Potential secret: {secret_type}",
                        severity=severity,
                        file_path=file_path,
                        line_start=hit.get("line_number"),
                        description=(
                            "Possible hardcoded secret detected. Verify this is not a "
                            "real credential; if it's a false positive, add it to the "
                            "detect-secrets baseline."
                        ),
                    )
                )
        return findings
