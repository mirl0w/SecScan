from __future__ import annotations

import json

from secscan.core.findings import AggregatedResults
from secscan.core.reporter import Reporter


class JSONReporter(Reporter):
    name = "json"
    file_extension = "json"

    def render(self, results: AggregatedResults) -> str:
        payload = {
            "summary": {
                "total_findings": len(results.actionable_findings),
                "by_severity": results.counts_by_severity(),
            },
            "scanner_runs": [
                {
                    "scanner": run.scanner,
                    "success": run.success,
                    "duration_seconds": round(run.duration_seconds, 2),
                    "error_message": run.error_message,
                    "findings": [
                        {
                            "fingerprint": f.fingerprint,
                            "scanner": f.scanner,
                            "rule_id": f.rule_id,
                            "title": f.title,
                            "severity": f.severity.value,
                            "file_path": f.file_path,
                            "line_start": f.line_start,
                            "line_end": f.line_end,
                            "description": f.description,
                            "suppressed": f.suppressed,
                        }
                        for f in run.findings
                    ],
                }
                for run in results.scanner_runs
            ],
        }
        return json.dumps(payload, indent=2)
