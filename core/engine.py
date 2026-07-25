"""
Execution engine.

Takes a config + a list of available adapters, decides which scanners to
run, runs them, and aggregates results. A scanner crashing, timing out,
or not being installed never aborts the other scanners' runs — that
isolation is the main job of this module.
"""
from __future__ import annotations

from pathlib import Path

from secscan.core.adapter import ScannerAdapter
from secscan.core.config import SecscanConfig
from secscan.core.findings import AggregatedResults, ScannerRunResult


class Engine:
    def __init__(self, adapters: list[ScannerAdapter], config: SecscanConfig):
        self.adapters = adapters
        self.config = config

    def enabled_adapters(self) -> list[ScannerAdapter]:
        return [a for a in self.adapters if self.config.scanner_enabled(a.name)]

    def run(self, target_dir: Path, progress_callback=None) -> AggregatedResults:
        """
        Run every enabled scanner against target_dir.

        progress_callback, if given, is called as (scanner_name, ScannerRunResult)
        right after each scanner finishes — this is the hook the MCP server's
        streaming-progress tool would use later.
        """
        results = AggregatedResults()

        for adapter in self.enabled_adapters():
            adapter.options = {**adapter.options, **self.config.scanner_options(adapter.name)}
            run_result: ScannerRunResult = adapter.run(target_dir)
            results.scanner_runs.append(run_result)
            if progress_callback:
                progress_callback(adapter.name, run_result)

        return results
