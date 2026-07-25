"""
Reporter interface — the output-side mirror of ScannerAdapter.

Every reporter takes AggregatedResults and renders it as one string
(the file content to write out). Adding a new output format means
adding a new Reporter subclass; nothing else in the codebase changes.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from secscan.core.findings import AggregatedResults


class Reporter(ABC):
    name: str = "unnamed-reporter"
    file_extension: str = "txt"

    def __init__(self, options: dict | None = None):
        self.options = options or {}

    @abstractmethod
    def render(self, results: AggregatedResults) -> str:
        raise NotImplementedError
