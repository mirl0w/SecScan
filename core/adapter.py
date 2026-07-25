"""
Scanner adapter interface.

Every security tool we wrap (Bandit, detect-secrets, and anything added
later) implements this ABC. The execution engine only ever talks to
`ScannerAdapter` — it never knows or cares that "bandit" means running a
pip-installed Python linter and "detect-secrets" means something else
entirely. This is what lets us add scanner #3 without touching scanners
#1 and #2, or the engine that runs them.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from pathlib import Path

from secscan.core.findings import ScannerRunResult


class ScannerAdapter(ABC):
    """Base class all scanner plugins must implement."""

    #: Unique short name used in config, CLI flags, and Finding.scanner
    name: str = "unnamed-scanner"

    #: The executable this adapter shells out to (for availability checks)
    binary_name: str = ""

    def __init__(self, options: dict | None = None):
        self.options = options or {}

    def is_available(self) -> bool:
        """Whether the underlying tool is installed and on PATH."""
        if not self.binary_name:
            return True
        return shutil.which(self.binary_name) is not None

    @abstractmethod
    def build_command(self, target_dir: Path) -> list[str]:
        """Return the subprocess argv to invoke this scanner against target_dir."""
        raise NotImplementedError

    @abstractmethod
    def parse_output(self, stdout: str, stderr: str, returncode: int) -> list:
        """Parse the tool's raw output into a list of Finding objects."""
        raise NotImplementedError

    def run(self, target_dir: Path, timeout: int = 300) -> ScannerRunResult:
        """
        Execute the scanner end-to-end: build command, run subprocess,
        parse output, wrap in a ScannerRunResult. Adapters normally don't
        need to override this — just build_command and parse_output.
        """
        start = time.monotonic()

        if not self.is_available():
            return ScannerRunResult(
                scanner=self.name,
                success=False,
                duration_seconds=0.0,
                error_message=f"'{self.binary_name}' not found on PATH. Is it installed?",
            )

        command = self.build_command(target_dir)

        try:
            proc = subprocess.run(
                command,
                cwd=str(target_dir),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return ScannerRunResult(
                scanner=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                error_message=f"Scanner timed out after {timeout}s",
            )
        except FileNotFoundError as e:
            return ScannerRunResult(
                scanner=self.name,
                success=False,
                duration_seconds=time.monotonic() - start,
                error_message=str(e),
            )

        duration = time.monotonic() - start

        try:
            findings = self.parse_output(proc.stdout, proc.stderr, proc.returncode)
        except Exception as e:  # a parse failure shouldn't crash the whole run
            return ScannerRunResult(
                scanner=self.name,
                success=False,
                duration_seconds=duration,
                error_message=f"Failed to parse {self.name} output: {e}",
            )

        return ScannerRunResult(
            scanner=self.name,
            success=True,
            duration_seconds=duration,
            findings=findings,
        )
