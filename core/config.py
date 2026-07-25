"""
Configuration system.

Loads `.secscan/secscan.yaml`, validates its shape, and merges in any CLI
overrides. We hand-roll validation here with dataclasses instead of using
pydantic — the pattern (parse -> validate -> typed object) is identical,
this just doesn't pull in a third-party dependency.
"""
from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path

from secscan.core.findings import Severity

_VALID_SEVERITIES = {s.value for s in Severity}


class ConfigError(ValueError):
    """Raised when the config file is malformed or fails validation."""


@dataclass
class ScannerConfig:
    enabled: bool = True
    options: dict = field(default_factory=dict)


@dataclass
class GlobalSettings:
    severity_threshold: Severity = Severity.MEDIUM
    fail_on_findings: bool = True
    ignore_paths: list[str] = field(default_factory=list)


@dataclass
class ReporterConfig:
    enabled: bool = True
    options: dict = field(default_factory=dict)


@dataclass
class SecscanConfig:
    project_name: str = "unnamed-project"
    global_settings: GlobalSettings = field(default_factory=GlobalSettings)
    scanners: dict[str, ScannerConfig] = field(default_factory=dict)
    reporters: dict[str, ReporterConfig] = field(default_factory=dict)

    def scanner_enabled(self, name: str) -> bool:
        cfg = self.scanners.get(name)
        # A scanner with no explicit entry is enabled by default.
        return cfg.enabled if cfg is not None else True

    def scanner_options(self, name: str) -> dict:
        cfg = self.scanners.get(name)
        return cfg.options if cfg is not None else {}


def _validate_severity(value: str, context: str) -> Severity:
    value = str(value).upper()
    if value not in _VALID_SEVERITIES:
        raise ConfigError(
            f"Invalid severity '{value}' in {context}. "
            f"Must be one of: {', '.join(sorted(_VALID_SEVERITIES))}"
        )
    return Severity(value)


def load_config(path: Path | None) -> SecscanConfig:
    """
    Load and validate a secscan.yaml file. Returns a default config
    (all scanners enabled, MEDIUM threshold) if no file is given or found.
    """
    if path is None or not path.exists():
        return SecscanConfig()

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a YAML mapping at the top level")

    global_raw = raw.get("global_settings", {})
    if not isinstance(global_raw, dict):
        raise ConfigError("'global_settings' must be a mapping")

    global_settings = GlobalSettings(
        severity_threshold=_validate_severity(
            global_raw.get("severity_threshold", "MEDIUM"), "global_settings.severity_threshold"
        ),
        fail_on_findings=bool(global_raw.get("fail_on_findings", True)),
        ignore_paths=list(global_raw.get("ignore_paths", [])),
    )

    scanners = {}
    for name, entry in (raw.get("scanners") or {}).items():
        if entry is None:
            entry = {}
        if not isinstance(entry, dict):
            raise ConfigError(f"scanners.{name} must be a mapping")
        scanners[name] = ScannerConfig(
            enabled=bool(entry.get("enabled", True)),
            options=entry.get("options", {}) or {},
        )

    reporters = {}
    for name, entry in (raw.get("reporters") or {}).items():
        if entry is None:
            entry = {}
        if not isinstance(entry, dict):
            raise ConfigError(f"reporters.{name} must be a mapping")
        reporters[name] = ReporterConfig(
            enabled=bool(entry.get("enabled", True)),
            options=entry.get("options", {}) or {},
        )

    return SecscanConfig(
        project_name=raw.get("project_name", "unnamed-project"),
        global_settings=global_settings,
        scanners=scanners,
        reporters=reporters,
    )
