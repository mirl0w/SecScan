from __future__ import annotations

import sys
from pathlib import Path

import click

from secscan.adapters.bandit_adapter import BanditAdapter
from secscan.adapters.detect_secrets_adapter import DetectSecretsAdapter
from secscan.core.config import ConfigError, load_config
from secscan.core.engine import Engine
from secscan.core.findings import Severity
from secscan.reporters.json_reporter import JSONReporter
from secscan.reporters.markdown_reporter import MarkdownReporter

# Registries: this is the one place that knows every adapter/reporter that
# exists. Adding scanner #3 means one new adapter file + one line here.
ALL_ADAPTERS = [BanditAdapter, DetectSecretsAdapter]
ALL_REPORTERS = {"json": JSONReporter, "markdown": MarkdownReporter}


@click.group()
def cli():
    """secscan — a small security scanner orchestrator (ASH-inspired)."""


@cli.command()
@click.option(
    "--target", "-t", default=".", type=click.Path(exists=True, file_okay=False),
    help="Directory to scan.",
)
@click.option(
    "--config", "-c", "config_path", default=None, type=click.Path(exists=True),
    help="Path to secscan.yaml. Defaults to .secscan/secscan.yaml if present.",
)
@click.option(
    "--output-dir", "-o", default=".secscan/output", type=click.Path(),
    help="Where to write report files.",
)
@click.option(
    "--severity-threshold", default=None,
    type=click.Choice([s.value for s in Severity], case_sensitive=False),
    help="Override the config's severity_threshold for pass/fail purposes.",
)
@click.option(
    "--format", "-f", "formats", multiple=True,
    type=click.Choice(list(ALL_REPORTERS.keys())),
    help="Report format(s) to generate. Defaults to all if omitted.",
)
def scan(target, config_path, output_dir, severity_threshold, formats):
    """Run all enabled scanners against TARGET and write reports."""
    target_dir = Path(target).resolve()

    resolved_config_path = Path(config_path) if config_path else Path(".secscan/secscan.yaml")
    try:
        config = load_config(resolved_config_path if resolved_config_path.exists() else None)
    except ConfigError as e:
        click.secho(f"Config error: {e}", fg="red", err=True)
        sys.exit(1)

    if severity_threshold:
        config.global_settings.severity_threshold = Severity(severity_threshold.upper())

    adapters = [cls() for cls in ALL_ADAPTERS]
    engine = Engine(adapters, config)

    click.echo(f"Scanning '{target_dir}' with: "
               f"{', '.join(a.name for a in engine.enabled_adapters())}")

    def on_progress(scanner_name, run_result):
        if run_result.success:
            click.echo(f"  ✓ {scanner_name}: {run_result.actionable_count} finding(s) "
                       f"({run_result.duration_seconds:.1f}s)")
        else:
            click.secho(f"  ✗ {scanner_name}: {run_result.error_message}", fg="yellow")

    results = engine.run(target_dir, progress_callback=on_progress)

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    selected_formats = list(formats) if formats else list(ALL_REPORTERS.keys())
    for fmt_name in selected_formats:
        reporter = ALL_REPORTERS[fmt_name]()
        content = reporter.render(results)
        out_path = out_dir / f"secscan.{reporter.file_extension}"
        out_path.write_text(content)
        click.echo(f"  wrote {out_path}")

    counts = results.counts_by_severity()
    click.echo("")
    click.echo("Summary: " + ", ".join(f"{k}={v}" for k, v in counts.items()))

    failed_scanners = [r for r in results.scanner_runs if not r.success]
    if failed_scanners:
        names = ", ".join(r.scanner for r in failed_scanners)
        click.secho(f"FAILED: scanner(s) did not run successfully: {names}", fg="red")
        sys.exit(1)

    threshold = config.global_settings.severity_threshold
    if config.global_settings.fail_on_findings and results.exceeds_threshold(threshold):
        click.secho(
            f"FAILED: actionable findings at or above {threshold.value} threshold.",
            fg="red",
        )
        sys.exit(2)

    click.secho("PASSED", fg="green")


@cli.command()
def check_installation():
    """Verify each scanner's underlying tool is installed and on PATH."""
    for cls in ALL_ADAPTERS:
        adapter = cls()
        status = "available" if adapter.is_available() else "NOT FOUND"
        color = "green" if adapter.is_available() else "red"
        click.secho(f"{adapter.name} ({adapter.binary_name}): {status}", fg=color)


if __name__ == "__main__":
    cli()
