SECSCAN
A small security scanner orchestrator, inspired by AWS Labs' ASH (automated-security-helper).

WHAT IT DOES
Instead of running several separate security tools by hand, each with its own command, config, and output format, secscan wraps them behind one CLI, one config file, and one set of report formats. Right now it wraps two tools: Bandit (finds security bugs in Python code) and detect-secrets (finds hardcoded passwords, API keys, and similar secrets in your files).

HOW IT'S STRUCTURED

core/findings.py
Defines the shared data shapes: Finding (one normalized security issue), ScannerRunResult (how one scanner's run went), and AggregatedResults (everything combined). Every tool's output eventually becomes these shapes.

core/adapter.py
Defines the rules any scanner plugin must follow: build a command to run, and parse that tool's raw output into Finding objects. Handles running the subprocess, timeouts, and crashes so one broken scanner never takes down the whole program.

adapters/bandit_adapter.py and adapters/detect_secrets_adapter.py
The two actual scanner plugins, built on top of core/adapter.py.

core/config.py
Loads and checks the secscan.yaml config file (which scanners are on, which reporters are on, severity threshold, etc).

core/engine.py
Runs every enabled scanner and collects the results. If one scanner fails, the others still run.

core/reporter.py, reporters/json_reporter.py, reporters/markdown_reporter.py
Same plugin idea as scanners, but for output. JSON is for machines and CI pipelines. Markdown is for humans, readable in a pull request.

cli.py
The actual command line tool. Running "secscan scan" loads the config, runs every enabled scanner, writes the report files, and exits with a code your CI can check: 0 means clean, 1 means a scanner itself broke, 2 means it ran fine but found real security issues.

SETUP
pip install -e .
This installs the secscan command and pulls in bandit and detect-secrets as dependencies.

USAGE
secscan check-installation
Confirms both scanner tools are installed and available.

secscan scan --target ./my-project
Runs a full scan against a folder.

secscan scan -t . -o ./reports -f json -f markdown --severity-threshold HIGH
Same thing, but lets you choose the output folder, which report formats to generate, and how strict the pass/fail threshold is.

Config is read from .secscan/secscan.yaml by default. A sample is included in the project. Use it to turn scanners or reporters on and off, set per-scanner options, and set the severity threshold.

TRY IT ON THE SAMPLE PROJECT
secscan scan -t examples/vulnerable_sample
cat .secscan/output/secscan.md

The examples/vulnerable_sample folder intentionally contains a shell injection bug, a weak password hash, an unsafe pickle load, and a couple of fake AWS credentials, so both scanners have something real to catch.

RUNNING THE TESTS
pytest tests/
If pytest isn't installed yet, run "python tests/run_tests.py" instead, which does the same job with a tiny script that only needs the Python standard library.

HOW TO ADD A NEW SCANNER
Create a new adapter file, make it follow the same rules as bandit_adapter.py (build a command, parse the output into Finding objects), add it to the list of scanners in cli.py, then write tests against a sample of that tool's real output.

HOW TO ADD A NEW REPORT FORMAT
Create a new reporter file, make it turn AggregatedResults into a string, then add it to the list of reporters in cli.py.

WHAT'S NOT BUILT YET
SARIF, HTML, CSV, and JUnit report formats. More scanners such as Semgrep and Checkov. The MCP server layer that would let an AI assistant call this tool directly. Suppression and baseline file support, so known false positives can be marked as acceptable instead of showing up every scan. Container-based execution mode.
