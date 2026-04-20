# takeovflow

Advanced subdomain takeover scanner.

> 🇪🇸 [Versión en español](README.es.md)

---

## What does it do?

Scans subdomains for takeover signals using:
- passive discovery
- active checks
- CNAME fingerprinting

Important: findings are candidates, not confirmed takeovers.

---

## Features

- Passive discovery with `subfinder` + `assetfinder`
- Active checks with `dnsx`, `httpx`, `subjack`, `nuclei`
- CNAME pattern detection across known providers
- Normalized findings output
- JSON / JSONL export
- `stdout` mode for pipelines
- Clean `Ctrl+C` handling

---

## Installation

```bash
git clone https://github.com/theoffsecgirl/takeovflow.git
cd takeovflow
python3 takeovflow.py --help
```

---

## Usage

```bash
python3 takeovflow.py -d example.com
```

### Pipeline

```bash
python3 takeovflow.py -d target.com --format jsonl --stdout | bbcopilot ingest takeovflow -
```

### Save normalized findings

```bash
python3 takeovflow.py -d target.com --json-output --format jsonl --output-dir ./results
```

---

## Notes

- Logs go to `stderr`
- Findings go to `stdout` with `--stdout`
- `Ctrl+C` exits cleanly
- JSON output can include classic report + normalized findings file

---

## Parameters

```text
-d, --domain            Single domain
-f, --file              File with domains
-l, --list              Comma-separated domains
--passive-only          Passive phase only
--active-only           Active phase only
--subs-file PATH        Subdomains file for active phase
-t, --threads           Threads
-r, --rate              Rate limit
--timeout               Timeout per tool
--retries               Retries
--resolvers FILE        Custom resolvers
-v, --verbose           Verbose mode
-q, --quiet             Quiet mode
--json-output           Generate classic JSON report and normalized findings file
--output-dir DIR        Output directory
--nuclei-templates      Custom nuclei templates
--min-severity          Minimum severity filter
--format json|jsonl     Normalized findings format
--stdout                Print normalized findings to stdout
--version               Show version
```

---

## License

MIT
