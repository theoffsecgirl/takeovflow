<div align="center">

# takeovflow

**Advanced Subdomain Takeover Scanner**

![Language](https://img.shields.io/badge/Python-3.7+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.4.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Recon-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇪🇸 [Versión en español](README.es.md)

</div>

---

## What does it do?

Combines passive discovery, active DNS resolution, HTTP fingerprinting and CNAME dangling detection to identify subdomains vulnerable to takeover. No external scanner required — has its own HTTP fingerprint engine. Resilient: skips phases for missing tools without aborting.

**Detection layers:**
1. CNAME pattern matching (55 services)
2. Dangling CNAME detection (NXDOMAIN verification → high confidence)
3. HTTP body fingerprinting (32 service error patterns, no false positives)
4. nuclei takeover templates
5. subjack (optional)

---

## Quickstart

```bash
git clone https://github.com/theoffsecgirl/takeovflow.git
cd takeovflow
bash install.sh          # installs all external tools
python3 takeovflow.py -d example.com -v
```

Or install as a CLI command:
```bash
pip install -e .
takeovflow -d example.com -v
```

---

## External tools

`subfinder` `assetfinder` `amass` `dnsx` `httpx` `subjack` `nuclei` `dig` `curl`

All optional — install with `bash install.sh` (macOS + Debian/Ubuntu).

---

## Usage

```bash
# Single domain, full scan
python3 takeovflow.py -d example.com -v

# File with multiple domains, JSON output
python3 takeovflow.py -f scope.txt --json-output --output-dir ./reports

# Passive only (discovery)
python3 takeovflow.py -d example.com --passive-only

# Active only from known subdomains
python3 takeovflow.py --active-only --subs-file subdomains.txt -d example.com

# Pipeline mode: only HIGH findings to stdout
python3 takeovflow.py -d example.com --silent --min-severity HIGH

# JSONL output for jq/SIEM integration
python3 takeovflow.py -d example.com --jsonl | jq 'select(.severity=="HIGH")'

# Custom resolvers + rate limit
python3 takeovflow.py -d example.com --resolvers resolvers.txt --rate 300

# Skip subjack (unmaintained), keep everything else
python3 takeovflow.py -d example.com --no-subjack
```

---

## Detection layers

| Layer | Method | Confidence |
|-------|--------|------------|
| CNAME dangling | dig CNAME + NXDOMAIN check | 🔴 HIGH |
| HTTP fingerprinting | curl body pattern match | 🔴 HIGH |
| nuclei | takeover templates | 🔴 HIGH / 🟡 MEDIUM |
| CNAME pattern | known service patterns | 🟡 MEDIUM |
| subjack | fingerprint DB | 🟡 MEDIUM |

---

## Parameters

```text
Targets:
  -d, --domain            Single domain
  -f, --file              File with domains (one per line)
  -l, --list              Comma-separated domains

Mode:
  --passive-only          Passive discovery only
  --active-only           Active phase only (requires --subs-file or --file)
  --subs-file PATH        Subdomains file for active phase

Scan:
  -t, --threads N         Threads (default: 50)
  -r, --rate N            Rate limit req/s for dnsx + httpx (default: 150)
  --timeout N             Per-tool timeout in seconds (default: 30)
  --retries N             Retries on failure (default: 2)
  --resolvers FILE        Custom DNS resolvers for dnsx
  --no-http-fp            Disable built-in HTTP fingerprinting
  --no-subjack            Disable subjack
  -v, --verbose           Verbose mode
  --silent                Findings only to stdout (for piping)
  --jsonl                 Emit each finding as JSON line to stdout
  --json-output           Write JSON report file
  --output-dir DIR        Output directory (default: CWD)
  --nuclei-templates PATH Custom nuclei templates path
  --min-severity LEVEL    HIGH | MEDIUM | LOW | INFO (default: INFO)
      --version           Show version
```

---

## Severity levels

| Level | Meaning |
|-------|---------|
| 🔴 HIGH | Dangling CNAME (NXDOMAIN) or HTTP body match — immediate action |
| 🟡 MEDIUM | CNAME pattern match, destino activo — manual verification |
| 🟢 LOW | Low risk informational |
| ⚪ INFO | Context only |

---

## Run tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Ethical use

For bug bounty, labs and authorized audits only.

---

## License

MIT · [theoffsecgirl](https://theoffsecgirl.com)
