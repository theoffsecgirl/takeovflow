<div align="center">

# takeovflow

**Advanced subdomain takeover scanner — passive + active + CNAME fingerprinting**

![Language](https://img.shields.io/badge/Python-3.8+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Recon-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇪🇸 [Versión en español](README.es.md)

</div>

---

## What does it do?

Scans subdomains for takeover vulnerabilities using three approaches:
- **Passive**: subdomain discovery via `subfinder` + `assetfinder`, DNS CNAME resolution
- **Active**: HTTP response analysis with `httpx`, takeover confirmation with `subjack` + `nuclei`
- **Fingerprinting**: provider-specific CNAME pattern matching across takeover-prone services

Resilient: if an external tool is missing, it continues with the available ones — **does not abort**.

Important: normalized findings are **signals / candidates**, not guaranteed takeovers.

---

## New workflow features

- normalized findings schema compatible with `bbcopilot`
- `confidence` per finding
- `reason` and `evidence`
- `--format json|jsonl`
- `--stdout` for pipelines
- logs and banners sent to `stderr`

---

## Normalized finding example

```json
{"type":"candidate","vector":"subdomain_takeover","target":"blog.example.com","host":"blog.example.com","method":"DNS/HTTP","param":null,"severity":"high","confidence":"medium","reason":"CNAME points to a known takeover-prone provider (GitHub Pages)","evidence":["cname match: example.github.io","provider fingerprint: GitHub Pages"],"tags":["takeover","cname-pattern","github-pages"],"raw":{"source":"cname-pattern","subdomain":"blog.example.com","cname":"example.github.io","service":"GitHub Pages","severity":"HIGH"}}
```

### Confidence heuristic

- **high** → `subjack` or strong `nuclei` signal
- **medium** → CNAME points to a known takeover-prone provider
- **low** → weak or generic signal

---

## Usage

```bash
# Classic usage
python3 takeovflow.py -d example.com -v
python3 takeovflow.py -f scope.txt --json-output

# Normalized JSONL output to file
python3 takeovflow.py -d example.com --json-output --format jsonl --output-dir ./results

# Normalized findings to stdout
python3 takeovflow.py -d example.com --format jsonl --stdout
```

---

## Workflow integration

### Save and ingest into `bb-copilot`

```bash
python3 takeovflow.py -d example.com --json-output --format jsonl --output-dir ./results
bbcopilot ingest takeovflow ./results/takeovflow_findings_YYYYMMDD_HHMM.jsonl
bbcopilot findings --tool takeovflow
bbcopilot correlate
bbcopilot auto-triage
```

### Pipe-oriented workflow

```bash
python3 takeovflow.py -d example.com --format jsonl --stdout > takeovers.jsonl
bbcopilot ingest takeovflow takeovers.jsonl
```

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
  -r, --rate N            Rate limit req/s for httpx/dnsx (default: 150)
  --timeout N             Per-tool timeout in seconds (default: 30)
  --retries N             Retries on failure (default: 2)
  --resolvers FILE        Custom DNS resolvers file for dnsx
  -v, --verbose           Verbose mode
  -q, --quiet             Suppress banner and intermediate output
  --json-output           Generate classic JSON report and normalized findings file
  --output-dir DIR        Output directory for reports (default: CWD)
  --nuclei-templates PATH Path to custom nuclei templates
  --min-severity LEVEL    Minimum severity: CRITICAL | HIGH | MEDIUM | LOW | INFO (default: INFO)
  --format                Normalized findings format: json | jsonl
  --stdout                Print normalized findings to stdout
  --version               Show version
```

---

## Ethical use

Only on programs where subdomain takeover testing is in scope. For bug bounty, labs and authorized audits only.

---

## License

MIT · [theoffsecgirl](https://theoffsecgirl.com)
