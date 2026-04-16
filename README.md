<div align="center">

# takeovflow

**Advanced Subdomain Takeover Scanner**

![Language](https://img.shields.io/badge/Python-3.7+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.3.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Recon-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇪🇸 [Versión en español](README.es.md)

</div>

---

## What does it do?

Combines passive discovery, active resolution, fingerprinting and CNAME pattern detection to identify subdomains vulnerable to takeover. Resilient: if an external tool is missing, it continues with the available ones.

**v1.3.0 highlights:** concurrent CNAME analysis, 55 service fingerprints, deduplication, severity filtering, configurable timeout/retries, custom DNS resolvers and flexible output directory.

---

## External tools

`subfinder` `assetfinder` `dnsx` `httpx` `subjack` `nuclei` `dig` `jq` `curl`

The script checks availability at startup and skips phases for missing tools — **does not abort**.

---

## Installation

```bash
git clone https://github.com/theoffsecgirl/takeovflow.git
cd takeovflow
chmod +x takeovflow.py
```

---

## Usage

```bash
# Single domain
python3 takeovflow.py -d example.com -v

# File with domains
python3 takeovflow.py -f scope.txt

# Passive phase only (discovery)
python3 takeovflow.py -d example.com --passive-only

# Active phase only with known subdomains
python3 takeovflow.py --active-only --subs-file subdomains.txt -d example.com

# Custom resolvers + output dir + only HIGH severity
python3 takeovflow.py -d example.com --resolvers resolvers.txt --output-dir ./reports --min-severity HIGH

# Custom nuclei templates, JSON output, 100 threads
python3 takeovflow.py -f scope.txt -t 100 -v --json-output --nuclei-templates ./takeover-templates/

# Show version
python3 takeovflow.py --version
```

---

## Technical flow

```text
[PASSIVE]  subfinder + assetfinder → deduplication
[ACTIVE]   dnsx → httpx → subjack → nuclei → CNAME patterns (concurrent)
[OUTPUT]   takeovflow_report_YYYYMMDD_HHMM.md + JSON (optional)
```

Services detected via CNAME (55 total): AWS S3/CloudFront/Beanstalk, Azure Web Apps/Traffic Manager/Blob, Heroku, GitHub Pages, Fastly, Akamai, Netlify, Vercel, Webflow, GitBook, Shopify, Ghost, Surge, Statuspage, Bitbucket Pages, Pantheon, Kinsta, HubSpot, Freshdesk, Intercom, Cargo, Wix, Weebly, Tilda, Zendesk, and more.

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
  -r, --rate N            Rate limit (default: 2)
  --timeout N             Per-tool timeout in seconds (default: 30)
  --retries N             Retries on failure (default: 2)
  --resolvers FILE        Custom DNS resolvers file for dnsx
  -v, --verbose           Verbose mode
  --no-color              Disable emoji/color output
  --json-output           Generate JSON report
  --output-dir DIR        Output directory for reports (default: CWD)
  --nuclei-templates PATH Path to custom nuclei templates
  --min-severity LEVEL    Minimum severity to include in report: HIGH | MEDIUM | LOW | INFO (default: INFO)
      --version           Show version
```

---

## Severity levels

| Level | Meaning |
|-------|---------|
| 🔴 HIGH | Very likely vulnerable, immediate action recommended |
| 🟡 MEDIUM | Needs manual verification |
| 🟢 LOW | Informational, low risk |
| ⚪ INFO | Context only |

---

## Ethical use

For bug bounty, labs and authorized audits only.

---

## License

MIT · [theoffsecgirl](https://theoffsecgirl.com)
