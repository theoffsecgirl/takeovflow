<div align="center">

# takeovflow

**Advanced Subdomain Takeover Scanner**

![Language](https://img.shields.io/badge/Python-3.7+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.2.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Recon-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇪🇸 [Versión en español](README.es.md)

</div>

---

## What does it do?

Combines passive discovery, active resolution, fingerprinting and CNAME pattern detection to identify subdomains vulnerable to takeover. Resilient: if an external tool is missing, it continues with the available ones.

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

# Active-only with subdomains file (no root domain)
python3 takeovflow.py --active-only --subs-file subdomains.txt

# Custom nuclei templates and JSON output
python3 takeovflow.py -f scope.txt -t 100 -v --json-output --nuclei-templates ./takeover-templates/

# Show version
python3 takeovflow.py --version
```

---

## Technical flow

```text
[PASSIVE]  subfinder + assetfinder → deduplication
[ACTIVE]   dnsx → httpx → subjack → nuclei → CNAME patterns
[OUTPUT]   takeovflow_report_YYYYMMDD_HHMM.md + JSON (optional)
```

Services detected via CNAME: AWS S3, CloudFront, GitHub Pages, Heroku, Azure, Fastly, Shopify, Ghost, Surge and others.

---

## Parameters

```text
Targets:
  -d, --domain        Single domain
  -f, --file          File with domains (one per line)
  -l, --list          Comma-separated domains

Mode:
  --passive-only      Passive discovery only
  --active-only       Active phase only (requires --subs-file or --file)
  --subs-file PATH    Subdomains file for active phase

Scan:
  -t, --threads       Threads (default: 50)
  -r, --rate          Rate limit (default: 2)
  -v, --verbose       Verbose mode
  --json-output       Generate JSON report
  --nuclei-templates  Path to custom nuclei templates
      --version       Show version
```

---

## Ethical use

For bug bounty, labs and authorized audits only.

---

## License

MIT · [theoffsecgirl](https://theoffsecgirl.com)
