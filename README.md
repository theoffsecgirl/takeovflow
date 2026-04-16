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
- **Fingerprinting**: provider-specific CNAME pattern matching across 55 services (GitHub Pages, Heroku, Fastly, S3, Shopify, etc.)

Resilient: if an external tool is missing, it continues with the available ones — **does not abort**.

---

## Supported providers

| Provider | Detection method |
|----------|------------------|
| GitHub Pages | CNAME (`github.io`) + body pattern |
| Heroku | CNAME (`herokudns.com`, `herokuapp.com`) + status |
| Amazon S3 / Beanstalk | CNAME (`amazonaws.com`, `elasticbeanstalk.com`) |
| AWS CloudFront | CNAME (`cloudfront.net`) |
| Azure Web Apps | CNAME (`azurewebsites.net`, `trafficmanager.net`) |
| Fastly | CNAME (`fastly.net`) |
| Shopify | CNAME (`shopify.com`) + body |
| Zendesk | CNAME (`zendesk.com`) + status |
| Netlify | CNAME (`netlify.app`, `netlify.com`) |
| Vercel | CNAME (`vercel.app`) |
| Ghost | CNAME (`ghost.io`) + body |
| Surge.sh | CNAME (`surge.sh`) + body |
| Readme.io | CNAME (`readme.io`) + body |
| Unbounce | CNAME (`unbouncepages.com`) + body |
| Webflow | CNAME (`webflow.io`) |
| GitBook | CNAME (`gitbook.io`, `gitbook.com`) |
| Wix | CNAME (`wixdns.net`) |
| Weebly | CNAME (`weebly.com`) |
| Tilda | CNAME (`tilda.ws`) |
| Statuspage | CNAME (`statuspage.io`) |
| + 35 more | Akamai, HubSpot, Freshdesk, Pantheon, Kinsta… |

---

## Output example

```text
[*] Domains loaded: 1
[*] Running passive discovery: subfinder, assetfinder
[*] Subdomains found: 1247
[*] Resolving CNAMEs (concurrent)...

[!] POTENTIAL TAKEOVER → blog.example.com
    CNAME : example.github.io
    Service: GitHub Pages
    Severity: HIGH

[!] POTENTIAL TAKEOVER → cdn.example.com
    CNAME : example.s3.amazonaws.com
    Service: AWS S3 / Elastic Beanstalk
    Severity: HIGH

[~] INVESTIGATE → api.example.com
    CNAME : example.herokudns.com
    Service: Heroku
    Severity: HIGH

[+] CNAME findings: 3
[+] Report saved → takeovflow_report_20240416_1523.md
[+] JSON saved   → takeovflow_report_20240416_1523.json
```

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
python3 takeovflow.py --help
```

---

## Usage

```bash
# Single domain (passive + active + CNAME)
python3 takeovflow.py -d example.com -v

# File with multiple domains
python3 takeovflow.py -f scope.txt

# Passive phase only (discovery + CNAME)
python3 takeovflow.py -d example.com --passive-only

# Active phase only with a known subdomains file
python3 takeovflow.py --active-only --subs-file subdomains.txt -d example.com

# Custom resolvers + output dir + only HIGH severity
python3 takeovflow.py -d example.com --resolvers resolvers.txt --output-dir ./reports --min-severity HIGH

# Custom nuclei templates, JSON output, 100 threads
python3 takeovflow.py -f scope.txt -t 100 -v --json-output --nuclei-templates ./takeover-templates/

# Comma-separated list of domains
python3 takeovflow.py -l example.com,target.io,scope.net

# Show version
python3 takeovflow.py --version
```

---

## Workflow integration

```bash
# Full recon pipeline — discover + scan in one shot
subfinder -d example.com -silent > subdomains.txt && \
  python3 takeovflow.py --active-only --subs-file subdomains.txt -d example.com --json-output

# After assetfinder
assetfinder --subs-only example.com > subs.txt && \
  python3 takeovflow.py --active-only --subs-file subs.txt -d example.com

# Multiple targets from a scope file
python3 takeovflow.py -f scope.txt -t 100 --min-severity HIGH --json-output --output-dir ./results
```

---

## Technical flow

```text
[PASSIVE]  subfinder + assetfinder → deduplication
[ACTIVE]   dnsx → httpx → subjack → nuclei → CNAME patterns (concurrent)
[OUTPUT]   takeovflow_report_YYYYMMDD_HHMM.md + JSON (optional)
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
  --no-color              Disable emoji/color output
  --json-output           Generate JSON report
  --output-dir DIR        Output directory for reports (default: CWD)
  --nuclei-templates PATH Path to custom nuclei templates
  --min-severity LEVEL    Minimum severity: CRITICAL | HIGH | MEDIUM | LOW | INFO (default: INFO)
  --version               Show version
```

---

## Severity levels

| Level | Meaning |
|-------|---------|
| 🔴 CRITICAL | Confirmed takeover vector, immediate action required |
| 🔴 HIGH | Very likely vulnerable, immediate action recommended |
| 🟡 MEDIUM | Needs manual verification |
| 🟢 LOW | Informational, low risk |
| ⚪ INFO | Context only |

---

## Ethical use

Only on programs where subdomain takeover testing is in scope. For bug bounty, labs and authorized audits only.

---

## Contributing

PRs welcome. Especially:
- New provider fingerprints
- False positive fixes
- Performance improvements for large subdomain lists

---

## License

MIT · [theoffsecgirl](https://theoffsecgirl.com)
