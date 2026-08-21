<div align="center">

# takeovflow

**Advanced subdomain takeover scanner — passive + active + CNAME fingerprinting**

![Language](https://img.shields.io/badge/Python-3.8+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.6.0-9E4AFF?style=flat-square)
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

**v1.6.0 highlights:** confirmed vs. unconfirmed findings (pattern-only CNAME matches are no longer reported with the same confidence as a real subjack/nuclei signature match), cross-source finding merge with confidence promotion, and optional active HTTP signature verification for the most common CNAME patterns (AWS S3, GitHub Pages, Heroku).

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
  --skip-http-verify      Disable active HTTP signature verification for cname-pattern
                          findings (faster, but those findings stay unconfirmed unless
                          corroborated by another source)
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

### Confirmed vs. unconfirmed findings

Not every finding carries the same confidence. `subjack` and `nuclei` verify a takeover
by matching a known service **fingerprint/signature** in the live HTTP response — that's
a real confirmation. takeovflow's own CNAME pattern analysis (`cname-pattern` source),
on the other hand, only checks whether the CNAME target *string* matches a known
provider's domain (e.g. `*.amazonaws.com`) — it does **not** check whether that remote
resource is actually unclaimed/dangling. A CNAME pointing to an S3 bucket that's alive
and in active use looks identical, pattern-wise, to one pointing at a deleted bucket.

To reflect that difference:

- Pattern-only matches are automatically downgraded one severity step (HIGH → MEDIUM,
  MEDIUM → LOW) and marked `"confirmed": false` in the JSON output.
- In the Markdown report, any such finding is prefixed with
  **`[PATRÓN SIN CONFIRMAR — requiere verificación manual]`** in its detail column.
- Findings from `subjack` or `nuclei` (real signature match) are never prefixed and are
  treated as `confirmed: true`.
- If the same subdomain is corroborated by another source (e.g. also flagged by
  `subjack`/`nuclei`), or confirmed via built-in HTTP signature verification, it's
  promoted back to `confirmed: true` with full severity (see below).

**Rule of thumb:** anything tagged `[PATRÓN SIN CONFIRMAR]` needs manual verification
(check the DNS record is actually dangling, try to claim the resource in a sandbox,
etc.) before it goes in a report. A finding confirmed by subjack/nuclei/HTTP-signature
carries meaningfully higher confidence, but manual verification before submission is
still recommended for anything you plan to report.

### Multi-source corroboration

If the same subdomain is flagged by more than one source (e.g. `cname-pattern` *and*
`nuclei`), the findings are merged into a single entry instead of appearing twice:

- The merged finding lists every source that detected it (`Detectado por: cname-pattern,
  nuclei`) and keeps each source's individual evidence in the report row.
- If at least one contributing source did real signature verification (`subjack` or
  `nuclei`), the merged finding is promoted to `confirmed: true` with full severity —
  even if the `cname-pattern` component alone was unconfirmed.
- A subdomain flagged only by `cname-pattern`, with no corroboration, stays unconfirmed
  as described above.

### HTTP signature verification (`--skip-http-verify`)

For the CNAME patterns most common in real-world bug bounty targets — **AWS S3**,
**GitHub Pages**, and **Heroku** — takeovflow performs an extra, optional step: a plain
HTTP GET to the subdomain, checking the response body for the provider's known "resource
not found" error signature (sourced from
[EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz), the
same fingerprint database `subjack` uses internally):

| Service | Signature checked |
|---|---|
| AWS S3 | `The specified bucket does not exist` |
| GitHub Pages | `There isn't a GitHub Pages site here.` |
| Heroku | `No such app` |

If the signature matches, the finding is promoted to `confirmed: true` with full
severity and a note showing which signature was found. For GitHub Pages and Heroku, the
note also flags that the signature is an **edge case** in the source database (not a
guaranteed takeover — both providers added anti-takeover protections that can produce
this same 404 without the subdomain actually being reclaimable), so manual verification
is still warranted before reporting.

This check runs by default and adds one extra HTTP request per matched subdomain (with a
short timeout; network failures just leave the finding unconfirmed, they never abort the
scan). Use `--skip-http-verify` to skip it entirely — trade-off: faster scans, but more
`cname-pattern` findings will stay in the unconfirmed/lower-severity bucket even when
they'd have been confirmable with one extra request.

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
