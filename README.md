<div align="center">

# takeovflow

**Advanced Subdomain Takeover Scanner**

![Language](https://img.shields.io/badge/Python-3.7+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.6.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Recon-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇪🇸 [Versión en español](README.es.md)

</div>

---

## What does it do?

Combines passive discovery, active resolution, fingerprinting and CNAME pattern detection to identify subdomains vulnerable to takeover. Resilient: if an external tool is missing, it continues with the available ones.

**v1.6.0 highlights:** confirmed vs. unconfirmed findings (pattern-only CNAME matches are no longer reported with the same confidence as a real subjack/nuclei signature match), cross-source finding merge with confidence promotion, and optional active HTTP signature verification for the most common CNAME patterns (AWS S3, GitHub Pages, Heroku).

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
  --skip-http-verify      Disable active HTTP signature verification for cname-pattern
                          findings (faster, but those findings stay unconfirmed unless
                          corroborated by another source)
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

For bug bounty, labs and authorized audits only.

---

## License

MIT · [theoffsecgirl](https://theoffsecgirl.com)
