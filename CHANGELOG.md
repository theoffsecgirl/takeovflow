# Changelog

All notable changes to **takeovflow** are documented here.

---

## [1.6.0] – 2026-08-21

### Added
- **Confirmed vs. unconfirmed findings.** `cname-pattern` findings (from `analyze_cname_patterns` / `_check_cname_single`) are no longer reported with the same confidence as a real `subjack`/`nuclei` signature match. A pattern-only CNAME match now gets `"confirmed": false` in the JSON output, its severity is downgraded one step (HIGH → MEDIUM, MEDIUM → LOW), and the Markdown report prefixes it with `[PATRÓN SIN CONFIRMAR — requiere verificación manual]`.
- **Cross-source finding merge.** `deduplicate_takeovers` now groups findings by subdomain across all sources (not just `source:subdomain` as before). When the same subdomain is flagged by two or more sources, they merge into one finding that lists every detecting source (`Detectado por: ...`), keeps each source's individual evidence (`sources_detail`), and is promoted to `confirmed: true` with full (undegraded) severity if at least one contributing source did real signature verification (`subjack`/`nuclei`).
- **Minimal active HTTP verification** for the most common CNAME patterns in real-world bug bounty targets: AWS S3, GitHub Pages, and Heroku. `_check_cname_single` performs one GET request and checks the response body against a known "resource not found" signature per provider (sourced from `EdOverflow/can-i-take-over-xyz`, the same fingerprint base `subjack` uses). On a match, the finding is promoted to `confirmed: true` with full severity and an explanatory note (GitHub Pages/Heroku signatures are flagged as "edge case" per the source database — not a 100% guarantee).
- `--skip-http-verify` — disables the HTTP verification step above for faster scans, at the cost of more `cname-pattern` findings staying unconfirmed.

### Changed
- `_check_cname_single` return dict gains `"confirmed"` (bool) and, when applicable, `"note"` (str) fields.
- `deduplicate_takeovers` is now a two-pass function: exact `source:subdomain` dedup, then cross-source grouping/merge. Subdomain extraction from `raw` lines (subjack/nuclei output, which don't carry a clean `subdomain` field) is now done via `_extract_subdomain_from_raw` (URL-first, hostname-regex fallback) instead of a naive `raw.split()[0]`.
- `build_markdown_report` detail-cell rendering extracted into `_finding_detail_cell`, which understands merged findings (multi-source evidence joined with `<br>` inside the table cell) and renders the unconfirmed-pattern prefix / HTTP-verify note.
- README.md / README.es.md: new "Confirmed vs. unconfirmed findings", "Multi-source corroboration" and "HTTP signature verification" subsections under Severity levels; version badge and highlights updated to v1.6.0.

---

## [1.5.1] – 2026-04-16

### Fixed
- `run_subjack` detects whether the installed `subjack` binary supports the `-c` (custom fingerprints) flag before using it (`_subjack_supports_flag`, parses `subjack`'s own help output). Older subjack builds without `-c` no longer fail silently — they fall back to the binary's built-in fingerprints with a verbose notice.

### Changed
- `SEVERITY_COLOR` emoji values switched to explicit `\U0001Fxxx` / `\uXXXX` escapes for portability across terminal encodings.

---

## [1.5.0] – 2026-04-16

### Added
- `--quiet` / `-q` — suppresses the banner and intermediate progress prints; only fatal errors and the final report path are emitted. Intended for wrapper scripts and automation pipelines.
- Internal `log()` helper (module-level `_QUIET` flag) replacing direct `print()` calls throughout, with a `force=True` escape hatch for messages that must always be shown (fatal errors).

### Fixed
- `--quiet` and `--verbose` are now validated as mutually exclusive at argument-parsing time.

---

## [1.4.0] – 2026-04-16

### Added
- `CRITICAL` as its own severity level (above `HIGH`) in `SEVERITY_COLOR` / `_SEVERITY_ORDER` / `--min-severity` choices. `run_nuclei` now maps nuclei's `[critical]` tag to `CRITICAL` instead of collapsing it into `HIGH`.
- Explicit warning when `subjack`'s `fingerprints.json` can't be downloaded (missing `curl` or network failure) instead of failing silently.

### Fixed
- `run_cmd` retry loop: `range(retries)` → `range(max(retries, 1))`, so a misconfigured `retries=0` doesn't skip execution entirely; loop now actually retries on timeout instead of returning immediately on the first one.
- `--rate` was defined but never wired into `dnsx`/`httpx` calls — now passed as `dnsx -rl` and `httpx -rate` (default bumped from 2 to 150 req/s, the previous default made large scans unusably slow).
- `-d`/`-f` combined with `--active-only`: `--file` is only treated as a domain list when `--active-only` is *not* set, so it can be reused as the subdomains source in active-only mode without clashing with `-d`.
- `_check_cname_single` / `analyze_cname_patterns` `dig` timeout was hardcoded at 10s; now parametrized (`dig_timeout`, driven by `--timeout`).
- Temp directory cleanup moved into a `with tempfile.TemporaryDirectory(...)` context manager wrapping the whole per-run scan loop, guaranteeing cleanup even on unhandled exceptions.
- `print_banner()` width is now computed from the actual banner text length instead of a hardcoded 58 chars, so it doesn't break with longer version strings.

---

## [1.3.0] – 2026-04-16

### Added
- **Concurrent CNAME analysis** via `ThreadPoolExecutor` — previously sequential `dig` calls, now fully parallel (controlled by `--threads`). Up to 50x faster on large subdomain lists.
- **55 CNAME service fingerprints** (up from 19). New services: Netlify, Vercel, Webflow, GitBook, Statuspage, Bitbucket Pages, Pantheon, Kinsta, HubSpot Sites, Freshdesk, Intercom, Cargo, Wix, Weebly, Tilda, Acquia, Launchrock, AfterShip, BigCartel, FeedPress, Azure Blob/API/CloudApp, Heroku App, Elastic Beanstalk, and more. Each fingerprint includes service name and severity.
- **Severity system** (`HIGH` / `MEDIUM` / `LOW` / `INFO`) across all finding sources. nuclei severity parsed from actual output (`[critical]`, `[high]`, etc.).
- **Finding deduplication** — same subdomain reported by multiple tools appears only once.
- `--timeout N` — configurable per-tool timeout in seconds (default: 30).
- `--retries N` — retry count on transient failures (default: 2).
- `--resolvers FILE` — custom DNS resolver list passed to dnsx.
- `--output-dir DIR` — specify output directory for reports instead of always using CWD.
- `--min-severity LEVEL` — filter report to show only findings at or above the specified severity.
- `--no-color` — flag for piping/log environments without emoji support.
- Real-time finding output to stdout as each takeover is detected.
- Markdown report now uses tables (summary table + per-domain findings table sorted by severity).
- JSON report includes `started` and `finished` timestamps and uses `ensure_ascii=False`.
- UTC timestamps now use `timezone.utc` (replaces deprecated `datetime.utcnow()`).

### Fixed
- `normalize_domains()` now correctly strips paths and ports from URLs (`http://example.com:8080/path` → `example.com`).
- Subdomain filter removes entries without a dot (assetfinder false positives).
- `run_cmd` rewritten with `subprocess.run` + real timeout. No more indefinite hangs.
- stderr captured optionally in verbose mode to surface real tool errors.

### Changed
- `run_cmd` signature extended: `capture_stderr`, `timeout`, `retries` parameters.
- `CNAME_TAKEOVER_PATTERNS` (list of strings) replaced by `CNAME_SERVICES` (list of tuples with pattern, service name, severity).
- Markdown report layout: tables instead of bullet lists, findings sorted HIGH→INFO.
- Banner width updated for v1.3.0.

---

## [1.2.0] – 2026-03-25

### Added
- `--subs-file <path>`: acepta archivo externo de subdominios para usarlo directamente en fase activa.
- `validate_args()`: valida combinaciones invalidas de flags al arrancar (ej. `--passive-only` + `--active-only`).
- Patrones CNAME adicionales: `shopify.com`, `helpjuice.com`, `helpscoutdocs.com`, `ghost.io`, `readme.io`, `surge.sh`.
- Timestamp HH:MM en nombre de informe: `takeovflow_report_YYYYMMDD_HHMM.md`.
- JSON report incluye `tool` y `version`.
- `__version__ = "1.2.0"` y flag `--version`.

### Fixed
- `--active-only` ya no falla silenciosamente: ahora carga subdominios desde `--subs-file` o `--file` y ejecuta todos los scanners activos correctamente.

### Changed
- Nombre de informe: `subdomain_takeover_report_*.md` → `takeovflow_report_*.md`.
- Argparse reorganizado en grupos: `targets`, `mode`, `scan options`.
- Mensajes `[~]` para fases omitidas compactados.

---

## [1.1.0] – 2026-03-24

### Added
- `check_available_tools()`: no aborta si falta alguna herramienta, informa y omite la fase.
- Banner y badges de version.

### Changed
- Repo renombrado: `tool-takeovflow` → `takeovflow`.

---

## [1.0.0] – 2025-09-02

### Added
- Version inicial: subfinder, assetfinder, dnsx, httpx, subjack, nuclei, CNAME patterns, Markdown + JSON.
