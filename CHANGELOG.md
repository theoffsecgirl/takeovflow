# Changelog

All notable changes to **takeovflow** are documented here.

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
