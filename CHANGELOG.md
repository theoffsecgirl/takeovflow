# Changelog

All notable changes to **takeovflow** are documented here.

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
