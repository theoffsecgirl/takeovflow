# Changelog

All notable changes to **takeovflow** are documented here.

---

## [1.4.0] – 2026-04-16

### Added
- **HTTP fingerprinting propio** (`run_http_fingerprinting`): detecta takeovers confirmados via body/titulo HTTP sin depender de subjack. 32 patrones de servicios (GitHub Pages, Heroku, AWS S3, Azure, Netlify, Ghost, Surge, Fastly, Shopify, Zendesk, UserVoice, Webflow, GitBook, HubSpot, Pantheon, WordPress.com, ReadMe.io, Kinsta, Vercel, Bitbucket, Freshdesk, Intercom, Cargo, Acquia, Strikingly, Launchrock y mas). Concurrente con `ThreadPoolExecutor`.
- **Dangling CNAME detection**: el CNAME analysis ahora distingue entre `cname-dangling` (destino NXDOMAIN = takeover probable) y `cname-pattern` (destino activo = verificar). Reduce falsos positivos drasticamente.
- **`--rate` ahora funciona**: se pasa a `dnsx` (`-rate-limit`) y `httpx` (`-rate-limit`). Antes era un flag decorativo.
- **`--silent` mode**: suprime todo salvo los findings. Compatible con piping: `takeovflow.py -d example.com --silent | grep HIGH`.
- **`--jsonl`**: emite cada finding como JSON por linea en stdout. Ideal para integrar con jq, SIEM o pipelines.
- **`--no-http-fp`**: desactiva el HTTP fingerprinting propio.
- **`--no-subjack`**: desactiva subjack (ya que esta sin mantenimiento activo).
- **`amass`** integrado en fase pasiva (opcional, si esta disponible).
- **`install.sh`**: instalador completo para macOS (Homebrew) y Debian/Ubuntu (apt + go install). Detecta OS, instala Go si falta, verifica cada tool al final.
- **`pyproject.toml`**: permite `pip install -e .` y usar `takeovflow` como comando global.
- **`tests/test_takeovflow.py`**: suite de tests unitarios con pytest para `_clean_domain`, `is_valid_domain`, `deduplicate_takeovers` y `filter_by_severity`.
- **Progress bar en CNAME y HTTP-FP**: muestra `[CNAME] 42/500 (8%)` en tiempo real.
- **Validacion de formato de dominio** con regex antes de procesar. Informa dominios invalidos en lugar de fallar silenciosamente.

### Fixed
- `--rate` era decorativo, ahora se usa realmente en dnsx y httpx.
- `--silent` y `--verbose` mutuamente excluyentes (validacion).
- Markdown report no se genera en modo `--silent` (no tiene sentido).

### Changed
- Orden de ejecucion activa: CNAME -> HTTP-FP -> subjack -> nuclei (CNAME primero porque es mas rapido y no depende de curl).
- subjack marcado como opcional con `--no-subjack`.
- `_die()` y `_log()` helpers internos para manejo limpio de errores y output.

---

## [1.3.0] – 2026-04-16

### Added
- Concurrent CNAME analysis via `ThreadPoolExecutor`.
- 55 CNAME service fingerprints with severity.
- Finding deduplication.
- `--timeout`, `--retries`, `--resolvers`, `--output-dir`, `--min-severity`, `--no-color`.
- Severity system (HIGH/MEDIUM/LOW/INFO).
- Real-time finding output.
- Markdown report with tables.
- UTC timestamps with `timezone.utc`.
- JSON with `ensure_ascii=False` + `started`/`finished`.

### Fixed
- `normalize_domains()` strips ports/paths.
- Subdomain dot-filter.
- `subprocess.run` with real timeout.

---

## [1.2.0] – 2026-03-25

### Added
- `--subs-file`, `validate_args()`, patrones CNAME adicionales.
- Timestamp en nombre de informe.
- JSON incluye `tool` y `version`.
- `--version`.

### Fixed
- `--active-only` carga subdominios correctamente.

---

## [1.1.0] – 2026-03-24

### Added
- `check_available_tools()`: no aborta si falta herramienta.
- Banner y badges.

### Changed
- Repo renombrado: `tool-takeovflow` -> `takeovflow`.

---

## [1.0.0] – 2025-09-02

### Added
- Version inicial: subfinder, assetfinder, dnsx, httpx, subjack, nuclei, CNAME patterns, Markdown + JSON.
