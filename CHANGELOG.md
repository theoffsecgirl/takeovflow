# Changelog

All notable changes to **takeovflow** are documented here.

---

## [1.1.0] – 2026-03-24

### Added
- Banner ASCII en arranque.
- README actualizado con nuevo nombre (ex `tool-takeovflow`).

### Changed
- `ensure_tools()` reemplazado por `check_available_tools()`: ya no aborta si falta alguna herramienta externa, informa y omite la fase correspondiente.
- Cada fase (dnsx, httpx, subjack, nuclei, dig) comprueba disponibilidad antes de ejecutar.
- Mensaje `[~]` diferenciado para fases omitidas vs `[!]` errores.

---

## [1.0.0] – 2025-09-02

### Added
- Version inicial: subfinder, assetfinder, dnsx, httpx, subjack, nuclei, CNAME patterns, output Markdown + JSON.
