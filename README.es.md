<div align="center">

# takeovflow

**Scanner Avanzado de Subdomain Takeover**

![Language](https://img.shields.io/badge/Python-3.7+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.3.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Recon-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇬🇧 [English version](README.md)

</div>

---

## ¿Qué hace?

Combina descubrimiento pasivo, resolución activa, fingerprinting y detección de patrones CNAME para identificar subdominios vulnerables a takeover. Resiliente: si falta alguna herramienta externa, continúa con las disponibles.

**Novedades v1.3.0:** análisis CNAME concurrente, 55 fingerprints de servicios, deduplicación de findings, filtro por severidad, timeout/reintentos configurables, resolvers DNS personalizados y directorio de salida flexible.

---

## Herramientas externas

`subfinder` `assetfinder` `dnsx` `httpx` `subjack` `nuclei` `dig` `jq` `curl`

El script verifica disponibilidad al arrancar y omite las fases para herramientas no instaladas — **no aborta**.

---

## Instalación

```bash
git clone https://github.com/theoffsecgirl/takeovflow.git
cd takeovflow
chmod +x takeovflow.py
```

---

## Uso

```bash
# Dominio único
python3 takeovflow.py -d example.com -v

# Archivo con dominios
python3 takeovflow.py -f scope.txt

# Solo fase pasiva (descubrimiento)
python3 takeovflow.py -d example.com --passive-only

# Solo fase activa con subdominios conocidos
python3 takeovflow.py --active-only --subs-file subdomains.txt -d example.com

# Resolvers personalizados + directorio de salida + solo severidad HIGH
python3 takeovflow.py -d example.com --resolvers resolvers.txt --output-dir ./reportes --min-severity HIGH

# Templates nuclei personalizados, JSON, 100 hilos
python3 takeovflow.py -f scope.txt -t 100 -v --json-output --nuclei-templates ./takeover-templates/

# Ver versión
python3 takeovflow.py --version
```

---

## Flujo técnico

```text
[PASIVA]   subfinder + assetfinder → deduplicación
[ACTIVA]   dnsx → httpx → subjack → nuclei → patrones CNAME (concurrente)
[OUTPUT]   takeovflow_report_YYYYMMDD_HHMM.md + JSON (opcional)
```

Servicios detectados vía CNAME (55 en total): AWS S3/CloudFront/Beanstalk, Azure Web Apps/Traffic Manager/Blob, Heroku, GitHub Pages, Fastly, Akamai, Netlify, Vercel, Webflow, GitBook, Shopify, Ghost, Surge, Statuspage, Bitbucket Pages, Pantheon, Kinsta, HubSpot, Freshdesk, Intercom, Cargo, Wix, Weebly, Tilda, Zendesk y más.

---

## Parámetros

```text
Targets:
  -d, --domain            Dominio único
  -f, --file              Archivo con dominios (uno por línea)
  -l, --list              Lista de dominios separada por comas

Modo:
  --passive-only          Solo fase pasiva
  --active-only           Solo fase activa (requiere --subs-file o --file)
  --subs-file PATH        Archivo de subdominios para fase activa

Scan:
  -t, --threads N         Hilos (default: 50)
  -r, --rate N            Rate limit (default: 2)
  --timeout N             Timeout por herramienta en segundos (default: 30)
  --retries N             Reintentos ante fallo (default: 2)
  --resolvers FILE        Archivo con resolvers DNS para dnsx
  -v, --verbose           Modo verbose
  --no-color              Sin emojis/color en salida
  --json-output           Generar informe JSON
  --output-dir DIR        Directorio de salida para reportes (default: CWD)
  --nuclei-templates PATH Ruta a templates personalizados de nuclei
  --min-severity LEVEL    Severidad mínima en reporte: HIGH | MEDIUM | LOW | INFO (default: INFO)
      --version           Mostrar versión
```

---

## Niveles de severidad

| Nivel | Significado |
|-------|-------------|
| 🔴 HIGH | Muy probablemente vulnerable, acción inmediata recomendada |
| 🟡 MEDIUM | Requiere verificación manual |
| 🟢 LOW | Informativo, bajo riesgo |
| ⚪ INFO | Solo contexto |

---

## Uso ético

Solo para bug bounty, laboratorios y auditorías autorizadas.

---

## Licencia

MIT · [theoffsecgirl](https://theoffsecgirl.com)
