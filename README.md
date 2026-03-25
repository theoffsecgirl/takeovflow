<div align="center">

# takeovflow

**Escáner avanzado de Subdomain Takeover**

![Language](https://img.shields.io/badge/Python-3.7+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.1.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Recon-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

</div>

---

```text
┌──────────────────────────────────────────────────────┐
│                                                      │
│  ███████╗██████╗ ██╗  ███████╗██████╗ ██╗   │
│  ██╔════╝██╔══██╗██║  ╚══██╔═╝██╔══██╗██║   │
│  █████╗  ██████╔╝██║     ██║  ██║  ██║██║   │
│  ██╔══╝  ██╔═══╝ ██║     ██║  ██║  ██║╚═╝   │
│  ██║     ██║     ███████╗██║  ██████╔╝██╗   │
│  ╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═════╝ ╚═╝   │
│                                                      │
│  Subdomain Takeover Scanner  v1.1.0                  │
│  subfinder · dnsx · subjack · nuclei · CNAME         │
│  by theoffsecgirl                                    │
└──────────────────────────────────────────────────────┘
```

---

## ¿Qué hace?

Combina descubrimiento pasivo, resolución activa, fingerprinting y detección de patrones CNAME para identificar subdominios susceptibles de takeover. Resiliente: si falta alguna herramienta externa, continúa con las disponibles.

---

## Herramientas externas

`subfinder` `assetfinder` `dnsx` `httpx` `subjack` `nuclei` `dig` `jq` `curl`

El script comprueba disponibilidad al arrancar y omite las fases de las tools que falten — **no aborta**.

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

# Solo pasivo
python3 takeovflow.py -d example.com --passive-only

# Solo activo
python3 takeovflow.py -d example.com --active-only

# Informe JSON + templates nuclei personalizados
python3 takeovflow.py -f scope.txt -t 100 -v --json-output --nuclei-templates ./takeover-templates/
```

---

## Flujo técnico

```text
[PASIVA]  subfinder + assetfinder → deduplicación
[ACTIVA]  dnsx → httpx → subjack → nuclei → CNAME patterns
[OUTPUT]  Markdown report + JSON (opcional)
```

Servicios detectados vía CNAME: AWS S3, CloudFront, GitHub Pages, Heroku, Azure, Fastly y otros.

---

## Uso ético

Solo para bug bounty, laboratorios y auditorías autorizadas.

---

## Licencia

MIT · [theoffsecgirl](https://theoffsecgirl.com)
