<div align="center">

# takeovflow

**Escáner avanzado de Subdomain Takeover**

![Language](https://img.shields.io/badge/Python-3.7+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.2.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Recon-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

</div>

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

# Solo fase pasiva (descubrimiento)
python3 takeovflow.py -d example.com --passive-only

# Solo fase activa con subdominios ya conocidos
python3 takeovflow.py --active-only --subs-file subdomains.txt -d example.com

# Active-only con archivo de subdominios (sin dominio raiz)
python3 takeovflow.py --active-only --subs-file subdomains.txt

# Con templates nuclei personalizados y JSON
python3 takeovflow.py -f scope.txt -t 100 -v --json-output --nuclei-templates ./takeover-templates/

# Ver versión
python3 takeovflow.py --version
```

---

## Flujo técnico

```text
[PASIVA]  subfinder + assetfinder → deduplicación
[ACTIVA]  dnsx → httpx → subjack → nuclei → CNAME patterns
[OUTPUT]  takeovflow_report_YYYYMMDD_HHMM.md + JSON (opcional)
```

Servicios detectados vía CNAME: AWS S3, CloudFront, GitHub Pages, Heroku, Azure, Fastly, Shopify, Ghost, Surge y otros.

---

## Parámetros

```text
Targets:
  -d, --domain        Dominio unico
  -f, --file          Archivo con dominios (uno por linea)
  -l, --list          Dominios separados por comas

Mode:
  --passive-only      Solo descubrimiento pasivo
  --active-only       Solo fase activa (requiere --subs-file o --file)
  --subs-file PATH    Archivo de subdominios para fase activa

Scan:
  -t, --threads       Hilos (default: 50)
  -r, --rate          Rate limit (default: 2)
  -v, --verbose       Modo verbose
  --json-output       Generar informe JSON
  --nuclei-templates  Ruta a templates nuclei personalizados
      --version       Muestra la versión
```

---

## Uso ético

Solo para bug bounty, laboratorios y auditorías autorizadas.

---

## Licencia

MIT · [theoffsecgirl](https://theoffsecgirl.com)
