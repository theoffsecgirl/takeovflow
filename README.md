<div align="center">

# tool-takeovflow

**Escáner avanzado de Subdomain Takeover**

![Language](https://img.shields.io/badge/Python-3.7+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Recon-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

</div>

---

## ¿Qué hace?

`takeovflow` combina descubrimiento pasivo, resolución activa, fingerprinting y detección de patrones CNAME para identificar subdominios susceptibles de takeover. Genera informe en Markdown (y JSON opcional) al final del scan.

---

## Herramientas externas requeridas

`subfinder` `assetfinder` `dnsx` `httpx` `subjack` `nuclei` `dig` `jq` `curl`

El script comprueba su disponibilidad automáticamente al arrancar.

---

## Instalación

```bash
git clone https://github.com/theoffsecgirl/tool-takeovflow.git
cd tool-takeovflow
chmod +x takeovflow.py
```

---

## Uso

```bash
# Dominio único
python3 takeovflow.py -d example.com -v

# Archivo con dominios
python3 takeovflow.py -f scope.txt

# Lista separada por comas
python3 takeovflow.py -l "dom1.com,dom2.net"

# Solo pasivo
python3 takeovflow.py -d example.com --passive-only

# Solo activo
python3 takeovflow.py -d example.com --active-only

# Informe JSON
python3 takeovflow.py -d example.com --json-output

# Templates de nuclei personalizados
python3 takeovflow.py -d example.com --nuclei-templates ./mis-templates/

# Escaneo completo
python3 takeovflow.py -f scope.txt -t 100 -r 5 -v --json-output --nuclei-templates ./takeover-templates/
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

## Archivos generados

```text
takeovflow_tmp_*/
├── *_subfinder.txt
├── *_assetfinder.txt
├── *_subdomains_all.txt
├── *_dnsx.txt
├── *_httpx.txt
├── *_subjack.txt
├── *_nuclei.txt
├── *_cname_patterns.txt
├── subdomain_takeover_report_YYYYMMDD.md
└── subdomain_takeover_report_YYYYMMDD.json
```

---

## Limitaciones

- Depende de herramientas externas
- Posibles falsos positivos en detección CNAME — verificar manualmente

---

## Uso ético

Solo para bug bounty, laboratorios y auditorías autorizadas. Sin garantías.

---

## Licencia

MIT · [theoffsecgirl](https://theoffsecgirl.com)
