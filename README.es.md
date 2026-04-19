<div align="center">

# takeovflow

**Scanner avanzado de subdomain takeover — pasivo + activo + fingerprinting CNAME**

![Language](https://img.shields.io/badge/Python-3.8+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Recon-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇬🇧 [English version](README.md)

</div>

---

## ¿Qué hace?

Escanea subdominios en busca de vulnerabilidades de takeover usando:
- descubrimiento pasivo
- análisis activo HTTP
- fingerprinting de CNAME

Importante: los findings normalizados son **señales / candidatos**, no confirmaciones.

---

## Nuevas capacidades

- findings normalizados compatibles con `bbcopilot`
- campo `confidence`
- campo `reason` y `evidence`
- `--format json|jsonl`
- `--stdout` para pipelines
- logs enviados a `stderr`

---

## Ejemplo de finding

```json
{"type":"candidate","vector":"subdomain_takeover","target":"blog.example.com","severity":"high","confidence":"medium","reason":"CNAME apunta a proveedor vulnerable (GitHub Pages)","evidence":["cname match","provider fingerprint"],"tags":["takeover","cname-pattern"]}
```

### Confidence

- high → subjack / nuclei fuerte
- medium → CNAME sospechoso
- low → señal débil

---

## Uso

```bash
# uso clásico
python3 takeovflow.py -d example.com

# JSONL normalizado
python3 takeovflow.py -d example.com --format jsonl --json-output

# stdout pipeline
python3 takeovflow.py -d example.com --format jsonl --stdout
```

---

## Integración workflow

```bash
# fichero
python3 takeovflow.py -d target.com --format jsonl --json-output
bbcopilot ingest takeovflow takeovflow_findings.jsonl

# pipe
python3 takeovflow.py -d target.com --format jsonl --stdout > out.jsonl
bbcopilot ingest takeovflow out.jsonl
```

---

## Parámetros nuevos

```text
--format json|jsonl
--stdout
```

---

## Uso ético

Solo en entornos autorizados.

---

## Licencia

MIT
