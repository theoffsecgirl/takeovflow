<div align="center">

# takeovflow

**Scanner Avanzado de Subdomain Takeover**

![Language](https://img.shields.io/badge/Python-3.7+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.4.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Recon-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇬🇧 [English version](README.md)

</div>

---

## ¿Qué hace?

Combina descubrimiento pasivo, resolución DNS activa, fingerprinting HTTP y detección de CNAME dangling para identificar subdominios vulnerables a takeover. No necesita scanner externo — tiene su propio motor de fingerprinting HTTP. Resiliente: omite fases si falta alguna herramienta sin abortar.

**Capas de detección:**
1. CNAME pattern matching (55 servicios)
2. CNAME dangling detection (verificacion NXDOMAIN → alta confianza)
3. HTTP body fingerprinting (32 patrones de error por servicio, sin falsos positivos)
4. Templates de nuclei para takeover
5. subjack (opcional)

---

## Quickstart

```bash
git clone https://github.com/theoffsecgirl/takeovflow.git
cd takeovflow
bash install.sh          # instala todas las herramientas externas
python3 takeovflow.py -d example.com -v
```

O instalar como comando global:
```bash
pip install -e .
takeovflow -d example.com -v
```

---

## Herramientas externas

`subfinder` `assetfinder` `amass` `dnsx` `httpx` `subjack` `nuclei` `dig` `curl`

Todas opcionales — instala con `bash install.sh` (macOS + Debian/Ubuntu).

---

## Uso

```bash
# Dominio unico, scan completo
python3 takeovflow.py -d example.com -v

# Archivo con dominios, JSON output
python3 takeovflow.py -f scope.txt --json-output --output-dir ./reportes

# Solo fase pasiva
python3 takeovflow.py -d example.com --passive-only

# Solo fase activa desde subdominios conocidos
python3 takeovflow.py --active-only --subs-file subdomains.txt -d example.com

# Modo pipeline: solo findings HIGH por stdout
python3 takeovflow.py -d example.com --silent --min-severity HIGH

# JSONL para jq o SIEM
python3 takeovflow.py -d example.com --jsonl | jq 'select(.severity=="HIGH")'

# Resolvers personalizados + rate limit
python3 takeovflow.py -d example.com --resolvers resolvers.txt --rate 300

# Sin subjack (sin mantenimiento activo)
python3 takeovflow.py -d example.com --no-subjack
```

---

## Capas de deteccion

| Capa | Metodo | Confianza |
|------|--------|-----------|
| CNAME dangling | dig CNAME + check NXDOMAIN | 🔴 HIGH |
| HTTP fingerprinting | curl + patron en body | 🔴 HIGH |
| nuclei | templates takeover | 🔴 HIGH / 🟡 MEDIUM |
| CNAME pattern | patrones de servicio conocidos | 🟡 MEDIUM |
| subjack | fingerprint DB | 🟡 MEDIUM |

---

## Parametros

```text
Targets:
  -d, --domain            Dominio unico
  -f, --file              Archivo con dominios (uno por linea)
  -l, --list              Lista separada por comas

Modo:
  --passive-only          Solo fase pasiva
  --active-only           Solo fase activa (requiere --subs-file o --file)
  --subs-file PATH        Archivo de subdominios para fase activa

Scan:
  -t, --threads N         Hilos (default: 50)
  -r, --rate N            Rate limit req/s para dnsx + httpx (default: 150)
  --timeout N             Timeout por herramienta en segundos (default: 30)
  --retries N             Reintentos (default: 2)
  --resolvers FILE        Resolvers DNS para dnsx
  --no-http-fp            Desactivar HTTP fingerprinting propio
  --no-subjack            Desactivar subjack
  -v, --verbose           Verbose
  --silent                Solo findings en stdout (piping)
  --jsonl                 Emitir cada finding como JSON por linea
  --json-output           Generar informe JSON
  --output-dir DIR        Directorio de salida (default: CWD)
  --nuclei-templates PATH Templates nuclei personalizados
  --min-severity LEVEL    HIGH | MEDIUM | LOW | INFO (default: INFO)
      --version           Mostrar version
```

---

## Niveles de severidad

| Nivel | Significado |
|-------|-------------|
| 🔴 HIGH | CNAME dangling (NXDOMAIN) o match HTTP body — accion inmediata |
| 🟡 MEDIUM | CNAME pattern con destino activo — verificar manualmente |
| 🟢 LOW | Informativo, bajo riesgo |
| ⚪ INFO | Solo contexto |

---

## Ejecutar tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Uso etico

Solo para bug bounty, laboratorios y auditorias autorizadas.

---

## Licencia

MIT · [theoffsecgirl](https://theoffsecgirl.com)
