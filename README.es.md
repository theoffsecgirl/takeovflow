# takeovflow

Scanner avanzado de subdomain takeover.

> 🇬🇧 [English version](README.md)

---

## ¿Qué hace?

Escanea subdominios en busca de señales de takeover usando:
- descubrimiento pasivo
- checks activos
- fingerprinting de CNAME

Importante: los findings son candidatos, no takeovers confirmados.

---

## Funcionalidades

- Descubrimiento pasivo con `subfinder` + `assetfinder`
- Checks activos con `dnsx`, `httpx`, `subjack`, `nuclei`
- Detección de patrones CNAME en proveedores conocidos
- Output normalizado de findings
- Exportación en JSON / JSONL
- Modo `stdout` para pipelines
- Manejo limpio de `Ctrl+C`

---

## Instalación

```bash
git clone https://github.com/theoffsecgirl/takeovflow.git
cd takeovflow
python3 takeovflow.py --help
```

---

## Uso

```bash
python3 takeovflow.py -d example.com
```

### Pipeline

```bash
python3 takeovflow.py -d target.com --format jsonl --stdout | bbcopilot ingest takeovflow -
```

### Guardar findings normalizados

```bash
python3 takeovflow.py -d target.com --json-output --format jsonl --output-dir ./resultados
```

---

## Notas

- Los logs van a `stderr`
- Los findings van a `stdout` con `--stdout`
- `Ctrl+C` sale de forma limpia
- El output JSON puede incluir informe clásico + fichero de findings normalizados

---

## Parámetros

```text
-d, --domain            Dominio único
-f, --file              Archivo con dominios
-l, --list              Lista de dominios separada por comas
--passive-only          Solo fase pasiva
--active-only           Solo fase activa
--subs-file PATH        Archivo de subdominios para fase activa
-t, --threads           Hilos
-r, --rate              Rate limit
--timeout               Timeout por herramienta
--retries               Reintentos
--resolvers FILE        Resolvers personalizados
-v, --verbose           Modo verbose
-q, --quiet             Modo silencioso
--json-output           Generar informe JSON clásico y fichero de findings normalizados
--output-dir DIR        Directorio de salida
--nuclei-templates      Templates personalizados de nuclei
--min-severity          Filtro mínimo de severidad
--format json|jsonl     Formato de findings normalizados
--stdout                Imprimir findings normalizados por stdout
--version               Mostrar versión
```

---

## Licencia

MIT
