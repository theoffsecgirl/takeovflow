<div align="center">

# takeovflow

**Scanner avanzado de subdomain takeover — pasivo + activo + fingerprinting CNAME**

![Language](https://img.shields.io/badge/Python-3.8+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-1.6.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Recon-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇬🇧 [English version](README.md)

</div>

---

## ¿Qué hace?

Escanea subdominios en busca de vulnerabilidades de takeover usando tres enfoques:
- **Pasivo**: descubrimiento de subdominios con `subfinder` + `assetfinder`, resolución DNS de CNAMEs
- **Activo**: análisis de respuestas HTTP con `httpx`, confirmación de takeover con `subjack` + `nuclei`
- **Fingerprinting**: coincidencia de patrones CNAME específicos por proveedor en 55 servicios (GitHub Pages, Heroku, Fastly, S3, Shopify, etc.)

**Novedades v1.6.0:** distinción entre findings confirmados y sin confirmar (las coincidencias de patrón CNAME ya no se reportan con la misma confianza que una firma real de subjack/nuclei), fusión de findings entre fuentes con promoción de confianza, y verificación HTTP activa opcional por firma para los patrones CNAME más comunes (AWS S3, GitHub Pages, Heroku).

Resiliente: si falta alguna herramienta externa, continúa con las disponibles — **no aborta**.

---

## Proveedores soportados

| Proveedor | Método de detección |
|-----------|---------------------|
| GitHub Pages | CNAME (`github.io`) + patrón de body |
| Heroku | CNAME (`herokudns.com`, `herokuapp.com`) + status |
| Amazon S3 / Beanstalk | CNAME (`amazonaws.com`, `elasticbeanstalk.com`) |
| AWS CloudFront | CNAME (`cloudfront.net`) |
| Azure Web Apps | CNAME (`azurewebsites.net`, `trafficmanager.net`) |
| Fastly | CNAME (`fastly.net`) |
| Shopify | CNAME (`shopify.com`) + body |
| Zendesk | CNAME (`zendesk.com`) + status |
| Netlify | CNAME (`netlify.app`, `netlify.com`) |
| Vercel | CNAME (`vercel.app`) |
| Ghost | CNAME (`ghost.io`) + body |
| Surge.sh | CNAME (`surge.sh`) + body |
| Readme.io | CNAME (`readme.io`) + body |
| Unbounce | CNAME (`unbouncepages.com`) + body |
| Webflow | CNAME (`webflow.io`) |
| GitBook | CNAME (`gitbook.io`, `gitbook.com`) |
| Wix | CNAME (`wixdns.net`) |
| Weebly | CNAME (`weebly.com`) |
| Tilda | CNAME (`tilda.ws`) |
| Statuspage | CNAME (`statuspage.io`) |
| + 35 más | Akamai, HubSpot, Freshdesk, Pantheon, Kinsta… |

---

## Ejemplo de salida

```text
[*] Dominios cargados: 1
[*] Ejecutando descubrimiento pasivo: subfinder, assetfinder
[*] Subdominios encontrados: 1247
[*] Resolviendo CNAMEs (concurrente)...

[!] POSIBLE TAKEOVER → blog.example.com
    CNAME  : example.github.io
    Servicio: GitHub Pages
    Severidad: HIGH

[!] POSIBLE TAKEOVER → cdn.example.com
    CNAME  : example.s3.amazonaws.com
    Servicio: AWS S3 / Elastic Beanstalk
    Severidad: HIGH

[~] INVESTIGAR → api.example.com
    CNAME  : example.herokudns.com
    Servicio: Heroku
    Severidad: HIGH

[+] Hallazgos CNAME: 3
[+] Reporte guardado → takeovflow_report_20240416_1523.md
[+] JSON guardado    → takeovflow_report_20240416_1523.json
```

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
python3 takeovflow.py --help
```

---

## Uso

```bash
# Dominio único (pasivo + activo + CNAME)
python3 takeovflow.py -d example.com -v

# Archivo con múltiples dominios
python3 takeovflow.py -f scope.txt

# Solo fase pasiva (descubrimiento + CNAME)
python3 takeovflow.py -d example.com --passive-only

# Solo fase activa con archivo de subdominios conocidos
python3 takeovflow.py --active-only --subs-file subdomains.txt -d example.com

# Resolvers personalizados + directorio de salida + solo severidad HIGH
python3 takeovflow.py -d example.com --resolvers resolvers.txt --output-dir ./reportes --min-severity HIGH

# Templates nuclei personalizados, JSON, 100 hilos
python3 takeovflow.py -f scope.txt -t 100 -v --json-output --nuclei-templates ./takeover-templates/

# Lista de dominios separada por comas
python3 takeovflow.py -l example.com,target.io,scope.net

# Ver versión
python3 takeovflow.py --version
```

---

## Integración en pipelines

```bash
# Pipeline recon completo — descubrimiento + escaneo en un paso
subfinder -d example.com -silent > subdomains.txt && \
  python3 takeovflow.py --active-only --subs-file subdomains.txt -d example.com --json-output

# Después de assetfinder
assetfinder --subs-only example.com > subs.txt && \
  python3 takeovflow.py --active-only --subs-file subs.txt -d example.com

# Múltiples objetivos desde un archivo de scope
python3 takeovflow.py -f scope.txt -t 100 --min-severity HIGH --json-output --output-dir ./resultados
```

---

## Flujo técnico

```text
[PASIVA]   subfinder + assetfinder → deduplicación
[ACTIVA]   dnsx → httpx → subjack → nuclei → patrones CNAME (concurrente)
[OUTPUT]   takeovflow_report_YYYYMMDD_HHMM.md + JSON (opcional)
```

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
  -r, --rate N            Rate limit req/s para httpx/dnsx (default: 150)
  --timeout N             Timeout por herramienta en segundos (default: 30)
  --retries N             Reintentos ante fallo (default: 2)
  --resolvers FILE        Archivo con resolvers DNS para dnsx
  -v, --verbose           Modo verbose
  -q, --quiet             Suprime banner y prints intermedios
  --no-color              Sin emojis/color en salida
  --json-output           Generar informe JSON
  --output-dir DIR        Directorio de salida para reportes (default: CWD)
  --nuclei-templates PATH Ruta a templates personalizados de nuclei
  --min-severity LEVEL    Severidad mínima: CRITICAL | HIGH | MEDIUM | LOW | INFO (default: INFO)
  --skip-http-verify      Desactiva la verificación HTTP activa de firmas para los
                          findings de cname-pattern (más rápido, pero esos findings se
                          quedan sin confirmar salvo que otra fuente los corrobore)
  --version               Mostrar versión
```

---

## Niveles de severidad

| Nivel | Significado |
|-------|-------------|
| 🔴 CRITICAL | Vector de takeover confirmado, acción inmediata requerida |
| 🔴 HIGH | Muy probablemente vulnerable, acción inmediata recomendada |
| 🟡 MEDIUM | Requiere verificación manual |
| 🟢 LOW | Informativo, bajo riesgo |
| ⚪ INFO | Solo contexto |

### Findings confirmados vs. sin confirmar

No todos los findings tienen el mismo nivel de confianza. `subjack` y `nuclei`
confirman un takeover comprobando una **firma/fingerprint** conocida del servicio en la
respuesta HTTP real — eso es una confirmación de verdad. El análisis de patrones CNAME
propio de takeovflow (fuente `cname-pattern`), en cambio, solo comprueba si el
*string* del CNAME coincide con el dominio de un proveedor conocido (p. ej.
`*.amazonaws.com`) — **no** comprueba si ese recurso remoto está realmente huérfano o
reclamable. Un CNAME apuntando a un bucket S3 activo y en uso legítimo se ve idéntico,
a nivel de patrón, a uno que apunta a un bucket eliminado.

Para reflejar esa diferencia:

- Las coincidencias de patrón sin más verificación se degradan automáticamente un
  escalón de severidad (HIGH → MEDIUM, MEDIUM → LOW) y se marcan `"confirmed": false`
  en la salida JSON.
- En el reporte Markdown, cualquier finding de este tipo lleva el prefijo
  **`[PATRÓN SIN CONFIRMAR — requiere verificación manual]`** en su columna de detalle.
- Los findings de `subjack` o `nuclei` (confirmación real por firma) nunca llevan ese
  prefijo y se tratan como `confirmed: true`.
- Si el mismo subdominio se corrobora luego por otra fuente (p. ej. también lo marca
  `subjack`/`nuclei`), o se confirma mediante la verificación de firma HTTP integrada,
  se promociona de nuevo a `confirmed: true` con severidad completa (ver más abajo).

**Regla práctica:** cualquier finding con `[PATRÓN SIN CONFIRMAR]` necesita
verificación manual (comprobar que el registro DNS está realmente huérfano, intentar
reclamar el recurso en un sandbox, etc.) antes de meterlo en un reporte. Un finding
confirmado por subjack/nuclei/firma HTTP tiene una confianza notablemente mayor, pero
sigue siendo recomendable verificar a mano antes de enviar cualquier cosa.

### Corroboración entre fuentes

Si el mismo subdominio lo marcan dos o más fuentes distintas (p. ej. `cname-pattern` *y*
`nuclei`), los findings se fusionan en una sola entrada en vez de aparecer duplicados:

- El finding fusionado lista todas las fuentes que lo detectaron (`Detectado por:
  cname-pattern, nuclei`) y conserva la evidencia individual de cada una en la fila del
  reporte.
- Si al menos una de las fuentes hizo verificación real por firma (`subjack` o
  `nuclei`), el finding fusionado se promociona a `confirmed: true` con severidad
  completa — aunque el componente `cname-pattern` por separado estuviera sin confirmar.
- Un subdominio detectado solo por `cname-pattern`, sin corroboración, se queda sin
  confirmar como se explicó arriba.

### Verificación de firma HTTP (`--skip-http-verify`)

Para los patrones CNAME más frecuentes en targets reales de bug bounty — **AWS S3**,
**GitHub Pages** y **Heroku** — takeovflow hace un paso extra opcional: una petición GET
simple al subdominio, comprobando si el body de la respuesta contiene la firma de error
"recurso no encontrado" característica del proveedor (firmas tomadas de
[EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz), la
misma base de fingerprints que usa `subjack` internamente):

| Servicio | Firma comprobada |
|---|---|
| AWS S3 | `The specified bucket does not exist` |
| GitHub Pages | `There isn't a GitHub Pages site here.` |
| Heroku | `No such app` |

Si la firma coincide, el finding se promociona a `confirmed: true` con severidad
completa y una nota indicando qué firma se encontró. Para GitHub Pages y Heroku, la nota
también avisa de que esa firma es un **edge case** en la base de datos de origen (no
garantiza al 100% que sea reclamable — ambos proveedores añadieron protecciones
anti-takeover que pueden producir el mismo 404 sin que el subdominio sea realmente
tomable), así que sigue siendo necesaria la verificación manual antes de reportar.

Esta comprobación se ejecuta por defecto y añade una petición HTTP extra por cada
subdominio con patrón coincidente (con timeout corto; los fallos de red simplemente
dejan el finding sin confirmar, nunca abortan el escaneo). Usa `--skip-http-verify` para
desactivarla del todo — trade-off: escaneos más rápidos, pero más findings de
`cname-pattern` se quedarán en el rango sin confirmar/severidad degradada aunque
hubieran sido confirmables con una petición extra.

---

## Uso ético

Solo para bug bounty, laboratorios y auditorías autorizadas.

---

## Contribuir

PRs bienvenidas. Especialmente:
- Nuevos fingerprints de proveedores
- Corrección de falsos positivos
- Mejoras de rendimiento para listas grandes de subdominios

---

## Licencia

MIT · [theoffsecgirl](https://theoffsecgirl.com)
