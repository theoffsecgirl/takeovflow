# takeovflow v2.0

Subdomain Takeover Scanner avanzado con detección mejorada, arquitectura OOP y sistema de severidad.

---

## 🚀 Novedades v2.0 (2026)

### Mejoras Técnicas
- ✅ **Arquitectura OOP** con clases organizadas
- ✅ **Sistema de severidad** (Critical/High/Medium/Low)
- ✅ **Fingerprints ampliados** (100+ servicios)
- ✅ **Detección mejorada** de CNAME patterns
- ✅ **DNS resolution** con dnspython (más rápido)
- ✅ **HTML reporting** con gráficos
- ✅ **Webhook integration** para alertas
- ✅ **Rate limiting** avanzado por servicio
- ✅ **Colored output** con progress bars

### Servicios Detectados (100+)
- AWS S3, CloudFront, Elastic Beanstalk
- Azure Websites, Traffic Manager, Storage
- GitHub Pages, Heroku, Netlify
- Vercel, Fastly, Akamai
- WordPress, Tumblr, Shopify
- Zendesk, HelpScout, Statuspage
- Cargo, Pantheon, Bitbucket
- ... y muchos más

---

## 📦 Instalación

```bash
git clone https://github.com/theoffsecgirl/tool-takeovflow.git
cd tool-takeovflow
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Herramientas Externas (Opcionales)

```bash
# Descubrimiento
GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest

# Resolución y detección
GO111MODULE=on go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/haccer/subjack@latest
```

---

## 🔥 Uso Básico

### Dominio único

```bash
python3 takeovflow.py -d example.com
```

### Lista de dominios

```bash
python3 takeovflow.py -f domains.txt -o results
```

### Con todas las herramientas externas

```bash
python3 takeovflow.py -d example.com \
  --use-external \
  --threads 100 \
  -v
```

### Solo modo rápido (sin external tools)

```bash
python3 takeovflow.py -d example.com --quick
```

---

## ⚙️ Opciones CLI

| Flag                | Descripción                                      |
|---------------------|-------------------------------------------------|
| `-d, --domain`      | Dominio objetivo                                |
| `-f, --file`        | Archivo con lista de dominios                   |
| `-l, --list`        | Lista de dominios separada por comas            |
| `-o, --output`      | Directorio de output (default: takeovflow_out)  |
| `-t, --threads`     | Número de threads (default: 50)                 |
| `--use-external`    | Usar herramientas externas (subfinder, etc.)    |
| `--quick`           | Modo rápido (solo DNS + fingerprints)          |
| `--html-report`     | Generar reporte HTML                            |
| `--webhook`         | URL webhook para alertas                        |
| `--severity`        | Severidad mínima (critical/high/medium/low)    |
| `-v, --verbose`     | Modo verbose                                    |

---

## 🎯 Detección de Takeovers

### Sistema de Severidad

**Critical:**
- S3 bucket sin reclamar (AWS)
- GitHub Pages sin repo
- Heroku app eliminada
- Azure website no existe

**High:**
- CloudFront distribution dangling
- Netlify site sin claim
- Vercel deployment missing
- Shopify store no encontrada

**Medium:**
- Tumblr blog disponible
- WordPress.com site sin claim
- Bitbucket pages dangling

**Low:**
- CNAME sospechoso pero sin confirmar
- Wildcard DNS response

### Fingerprints Incluidos (100+)

```python
CRITICAL_SERVICES = [
    "s3.amazonaws.com",           # AWS S3
    "github.io",                   # GitHub Pages
    "herokuapp.com",               # Heroku
    "azurewebsites.net",           # Azure
]

HIGH_SERVICES = [
    "cloudfront.net",              # CloudFront
    "netlify.app",                 # Netlify
    "vercel.app",                  # Vercel
    "shopify.com",                 # Shopify
]

MEDIUM_SERVICES = [
    "tumblr.com",                  # Tumblr
    "wordpress.com",               # WordPress
    "bitbucket.io",                # Bitbucket
]
```

---

## 📊 Formatos de Output

### JSON Output

```json
{
  "scan_date": "2026-03-04T19:00:00Z",
  "scanner_version": "2.0",
  "domains_scanned": 5,
  "vulnerabilities_found": 3,
  "severity_summary": {
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0
  },
  "findings": [
    {
      "subdomain": "dev.example.com",
      "cname": "example-dev.s3.amazonaws.com",
      "service": "AWS S3",
      "severity": "critical",
      "evidence": "NoSuchBucket",
      "exploitable": true,
      "timestamp": 1709577600.123
    }
  ]
}
```

### HTML Report

- Summary dashboard con gráficos
- Tabla filtrable de vulnerabilidades
- Severidad por colores
- Export a CSV/PDF

### Markdown Report

```markdown
# Subdomain Takeover Report

Generated: 2026-03-04 19:00:00 UTC

## Summary

- Domains scanned: 5
- Vulnerabilities found: 3
- Critical: 1
- High: 2

## Findings

### 🚨 CRITICAL: dev.example.com

- **CNAME:** example-dev.s3.amazonaws.com
- **Service:** AWS S3
- **Evidence:** NoSuchBucket
- **Exploitable:** Yes
```

---

## 🔥 Ejemplos Avanzados

### Bug Bounty Pipeline

```bash
# Escaneo completo con todas las herramientas
python3 takeovflow.py -f scope.txt \
  --use-external \
  --html-report \
  --severity high \
  --webhook https://hooks.slack.com/YOUR_WEBHOOK \
  -o bug_bounty_scan
```

### CI/CD Integration

```bash
# Escaneo rápido solo para critical
python3 takeovflow.py -d staging.company.com \
  --quick \
  --severity critical \
  -o ci_scan

# Exit code 1 si encuentra vulnerabilidades
if [ $? -eq 1 ]; then
  echo "Vulnerabilidades detectadas!"
  exit 1
fi
```

### Monitoring Continuo

```bash
# Cron job diario
0 2 * * * cd /opt/takeovflow && python3 takeovflow.py -f domains.txt --webhook https://... -o daily_scan
```

---

## 🧪 Webhooks

Enviar alertas a Slack/Discord/Teams cuando se detecten vulnerabilidades:

```bash
python3 takeovflow.py -d example.com \
  --webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

**Payload enviado:**
```json
{
  "text": "🚨 CRITICAL Takeover Detected!",
  "attachments": [
    {
      "color": "danger",
      "fields": [
        {"title": "Subdomain", "value": "dev.example.com"},
        {"title": "Service", "value": "AWS S3"},
        {"title": "Severity", "value": "Critical"}
      ]
    }
  ]
}
```

---

## 🎯 Casos de Uso

### 1. Bug Bounty Recon
```bash
python3 takeovflow.py -f in_scope.txt \
  --use-external \
  --html-report \
  --severity high
```

### 2. Red Team Assessment
```bash
python3 takeovflow.py -d target.com \
  --threads 200 \
  -v
```

### 3. Asset Inventory
```bash
python3 takeovflow.py -f company_domains.txt \
  --quick \
  -o asset_inventory
```

---

## ⚠️ Limitaciones

- Requiere herramientas externas para funcionalidad completa
- Posibles falsos positivos en detecciones heurísticas
- Rate limiting puede afectar escaneos grandes
- CNAME analysis es heurístico (validar manualmente)

---

## 🔬 Roadmap

- [ ] Integración con subdomain enumeration pasiva (crt.sh, VirusTotal)
- [ ] Machine learning para reducción de falsos positivos
- [ ] Automatic exploitation PoC generation
- [ ] Cloud provider APIs integration
- [ ] Real-time monitoring dashboard

---

## 📚 Referencias

- [OWASP Subdomain Takeover](https://owasp.org/www-community/attacks/Subdomain_Takeover)
- [Can I take over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz)
- [Subjack Fingerprints](https://github.com/haccer/subjack)

---

## 📖 Uso Ético

Utiliza esta herramienta únicamente en:
- ✅ Sistemas propios
- ✅ Entornos autorizados
- ✅ Programas de bug bounty con scope definido

**El uso no autorizado es ilegal.**

---

## 📜 Licencia

MIT License
