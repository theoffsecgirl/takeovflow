# TakeOverFlow 🔍

TakeOverFlow es una solución todo-en-uno para identificar vulnerabilidades de subdomain takeover de manera eficiente, con capacidades de enumeración, detección y generación de reportes automatizados.

## ✨ Características Principales

- 🚀 **Enumeración de subdominios** con Subfinder y Assetfinder
- 🔍 **Detección de takeovers** con Subjack, Nuclei y DNSx
- 📊 **Análisis avanzado** de CNAMEs y respuestas HTTP
- 📝 **Generación de reportes** en Markdown listos para GitHub
- 🎨 **Interfaz colorida** con banner personalizado
- ⚡ **Multi-modo de entrada**: dominio único, archivo o lista
- 🔄 **Detección automática** de servicios (AWS, GitHub, Azure)

## 📦 Instalación

1. **Requisitos previos**:
   ```bash
   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install github.com/tomnomnom/assetfinder@latest
   go install github.com/haccer/subjack@latest
   go install github.com/projectdiscovery/httpx/cmd/httpx@latest
   go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
   go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
   ```

Clonar repositorio o instalar con Go:

```bash
go install github.com/TheOffSecGirl/takeovflow@latest
-----
git clone https://github.com/TheOffSecGirl/takeoverflow.git
cd takeoverflow
# Dar permisos de ejecución:
chmod +x takeoverflow.sh
```

# 🛠 Uso Básico

### Escanear un solo dominio

`./takeoverflow.sh -d example.com`

### Escanear múltiples dominios desde archivo

`./takeoverflow.sh -f dominios.txt`

### Escanear lista de dominios

`./takeoverflow.sh -l "domain1.com,domain2.com"`

### Personalizar threads y rate limit

`./takeoverflow.sh -d example.com -t 100 -r 5`
📌 Opciones Disponibles
Opción	Descripción	Valor por defecto
-d, --domain	Escanear un único dominio	-
-f, --file	Archivo con lista de dominios	-
-l, --list	Lista de dominios separados por comas	-
-t, --threads	Número de hilos a usar	50
-r, --rate	Rate limit de requests	2
-h, --help	Mostrar ayuda	-
📂 Estructura de Salida

results/
├── all_subdomains_combined.txt    # Todos los subdominios encontrados
├── potential_takeovers_combined.txt # Posibles vulnerabilidades
├── takeover_analysis.txt          # Análisis de DNS/CNAME
├── service_detection.txt          # Servicios detectados
├── takeover_http_analysis.json    # Resultados HTTP (JSON)
└── reports/
└── subdomain_takeover_report_[DATE].md  # Reporte final

🤝 Contribución
¡Contribuciones son bienvenidas! Por favor abre un issue o pull request con tus mejoras.
