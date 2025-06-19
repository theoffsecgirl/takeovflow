#!/bin/bash

# ==============================================
# ▗▄▄▄▖▗▞▀▜▌█  ▄ ▗▞▀▚▖ ▗▄▖ ▄   ▄ ▗▄▄▄▖█  ▄▄▄  ▄   ▄ 
#   █  ▝▚▄▟▌█▄▀  ▐▛▀▀▘▐▌ ▐▌█   █ ▐▌   █ █   █ █ ▄ █ 
#   █       █ ▀▄ ▝▚▄▄▖▐▌ ▐▌ ▀▄▀  ▐▛▀▀▘█ ▀▄▄▄▀ █▄█▄█ 
#   █       █  █      ▝▚▄▞▘      ▐▌   █             
#                                                  
#                           by TheOffSecGirl
# ==============================================

# Configuración avanzada
VERSION="3.0"
CONFIG_FILE="subdomain_config.conf"
LOG_FILE="subdomain_scan_$(date +%Y%m%d_%H%M%S).log"
THREADS=50
TIMEOUT=45
RATE_LIMIT=2
USER_AGENT="SubdomainScannerPro/3.0 (by TheOffSecGirl)"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables globales
DOMAINS_FILE=""
SINGLE_DOMAIN=""
INPUT_LIST=""
ELIGIBLE_DOMAINS=()

# Mostrar banner
show_banner() {
  clear
  echo -e "${PURPLE}"
  echo "▗▄▄▄▖▗▞▀▜▌█  ▄ ▗▞▀▚▖ ▗▄▖ ▄   ▄ ▗▄▄▄▖█  ▄▄▄  ▄   ▄"
  echo "  █  ▝▚▄▟▌█▄▀  ▐▛▀▀▘▐▌ ▐▌█   █ ▐▌   █ █   █ █ ▄ █"
  echo "  █       █ ▀▄ ▝▚▄▄▖▐▌ ▐▌ ▀▄▀  ▐▛▀▀▘█ ▀▄▄▄▀ █▄█▄█"
  echo "  █       █  █      ▝▚▄▞▘      ▐▌   █"
  echo "                                                  "
  echo -e "                           ${CYAN}by TheOffSecGirl${NC}"
  echo -e "${BLUE}Subdomain Takeover Scanner Pro v${VERSION}${NC}"
  echo -e "==================================================\n"
}

# Funciones útiles
log() {
  echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

check_tools() {
  local tools=("subfinder" "assetfinder" "subjack" "httpx" "dnsx" "nuclei")
  local missing=0
  
  log "${BLUE}[CHECK]${NC} Verificando herramientas requeridas..."
  
  for tool in "${tools[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
      log "${RED}[ERROR]${NC} $tool no está instalado"
      missing=$((missing+1))
    fi
  done
  
  if [ $missing -gt 0 ]; then
    log "${YELLOW}[SOLUTION]${NC} Instala las herramientas faltantes con:"
    echo "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    echo "go install github.com/tomnomnom/assetfinder@latest"
    echo "go install github.com/haccer/subjack@latest"
    echo "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    echo "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    echo "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    return 1
  fi
  return 0
}

install_subjack_fingerprints() {
  local fingerprint_dir="$HOME/go/src/github.com/haccer/subjack"
  local fingerprint_file="$fingerprint_dir/fingerprints.json"
  
  if [ ! -f "$fingerprint_file" ]; then
    log "${YELLOW}[INFO]${NC} Descargando fingerprints para Subjack..."
    mkdir -p "$fingerprint_dir"
    curl -sSfL -A "$USER_AGENT" https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -o "$fingerprint_file"
    
    if [ $? -ne 0 ]; then
      log "${RED}[ERROR]${NC} Fallo al descargar fingerprints.json"
      return 1
    fi
  fi
}

load_domains() {
  if [ -n "$SINGLE_DOMAIN" ]; then
    ELIGIBLE_DOMAINS=("$SINGLE_DOMAIN")
    log "${BLUE}[INPUT]${NC} Usando dominio único: $SINGLE_DOMAIN"
  elif [ -n "$DOMAINS_FILE" ] && [ -f "$DOMAINS_FILE" ]; then
    mapfile -t ELIGIBLE_DOMAINS < "$DOMAINS_FILE"
    log "${BLUE}[INPUT]${NC} Cargados ${#ELIGIBLE_DOMAINS[@]} dominios desde $DOMAINS_FILE"
  elif [ -n "$INPUT_LIST" ]; then
    ELIGIBLE_DOMAINS=($(echo "$INPUT_LIST" | tr ',' '\n'))
    log "${BLUE}[INPUT]${NC} Cargados ${#ELIGIBLE_DOMAINS[@]} dominios desde lista"
  else
    log "${RED}[ERROR]${NC} No se especificaron dominios para escanear"
    show_help
    exit 1
  fi
}

enumerate_subdomains() {
  local domain=$1
  local domain_safe=${domain//./_}
  local subfinder_output="${domain_safe}_subfinder.txt"
  local assetfinder_output="${domain_safe}_assetfinder.txt"
  local combined_output="${domain_safe}_all.txt"
  
  log "${BLUE}[ENUM]${NC} Procesando $domain con Subfinder..."
  subfinder -d "$domain" -o "$subfinder_output" -silent -rl "$RATE_LIMIT" -t "$THREADS" -timeout "$TIMEOUT"
  
  log "${BLUE}[ENUM]${NC} Procesando $domain con Assetfinder..."
  assetfinder -subs-only "$domain" 2>/dev/null | sort -u > "$assetfinder_output"
  
  # Combinar y filtrar resultados
  cat "$subfinder_output" "$assetfinder_output" | sort -u > "$combined_output"
  local count=$(wc -l < "$combined_output")
  
  log "${GREEN}[SUCCESS]${NC} Encontrados $count subdominios para $domain"
}

scan_takeovers() {
  log "${BLUE}[SCAN]${NC} Iniciando detección de subdomain takeovers..."
  
  # Verificar si hay subdominios para analizar
  if [ ! -s "all_subdomains_combined.txt" ]; then
    log "${YELLOW}[WARN]${NC} No hay subdominios para analizar"
    return
  fi
  
  # Primera pasada con Subjack
  log "${CYAN}[TOOL]${NC} Ejecutando Subjack..."
  subjack -w "all_subdomains_combined.txt" \
    -t "$THREADS" \
    -timeout "$TIMEOUT" \
    -o "potential_takeovers_subjack.txt" \
    -ssl \
    -c ~/go/src/github.com/haccer/subjack/fingerprints.json \
    -v 2>&1 | tee -a "$LOG_FILE"
  
  # Segunda pasada con Nuclei para mayor cobertura
  log "${CYAN}[TOOL]${NC} Ejecutando Nuclei..."
  nuclei -l "all_subdomains_combined.txt" \
    -tags takeover \
    -severity low,medium,high,critical \
    -rate-limit "$RATE_LIMIT" \
    -o "potential_takeovers_nuclei.txt" \
    -silent 2>&1 | tee -a "$LOG_FILE"
  
  # Tercera pasada con DNSx para verificación de CNAMEs
  log "${CYAN}[TOOL]${NC} Ejecutando DNSx..."
  dnsx -l "all_subdomains_combined.txt" \
    -cname \
    -resp \
    -o "dns_analysis.txt" \
    -silent 2>&1 | tee -a "$LOG_FILE"
  
  # Combinar resultados
  cat "potential_takeovers_"*.txt 2>/dev/null | sort -u > "potential_takeovers_combined.txt"
}

verify_takeovers() {
  log "${BLUE}[VERIFY]${NC} Verificando posibles takeovers..."
  
  if [ ! -s "potential_takeovers_combined.txt" ]; then
    log "${GREEN}[INFO]${NC} No se encontraron posibles takeovers"
    return
  fi
  
  # Análisis avanzado de CNAMEs
  log "${BLUE}[VERIFY]${NC} Analizando registros DNS..."
  while read -r subdomain; do
    cname=$(dig +short CNAME "$subdomain" | head -1)
    ip=$(dig +short A "$subdomain" | head -1)
    if [ -n "$cname" ]; then
      echo "[CNAME] $subdomain -> $cname" >> "takeover_analysis.txt"
      
      # Detección de servicios conocidos
      if [[ "$cname" == *"amazonaws.com"* ]]; then
        echo "[AWS] Posible S3 bucket: $subdomain -> $cname" >> "service_detection.txt"
      elif [[ "$cname" == *"github.io"* ]]; then
        echo "[GitHub] Posible GitHub Pages: $subdomain -> $cname" >> "service_detection.txt"
      elif [[ "$cname" == *"azure"* ]]; then
        echo "[Azure] Posible Azure resource: $subdomain -> $cname" >> "service_detection.txt"
      fi
    elif [ -n "$ip" ]; then
      echo "[A] $subdomain -> $ip" >> "takeover_analysis.txt"
    else
      echo "[NXDOMAIN] $subdomain no resuelve" >> "takeover_analysis.txt"
    fi
  done < "potential_takeovers_combined.txt"
  
  # Verificación HTTP avanzada
  log "${BLUE}[VERIFY]${NC} Analizando respuestas HTTP..."
  httpx -l "potential_takeovers_combined.txt" \
    -status-code \
    -content-length \
    -title \
    -tech-detect \
    -favicon \
    -json \
    -o "takeover_http_analysis.json" \
    -silent 2>&1 | tee -a "$LOG_FILE"
  
  # Convertir JSON a formato legible
  jq -r '.[] | "\(.url) [\(.status-code)] [\(.tech)] \(.title)"' "takeover_http_analysis.json" > "takeover_http_analysis.txt" 2>/dev/null
  
  log "${GREEN}[SUCCESS]${NC} Análisis completado."
}

generate_report() {
  log "${BLUE}[REPORT]${NC} Generando informe final..."
  
  local report_file="subdomain_takeover_report_$(date +%Y%m%d).md"
  local total_subs=$(wc -l < "all_subdomains_combined.txt")
  local potential_takeovers=$(wc -l < "potential_takeovers_combined.txt" 2>/dev/null || echo 0)
  
  echo "# Subdomain Takeover Scan Report" > "$report_file"
  echo "## Versión: $VERSION" >> "$report_file"
  echo "## Fecha: $(date)" >> "$report_file"
  echo "## Realizado por: TheOffSecGirl" >> "$report_file"
  echo "## Dominios analizados: ${#ELIGIBLE_DOMAINS[@]}" >> "$report_file"
  echo "## Total de subdominios encontrados: $total_subs" >> "$report_file"
  echo "## Posibles takeovers identificados: $potential_takeovers" >> "$report_file"
  
  echo -e "\n## Dominios Analizados:\n\`\`\`" >> "$report_file"
  printf "%s\n" "${ELIGIBLE_DOMAINS[@]}" >> "$report_file"
  echo -e "\`\`\`" >> "$report_file"
  
  if [ "$potential_takeovers" -gt 0 ]; then
    echo -e "\n## 🔥 Posibles Takeovers Identificados" >> "$report_file"
    echo -e "\n### Detalles:\n\`\`\`" >> "$report_file"
    cat "potential_takeovers_combined.txt" >> "$report_file"
    echo -e "\`\`\`" >> "$report_file"
    
    echo -e "\n### Análisis de DNS:\n\`\`\`" >> "$report_file"
    cat "takeover_analysis.txt" 2>/dev/null >> "$report_file"
    echo -e "\`\`\`" >> "$report_file"
    
    echo -e "\n### Detección de Servicios:\n\`\`\`" >> "$report_file"
    cat "service_detection.txt" 2>/dev/null >> "$report_file"
    echo -e "\`\`\`" >> "$report_file"
    
    echo -e "\n### Resultados HTTP:\n\`\`\`" >> "$report_file"
    cat "takeover_http_analysis.txt" 2>/dev/null >> "$report_file"
    echo -e "\`\`\`" >> "$report_file"
    
    echo -e "\n## 🛠 Recomendaciones:" >> "$report_file"
    echo "1. Verificar manualmente cada posible takeover" >> "$report_file"
    echo "2. Reclamar dominios vulnerables en los servicios correspondientes" >> "$report_file"
    echo "3. Monitorear regularmente con este script" >> "$report_file"
  else
    echo -e "\n## ✅ No se encontraron posibles takeovers" >> "$report_file"
  fi
  
  echo -e "\n## 📊 Estadísticas" >> "$report_file"
  echo "- Subdominios únicos encontrados: $total_subs" >> "$report_file"
  echo "- Posibles takeovers: $potential_takeovers" >> "$report_file"
  
  echo -e "\n---\nReporte generado automáticamente por Subdomain Takeover Scanner Pro v$VERSION" >> "$report_file"
  
  log "${GREEN}[REPORT]${NC} Informe generado: $report_file"
}

cleanup() {
  log "${BLUE}[CLEANUP]${NC} Limpiando archivos temporales..."
  rm -f *_subfinder.txt *_assetfinder.txt *_all.txt
}

show_help() {
  echo -e "${GREEN}Uso:${NC}"
  echo "  $0 [opciones]"
  echo ""
  echo -e "${GREEN}Opciones:${NC}"
  echo "  -d, --domain <dominio>      Escanear un único dominio"
  echo "  -f, --file <archivo>        Archivo con lista de dominios (uno por línea)"
  echo "  -l, --list <lista>          Lista de dominios separados por comas"
  echo "  -t, --threads <número>      Número de hilos a usar (default: 50)"
  echo "  -r, --rate <número>         Rate limit (default: 2)"
  echo "  -h, --help                  Mostrar este mensaje de ayuda"
  echo ""
  echo -e "${GREEN}Ejemplos:${NC}"
  echo "  $0 -d example.com"
  echo "  $0 -f dominios.txt"
  echo "  $0 -l \"domain1.com,domain2.com\""
  echo ""
  echo -e "${CYAN}by TheOffSecGirl${NC}"
}

parse_arguments() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      -d|--domain)
        SINGLE_DOMAIN="$2"
        shift 2
        ;;
      -f|--file)
        DOMAINS_FILE="$2"
        shift 2
        ;;
      -l|--list)
        INPUT_LIST="$2"
        shift 2
        ;;
      -t|--threads)
        THREADS="$2"
        shift 2
        ;;
      -r|--rate)
        RATE_LIMIT="$2"
        shift 2
        ;;
      -h|--help)
        show_help
        exit 0
        ;;
      *)
        echo -e "${RED}[ERROR]${NC} Opción desconocida: $1"
        show_help
        exit 1
        ;;
    esac
  done
}

## Ejecución principal
main() {
  show_banner
  parse_arguments "$@"
  
  # Verificar herramientas
  if ! check_tools; then
    exit 1
  fi
  
  # Instalar fingerprints de Subjack si es necesario
  install_subjack_fingerprints || exit 1
  
  # Cargar dominios a analizar
  load_domains
  
  # Enumerar subdominios para cada dominio
  for domain in "${ELIGIBLE_DOMAINS[@]}"; do
    enumerate_subdomains "$domain"
  done
  
  # Combinar todos los subdominios
  cat *_all.txt | sort -u > "all_subdomains_combined.txt"
  local total_subs=$(wc -l < "all_subdomains_combined.txt")
  log "${GREEN}[TOTAL]${NC} Subdominios únicos encontrados: $total_subs"
  
  # Escanear takeovers
  scan_takeovers
  
  # Verificación adicional
  verify_takeovers
  
  # Generar reporte
  generate_report
  
  # Limpieza
  cleanup
  
  echo -e "\n${GREEN}=== [🎀] Escaneo completado con éxito [🎀] ===${NC}"
  echo -e "Revise los archivos de resultados y el informe generado.\n"
}

main "$@"
