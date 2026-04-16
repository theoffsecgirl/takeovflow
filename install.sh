#!/usr/bin/env bash
# takeovflow - install.sh
# Instala todas las herramientas externas necesarias
# Soporta: macOS (Homebrew), Debian/Ubuntu (apt + go install)

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[x]${NC} $*"; exit 1; }

check() { command -v "$1" &>/dev/null; }

detect_os() {
    if [[ "$(uname)" == "Darwin" ]]; then
        echo "macos"
    elif check apt-get; then
        echo "debian"
    elif check yum; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

install_go() {
    if check go; then
        log "Go ya instalado: $(go version)"
        return
    fi
    warn "Go no encontrado. Instalando..."
    local OS
    OS=$(detect_os)
    if [[ "$OS" == "macos" ]]; then
        brew install go
    elif [[ "$OS" == "debian" ]]; then
        sudo apt-get install -y golang-go
    else
        die "Instala Go manualmente desde https://go.dev/dl/ y vuelve a ejecutar este script."
    fi
}

install_tool_go() {
    local name="$1"
    local pkg="$2"
    if check "$name"; then
        log "$name ya instalado"
        return
    fi
    log "Instalando $name..."
    go install "$pkg" 2>/dev/null || warn "Fallo instalando $name via go install. Intenta manualmente."
}

install_tool_brew() {
    local name="$1"
    local formula="${2:-$1}"
    if check "$name"; then
        log "$name ya instalado"
        return
    fi
    log "Instalando $name via brew..."
    brew install "$formula" || warn "Fallo instalando $name."
}

install_tool_apt() {
    local name="$1"
    local pkg="${2:-$1}"
    if check "$name"; then
        log "$name ya instalado"
        return
    fi
    log "Instalando $name via apt..."
    sudo apt-get install -y "$pkg" || warn "Fallo instalando $name."
}

main() {
    echo "+--------------------------------------------------+"
    echo "|  takeovflow - Instalador de dependencias         |"
    echo "+--------------------------------------------------+"
    echo

    local OS
    OS=$(detect_os)
    log "Sistema detectado: $OS"

    # Go (necesario para herramientas ProjectDiscovery)
    install_go

    # Asegurar que GOPATH/bin está en PATH
    export PATH="$PATH:$(go env GOPATH)/bin"

    if [[ "$OS" == "macos" ]]; then
        # Homebrew tools
        check brew || die "Homebrew no encontrado. Instala desde https://brew.sh"
        install_tool_brew "subfinder"    "subfinder"
        install_tool_brew "assetfinder"  "assetfinder"
        install_tool_brew "dnsx"         "dnsx"
        install_tool_brew "httpx"        "httpx"
        install_tool_brew "nuclei"       "nuclei"
        install_tool_brew "amass"        "amass"
        # dig ya viene con macOS (bind-tools)
        check dig || install_tool_brew "dig" "bind"

    elif [[ "$OS" == "debian" ]]; then
        sudo apt-get update -qq
        install_tool_apt "dig"  "dnsutils"
        install_tool_apt "curl" "curl"
        install_tool_apt "jq"   "jq"
        install_tool_apt "git"  "git"
        # Go tools via go install
        install_tool_go "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        install_tool_go "assetfinder" "github.com/tomnomnom/assetfinder@latest"
        install_tool_go "dnsx"        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        install_tool_go "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        install_tool_go "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        install_tool_go "amass"       "github.com/owasp-amass/amass/v4/...@master"
    else
        warn "OS no soportado automaticamente."
        warn "Instala manualmente: subfinder, assetfinder, dnsx, httpx, nuclei, amass, dig, curl, jq"
    fi

    # subjack (Go)
    install_tool_go "subjack" "github.com/haccer/subjack@latest"

    echo
    echo "+--------------------------------------------------+"
    log "Instalacion completada. Verificando..."
    echo
    for tool in subfinder assetfinder dnsx httpx nuclei amass subjack dig curl jq; do
        if check "$tool"; then
            echo -e "  ${GREEN}OK${NC}  $tool"
        else
            echo -e "  ${RED}NO${NC}  $tool"
        fi
    done
    echo
    warn "Ejecuta: export PATH=\$PATH:\$(go env GOPATH)/bin"
    warn "O añadelo a tu ~/.zshrc / ~/.bashrc para persistencia."
    echo "+--------------------------------------------------+"
}

main "$@"
