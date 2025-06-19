package scanner

import (
    "fmt"
    "os/exec"
    "strings"
)

func EnumerateSubdomains(domain string) {
    fmt.Printf("[ENUM] Procesando %s con Subfinder...\n", domain)
    runCmd("subfinder", "-d", domain, "-o", fmt.Sprintf("%s_subfinder.txt", domain))
    fmt.Printf("[ENUM] Procesando %s con Assetfinder...\n", domain)
    cmd := exec.Command("assetfinder", "-subs-only", domain)
    out, _ := cmd.Output()
    ioutil.WriteFile(fmt.Sprintf("%s_assetfinder.txt", domain), out, 0644)
}

func CombineSubdomains(pattern, outFile string) {
    cmd := exec.Command("cat", append(strings.Fields(pattern), "| sort -u > "+outFile)...)
    cmd.Run()
}

func ScanTakeovers(file string) {
    fmt.Println("[SCAN] Iniciando detección de takeovers...")
    runCmd("subjack", "-w", file, "-t", "50", "-timeout", "45", "-o", "potential_takeovers_subjack.txt", "-ssl", "-c", "~/.fingerprints.json", "-v")
    runCmd("nuclei", "-l", file, "-tags", "takeover", "-severity", "low,medium,high,critical", "-rate-limit", "2", "-o", "potential_takeovers_nuclei.txt", "-silent")
    runCmd("dnsx", "-l", file, "-cname", "-resp", "-o", "dns_analysis.txt", "-silent")
    runCmd("cat", "potential_takeovers_*.txt", "| sort -u > potential_takeovers_combined.txt")
}

func VerifyTakeovers(file string) {
    fmt.Println("[VERIFY] Analizando DNS y HTTP...")
    runCmd("dig", "+short", "CNAME", "@", file)
    runCmd("httpx", "-l", file, "-status-code", "-content-length", "-title", "-tech-detect", "-favicon", "-json", "-o", "takeover_http_analysis.json")
}

func GenerateReport(domains []string) {
    // Aquí puedes usar plantillas o simplemente concatenar texto
    fmt.Println("[REPORT] Generando informe final...")
    // Ejemplo básico
    report := "# Subdomain Takeover Report\n"
    report += fmt.Sprintf("## Dominios: %v\n", domains)
    ioutil.WriteFile("report.md", []byte(report), 0644)
}

func runCmd(name string, args ...string) {
    cmd := exec.Command(name, args...)
    out, _ := cmd.CombinedOutput()
    fmt.Println(string(out))
}