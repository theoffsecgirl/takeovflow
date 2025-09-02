package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	userAgent  = "SubdomainScannerPro (by TheOffSecGirl)"
	logFormat  = "[%s] [%s] %s\n"
	colorReset = "\033[0m"
	colorPurple= "\033[0;35m"
	colorCyan  = "\033[0;36m"
	colorBlue  = "\033[0;34m"
	colorGreen = "\033[0;32m"
	colorRed   = "\033[0;31m"
)

var (
	verbose      bool
	threads      = 50
	timeout      = 45
	rateLimit    = 2
	domainsFile  string
	singleDomain string
	inputList    string
	tmpDir       string
	logFile      *os.File
	logMu        sync.Mutex
	elasticWG    sync.WaitGroup
	eligibleDomains []string
	domainRx     = regexp.MustCompile(`^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$`)
)

func main() {
	showBanner()
	parseArgs()
	validateParams()
	initTmpDir()
	defer cleanup()

	openLog()
	defer logFile.Close()

	if err := checkTools([]string{"subfinder", "assetfinder", "subjack", "httpx", "dnsx", "nuclei", "dig", "jq", "curl"}); err != nil {
		log("ERROR", err.Error())
		os.Exit(1)
	}
	if err := installSubjackFingerprints(); err != nil {
		log("ERROR", err.Error())
		os.Exit(1)
	}

	loadDomains()

	log("INFO", fmt.Sprintf("Dominios cargados: %d", len(eligibleDomains)))

	// Enumerate subdomains concurrently
	type result struct {
		domain string
		err    error
	}
	resultsChan := make(chan result, len(eligibleDomains))
	sem := make(chan struct{}, threads)

	for _, d := range eligibleDomains {
		sem <- struct{}{}
		go func(domain string) {
			defer func() { <-sem }()
			err := enumerateSubdomains(domain)
			resultsChan <- result{domain, err}
		}(d)
	}

	for i := 0; i < len(eligibleDomains); i++ {
		r := <-resultsChan
		if r.err != nil {
			log("WARN", fmt.Sprintf("Error en enumerar %s: %v", r.domain, r.err))
		}
	}

	allSubdomainsFile := filepath.Join(tmpDir, "all_subdomains_combined.txt")
	if err := combineAllSubdomains(allSubdomainsFile); err != nil {
		log("ERROR", err.Error())
		os.Exit(1)
	}
	count, err := lineCount(allSubdomainsFile)
	if err != nil {
		log("ERROR", err.Error())
		os.Exit(1)
	}
	log("INFO", fmt.Sprintf("Subdominios únicos encontrados: %d", count))

	scanTakeovers(allSubdomainsFile)
	verifyTakeovers()
	generateReport(allSubdomainsFile)

	log("INFO", "Escaneo completado.")
	fmt.Printf("\n%s=== Escaneo completado con éxito ===%s\n", colorGreen, colorReset)
	fmt.Println("Revise archivos de resultado e informe.\n")
}

func showBanner() {
	clearScreen()
	fmt.Print(colorPurple)
	fmt.Println("▗▄▄▄▖▗▞▀▜▌█  ▄ ▗▞▀▚▖ ▗▄▖ ▄   ▄ ▗▄▄▄▖█  ▄▄▄  ▄   ▄")
	fmt.Println("  █  ▝▚▄▟▌█▄▀  ▐▛▀▀▘▐▌ ▐▌█   █ ▐▌   █ █   █ █ ▄ █")
	fmt.Println("  █       █ ▀▄ ▝▚▄▄▖▐▌ ▐▌ ▀▄▀  ▐▛▀▀▘█ ▀▄▄▄▀ █▄█▄█")
	fmt.Println("  █       █  █      ▝▚▄▞▘      ▐▌   █")
	fmt.Printf("                           %sby TheOffSecGirl%s\n", colorCyan, colorReset)
	fmt.Printf("%sSubdomain Takeover Scanner Pro%s\n", colorBlue, colorReset)
	fmt.Println("==================================================\n")
	fmt.Print(colorReset)
}

func clearScreen() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		fmt.Print("\033[H\033[2J")
	}
}

func parseArgs() {
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-d", "--domain":
			i++
			if i < len(args) {
				singleDomain = args[i]
			} else {
				showHelpAndExit("Falta valor para -d/--domain")
			}
		case "-f", "--file":
			i++
			if i < len(args) {
				domainsFile = args[i]
			} else {
				showHelpAndExit("Falta valor para -f/--file")
			}
		case "-l", "--list":
			i++
			if i < len(args) {
				inputList = args[i]
			} else {
				showHelpAndExit("Falta valor para -l/--list")
			}
		case "-t", "--threads":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &threads)
			} else {
				showHelpAndExit("Falta valor para -t/--threads")
			}
		case "-r", "--rate":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &rateLimit)
			} else {
				showHelpAndExit("Falta valor para -r/--rate")
			}
		case "-v", "--verbose":
			verbose = true
		case "-h", "--help":
			showHelpAndExit("")
		default:
			showHelpAndExit(fmt.Sprintf("Opción desconocida: %s", arg))
		}
	}
}

func validateParams() {
	if threads < 1 {
		log("ERROR", "Threads debe ser un número entero positivo")
		os.Exit(1)
	}
	if rateLimit < 1 {
		log("ERROR", "Rate limit debe ser un número entero positivo")
		os.Exit(1)
	}
}

func showHelpAndExit(msg string) {
	if msg != "" {
		fmt.Fprintf(os.Stderr, "%s%s%s\n\n", colorGreen, msg, colorReset)
	}
	fmt.Printf(`%sUso:%s main.go [opciones]
%sOpciones:%s
 -d, --domain    Escanear un único dominio
 -f, --file      Archivo con lista de dominios (uno por línea)
 -l, --list      Lista de dominios separados por comas
 -t, --threads   Número de hilos a usar (default: 50)
 -r, --rate      Rate limit (default: 2)
 -v, --verbose   Modo verbose (detallado)
 -h, --help      Mostrar esta ayuda

Ejemplo: main.go -d example.com -t 100 -r 5 -v
`, colorGreen, colorReset, colorGreen, colorReset)
	os.Exit(1)
}

func initTmpDir() {
	var err error
	tmpDir, err = os.MkdirTemp("", "takeovflow_tmp")
	if err != nil {
		fmt.Fprintf(os.Stderr, "No se pudo crear directorio temporal: %v\n", err)
		os.Exit(1)
	}
}

func openLog() {
	f, err := os.OpenFile(fmt.Sprintf("subdomain_scan_%s.log", time.Now().Format("20060102_150405")), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "No se pudo abrir log file: %v\n", err)
		os.Exit(1)
	}
	logFile = f
}

func log(level, msg string) {
	logMu.Lock()
	defer logMu.Unlock()
	if verbose || level == "ERROR" || level == "WARN" || level == "INFO" {
		text := fmt.Sprintf(logFormat, time.Now().Format("2006-01-02 15:04:05"), level, msg)
		fmt.Print(text)
		logFile.WriteString(text)
	}
}

func cleanup() {
	os.RemoveAll(tmpDir)
	log("INFO", "Limpiando archivos temporales...")
	log("INFO", "Limpieza completada.")
}

func checkTools(tools []string) error {
	log("INFO", "Verificando herramientas requeridas...")
	missing := []string{}
	for _, t := range tools {
		if _, err := exec.LookPath(t); err != nil {
			log("ERROR", fmt.Sprintf("%s no está instalado", t))
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		log("WARN", "Instala las herramientas faltantes. Ejemplo para subfinder:")
		log("WARN", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
		return fmt.Errorf("herramientas faltantes: %v", missing)
	}
	return nil
}

func installSubjackFingerprints() error {
	fpDir := filepath.Join(os.Getenv("HOME"), "go", "src", "github.com", "haccer", "subjack")
	fpFile := filepath.Join(fpDir, "fingerprints.json")
	if _, err := os.Stat(fpFile); os.IsNotExist(err) {
		log("INFO", "Descargando fingerprints para Subjack...")
		os.MkdirAll(fpDir, 0755)
		cmd := exec.Command("curl", "-sSfL", "-A", userAgent, "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json", "-o", fpFile)
		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("fallo al descargar fingerprints.json: %v", err)
		}
	}
	return nil
}

func cleanDomain(domain string) string {
	d := strings.TrimSpace(domain)
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimSuffix(d, "/")
	return d
}

func validateDomain(domain string) bool {
	return domainRx.MatchString(domain)
}

func loadDomains() {
	if singleDomain != "" {
		d := cleanDomain(singleDomain)
		if !validateDomain(d) {
			log("ERROR", fmt.Sprintf("Dominio inválido: %s", singleDomain))
			os.Exit(1)
		}
		eligibleDomains = []string{d}
		log("INFO", fmt.Sprintf("Usando dominio limpio: %s", d))
		return
	}
	if domainsFile != "" {
		data, err := os.ReadFile(domainsFile)
		if err != nil {
			log("ERROR", "No se pudo leer archivo de dominios: "+err.Error())
			os.Exit(1)
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			d := cleanDomain(line)
			if validateDomain(d) {
				eligibleDomains = append(eligibleDomains, d)
			}
		}
	}
	if inputList != "" {
		items := strings.Split(inputList, ",")
		for _, i := range items {
			d := cleanDomain(i)
			if validateDomain(d) {
				eligibleDomains = append(eligibleDomains, d)
			}
		}
	}

	if len(eligibleDomains) == 0 {
		log("ERROR", "No se especificaron dominios válidos para escanear")
		showHelpAndExit("")
	}
	// sin duplicados
	sort.Strings(eligibleDomains)
	uniq := []string{}
	for i, d := range eligibleDomains {
		if i == 0 || d != eligibleDomains[i-1] {
			uniq = append(uniq, d)
		}
	}
	eligibleDomains = uniq
}

func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	// set User-Agent if relevant (for curl or others)
	if name == "curl" {
		cmd.Args = append(cmd.Args, "-A", userAgent)
	}

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("%v, stderr: %s", err, errb.String())
	}
	return outb.String(), nil
}

func enumerateSubdomains(domain string) error {
	base := strings.ReplaceAll(domain, ".", "_")
	sf := filepath.Join(tmpDir, base+"_subfinder.txt")
	af := filepath.Join(tmpDir, base+"_assetfinder.txt")
	allf := filepath.Join(tmpDir, base+"_all.txt")

	log("INFO", fmt.Sprintf("Procesando %s con Subfinder...", domain))
	if err := runSubfinder(domain, sf); err != nil {
		log("WARN", fmt.Sprintf("subfinder falló para %s: %v", domain, err))
	}

	log("INFO", fmt.Sprintf("Procesando %s con Assetfinder...", domain))
	if err := runAssetfinder(domain, af); err != nil {
		log("WARN", fmt.Sprintf("assetfinder falló para %s: %v", domain, err))
	}

	// Combina y ordena
	all, err := combineFiles(sf, af, allf)
	if err != nil {
		return err
	}
	log("INFO", fmt.Sprintf("Encontrados %d subdominios para %s", all, domain))
	return nil
}

func runSubfinder(domain, outFile string) error {
	cmd := exec.Command("subfinder", "-d", domain, "-o", outFile, "-silent", "-rl", fmt.Sprint(rateLimit), "-t", fmt.Sprint(threads), "-timeout", fmt.Sprint(timeout))
	return cmd.Run()
}

func runAssetfinder(domain, outFile string) error {
	out, err := runCommand("assetfinder", "-subs-only", domain)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	sort.Strings(lines)
	lines = uniqStrings(lines)
	return os.WriteFile(outFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func combineFiles(f1, f2, out string) (int, error) {
	set := make(map[string]struct{})
	for _, f := range []string{f1, f2} {
		if _, err := os.Stat(f); err == nil {
			data, err := os.ReadFile(f)
			if err != nil {
				return 0, err
			}
			lines := strings.Split(string(data), "\n")
			for _, ln := range lines {
				ln = strings.TrimSpace(ln)
				if ln != "" {
					set[ln] = struct{}{}
				}
			}
		}
	}
	result := make([]string, 0, len(set))
	for k := range set {
		result = append(result, k)
	}
	sort.Strings(result)
	err := os.WriteFile(out, []byte(strings.Join(result, "\n")+"\n"), 0644)
	return len(result), err
}

func uniqStrings(in []string) []string {
	if len(in) < 2 {
		return in
	}
	out := []string{in[0]}
	for i := 1; i < len(in); i++ {
		if in[i] != in[i-1] {
			out = append(out, in[i])
		}
	}
	return out
}

func combineAllSubdomains(outFile string) error {
	files, err := filepath.Glob(filepath.Join(tmpDir, "*_all.txt"))
	if err != nil {
		return err
	}
	var allSubs []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		allSubs = append(allSubs, strings.Split(string(data), "\n")...)
	}
	// Uniq & clean
	uniqSubs := uniqStrings(sortedFiltered(allSubs))
	return os.WriteFile(outFile, []byte(strings.Join(uniqSubs, "\n")), 0644)
}

func sortedFiltered(in []string) []string {
	set := make(map[string]struct{})
	var clean []string
	for _, s := range in {
		t := strings.TrimSpace(s)
		if t != "" {
			if _, ok := set[t]; !ok {
				set[t] = struct{}{}
				clean = append(clean, t)
			}
		}
	}
	sort.Strings(clean)
	return clean
}

func scanTakeovers(subdomainsFile string) {
	log("INFO", "Iniciando detección de subdomain takeovers...")

	if stat, err := os.Stat(subdomainsFile); err != nil || stat.Size() == 0 {
		log("WARN", "No hay subdominios para analizar")
		return
	}

	runOrWarn("subjack", []string{
		"-w", subdomainsFile,
		"-t", fmt.Sprint(threads),
		"-timeout", fmt.Sprint(timeout),
		"-o", filepath.Join(tmpDir, "potential_takeovers_subjack.txt"),
		"-ssl",
		"-c", filepath.Join(os.Getenv("HOME"), "go", "src", "github.com", "haccer", "subjack", "fingerprints.json"),
		"-v",
	}, "subjack")

	runOrWarn("nuclei", []string{
		"-l", subdomainsFile,
		"-tags", "takeover",
		"-severity", "low,medium,high,critical",
		"-rate-limit", fmt.Sprint(rateLimit),
		"-o", filepath.Join(tmpDir, "potential_takeovers_nuclei.txt"),
		"-silent",
	}, "nuclei")

	runOrWarn("dnsx", []string{
		"-l", subdomainsFile,
		"-cname",
		"-resp",
		"-o", filepath.Join(tmpDir, "dns_analysis.txt"),
		"-silent",
	}, "dnsx")

	// Combinar resultados
	resultsFiles, _ := filepath.Glob(filepath.Join(tmpDir, "potential_takeovers_*.txt"))
	var combined []string
	for _, f := range resultsFiles {
		data, err := os.ReadFile(f)
		if err == nil {
			combined = append(combined, strings.Split(string(data), "\n")...)
		}
	}
	uniqCombined := uniqStrings(sortedFiltered(combined))
	os.WriteFile(filepath.Join(tmpDir, "potential_takeovers_combined.txt"), []byte(strings.Join(uniqCombined, "\n")), 0644)
}

func runOrWarn(cmdName string, args []string, label string) {
	cmd := exec.Command(cmdName, args...)
	outpipe, _ := cmd.StdoutPipe()
	errpipe, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		log("WARN", fmt.Sprintf("%s falló al iniciar: %v", label, err))
		return
	}

	go io.Copy(io.Discard, outpipe)
	go io.Copy(io.Discard, errpipe)

	err := cmd.Wait()
	if err != nil {
		log("WARN", fmt.Sprintf("%s falló: %v", label, err))
	}
}

func verifyTakeovers() {
	log("INFO", "Verificando posibles takeovers...")
	combinedFile := filepath.Join(tmpDir, "potential_takeovers_combined.txt")

	stat, err := os.Stat(combinedFile)
	if err != nil || stat.Size() == 0 {
		log("INFO", "No se encontraron posibles takeovers")
		return
	}

	takeoverAnalysis := filepath.Join(tmpDir, "takeover_analysis.txt")
	serviceDetection := filepath.Join(tmpDir, "service_detection.txt")

	takeoverFile, _ := os.Create(takeoverAnalysis)
	defer takeoverFile.Close()
	serviceFile, _ := os.Create(serviceDetection)
	defer serviceFile.Close()

	file, err := os.Open(combinedFile)
	if err != nil {
		log("ERROR", "Error al abrir archivo combinado: "+err.Error())
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		sub := scanner.Text()
		cname, _ := runCommand("dig", "+short", "CNAME", sub)
		cname = strings.TrimSpace(strings.Split(cname, "\n")[0])
		ip, _ := runCommand("dig", "+short", "A", sub)
		ip = strings.TrimSpace(strings.Split(ip, "\n")[0])

		if cname != "" {
			fmt.Fprintf(takeoverFile, "[CNAME] %s -> %s\n", sub, cname)
			switch {
			case strings.Contains(cname, "amazonaws.com"):
				fmt.Fprintf(serviceFile, "[AWS] Posible S3 bucket: %s -> %s\n", sub, cname)
			case strings.Contains(cname, "github.io"):
				fmt.Fprintf(serviceFile, "[GitHub] Posible GitHub Pages: %s -> %s\n", sub, cname)
			case strings.Contains(cname, "azure"):
				fmt.Fprintf(serviceFile, "[Azure] Posible Azure resource: %s -> %s\n", sub, cname)
			}
		} else if ip != "" {
			fmt.Fprintf(takeoverFile, "[A] %s -> %s\n", sub, ip)
		} else {
			fmt.Fprintf(takeoverFile, "[NXDOMAIN] %s no resuelve\n", sub)
		}
	}

	// httpx analysis
	log("INFO", "Analizando respuestas HTTP...")
	httpxOut := filepath.Join(tmpDir, "takeover_http_analysis.json")
	err = exec.Command("httpx",
		"-l", combinedFile,
		"-status-code", "-content-length", "-title", "-tech-detect", "-favicon",
		"-json", "-o", httpxOut,
		"-silent").Run()

	if err != nil {
		log("WARN", "httpx falló: "+err.Error())
		return
	}

	jqOut := filepath.Join(tmpDir, "takeover_http_analysis.txt")
	jqCmd := exec.Command("jq", "-r", `.[] | "\(.url) [\(.status-code)] [\(.tech)] \(.title)"`, httpxOut)
	jqFile, _ := os.Create(jqOut)
	defer jqFile.Close()
	jqCmd.Stdout = jqFile
	jqCmd.Run()
}

func generateReport(allSubsFile string) {
	log("INFO", "Generando informe final...")

	report := fmt.Sprintf("subdomain_takeover_report_%s.md", time.Now().Format("20060102"))
	subsCount, err := lineCount(allSubsFile)
	if err != nil {
		log("WARN", "No se pudo contar subdominios: "+err.Error())
		subsCount = 0
	}
	takeoverFile := filepath.Join(tmpDir, "potential_takeovers_combined.txt")
	takeoversCount := 0
	if stat, err := os.Stat(takeoverFile); err == nil {
		takeoversCount, _ = lineCount(takeoverFile)
	}

	reportFile, err := os.Create(report)
	if err != nil {
		log("ERROR", "Error al crear informe: "+err.Error())
		return
	}
	defer reportFile.Close()

	reportFile.WriteString("# Subdomain Takeover Scan Report\n")
	reportFile.WriteString(fmt.Sprintf("## Fecha: %s\n", time.Now().Format(time.RFC1123)))
	reportFile.WriteString("## Realizado por: TheOffSecGirl\n")
	reportFile.WriteString(fmt.Sprintf("## Dominios analizados: %d\n", len(eligibleDomains)))
	reportFile.WriteString(fmt.Sprintf("## Total de subdominios encontrados: %d\n", subsCount))
	reportFile.WriteString(fmt.Sprintf("## Posibles takeovers identificados: %d\n\n", takeoversCount))

	reportFile.WriteString("## Dominios Analizados:\n```
	for _, d := range eligibleDomains {
		reportFile.WriteString(d + "\n")
	}
	reportFile.WriteString("```\n")

	if takeoversCount > 0 {
		reportFile.WriteString("## Posibles Takeovers Identificados\n\n")
		reportFile.WriteString("### Detalles:\n```
		reportFile.WriteString(readFileContent(filepath.Join(tmpDir, "potential_takeovers_combined.txt")))
		reportFile.WriteString("```\n")

		reportFile.WriteString("### Análisis de DNS:\n```
		reportFile.WriteString(readFileContent(filepath.Join(tmpDir, "takeover_analysis.txt")))
		reportFile.WriteString("```\n")

		reportFile.WriteString("### Detección de Servicios:\n```
		reportFile.WriteString(readFileContent(filepath.Join(tmpDir, "service_detection.txt")))
		reportFile.WriteString("```\n")

		reportFile.WriteString("### Resultados HTTP:\n```
		reportFile.WriteString(readFileContent(filepath.Join(tmpDir, "takeover_http_analysis.txt")))
		reportFile.WriteString("```\n")

		reportFile.WriteString("## Recomendaciones:\n")
		reportFile.WriteString("1. Verificar manualmente cada posible takeover\n")
		reportFile.WriteString("2. Reclamar dominios vulnerables en los servicios correspondientes\n")
		reportFile.WriteString("3. Monitorear regularmente con este script\n\n")
	} else {
		reportFile.WriteString("## No se encontraron posibles takeovers\n\n")
	}

	reportFile.WriteString("## Estadísticas\n")
	reportFile.WriteString(fmt.Sprintf("- Subdominios únicos encontrados: %d\n", subsCount))
	reportFile.WriteString(fmt.Sprintf("- Posibles takeovers: %d\n", takeoversCount))
	reportFile.WriteString("\n---\nReporte generado automáticamente por Subdomain Takeover Scanner Pro\n")
}

func readFileContent(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "(error leyendo archivo)"
	}
	return string(data)
}

func lineCount(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count, scanner.Err()
}
