#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import subprocess
import threading
import queue
import tempfile
import datetime
import time
import json
import shutil
import signal

USER_AGENT = "SubdomainScannerPro (by TheOffSecGirl)"
LOG_FORMAT = "[{time}] [{level}] {msg}"
LOG_LOCK = threading.Lock()
VERBOSE = False
THREADS = 50
TIMEOUT = 45
RATE_LIMIT = 2

domain_rx = re.compile(r'^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$')

eligible_domains = []
tmp_dir = None
log_file = None


def log(level, msg):
    """Registra mensajes en consola y archivo de log"""
    global log_file
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = LOG_FORMAT.format(time=now, level=level, msg=msg)
    with LOG_LOCK:
        if VERBOSE or level in ["ERROR", "WARN", "INFO"]:
            print(line)
        if log_file:
            log_file.write(line + "\n")
            log_file.flush()


def parse_args():
    """Parsea argumentos de línea de comandos"""
    import argparse
    global VERBOSE, THREADS, RATE_LIMIT, eligible_domains

    parser = argparse.ArgumentParser(
        description="Subdomain Takeover Scanner Pro",
        usage="python3 script.py [opciones]\nEjemplo: python3 script.py -d example.com -t 100 -r 5 -v"
    )
    parser.add_argument("-d", "--domain", help="Escanear un único dominio")
    parser.add_argument("-f", "--file", help="Archivo con lista de dominios (uno por línea)")
    parser.add_argument("-l", "--list", help="Lista de dominios separados por comas")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Número de hilos a usar (default: 50)")
    parser.add_argument("-r", "--rate", type=int, default=2, help="Rate limit (default: 2)")
    parser.add_argument("-v", "--verbose", action='store_true', help="Modo verbose (detallado)")

    args = parser.parse_args()
    VERBOSE = args.verbose
    
    if args.threads < 1:
        log("ERROR", "Threads debe ser un número entero positivo")
        sys.exit(1)
    if args.rate < 1:
        log("ERROR", "Rate limit debe ser un número entero positivo")
        sys.exit(1)
    
    THREADS = args.threads
    RATE_LIMIT = args.rate

    domains_input = []

    if args.domain:
        domain = clean_domain(args.domain)
        if not validate_domain(domain):
            log("ERROR", f"Dominio inválido: {args.domain}")
            sys.exit(1)
        domains_input.append(domain)
    
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                for line in f:
                    domain = clean_domain(line)
                    if validate_domain(domain):
                        domains_input.append(domain)
        except Exception as e:
            log("ERROR", f"No se pudo leer archivo de dominios: {e}")
            sys.exit(1)
    
    if args.list:
        for item in args.list.split(","):
            domain = clean_domain(item)
            if validate_domain(domain):
                domains_input.append(domain)

    if not domains_input:
        log("ERROR", "No se especificaron dominios válidos para escanear")
        parser.print_help()
        sys.exit(1)

    # Eliminar duplicados y ordenar
    eligible_domains = sorted(set(domains_input))


def clean_domain(domain):
    """Limpia y normaliza el dominio"""
    d = domain.strip()
    d = re.sub(r'^https?://', '', d)
    d = d.rstrip('/')
    return d


def validate_domain(domain):
    """Valida el formato del dominio"""
    return bool(domain_rx.match(domain))


def show_banner():
    """Muestra el banner de inicio"""
    os.system('clear' if os.name != 'nt' else 'cls')
    print("\033[0;35m")
    print("▗▄▄▄▖▗▞▀▜▌█  ▄ ▗▞▀▚▖ ▗▄▖ ▄   ▄ ▗▄▄▄▖█  ▄▄▄  ▄   ▄")
    print("  █  ▝▚▄▟▌█▄▀  ▐▛▀▀▘▐▌ ▐▌█   █ ▐▌   █ █   █ █ ▄ █")
    print("  █       █ ▀▄ ▝▚▄▄▖▐▌ ▐▌ ▀▄▀  ▐▛▀▀▘█ ▀▄▄▄▀ █▄█▄█")
    print("  █       █  █      ▝▚▄▞▘      ▐▌   █")
    print(f"                           \033[0;36mby TheOffSecGirl\033[0m")
    print(f"\033[0;34mSubdomain Takeover Scanner Pro\033[0;36m\033[0m")
    print("==================================================\n")
    print("\033[0m")


def open_log():
    """Abre archivo de log"""
    global log_file
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"subdomain_scan_{timestamp}.log"
    log_file = open(log_filename, "a", encoding="utf-8")


def cleanup():
    """Limpia archivos temporales"""
    global tmp_dir
    if tmp_dir and os.path.isdir(tmp_dir):
        log("INFO", "Limpiando archivos temporales...")
        try:
            shutil.rmtree(tmp_dir)
            log("INFO", "Limpieza completada.")
        except Exception as e:
            log("WARN", f"No se pudo limpiar tmpdir: {e}")


def check_tools(tools):
    """Verifica que las herramientas necesarias estén instaladas"""
    log("INFO", "Verificando herramientas requeridas...")
    missing = []
    for tool in tools:
        if not shutil.which(tool):
            log("ERROR", f"{tool} no está instalado")
            missing.append(tool)
    if missing:
        log("WARN", "Instala las herramientas faltantes. Ejemplo para subfinder:")
        log("WARN", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        return False
    return True


def run_command(cmd, capture_output=True, silent=False):
    """Ejecuta comando del sistema"""
    try:
        if capture_output:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
            if result.returncode != 0 and not silent:
                return None
            return result.stdout.strip()
        else:
            subprocess.run(cmd, timeout=TIMEOUT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return None
    except subprocess.TimeoutExpired:
        if not silent:
            log("WARN", f"Timeout ejecutando {cmd[0]}")
        return None
    except Exception as e:
        if not silent:
            log("WARN", f"Error ejecutando {cmd[0]}: {e}")
        return None


def enumerate_subdomains(domain):
    """Enumera subdominios usando subfinder y assetfinder"""
    base = domain.replace(".", "_")
    sf = os.path.join(tmp_dir, base + "_subfinder.txt")
    af = os.path.join(tmp_dir, base + "_assetfinder.txt")
    allf = os.path.join(tmp_dir, base + "_all.txt")

    log("INFO", f"Procesando {domain} con Subfinder...")
    cmd_sf = ["subfinder", "-d", domain, "-o", sf, "-silent", "-rl", str(RATE_LIMIT), 
              "-t", str(THREADS), "-timeout", str(TIMEOUT)]
    run_command(cmd_sf, capture_output=False, silent=True)

    log("INFO", f"Procesando {domain} con Assetfinder...")
    out = run_command(["assetfinder", "-subs-only", domain], silent=True)
    if out:
        lines = sorted(set(line.strip() for line in out.splitlines() if line.strip()))
        with open(af, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    else:
        open(af, "w").close()

    combined = combine_files([sf, af], allf)
    log("INFO", f"Encontrados {combined} subdominios para {domain}")


def combine_files(input_files, out_file):
    """Combina archivos eliminando duplicados"""
    result_set = set()
    for f in input_files:
        if os.path.isfile(f):
            try:
                with open(f, "r", encoding="utf-8") as file:
                    for line in file:
                        line = line.strip()
                        if line:
                            result_set.add(line)
            except Exception as e:
                log("WARN", f"Error leyendo {f}: {e}")
    result_list = sorted(result_set)
    with open(out_file, "w", encoding="utf-8") as f_out:
        f_out.write("\n".join(result_list) + "\n")
    return len(result_list)


def combine_all_subdomains(out_file):
    """Combina todos los archivos de subdominios"""
    try:
        files = [os.path.join(tmp_dir, f) for f in os.listdir(tmp_dir) if f.endswith("_all.txt")]
    except:
        files = []
    
    all_subs = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as file:
                all_subs.extend(file.read().splitlines())
        except Exception as e:
            log("WARN", f"Error leyendo {f}: {e}")
    
    uniq_subs = sorted(set(s.strip() for s in all_subs if s.strip()))
    with open(out_file, "w", encoding="utf-8") as f_out:
        f_out.write("\n".join(uniq_subs))


def worker_domain(q):
    """Worker thread para procesar dominios"""
    while True:
        domain = q.get()
        if domain is None:
            break
        try:
            enumerate_subdomains(domain)
        except Exception as e:
            log("WARN", f"Error en enumerar {domain}: {e}")
        q.task_done()


def line_count(filepath):
    """Cuenta líneas no vacías en un archivo"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
    except:
        return 0


def scan_takeovers(subdomains_file):
    """Escanea posibles subdomain takeovers"""
    log("INFO", "Iniciando detección de subdomain takeovers...")

    if not os.path.isfile(subdomains_file) or os.path.getsize(subdomains_file) == 0:
        log("WARN", "No hay subdominios para analizar")
        return

    # Subjack scan
    subjack_out = os.path.join(tmp_dir, "potential_takeovers_subjack.txt")
    cmd_subjack = ["subjack", "-w", subdomains_file, "-t", str(THREADS), 
                   "-timeout", str(TIMEOUT), "-o", subjack_out, "-ssl", "-v"]
    log("INFO", "Ejecutando Subjack...")
    run_command(cmd_subjack, capture_output=False, silent=True)

    # Nuclei scan
    nuclei_out = os.path.join(tmp_dir, "potential_takeovers_nuclei.txt")
    cmd_nuclei = ["nuclei", "-l", subdomains_file, "-tags", "takeover",
                  "-severity", "low,medium,high,critical", "-rate-limit", str(RATE_LIMIT),
                  "-o", nuclei_out, "-silent"]
    log("INFO", "Ejecutando Nuclei...")
    run_command(cmd_nuclei, capture_output=False, silent=True)

    # DNSX scan
    dnsx_out = os.path.join(tmp_dir, "dns_analysis.txt")
    cmd_dnsx = ["dnsx", "-l", subdomains_file, "-cname", "-resp", "-o", dnsx_out, "-silent"]
    log("INFO", "Ejecutando DNSX...")
    run_command(cmd_dnsx, capture_output=False, silent=True)

    # Combinar resultados
    combined_takeovers = os.path.join(tmp_dir, "potential_takeovers_combined.txt")
    result_set = set()
    
    for out_file in [subjack_out, nuclei_out]:
        if os.path.isfile(out_file):
            try:
                with open(out_file, "r", encoding="utf-8") as f:
                    result_set.update(line.strip() for line in f if line.strip())
            except:
                pass
    
    with open(combined_takeovers, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(result_set)))


def verify_takeovers():
    """Verifica y analiza posibles takeovers"""
    log("INFO", "Verificando posibles takeovers...")
    combined_file = os.path.join(tmp_dir, "potential_takeovers_combined.txt")

    if not os.path.isfile(combined_file) or os.path.getsize(combined_file) == 0:
        log("INFO", "No se encontraron posibles takeovers")
        return

    takeover_analysis = os.path.join(tmp_dir, "takeover_analysis.txt")
    service_detection = os.path.join(tmp_dir, "service_detection.txt")

    with open(takeover_analysis, "w", encoding="utf-8") as t_file, \
         open(service_detection, "w", encoding="utf-8") as s_file:
        
        with open(combined_file, "r", encoding="utf-8") as f:
            for line in f:
                sub = line.strip()
                if not sub:
                    continue
                
                # Obtener CNAME
                cname = run_command(["dig", "+short", "CNAME", sub], silent=True)
                cname = cname.split("\n")[0].strip() if cname else ""
                
                # Obtener IP
                ip = run_command(["dig", "+short", "A", sub], silent=True)
                ip = ip.split("\n")[0].strip() if ip else ""

                if cname:
                    t_file.write(f"[CNAME] {sub} -> {cname}\n")
                    if "amazonaws.com" in cname:
                        s_file.write(f"[AWS] Posible S3 bucket: {sub} -> {cname}\n")
                    elif "github.io" in cname:
                        s_file.write(f"[GitHub] Posible GitHub Pages: {sub} -> {cname}\n")
                    elif "azure" in cname:
                        s_file.write(f"[Azure] Posible Azure resource: {sub} -> {cname}\n")
                elif ip:
                    t_file.write(f"[A] {sub} -> {ip}\n")
                else:
                    t_file.write(f"[NXDOMAIN] {sub} no resuelve\n")

    # Análisis HTTP con httpx
    log("INFO", "Analizando respuestas HTTP...")
    httpx_out = os.path.join(tmp_dir, "takeover_http_analysis.json")
    cmd_httpx = ["httpx", "-l", combined_file, "-status-code", "-content-length",
                 "-title", "-tech-detect", "-favicon", "-json", "-o", httpx_out, "-silent"]
    run_command(cmd_httpx, capture_output=False, silent=True)

    # Procesar con jq
    jq_out = os.path.join(tmp_dir, "takeover_http_analysis.txt")
    if os.path.isfile(httpx_out):
        cmd_jq = ["jq", "-r", '.[] | "\\(.url) [\\(.status_code)] [\\(.tech)] \\(.title)"', httpx_out]
        result = run_command(cmd_jq, silent=True)
        if result:
            with open(jq_out, "w", encoding="utf-8") as f:
                f.write(result)


def read_file_content(path):
    """Lee contenido de archivo"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except:
        return "(error leyendo archivo)"


def generate_report(all_subs_file):
    """Genera reporte final en formato Markdown"""
    log("INFO", "Generando informe final...")

    report_filename = f"subdomain_takeover_report_{datetime.datetime.now().strftime('%Y%m%d')}.md"
    subs_count = line_count(all_subs_file)
    
    takeover_file = os.path.join(tmp_dir, "potential_takeovers_combined.txt")
    takeovers_count = line_count(takeover_file) if os.path.isfile(takeover_file) else 0

    with open(report_filename, "w", encoding="utf-8") as report:
        report.write("# Subdomain Takeover Scan Report\n\n")
        report.write(f"## Fecha: {datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S')}\n")
        report.write("## Realizado por: TheOffSecGirl\n")
        report.write(f"## Dominios analizados: {len(eligible_domains)}\n")
        report.write(f"## Total de subdominios encontrados: {subs_count}\n")
        report.write(f"## Posibles takeovers identificados: {takeovers_count}\n\n")

        report.write("## Dominios Analizados:\n```\n")
        for d in eligible_domains:
            report.write(f"{d}\n")
        report.write("```\n\n")

        if takeovers_count > 0:
            report.write("## Posibles Takeovers Identificados\n\n")
            
            report.write("### Detalles:\n```\n")
            report.write(read_file_content(os.path.join(tmp_dir, "potential_takeovers_combined.txt")))
            report.write("\n```\n\n")

            report.write("### Análisis de DNS:\n```\n")
            report.write(read_file_content(os.path.join(tmp_dir, "takeover_analysis.txt")))
            report.write("\n```\n\n")

            report.write("### Detección de Servicios:\n```\n")
            report.write(read_file_content(os.path.join(tmp_dir, "service_detection.txt")))
            report.write("\n```\n\n")

            report.write("### Resultados HTTP:\n```\n")
            report.write(read_file_content(os.path.join(tmp_dir, "takeover_http_analysis.txt")))
            report.write("\n```\n\n")

            report.write("## Recomendaciones:\n")
            report.write("1. Verificar manualmente cada posible takeover\n")
            report.write("2. Reclamar dominios vulnerables en los servicios correspondientes\n")
            report.write("3. Monitorear regularmente con este script\n\n")
        else:
            report.write("## No se encontraron posibles takeovers\n\n")

        report.write("## Estadísticas\n")
        report.write(f"- Subdominios únicos encontrados: {subs_count}\n")
        report.write(f"- Posibles takeovers: {takeovers_count}\n\n")
        report.write("---\n")
        report.write("Reporte generado automáticamente por Subdomain Takeover Scanner Pro\n")

    log("INFO", f"Reporte guardado en: {report_filename}")


def main():
    """Función principal"""
    global tmp_dir
    
    # Manejador de CTRL+C
    def signal_handler(sig, frame):
        log("INFO", "Interrupción del usuario detectada")
        cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)

    show_banner()
    parse_args()
    open_log()
    tmp_dir = tempfile.mkdtemp(prefix="takeovflow_tmp_")

    required_tools = ["subfinder", "assetfinder", "subjack", "httpx", "dnsx", "nuclei", "dig", "jq", "curl"]
    if not check_tools(required_tools):
        log("ERROR", "Faltan herramientas requeridas")
        cleanup()
        sys.exit(1)

    log("INFO", f"Dominios cargados: {len(eligible_domains)}")

    # Procesar dominios con threads
    q = queue.Queue()
    for domain in eligible_domains:
        q.put(domain)

    threads_list = []
    for _ in range(min(THREADS, len(eligible_domains))):
        t = threading.Thread(target=worker_domain, args=(q,), daemon=False)
        t.start()
        threads_list.append(t)

    q.join()

    for _ in threads_list:
        q.put(None)
    for t in threads_list:
        t.join()

    # Combinar subdominios
    all_subdomains_file = os.path.join(tmp_dir, "all_subdomains_combined.txt")
    combine_all_subdomains(all_subdomains_file)

    unique_count = line_count(all_subdomains_file)
    log("INFO", f"Subdominios únicos encontrados: {unique_count}")

    # Escanear takeovers
    scan_takeovers(all_subdomains_file)
    
    # Verificar takeovers
    verify_takeovers()
    
    # Generar reporte
    generate_report(all_subdomains_file)

    log("INFO", "Escaneo completado.")
    print("\n\033[0;32m=== Escaneo completado con éxito ===\033[0m")
    print("Revise archivos de resultado e informe.\n")

    cleanup()
    if log_file:
        log_file.close()


if __name__ == "__main__":
    main()
