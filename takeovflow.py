#!/usr/bin/env python3
"""
takeovflow - Advanced Subdomain Takeover Scanner
by theoffsecgirl

Flujo:
  [PASIVA]  subfinder + assetfinder -> deduplicacion
  [ACTIVA]  dnsx -> httpx -> subjack -> nuclei -> CNAME patterns (concurrente)
  [OUTPUT]  Markdown + JSON (opcional)

Flags de modo:
  --passive-only          Solo descubrimiento pasivo, sin scanners activos
  --active-only           Solo fase activa; requiere --subs-file o --file
  --subs-file <path>      Archivo de subdominios para usar en fase activa
"""

__version__ = "1.3.0"

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ------------------------------------------------------------------ #
# Constants
# ------------------------------------------------------------------ #

ALL_TOOLS = [
    "subfinder",
    "assetfinder",
    "subjack",
    "dnsx",
    "httpx",
    "nuclei",
    "dig",
    "jq",
    "curl",
]

# (pattern, service_name, severity)
# severity: HIGH = almost certainly vulnerable, MEDIUM = needs manual verification
CNAME_SERVICES: List[Tuple[str, str, str]] = [
    # AWS
    ("amazonaws.com",           "AWS S3 / Elastic Beanstalk", "HIGH"),
    ("cloudfront.net",          "AWS CloudFront",              "MEDIUM"),
    ("elasticbeanstalk.com",    "AWS Elastic Beanstalk",       "HIGH"),
    # Azure
    ("azurewebsites.net",       "Azure Web Apps",              "HIGH"),
    ("trafficmanager.net",      "Azure Traffic Manager",       "HIGH"),
    ("blob.core.windows.net",   "Azure Blob Storage",          "HIGH"),
    ("azure-api.net",           "Azure API Management",        "MEDIUM"),
    ("cloudapp.net",            "Azure Cloud App",             "MEDIUM"),
    # Heroku
    ("herokudns.com",           "Heroku",                      "HIGH"),
    ("herokuapp.com",           "Heroku",                      "HIGH"),
    # GitHub
    ("github.io",               "GitHub Pages",                "HIGH"),
    ("githubusercontent.com",   "GitHub Raw",                  "MEDIUM"),
    # Fastly / Akamai / CDN
    ("fastly.net",              "Fastly CDN",                  "HIGH"),
    ("edgesuite.net",           "Akamai",                      "MEDIUM"),
    ("akamai.net",              "Akamai",                      "MEDIUM"),
    ("akamaized.net",           "Akamai",                      "MEDIUM"),
    # SaaS / Plataformas
    ("unbouncepages.com",       "Unbounce",                    "HIGH"),
    ("wordpress.com",           "WordPress.com",               "HIGH"),
    ("zendesk.com",             "Zendesk",                     "HIGH"),
    ("shopify.com",             "Shopify",                     "HIGH"),
    ("helpjuice.com",           "HelpJuice",                   "HIGH"),
    ("helpscoutdocs.com",       "HelpScout Docs",              "HIGH"),
    ("ghost.io",                "Ghost",                       "HIGH"),
    ("readme.io",               "ReadMe.io",                   "HIGH"),
    ("surge.sh",                "Surge.sh",                    "HIGH"),
    ("strikingly.com",          "Strikingly",                  "HIGH"),
    ("squarespace.com",         "Squarespace",                 "MEDIUM"),
    ("wixdns.net",              "Wix",                         "MEDIUM"),
    ("weebly.com",              "Weebly",                      "HIGH"),
    ("tilda.ws",                "Tilda",                       "HIGH"),
    ("webflow.io",              "Webflow",                     "HIGH"),
    ("netlify.app",             "Netlify",                     "HIGH"),
    ("netlify.com",             "Netlify",                     "HIGH"),
    ("vercel.app",              "Vercel",                      "HIGH"),
    # Docs / Support
    ("gitbook.io",              "GitBook",                     "HIGH"),
    ("gitbook.com",             "GitBook",                     "HIGH"),
    ("statuspage.io",           "Atlassian Statuspage",        "HIGH"),
    ("uservoice.com",           "UserVoice",                   "HIGH"),
    ("desk.com",                "Salesforce Desk",             "HIGH"),
    ("freshdesk.com",           "Freshdesk",                   "HIGH"),
    ("intercom.help",           "Intercom",                    "HIGH"),
    ("cargo.site",              "Cargo",                       "HIGH"),
    # Analytics / Marketing
    ("pantheonsite.io",         "Pantheon",                    "HIGH"),
    ("kinsta.cloud",            "Kinsta",                      "HIGH"),
    ("flywheel.io",             "Flywheel",                    "HIGH"),
    ("myshopify.com",           "Shopify",                     "HIGH"),
    ("hubspot.com",             "HubSpot",                     "MEDIUM"),
    ("hs-sites.com",            "HubSpot Sites",               "HIGH"),
    ("bitbucket.io",            "Bitbucket Pages",             "HIGH"),
    ("smartling.com",           "Smartling",                   "HIGH"),
    ("launchrock.com",          "Launchrock",                  "HIGH"),
    ("aftership.com",           "AfterShip",                   "HIGH"),
    ("sprintful.com",           "Sprintful",                   "HIGH"),
    ("bigcartel.com",           "Big Cartel",                  "HIGH"),
    ("feedpress.me",            "FeedPress",                   "HIGH"),
    ("cargocollective.com",     "Cargo Collective",            "HIGH"),
    ("simplebooklet.com",       "SimpleBooklet",               "HIGH"),
    ("acquia-sites.com",        "Acquia",                      "HIGH"),
]

SEVERITY_COLOR = {
    "HIGH":   "🔴",
    "MEDIUM": "🟡",
    "LOW":    "🟢",
    "INFO":   "⚪",
}


# ------------------------------------------------------------------ #
# Banner
# ------------------------------------------------------------------ #

def print_banner() -> None:
    print("+" + "-" * 58 + "+")
    print("|"
          "  takeovflow  v{}  –  Subdomain Takeover Scanner".format(__version__).ljust(58)
          + "|")
    print("|" + "  by theoffsecgirl".ljust(58) + "|")
    print("+" + "-" * 58 + "+")
    print()


# ------------------------------------------------------------------ #
# Tools
# ------------------------------------------------------------------ #

def check_available_tools(verbose: bool = False) -> Set[str]:
    available: Set[str] = set()
    missing: List[str] = []
    for tool in ALL_TOOLS:
        if shutil.which(tool):
            available.add(tool)
        else:
            missing.append(tool)
    if missing:
        print("[!] Tools no encontradas (fases omitidas): {}".format(", ".join(missing)))
    if verbose and available:
        print("[+] Tools disponibles: {}".format(", ".join(sorted(available))))
    print()
    return available


def run_cmd(
    cmd: List[str],
    verbose: bool = False,
    capture_stderr: bool = False,
    timeout: int = 300,
    retries: int = 1,
) -> str:
    """Ejecuta un comando y devuelve stdout. Reintenta si falla."""
    if verbose:
        print("[cmd] {}".format(" ".join(cmd)))
    stderr_pipe = subprocess.PIPE if capture_stderr else subprocess.DEVNULL
    for attempt in range(retries):
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=stderr_pipe,
                timeout=timeout,
            )
            if capture_stderr and result.returncode != 0 and verbose:
                err = result.stderr.decode(errors="ignore").strip()
                if err:
                    print("[stderr] {}".format(err[:400]))
            return result.stdout.decode(errors="ignore")
        except subprocess.TimeoutExpired:
            if verbose:
                print("[!] Timeout ({} s): {}".format(timeout, " ".join(cmd[:3])))
            return ""
        except FileNotFoundError:
            return ""
        except Exception as exc:
            if verbose:
                print("[!] Error inesperado (intento {}/{}): {}".format(attempt + 1, retries, exc))
    return ""


# ------------------------------------------------------------------ #
# Args
# ------------------------------------------------------------------ #

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="takeovflow v{} - Advanced Subdomain Takeover Scanner".format(__version__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Ejemplos:\n"
               "  takeovflow.py -d example.com -v\n"
               "  takeovflow.py -f scope.txt --json-output\n"
               "  takeovflow.py --active-only --subs-file subs.txt -d example.com\n",
    )

    target = parser.add_argument_group("targets")
    target.add_argument("-d", "--domain", help="Dominio único a analizar")
    target.add_argument("-f", "--file",   help="Archivo con dominios (uno por línea)")
    target.add_argument("-l", "--list",   help="Lista de dominios separada por comas")

    mode = parser.add_argument_group("mode")
    mode.add_argument(
        "--passive-only", action="store_true",
        help="Solo fase pasiva (descubrimiento de subdominios)",
    )
    mode.add_argument(
        "--active-only", action="store_true",
        help="Solo fase activa. Requiere --subs-file o --file.",
    )
    mode.add_argument(
        "--subs-file", metavar="PATH",
        help="Archivo de subdominios para usar en fase activa.",
    )

    scan = parser.add_argument_group("scan options")
    scan.add_argument("-t", "--threads",  type=int, default=50,  help="Hilos (default: 50)")
    scan.add_argument("-r", "--rate",     type=int, default=2,   help="Rate limit (default: 2)")
    scan.add_argument("--timeout",        type=int, default=30,  help="Timeout por herramienta en segundos (default: 30)")
    scan.add_argument("--retries",        type=int, default=2,   help="Reintentos ante fallo (default: 2)")
    scan.add_argument("--resolvers",      metavar="FILE",        help="Archivo con resolvers DNS personalizados (para dnsx)")
    scan.add_argument("-v", "--verbose",  action="store_true",   help="Modo verbose")
    scan.add_argument("--no-color",       action="store_true",   help="Sin emojis/colores en salida")
    scan.add_argument("--json-output",    action="store_true",   help="Generar informe JSON")
    scan.add_argument("--output-dir",     metavar="DIR",         help="Directorio de salida para reportes (default: CWD)")
    scan.add_argument("--nuclei-templates", help="Ruta a templates personalizados de nuclei")
    scan.add_argument("--min-severity",   choices=["HIGH", "MEDIUM", "LOW", "INFO"],
                      default="INFO",      help="Filtro mínimo de severidad en reporte (default: INFO)")
    parser.add_argument(
        "--version", action="version",
        version="takeovflow {}".format(__version__),
    )
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.passive_only and args.active_only:
        print("[!] --passive-only y --active-only son mutuamente excluyentes.")
        sys.exit(1)
    if args.active_only and not (args.subs_file or args.file):
        print("[!] --active-only requiere --subs-file <archivo> o --file <archivo>.")
        sys.exit(1)
    if args.subs_file and not Path(args.subs_file).exists():
        print("[!] --subs-file: archivo no encontrado: {}".format(args.subs_file))
        sys.exit(1)
    if args.resolvers and not Path(args.resolvers).exists():
        print("[!] --resolvers: archivo no encontrado: {}".format(args.resolvers))
        sys.exit(1)
    if args.output_dir:
        Path(args.output_dir).mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------------ #
# Domains
# ------------------------------------------------------------------ #

def load_domains_from_file(path: str) -> List[str]:
    domains: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            d = line.strip()
            if d and not d.startswith("#"):
                domains.append(d)
    return domains


def _clean_domain(d: str) -> str:
    d = d.lower().strip()
    for prefix in ("http://", "https://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.strip("/").split("/")[0]  # eliminar paths
    # eliminar puerto si lo hay
    if ":" in d and not d.startswith("["):  # IPv6 excluido
        d = d.split(":")[0]
    return d


def normalize_domains(args: argparse.Namespace) -> List[str]:
    domains: List[str] = []
    if args.domain:
        domains.append(args.domain.strip())
    if args.file and not args.active_only:
        domains.extend(load_domains_from_file(args.file))
    if args.list:
        parts = [p.strip() for p in args.list.split(",")]
        domains.extend([p for p in parts if p])

    clean: List[str] = []
    seen: Set[str] = set()
    for d in domains:
        d = _clean_domain(d)
        if d and d not in seen:
            seen.add(d)
            clean.append(d)

    if not clean and not args.active_only:
        print("[!] No se han proporcionado dominios válidos.")
        sys.exit(1)
    return clean


def build_subs_file_from_external(path: str, domain: str, tmpdir: Path) -> Path:
    dest = tmpdir / "{}_subdomains_all.txt".format(domain)
    lines: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            sub = line.strip()
            if sub and not sub.startswith("#"):
                lines.append(sub)
    dest.write_text("\n".join(sorted(set(lines))), encoding="utf-8")
    return dest


# ------------------------------------------------------------------ #
# Passive
# ------------------------------------------------------------------ #

def discover_subdomains(
    domain: str, tmpdir: Path, threads: int,
    verbose: bool, available: Set[str],
    timeout: int = 120,
) -> Path:
    combined_out = tmpdir / "{}_subdomains_all.txt".format(domain)
    subs: List[str] = []

    if "subfinder" in available:
        subfinder_out = tmpdir / "{}_subfinder.txt".format(domain)
        run_cmd(
            ["subfinder", "-d", domain, "-silent", "-o", str(subfinder_out)],
            verbose=verbose, timeout=timeout,
        )
        if subfinder_out.exists():
            subs += [
                l.strip()
                for l in subfinder_out.read_text(errors="ignore").splitlines() if l.strip()
            ]
    elif verbose:
        print("[~] subfinder no disponible.")

    if "assetfinder" in available:
        out = run_cmd(
            ["assetfinder", "--subs-only", domain],
            verbose=verbose, timeout=timeout,
        )
        subs += [l.strip() for l in out.splitlines() if l.strip()]
    elif verbose:
        print("[~] assetfinder no disponible.")

    # Deduplicar y filtrar entradas vacías/inválidas
    subs = sorted(set(s for s in subs if s and "." in s))
    combined_out.write_text("\n".join(subs), encoding="utf-8")

    print("[+] {}: {} subdominios (pasivo)".format(domain, len(subs)))
    return combined_out


# ------------------------------------------------------------------ #
# Active
# ------------------------------------------------------------------ #

def resolve_subdomains(
    domain: str, subs_file: Path, tmpdir: Path,
    threads: int, verbose: bool, available: Set[str],
    resolvers: Optional[str] = None,
    timeout: int = 60,
    retries: int = 2,
) -> Dict[str, Any]:
    results: Dict[str, Any] = {"resolved": [], "httpx": []}
    if not subs_file.exists() or subs_file.stat().st_size == 0:
        return results

    if "dnsx" in available:
        dnsx_out = tmpdir / "{}_dnsx.txt".format(domain)
        cmd = ["dnsx", "-silent", "-resp", "-l", str(subs_file), "-o", str(dnsx_out),
               "-t", str(threads)]
        if resolvers:
            cmd += ["-r", resolvers]
        run_cmd(cmd, verbose=verbose, capture_stderr=verbose, timeout=timeout, retries=retries)
        if dnsx_out.exists():
            resolved = [
                l.split()[0].strip()
                for l in dnsx_out.read_text(errors="ignore").splitlines() if l.strip()
            ]
            results["resolved"] = sorted(set(resolved))
    else:
        if verbose:
            print("[~] dnsx no disponible, usando lista sin resolver.")
        results["resolved"] = [
            l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()
        ]

    if "httpx" in available:
        httpx_out = tmpdir / "{}_httpx.txt".format(domain)
        run_cmd([
            "httpx", "-silent", "-status-code", "-title", "-follow-redirects",
            "-threads", str(threads), "-l", str(subs_file), "-o", str(httpx_out),
        ], verbose=verbose, capture_stderr=verbose, timeout=timeout, retries=retries)
        if httpx_out.exists():
            results["httpx"] = [
                {"raw": l.strip()}
                for l in httpx_out.read_text(errors="ignore").splitlines() if l.strip()
            ]
    elif verbose:
        print("[~] httpx no disponible.")

    if verbose:
        print("[+] {}: {} resueltos, {} HTTP".format(
            domain, len(results["resolved"]), len(results["httpx"])
        ))
    return results


def run_subjack(
    domain: str, subs_file: Path, tmpdir: Path,
    verbose: bool, available: Set[str],
    timeout: int = 120, retries: int = 2,
) -> List[Dict[str, Any]]:
    if "subjack" not in available or not subs_file.exists() or subs_file.stat().st_size == 0:
        if "subjack" not in available and verbose:
            print("[~] subjack no disponible.")
        return []

    out_file = tmpdir / "{}_subjack.txt".format(domain)
    fingerprints = tmpdir / "fingerprints.json"

    if not fingerprints.exists() and "curl" in available:
        url = "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json"
        run_cmd(["curl", "-sL", url, "-o", str(fingerprints)], verbose=verbose, timeout=30)

    cmd = [
        "subjack", "-w", str(subs_file),
        "-t", "100", "-timeout", str(timeout), "-ssl", "-v", "-o", str(out_file),
    ]
    if fingerprints.exists():
        cmd += ["-c", str(fingerprints)]
    run_cmd(cmd, verbose=verbose, capture_stderr=verbose, timeout=timeout * 2, retries=retries)

    findings = []
    if out_file.exists():
        for line in out_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line:
                findings.append({"source": "subjack", "severity": "HIGH", "raw": line})
                print("  {} [subjack] {}".format(SEVERITY_COLOR["HIGH"], line))
    return findings


def run_nuclei(
    domain: str, subs_file: Path, tmpdir: Path,
    threads: int, templates: Optional[str],
    verbose: bool, available: Set[str],
    timeout: int = 120, retries: int = 2,
) -> List[Dict[str, Any]]:
    if "nuclei" not in available or not subs_file.exists() or subs_file.stat().st_size == 0:
        if "nuclei" not in available and verbose:
            print("[~] nuclei no disponible.")
        return []

    out_file = tmpdir / "{}_nuclei.txt".format(domain)
    if templates:
        cmd = ["nuclei", "-silent", "-l", str(subs_file), "-t", templates,
               "-o", str(out_file), "-c", str(threads)]
    else:
        cmd = ["nuclei", "-silent", "-l", str(subs_file), "-tags", "takeover",
               "-o", str(out_file), "-c", str(threads)]
    run_cmd(cmd, verbose=verbose, capture_stderr=verbose, timeout=timeout, retries=retries)

    findings = []
    if out_file.exists():
        for line in out_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line:
                # nuclei indica severidad en brackets: [critical] [high] etc.
                severity = "MEDIUM"
                m = re.search(r"\[(critical|high|medium|low|info)\]", line, re.I)
                if m:
                    lvl = m.group(1).upper()
                    severity = lvl if lvl in ("HIGH", "MEDIUM", "LOW", "INFO") else "HIGH"
                findings.append({"source": "nuclei", "severity": severity, "raw": line})
                print("  {} [nuclei] {}".format(SEVERITY_COLOR.get(severity, "⚪"), line))
    return findings


def _check_cname_single(
    sub: str,
    verbose: bool,
) -> Optional[Dict[str, Any]]:
    """Resuelve CNAME de un único subdominio con dig y retorna finding si coincide."""
    try:
        result = subprocess.run(
            ["dig", sub, "CNAME", "+short"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
        )
        cname = result.stdout.decode(errors="ignore").strip().lower()
    except Exception:
        return None
    if not cname:
        return None
    for pattern, service, severity in CNAME_SERVICES:
        if pattern in cname:
            return {
                "source": "cname-pattern",
                "subdomain": sub,
                "cname": cname,
                "service": service,
                "severity": severity,
            }
    return None


def analyze_cname_patterns(
    domain: str, subs_file: Path, tmpdir: Path,
    verbose: bool, available: Set[str],
    threads: int = 50,
) -> List[Dict[str, Any]]:
    if "dig" not in available:
        if verbose:
            print("[~] dig no disponible, omitiendo CNAME.")
        return []
    if not subs_file.exists() or subs_file.stat().st_size == 0:
        return []

    subdomains = [
        l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()
    ]
    findings: List[Dict[str, Any]] = []
    out_file = tmpdir / "{}_cname_patterns.txt".format(domain)
    suspicious_lines: List[str] = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_check_cname_single, sub, verbose): sub for sub in subdomains}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)
                line = "{} -> {} [{}]".format(result["subdomain"], result["cname"], result["service"])
                suspicious_lines.append(line)
                print("  {} [cname] {}".format(
                    SEVERITY_COLOR.get(result["severity"], "⚪"), line
                ))

    if suspicious_lines:
        out_file.write_text("\n".join(suspicious_lines), encoding="utf-8")

    print("[+] {}: {} CNAMEs sospechosos".format(domain, len(findings)))
    return findings


def deduplicate_takeovers(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Elimina duplicados: mismo subdominio + misma fuente."""
    seen: Set[str] = set()
    unique: List[Dict[str, Any]] = []
    for f in findings:
        sub = f.get("subdomain") or f.get("raw", "")
        key = "{}:{}".format(f.get("source", ""), sub)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def filter_by_severity(
    findings: List[Dict[str, Any]], min_severity: str
) -> List[Dict[str, Any]]:
    threshold = _SEVERITY_ORDER.get(min_severity, 3)
    return [
        f for f in findings
        if _SEVERITY_ORDER.get(f.get("severity", "INFO"), 3) <= threshold
    ]


# ------------------------------------------------------------------ #
# Report
# ------------------------------------------------------------------ #

def build_markdown_report(
    report_path: Path, summary: Dict[str, Any], verbose: bool
) -> None:
    now_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines: List[str] = []
    lines.append("# Subdomain Takeover Report")
    lines.append("")
    lines.append("> Generado: `{}` UTC  |  takeovflow v{}".format(now_utc, __version__))
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Resumen")
    lines.append("")
    lines.append("| Métrica | Valor |")
    lines.append("|---------|-------|")
    lines.append("| Dominios analizados | **{}** |".format(len(summary["domains"])))
    total_subs      = sum(len(d.get("subdomains", []))          for d in summary["domains"].values())
    total_resolved  = sum(len(d.get("resolved", []))            for d in summary["domains"].values())
    total_http      = sum(len(d.get("httpx", []))               for d in summary["domains"].values())
    total_takeovers = sum(len(d.get("potential_takeovers", [])) for d in summary["domains"].values())
    high_count      = sum(
        1 for d in summary["domains"].values()
        for f in d.get("potential_takeovers", [])
        if f.get("severity") == "HIGH"
    )
    lines.append("| Subdominios descubiertos | **{}** |".format(total_subs))
    lines.append("| Resueltos DNS | **{}** |".format(total_resolved))
    lines.append("| Servicios HTTP | **{}** |".format(total_http))
    lines.append("| Posibles takeovers | **{}** |".format(total_takeovers))
    lines.append("| Severidad HIGH | **{}** |".format(high_count))
    lines.append("")

    for domain, data in summary["domains"].items():
        lines.append("---")
        lines.append("")
        lines.append("## `{}`".format(domain))
        lines.append("")
        lines.append("| | |")
        lines.append("|--|--|")
        lines.append("| Subdominios | {} |".format(len(data.get("subdomains", []))))
        lines.append("| Resueltos | {} |".format(len(data.get("resolved", []))))
        lines.append("| HTTP | {} |".format(len(data.get("httpx", []))))
        lines.append("| Posibles takeovers | {} |".format(len(data.get("potential_takeovers", []))))
        lines.append("")

        if data.get("potential_takeovers"):
            lines.append("### ⚠️ Posibles Takeovers")
            lines.append("")
            lines.append("| Severidad | Fuente | Detalle |")
            lines.append("|-----------|--------|---------|")
            for f in sorted(
                data["potential_takeovers"],
                key=lambda x: _SEVERITY_ORDER.get(x.get("severity", "INFO"), 3),
            ):
                sev   = f.get("severity", "INFO")
                src   = f.get("source", "unknown")
                raw   = f.get("raw") or ""
                sub   = f.get("subdomain") or ""
                cname = f.get("cname") or ""
                svc   = f.get("service") or ""
                emoji = SEVERITY_COLOR.get(sev, "⚪")
                if raw:
                    detail = raw.replace("|", "\\|")
                else:
                    detail = "`{}` → `{}` ({})".format(sub, cname, svc)
                lines.append("| {} {} | `{}` | {} |".format(emoji, sev, src, detail))
            lines.append("")

        if data.get("httpx"):
            lines.append("### Servicios HTTP activos")
            lines.append("")
            for entry in data["httpx"][:100]:
                lines.append("- `{}`".format(entry.get("raw", "")))
            if len(data["httpx"]) > 100:
                lines.append("- *... {} más*".format(len(data["httpx"]) - 100))
            lines.append("")

        if data.get("subdomains"):
            lines.append("### Subdominios descubiertos")
            lines.append("")
            shown = data["subdomains"][:100]
            for s in shown:
                lines.append("- `{}`".format(s))
            if len(data["subdomains"]) > 100:
                lines.append("- *... {} más*".format(len(data["subdomains"]) - 100))
            lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    if verbose:
        print("[+] Informe Markdown: {}".format(report_path))


# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #

def main() -> None:
    print_banner()
    args = parse_args()
    validate_args(args)

    available = check_available_tools(verbose=args.verbose)

    discovery_tools = {"subfinder", "assetfinder"}
    if not discovery_tools & available and not args.active_only:
        print("[!] Sin tools de descubrimiento pasivo. Instala subfinder/assetfinder o usa --active-only.")

    domains = normalize_domains(args)

    if args.active_only and not domains:
        domains = ["scope"]

    if args.verbose:
        print("[+] Dominios: {}\n".format(", ".join(domains)))

    output_dir = Path(args.output_dir) if args.output_dir else Path.cwd()
    tmpdir = Path(tempfile.mkdtemp(prefix="takeovflow_tmp_"))
    summary: Dict[str, Any] = {
        "tool": "takeovflow",
        "version": __version__,
        "started": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "domains": {},
    }

    for domain in domains:
        print("\n[*] Analizando: {}".format(domain))
        domain_data: Dict[str, Any] = {}
        subs_file: Optional[Path] = None

        # --- Fase pasiva ---
        if args.active_only:
            src = args.subs_file or args.file
            if src:
                subs_file = build_subs_file_from_external(src, domain, tmpdir)
                domain_data["subdomains"] = [
                    l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()
                ]
                print("[+] {} subdominios cargados desde {}".format(
                    len(domain_data["subdomains"]), src
                ))
            else:
                print("[!] --active-only requiere --subs-file o --file.")
                sys.exit(1)
        else:
            subs_file = discover_subdomains(
                domain, tmpdir, args.threads, args.verbose, available,
                timeout=120,
            )
            domain_data["subdomains"] = [
                l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()
            ] if subs_file and subs_file.exists() else []

        # --- Fase activa ---
        if not args.passive_only and subs_file and subs_file.exists() and subs_file.stat().st_size > 0:
            resolved_info = resolve_subdomains(
                domain, subs_file, tmpdir, args.threads, args.verbose, available,
                resolvers=args.resolvers,
                timeout=args.timeout * 2,
                retries=args.retries,
            )
            domain_data["resolved"] = resolved_info["resolved"]
            domain_data["httpx"]    = resolved_info["httpx"]

            print("[*] Buscando takeovers en {}...".format(domain))
            takeovers: List[Dict[str, Any]] = []
            takeovers += run_subjack(
                domain, subs_file, tmpdir, args.verbose, available,
                timeout=args.timeout * 4, retries=args.retries,
            )
            takeovers += run_nuclei(
                domain, subs_file, tmpdir, args.threads,
                args.nuclei_templates, args.verbose, available,
                timeout=args.timeout * 4, retries=args.retries,
            )
            takeovers += analyze_cname_patterns(
                domain, subs_file, tmpdir, args.verbose, available,
                threads=args.threads,
            )

            takeovers = deduplicate_takeovers(takeovers)
            takeovers = filter_by_severity(takeovers, args.min_severity)
            domain_data["potential_takeovers"] = takeovers
        else:
            domain_data.setdefault("resolved", [])
            domain_data.setdefault("httpx", [])
            domain_data.setdefault("potential_takeovers", [])

        summary["domains"][domain] = domain_data

    now = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    report_md   = output_dir / "takeovflow_report_{}.md".format(now)
    report_json: Optional[Path] = None

    build_markdown_report(report_md, summary, verbose=args.verbose)

    if args.json_output:
        report_json = output_dir / "takeovflow_report_{}.json".format(now)
        summary["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        report_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        if args.verbose:
            print("[+] Informe JSON: {}".format(report_json))

    print("\n" + "=" * 60)
    print("[OK] Análisis completado.")
    print("     Markdown  : {}".format(report_md))
    if report_json:
        print("     JSON      : {}".format(report_json))
    total_findings = sum(len(d.get("potential_takeovers", [])) for d in summary["domains"].values())
    if total_findings:
        print("     ⚠️  {} posible(s) takeover(s) encontrado(s)".format(total_findings))
    else:
        print("     ✅ Sin takeovers detectados")
    print("=" * 60)


if __name__ == "__main__":
    main()
