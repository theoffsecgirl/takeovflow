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
  --quiet                 Suprime banner y prints intermedios (ideal para wrappers/automatizacion)
  --skip-http-verify      Desactiva la verificacion HTTP de firmas (S3/GitHub Pages/Heroku)
                          sobre los hallazgos de cname-pattern (mas rapido, menos preciso)
"""

__version__ = "1.6.0"

import argparse
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ------------------------------------------------------------------ #
# Output helper
# ------------------------------------------------------------------ #

_QUIET: bool = False


def log(msg: str, force: bool = False) -> None:
    if not _QUIET or force:
        print(msg)


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

CNAME_SERVICES: List[Tuple[str, str, str]] = [
    ("amazonaws.com",           "AWS S3 / Elastic Beanstalk", "HIGH"),
    ("cloudfront.net",          "AWS CloudFront",              "MEDIUM"),
    ("elasticbeanstalk.com",    "AWS Elastic Beanstalk",       "HIGH"),
    ("azurewebsites.net",       "Azure Web Apps",              "HIGH"),
    ("trafficmanager.net",      "Azure Traffic Manager",       "HIGH"),
    ("blob.core.windows.net",   "Azure Blob Storage",          "HIGH"),
    ("azure-api.net",           "Azure API Management",        "MEDIUM"),
    ("cloudapp.net",            "Azure Cloud App",             "MEDIUM"),
    ("herokudns.com",           "Heroku",                      "HIGH"),
    ("herokuapp.com",           "Heroku",                      "HIGH"),
    ("github.io",               "GitHub Pages",                "HIGH"),
    ("githubusercontent.com",   "GitHub Raw",                  "MEDIUM"),
    ("fastly.net",              "Fastly CDN",                  "HIGH"),
    ("edgesuite.net",           "Akamai",                      "MEDIUM"),
    ("akamai.net",              "Akamai",                      "MEDIUM"),
    ("akamaized.net",           "Akamai",                      "MEDIUM"),
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
    ("gitbook.io",              "GitBook",                     "HIGH"),
    ("gitbook.com",             "GitBook",                     "HIGH"),
    ("statuspage.io",           "Atlassian Statuspage",        "HIGH"),
    ("uservoice.com",           "UserVoice",                   "HIGH"),
    ("desk.com",                "Salesforce Desk",             "HIGH"),
    ("freshdesk.com",           "Freshdesk",                   "HIGH"),
    ("intercom.help",           "Intercom",                    "HIGH"),
    ("cargo.site",              "Cargo",                       "HIGH"),
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

# Verificacion HTTP activa minima (opcional, ver --skip-http-verify) para los
# patrones CNAME mas frecuentes en bug bounty real. Firmas de error de
# "recurso no encontrado" tomadas de EdOverflow/can-i-take-over-xyz
# (fingerprints.json), la misma base que usa subjack. "edge_case": True marca
# servicios donde la propia fuente no clasifica la firma como "Vulnerable"
# puro (puede haber falsos positivos por protecciones anti-takeover del
# proveedor) -- se confirma igual pero con nota explicita en el reporte.
HTTP_VERIFY_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "amazonaws.com": {
        "signature": "The specified bucket does not exist",
        "edge_case": False,
    },
    "github.io": {
        "signature": "There isn't a GitHub Pages site here.",
        "edge_case": True,
    },
    "herokuapp.com": {
        "signature": "No such app",
        "edge_case": True,
    },
    "herokudns.com": {
        "signature": "No such app",
        "edge_case": True,
    },
}

SEVERITY_COLOR = {
    "CRITICAL": "\U0001f6a8",
    "HIGH":     "\U0001f534",
    "MEDIUM":   "\U0001f7e1",
    "LOW":      "\U0001f7e2",
    "INFO":     "\u26aa",
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# cname-pattern findings sin verificacion adicional se degradan un escalon:
# la coincidencia de patron por si sola no confirma que el recurso remoto
# este realmente huerfano/reclamable (a diferencia de subjack/nuclei, que
# verifican por firma).
_UNCONFIRMED_DOWNGRADE = {"HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}

UNCONFIRMED_PREFIX = "[PATRÓN SIN CONFIRMAR — requiere verificación manual] "


# ------------------------------------------------------------------ #
# Banner
# ------------------------------------------------------------------ #

def print_banner() -> None:
    inner = "  takeovflow  v{}  -  Subdomain Takeover Scanner".format(__version__)
    width = max(58, len(inner) + 2)
    log("+" + "-" * width + "+")
    log("|" + inner.ljust(width) + "|")
    log("|" + "  by theoffsecgirl".ljust(width) + "|")
    log("+" + "-" * width + "+")
    log("")


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
        log("[!] Tools no encontradas (fases omitidas): {}".format(", ".join(missing)))
    if verbose and available:
        log("[+] Tools disponibles: {}".format(", ".join(sorted(available))))
    log("")
    return available


def _subjack_supports_flag(flag: str) -> bool:
    """Devuelve True si la version instalada de subjack acepta el flag dado.
    Lanza subjack sin argumentos y parsea el help de stderr.
    """
    try:
        result = subprocess.run(
            ["subjack"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        output = (result.stdout + result.stderr).decode(errors="ignore")
        return flag in output
    except Exception:
        return False


def run_cmd(
    cmd: List[str],
    verbose: bool = False,
    capture_stderr: bool = False,
    timeout: int = 300,
    retries: int = 1,
) -> str:
    if verbose:
        log("[cmd] {}".format(" ".join(cmd)))
    stderr_pipe = subprocess.PIPE if capture_stderr else subprocess.DEVNULL
    for attempt in range(max(retries, 1)):
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
                    log("[stderr] {}".format(err[:400]))
            return result.stdout.decode(errors="ignore")
        except subprocess.TimeoutExpired:
            if verbose:
                log("[!] Timeout ({} s) intento {}/{}: {}".format(
                    timeout, attempt + 1, retries, " ".join(cmd[:3])
                ))
        except FileNotFoundError:
            return ""
        except Exception as exc:
            if verbose:
                log("[!] Error inesperado (intento {}/{}): {}".format(attempt + 1, retries, exc))
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
               "  takeovflow.py --active-only --subs-file subs.txt -d example.com\n"
               "  takeovflow.py -d example.com --quiet --json-output  # para wrappers\n",
    )

    target = parser.add_argument_group("targets")
    target.add_argument("-d", "--domain", help="Dominio \u00fanico a analizar")
    target.add_argument("-f", "--file",   help="Archivo con dominios (uno por l\u00ednea)")
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
    scan.add_argument("-r", "--rate",     type=int, default=150, help="Rate limit req/s para httpx/dnsx (default: 150)")
    scan.add_argument("--timeout",        type=int, default=30,  help="Timeout por herramienta en segundos (default: 30)")
    scan.add_argument("--retries",        type=int, default=2,   help="Reintentos ante fallo (default: 2)")
    scan.add_argument("--resolvers",      metavar="FILE",        help="Archivo con resolvers DNS personalizados (para dnsx)")
    scan.add_argument("-v", "--verbose",  action="store_true",   help="Modo verbose")
    scan.add_argument("-q", "--quiet",    action="store_true",
                      help="Modo silencioso: suprime banner y prints intermedios. "
                           "Solo se emiten errores fatales y la ruta del reporte al finalizar. "
                           "Ideal para wrappers y automatizaciones.")
    scan.add_argument("--no-color",       action="store_true",   help="Sin emojis/colores en salida")
    scan.add_argument("--json-output",    action="store_true",   help="Generar informe JSON")
    scan.add_argument("--output-dir",     metavar="DIR",         help="Directorio de salida para reportes (default: CWD)")
    scan.add_argument("--nuclei-templates", help="Ruta a templates personalizados de nuclei")
    scan.add_argument("--min-severity",   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                      default="INFO",      help="Filtro m\u00ednimo de severidad en reporte (default: INFO)")
    scan.add_argument(
        "--skip-http-verify", action="store_true",
        help="Desactiva la verificacion HTTP activa de firmas (S3/GitHub Pages/Heroku) "
             "sobre los hallazgos de cname-pattern. Mas rapido, pero esos hallazgos se "
             "quedan como 'patron sin confirmar' salvo que otra fuente los corrobore.",
    )
    parser.add_argument(
        "--version", action="version",
        version="takeovflow {}".format(__version__),
    )
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.quiet and args.verbose:
        print("[!] --quiet y --verbose son mutuamente excluyentes.", file=sys.stderr)
        sys.exit(1)
    if args.passive_only and args.active_only:
        log("[!] --passive-only y --active-only son mutuamente excluyentes.", force=True)
        sys.exit(1)
    if args.active_only and not (args.subs_file or args.file):
        log("[!] --active-only requiere --subs-file <archivo> o --file <archivo>.", force=True)
        sys.exit(1)
    if args.subs_file and not Path(args.subs_file).exists():
        log("[!] --subs-file: archivo no encontrado: {}".format(args.subs_file), force=True)
        sys.exit(1)
    if args.resolvers and not Path(args.resolvers).exists():
        log("[!] --resolvers: archivo no encontrado: {}".format(args.resolvers), force=True)
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
    d = d.strip("/").split("/")[0]
    if ":" in d and not d.startswith("["):
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
        log("[!] No se han proporcionado dominios v\u00e1lidos.", force=True)
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
        log("[~] subfinder no disponible.")

    if "assetfinder" in available:
        out = run_cmd(
            ["assetfinder", "--subs-only", domain],
            verbose=verbose, timeout=timeout,
        )
        subs += [l.strip() for l in out.splitlines() if l.strip()]
    elif verbose:
        log("[~] assetfinder no disponible.")

    subs = sorted(set(s for s in subs if s and "." in s))
    combined_out.write_text("\n".join(subs), encoding="utf-8")

    log("[+] {}: {} subdominios (pasivo)".format(domain, len(subs)))
    return combined_out


# ------------------------------------------------------------------ #
# Active
# ------------------------------------------------------------------ #

def resolve_subdomains(
    domain: str, subs_file: Path, tmpdir: Path,
    threads: int, rate: int, verbose: bool, available: Set[str],
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
               "-t", str(threads), "-rl", str(rate)]
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
            log("[~] dnsx no disponible, usando lista sin resolver.")
        results["resolved"] = [
            l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()
        ]

    if "httpx" in available:
        httpx_out = tmpdir / "{}_httpx.txt".format(domain)
        run_cmd([
            "httpx", "-silent", "-status-code", "-title", "-follow-redirects",
            "-threads", str(threads), "-rate", str(rate),
            "-l", str(subs_file), "-o", str(httpx_out),
        ], verbose=verbose, capture_stderr=verbose, timeout=timeout, retries=retries)
        if httpx_out.exists():
            results["httpx"] = [
                {"raw": l.strip()}
                for l in httpx_out.read_text(errors="ignore").splitlines() if l.strip()
            ]
    elif verbose:
        log("[~] httpx no disponible.")

    if verbose:
        log("[+] {}: {} resueltos, {} HTTP".format(
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
            log("[~] subjack no disponible.")
        return []

    out_file     = tmpdir / "{}_subjack.txt".format(domain)
    fingerprints = tmpdir / "fingerprints.json"

    # Detectar si esta version de subjack soporta -c (fingerprints custom)
    supports_c = _subjack_supports_flag("-c")

    if supports_c and not fingerprints.exists():
        if "curl" in available:
            url = "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json"
            run_cmd(["curl", "-sL", url, "-o", str(fingerprints)], verbose=verbose, timeout=30)
        if not fingerprints.exists():
            log("[!] subjack: fingerprints.json no disponible. Los resultados pueden ser menos precisos.")

    cmd = [
        "subjack", "-w", str(subs_file),
        "-t", "100", "-timeout", str(timeout), "-ssl", "-v",
        "-o", str(out_file),
    ]
    if supports_c and fingerprints.exists():
        cmd += ["-c", str(fingerprints)]
    elif not supports_c and verbose:
        log("[~] subjack: flag -c no soportado en esta version, usando fingerprints integrados.")

    run_cmd(cmd, verbose=verbose, capture_stderr=verbose, timeout=timeout * 2, retries=retries)

    findings = []
    if out_file.exists():
        for line in out_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line:
                findings.append({"source": "subjack", "severity": "HIGH", "raw": line})
                log("  {} [subjack] {}".format(SEVERITY_COLOR["HIGH"], line))
    return findings


def run_nuclei(
    domain: str, subs_file: Path, tmpdir: Path,
    threads: int, templates: Optional[str],
    verbose: bool, available: Set[str],
    timeout: int = 120, retries: int = 2,
) -> List[Dict[str, Any]]:
    if "nuclei" not in available or not subs_file.exists() or subs_file.stat().st_size == 0:
        if "nuclei" not in available and verbose:
            log("[~] nuclei no disponible.")
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
                severity = "MEDIUM"
                m = re.search(r"\[(critical|high|medium|low|info)\]", line, re.I)
                if m:
                    lvl = m.group(1).upper()
                    if lvl == "CRITICAL":
                        severity = "CRITICAL"
                    elif lvl in _SEVERITY_ORDER:
                        severity = lvl
                    else:
                        severity = "HIGH"
                findings.append({"source": "nuclei", "severity": severity, "raw": line})
                log("  {} [nuclei] {}".format(SEVERITY_COLOR.get(severity, "\u26aa"), line))
    return findings


def _fetch_body_for_verify(sub: str, timeout: int) -> Optional[str]:
    """GET simple a http(s)://sub para verificacion de firma. Prueba https y
    luego http; certificados invalidos se ignoran (frecuentes en recursos
    huerfanos). Devuelve None ante cualquier fallo (timeout, DNS, conexion).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"User-Agent": "takeovflow/{}".format(__version__)}
    for scheme in ("https", "http"):
        url = "{}://{}".format(scheme, sub)
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.read(65536).decode(errors="ignore")
        except urllib.error.HTTPError as exc:
            # Los mensajes de "recurso no encontrado" (NoSuchBucket, 404 de
            # GitHub Pages/Heroku, etc.) casi siempre vienen en una respuesta
            # de error (4xx), que urlopen levanta como excepcion en vez de
            # devolverla como respuesta normal. El body sigue siendo legible.
            try:
                return exc.read(65536).decode(errors="ignore")
            except Exception:
                continue
        except Exception:
            continue
    return None


def _http_verify_cname(sub: str, cname: str, timeout: int) -> Optional[Dict[str, Any]]:
    """Verificacion HTTP minima para los patrones CNAME mas comunes (ver
    HTTP_VERIFY_SIGNATURES). Si la firma de "recurso no encontrado" del
    proveedor aparece en la respuesta, devuelve confirmacion; si no aplica o
    no se puede verificar, devuelve None y el finding se queda como patron
    sin confirmar.
    """
    sig_entry = None
    for pattern, info in HTTP_VERIFY_SIGNATURES.items():
        if pattern in cname:
            sig_entry = info
            break
    if not sig_entry:
        return None

    body = _fetch_body_for_verify(sub, timeout)
    if body is None or sig_entry["signature"] not in body:
        return None

    note = "Firma HTTP confirmada: \"{}\"".format(sig_entry["signature"])
    if sig_entry["edge_case"]:
        note += " (firma edge-case: puede requerir verificación adicional)"
    return {"confirmed": True, "note": note}


def _check_cname_single(
    sub: str,
    verbose: bool,
    timeout: int = 10,
    http_verify: bool = True,
    http_verify_timeout: int = 8,
) -> Optional[Dict[str, Any]]:
    try:
        result = subprocess.run(
            ["dig", sub, "CNAME", "+short"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        cname = result.stdout.decode(errors="ignore").strip().lower()
    except Exception:
        return None
    if not cname:
        return None
    for pattern, service, severity in CNAME_SERVICES:
        if pattern in cname:
            # Coincidencia de patron sin verificacion adicional: severidad
            # degradada y marcada explicitamente como no confirmada.
            finding = {
                "source": "cname-pattern",
                "subdomain": sub,
                "cname": cname,
                "service": service,
                "severity": _UNCONFIRMED_DOWNGRADE.get(severity, severity),
                "confirmed": False,
            }
            if http_verify:
                verified = _http_verify_cname(sub, cname, http_verify_timeout)
                if verified:
                    finding["severity"] = severity  # severidad completa original
                    finding["confirmed"] = True
                    finding["note"] = verified["note"]
            return finding
    return None


def analyze_cname_patterns(
    domain: str, subs_file: Path, tmpdir: Path,
    verbose: bool, available: Set[str],
    threads: int = 50,
    dig_timeout: int = 10,
    http_verify: bool = True,
    http_verify_timeout: int = 8,
) -> List[Dict[str, Any]]:
    if "dig" not in available:
        if verbose:
            log("[~] dig no disponible, omitiendo CNAME.")
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
        futures = {
            executor.submit(
                _check_cname_single, sub, verbose, dig_timeout,
                http_verify, http_verify_timeout,
            ): sub
            for sub in subdomains
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)
                tag = " [CONFIRMADO]" if result.get("confirmed") else " [sin confirmar]"
                line = "{} -> {} [{}]{}".format(
                    result["subdomain"], result["cname"], result["service"], tag
                )
                suspicious_lines.append(line)
                log("  {} [cname] {}".format(
                    SEVERITY_COLOR.get(result["severity"], "\u26aa"), line
                ))

    if suspicious_lines:
        out_file.write_text("\n".join(suspicious_lines), encoding="utf-8")

    log("[+] {}: {} CNAMEs sospechosos".format(domain, len(findings)))
    return findings


_URL_HOST_RE = re.compile(r"https?://([^\s/\\]+)", re.I)
_BARE_HOST_RE = re.compile(r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,62})?\.)+[a-zA-Z]{2,63})\b")

# fuentes que verifican el takeover por firma/fingerprint real, no solo por
# coincidencia de patron en el CNAME.
_STRONG_SOURCES = {"subjack", "nuclei"}


def _extract_subdomain_from_raw(raw: str) -> str:
    """Intenta sacar el host/subdominio de una linea 'raw' de subjack/nuclei.
    Prioriza una URL http(s) embebida; si no hay, busca un hostname suelto.
    """
    if not raw:
        return ""
    m = _URL_HOST_RE.search(raw)
    if m:
        return m.group(1).split(":")[0].strip().lower()
    m = _BARE_HOST_RE.search(raw)
    if m:
        return m.group(1).strip().lower()
    parts = raw.split()
    return parts[0].strip().lower() if parts else ""


def _finding_subdomain(f: Dict[str, Any]) -> str:
    sub = f.get("subdomain")
    if sub:
        return sub.strip().lower()
    return _extract_subdomain_from_raw(f.get("raw", ""))


def _service_base_severity(service: str) -> Optional[str]:
    """Severidad original (sin degradar) que CNAME_SERVICES asigna a un servicio."""
    for _pattern, svc, severity in CNAME_SERVICES:
        if svc == service:
            return severity
    return None


def _merge_findings(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Fusiona findings del mismo subdominio detectados por fuentes distintas.

    Si al menos una fuente fuerte (subjack/nuclei, verificacion real por firma)
    participa, el finding fusionado se marca confirmed=True y recupera la
    severidad original (sin el degradado de 'patron sin confirmar') para
    cualquier componente cname-pattern. Conserva el detalle de cada fuente
    individual en 'sources_detail' para no perder evidencia al fusionar.
    """
    sources: List[str] = []
    for it in items:
        s = it.get("source", "unknown")
        if s not in sources:
            sources.append(s)

    confirmed = any(it.get("confirmed", True) for it in items) or any(
        s in _STRONG_SOURCES for s in sources
    )

    candidate_severities: List[str] = []
    for it in items:
        sev = it.get("severity", "INFO")
        if confirmed and it.get("source") == "cname-pattern" and not it.get("confirmed", True):
            base = _service_base_severity(it.get("service", ""))
            if base:
                sev = base
        candidate_severities.append(sev)
    severity = min(candidate_severities, key=lambda s: _SEVERITY_ORDER.get(s, 4))

    subdomain = ""
    for it in items:
        subdomain = _finding_subdomain(it)
        if subdomain:
            break

    return {
        "source": ", ".join(sources),
        "sources": sources,
        "subdomain": subdomain,
        "severity": severity,
        "confirmed": confirmed,
        "merged": True,
        "sources_detail": items,
    }


def deduplicate_takeovers(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Paso 1: elimina duplicados exactos de la misma fuente+subdominio.
    seen: Set[str] = set()
    dedup_by_source: List[Dict[str, Any]] = []
    for f in findings:
        sub = _finding_subdomain(f)
        key = "{}:{}".format(f.get("source", ""), sub)
        if key not in seen:
            seen.add(key)
            dedup_by_source.append(f)

    # Paso 2: agrupa por subdominio, fusionando findings de fuentes distintas
    # que apuntan al mismo subdominio y subiendo la confianza cuando coinciden.
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for f in dedup_by_source:
        sub = _finding_subdomain(f)
        key = sub if sub else "__nosub__:{}".format(id(f))
        groups.setdefault(key, []).append(f)

    merged: List[Dict[str, Any]] = []
    for items in groups.values():
        merged.append(items[0] if len(items) == 1 else _merge_findings(items))
    return merged


def filter_by_severity(
    findings: List[Dict[str, Any]], min_severity: str
) -> List[Dict[str, Any]]:
    threshold = _SEVERITY_ORDER.get(min_severity, 4)
    return [
        f for f in findings
        if _SEVERITY_ORDER.get(f.get("severity", "INFO"), 4) <= threshold
    ]


# ------------------------------------------------------------------ #
# Report
# ------------------------------------------------------------------ #

def _finding_detail_cell(f: Dict[str, Any]) -> str:
    if f.get("merged"):
        detected_by = ", ".join(f.get("sources", []))
        sub = f.get("subdomain") or ""
        cell = ["**Detectado por:** {}".format(detected_by)]
        if sub:
            cell.append("`{}`".format(sub))
        for sd in f.get("sources_detail", []):
            s_src = sd.get("source", "unknown")
            if sd.get("raw"):
                ev = sd["raw"].replace("|", "\\|")
            else:
                ev = "→ `{}` ({})".format(sd.get("cname", ""), sd.get("service", ""))
                if sd.get("note"):
                    ev += " — {}".format(sd["note"])
            tag = "" if sd.get("confirmed", True) else " _(patrón sin confirmar)_"
            cell.append("- `{}`: {}{}".format(s_src, ev, tag))
        return "<br>".join(cell)

    raw = f.get("raw") or ""
    if raw:
        return raw.replace("|", "\\|")
    sub   = f.get("subdomain") or ""
    cname = f.get("cname") or ""
    svc   = f.get("service") or ""
    detail = "`{}` → `{}` ({})".format(sub, cname, svc)
    if f.get("note"):
        detail += " — {}".format(f["note"])
    return detail


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
    lines.append("| M\u00e9trica | Valor |")
    lines.append("|---------|-------|")
    lines.append("| Dominios analizados | **{}** |".format(len(summary["domains"])))
    total_subs      = sum(len(d.get("subdomains", []))          for d in summary["domains"].values())
    total_resolved  = sum(len(d.get("resolved", []))            for d in summary["domains"].values())
    total_http      = sum(len(d.get("httpx", []))               for d in summary["domains"].values())
    total_takeovers = sum(len(d.get("potential_takeovers", [])) for d in summary["domains"].values())
    critical_count  = sum(
        1 for d in summary["domains"].values()
        for f in d.get("potential_takeovers", [])
        if f.get("severity") == "CRITICAL"
    )
    high_count = sum(
        1 for d in summary["domains"].values()
        for f in d.get("potential_takeovers", [])
        if f.get("severity") == "HIGH"
    )
    lines.append("| Subdominios descubiertos | **{}** |".format(total_subs))
    lines.append("| Resueltos DNS | **{}** |".format(total_resolved))
    lines.append("| Servicios HTTP | **{}** |".format(total_http))
    lines.append("| Posibles takeovers | **{}** |".format(total_takeovers))
    lines.append("| Severidad CRITICAL | **{}** |".format(critical_count))
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
            lines.append("### \u26a0\ufe0f Posibles Takeovers")
            lines.append("")
            lines.append("| Severidad | Fuente | Detalle |")
            lines.append("|-----------|--------|---------|")
            for f in sorted(
                data["potential_takeovers"],
                key=lambda x: _SEVERITY_ORDER.get(x.get("severity", "INFO"), 4),
            ):
                sev       = f.get("severity", "INFO")
                src       = f.get("source", "unknown")
                confirmed = f.get("confirmed", True)
                emoji = SEVERITY_COLOR.get(sev, "\u26aa")
                detail = _finding_detail_cell(f)
                if not confirmed:
                    detail = UNCONFIRMED_PREFIX + detail
                lines.append("| {} {} | `{}` | {} |".format(emoji, sev, src, detail))
            lines.append("")

        if data.get("httpx"):
            lines.append("### Servicios HTTP activos")
            lines.append("")
            for entry in data["httpx"][:100]:
                lines.append("- `{}`".format(entry.get("raw", "")))
            if len(data["httpx"]) > 100:
                lines.append("- *... {} m\u00e1s*".format(len(data["httpx"]) - 100))
            lines.append("")

        if data.get("subdomains"):
            lines.append("### Subdominios descubiertos")
            lines.append("")
            shown = data["subdomains"][:100]
            for s in shown:
                lines.append("- `{}`".format(s))
            if len(data["subdomains"]) > 100:
                lines.append("- *... {} m\u00e1s*".format(len(data["subdomains"]) - 100))
            lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    if verbose:
        log("[+] Informe Markdown: {}".format(report_path))


# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #

def main() -> None:
    global _QUIET

    args = parse_args()
    _QUIET = args.quiet

    validate_args(args)
    print_banner()

    available = check_available_tools(verbose=args.verbose)

    discovery_tools = {"subfinder", "assetfinder"}
    if not discovery_tools & available and not args.active_only:
        log("[!] Sin tools de descubrimiento pasivo. Instala subfinder/assetfinder o usa --active-only.")

    domains = normalize_domains(args)

    if args.active_only and not domains:
        log("[~] --active-only sin -d: usando 'scope' como nombre de dominio en el reporte.")
        domains = ["scope"]

    if args.verbose:
        log("[+] Dominios: {}\n".format(", ".join(domains)))

    output_dir = Path(args.output_dir) if args.output_dir else Path.cwd()

    with tempfile.TemporaryDirectory(prefix="takeovflow_tmp_") as _tmpdir:
        tmpdir = Path(_tmpdir)
        summary: Dict[str, Any] = {
            "tool": "takeovflow",
            "version": __version__,
            "started": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "domains": {},
        }

        for domain in domains:
            log("\n[*] Analizando: {}".format(domain))
            domain_data: Dict[str, Any] = {}
            subs_file: Optional[Path] = None

            if args.active_only:
                src = args.subs_file or args.file
                if src:
                    subs_file = build_subs_file_from_external(src, domain, tmpdir)
                    domain_data["subdomains"] = [
                        l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()
                    ]
                    log("[+] {} subdominios cargados desde {}".format(
                        len(domain_data["subdomains"]), src
                    ))
                else:
                    log("[!] --active-only requiere --subs-file o --file.", force=True)
                    sys.exit(1)
            else:
                subs_file = discover_subdomains(
                    domain, tmpdir, args.threads, args.verbose, available,
                    timeout=120,
                )
                domain_data["subdomains"] = [
                    l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()
                ] if subs_file and subs_file.exists() else []

            if not args.passive_only and subs_file and subs_file.exists() and subs_file.stat().st_size > 0:
                resolved_info = resolve_subdomains(
                    domain, subs_file, tmpdir, args.threads, args.rate,
                    args.verbose, available,
                    resolvers=args.resolvers,
                    timeout=args.timeout * 2,
                    retries=args.retries,
                )
                domain_data["resolved"] = resolved_info["resolved"]
                domain_data["httpx"]    = resolved_info["httpx"]

                log("[*] Buscando takeovers en {}...".format(domain))
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
                    dig_timeout=args.timeout,
                    http_verify=not args.skip_http_verify,
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
                log("[+] Informe JSON: {}".format(report_json))

        print("\n" + "=" * 60)
        print("[OK] An\u00e1lisis completado.")
        print("     Markdown  : {}".format(report_md))
        if report_json:
            print("     JSON      : {}".format(report_json))
        total_findings = sum(len(d.get("potential_takeovers", [])) for d in summary["domains"].values())
        if total_findings:
            print("     \u26a0\ufe0f  {} posible(s) takeover(s) encontrado(s)".format(total_findings))
        else:
            print("     \u2705 Sin takeovers detectados")
        print("=" * 60)


if __name__ == "__main__":
    main()
