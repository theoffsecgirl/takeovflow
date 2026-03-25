#!/usr/bin/env python3
"""
takeovflow - Advanced Subdomain Takeover Scanner
by theoffsecgirl

Flujo:
  [PASIVA]  subfinder + assetfinder -> deduplicacion
  [ACTIVA]  dnsx -> httpx -> subjack -> nuclei -> CNAME patterns
  [OUTPUT]  Markdown + JSON (opcional)

Flags de modo:
  --passive-only          Solo descubrimiento pasivo, sin scanners activos
  --active-only           Solo fase activa; requiere --subs-file o --file con subdominios ya conocidos
  --subs-file <path>      Archivo de subdominios para usar directamente en fase activa
"""

__version__ = "1.2.0"

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


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

CNAME_TAKEOVER_PATTERNS = [
    "amazonaws.com",
    "cloudfront.net",
    "herokudns.com",
    "github.io",
    "githubusercontent.com",
    "azurewebsites.net",
    "trafficmanager.net",
    "fastly.net",
    "edgesuite.net",
    "akamai.net",
    "unbouncepages.com",
    "wordpress.com",
    "zendesk.com",
    "shopify.com",
    "helpjuice.com",
    "helpscoutdocs.com",
    "ghost.io",
    "readme.io",
    "surge.sh",
]


# ---------- Banner ---------- #

def print_banner() -> None:
    print("+" + "-" * 54 + "+")
    print("|"
          "  takeovflow  v{}  –  Subdomain Takeover Scanner".format(__version__).ljust(54)
          + "|")
    print("|" + "  by theoffsecgirl".ljust(54) + "|")
    print("+" + "-" * 54 + "+")
    print()


# ---------- Tools ---------- #

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


def run_cmd(cmd: List[str], verbose: bool = False) -> str:
    if verbose:
        print("[cmd] {}".format(" ".join(cmd)))
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return out.decode(errors="ignore")
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


# ---------- Args ---------- #

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="takeovflow v{} - Advanced Subdomain Takeover Scanner".format(__version__)
    )
    target = parser.add_argument_group("targets")
    target.add_argument("-d", "--domain", help="Dominio unico a analizar")
    target.add_argument("-f", "--file", help="Archivo con dominios (uno por linea)")
    target.add_argument("-l", "--list", help="Lista de dominios separada por comas")

    mode = parser.add_argument_group("mode")
    mode.add_argument(
        "--passive-only", action="store_true",
        help="Solo fase pasiva (descubrimiento de subdominios, sin scanners activos)",
    )
    mode.add_argument(
        "--active-only", action="store_true",
        help="Solo fase activa. Requiere --subs-file o --file apuntando a subdominios ya conocidos.",
    )
    mode.add_argument(
        "--subs-file", metavar="PATH",
        help="Archivo con subdominios ya conocidos para usar directamente en fase activa (con --active-only).",
    )

    scan = parser.add_argument_group("scan options")
    scan.add_argument("-t", "--threads", type=int, default=50, help="Hilos (default: 50)")
    scan.add_argument("-r", "--rate", type=int, default=2, help="Rate limit aproximado (default: 2)")
    scan.add_argument("-v", "--verbose", action="store_true", help="Modo verbose")
    scan.add_argument("--json-output", action="store_true", help="Generar informe JSON")
    scan.add_argument("--nuclei-templates", help="Ruta a templates personalizados de nuclei")
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
        print("[!] --active-only requiere --subs-file <archivo_subdominios> o --file <archivo_dominios>.")
        print("    Ejemplo: takeovflow.py --active-only --subs-file subdomains.txt -d example.com")
        sys.exit(1)
    if args.subs_file and not Path(args.subs_file).exists():
        print("[!] --subs-file: archivo no encontrado: {}".format(args.subs_file))
        sys.exit(1)


# ---------- Domains ---------- #

def load_domains_from_file(path: str) -> List[str]:
    domains: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            d = line.strip()
            if d and not d.startswith("#"):
                domains.append(d)
    return domains


def normalize_domains(args: argparse.Namespace) -> List[str]:
    domains: List[str] = []
    if args.domain:
        domains.append(args.domain.strip())
    if args.file and not args.active_only:
        # en active-only, --file son subdominios, no dominios raiz
        domains.extend(load_domains_from_file(args.file))
    if args.list:
        parts = [p.strip() for p in args.list.split(",")]
        domains.extend([p for p in parts if p])

    clean: List[str] = []
    for d in domains:
        d = d.lower()
        for prefix in ("http://", "https://"):
            if d.startswith(prefix):
                d = d[len(prefix):]
        d = d.strip("/")
        if d and d not in clean:
            clean.append(d)

    if not clean and not args.active_only:
        print("[!] No se han proporcionado dominios validos.")
        sys.exit(1)

    return clean


def build_subs_file_from_external(
    path: str, domain: str, tmpdir: Path
) -> Path:
    """Copia el archivo externo de subdominios al tmpdir del dominio."""
    dest = tmpdir / "{}_subdomains_all.txt".format(domain)
    lines = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            sub = line.strip()
            if sub and not sub.startswith("#"):
                lines.append(sub)
    dest.write_text("\n".join(sorted(set(lines))), encoding="utf-8")
    return dest


# ---------- Passive ---------- #

def discover_subdomains(
    domain: str, tmpdir: Path, threads: int, verbose: bool, available: Set[str]
) -> Path:
    combined_out = tmpdir / "{}_subdomains_all.txt".format(domain)
    subs: List[str] = []

    if "subfinder" in available:
        subfinder_out = tmpdir / "{}_subfinder.txt".format(domain)
        run_cmd(["subfinder", "-d", domain, "-silent", "-o", str(subfinder_out)], verbose=verbose)
        if subfinder_out.exists():
            subs += [l.strip() for l in subfinder_out.read_text(errors="ignore").splitlines() if l.strip()]
    elif verbose:
        print("[~] subfinder no disponible, omitiendo.")

    if "assetfinder" in available:
        out = run_cmd(["assetfinder", "--subs-only", domain], verbose=verbose)
        subs += [l.strip() for l in out.splitlines() if l.strip()]
    elif verbose:
        print("[~] assetfinder no disponible, omitiendo.")

    subs = sorted(set(subs))
    combined_out.write_text("\n".join(subs), encoding="utf-8")

    if verbose:
        print("[+] {}: {} subdominios descubiertos (pasivo)".format(domain, len(subs)))

    return combined_out


# ---------- Active ---------- #

def resolve_subdomains(
    domain: str, subs_file: Path, tmpdir: Path,
    threads: int, verbose: bool, available: Set[str]
) -> Dict[str, Any]:
    results: Dict[str, Any] = {"resolved": [], "httpx": []}
    if not subs_file.exists() or subs_file.stat().st_size == 0:
        return results

    if "dnsx" in available:
        dnsx_out = tmpdir / "{}_dnsx.txt".format(domain)
        run_cmd(["dnsx", "-silent", "-resp", "-l", str(subs_file), "-o", str(dnsx_out)], verbose=verbose)
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
        ], verbose=verbose)
        if httpx_out.exists():
            results["httpx"] = [
                {"raw": l.strip()}
                for l in httpx_out.read_text(errors="ignore").splitlines() if l.strip()
            ]
    elif verbose:
        print("[~] httpx no disponible, omitiendo.")

    if verbose:
        print("[+] {}: {} resueltos, {} HTTP".format(
            domain, len(results["resolved"]), len(results["httpx"])
        ))

    return results


def run_subjack(
    domain: str, subs_file: Path, tmpdir: Path,
    verbose: bool, available: Set[str]
) -> List[Dict[str, Any]]:
    if "subjack" not in available:
        if verbose:
            print("[~] subjack no disponible, omitiendo.")
        return []
    if not subs_file.exists() or subs_file.stat().st_size == 0:
        return []

    out_file = tmpdir / "{}_subjack.txt".format(domain)
    fingerprints = tmpdir / "fingerprints.json"

    if not fingerprints.exists() and "curl" in available:
        url = "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json"
        run_cmd(["curl", "-sL", url, "-o", str(fingerprints)], verbose=verbose)

    cmd = ["subjack", "-w", str(subs_file), "-t", "100", "-timeout", "30", "-ssl", "-v", "-o", str(out_file)]
    if fingerprints.exists():
        cmd += ["-c", str(fingerprints)]
    run_cmd(cmd, verbose=verbose)

    findings = []
    if out_file.exists():
        for line in out_file.read_text(errors="ignore").splitlines():
            if line.strip():
                findings.append({"source": "subjack", "raw": line.strip()})
    return findings


def run_nuclei(
    domain: str, subs_file: Path, tmpdir: Path,
    threads: int, templates: Optional[str],
    verbose: bool, available: Set[str]
) -> List[Dict[str, Any]]:
    if "nuclei" not in available:
        if verbose:
            print("[~] nuclei no disponible, omitiendo.")
        return []
    if not subs_file.exists() or subs_file.stat().st_size == 0:
        return []

    out_file = tmpdir / "{}_nuclei.txt".format(domain)
    if templates:
        cmd = ["nuclei", "-silent", "-l", str(subs_file), "-t", templates, "-o", str(out_file), "-c", str(threads)]
    else:
        cmd = ["nuclei", "-silent", "-l", str(subs_file), "-tags", "takeover", "-o", str(out_file), "-c", str(threads)]
    run_cmd(cmd, verbose=verbose)

    findings = []
    if out_file.exists():
        for line in out_file.read_text(errors="ignore").splitlines():
            if line.strip():
                findings.append({"source": "nuclei", "raw": line.strip()})
    return findings


def analyze_cname_patterns(
    domain: str, subs_file: Path, tmpdir: Path,
    verbose: bool, available: Set[str]
) -> List[Dict[str, Any]]:
    if "dig" not in available:
        if verbose:
            print("[~] dig no disponible, omitiendo CNAME.")
        return []
    if not subs_file.exists() or subs_file.stat().st_size == 0:
        return []

    out_file = tmpdir / "{}_cname_patterns.txt".format(domain)
    suspicious: List[str] = []
    findings: List[Dict[str, Any]] = []

    for line in subs_file.read_text(errors="ignore").splitlines():
        sub = line.strip()
        if not sub:
            continue
        cname = run_cmd(["dig", sub, "CNAME", "+short"]).strip()
        if not cname:
            continue
        for pattern in CNAME_TAKEOVER_PATTERNS:
            if pattern in cname:
                suspicious.append("{} -> {}".format(sub, cname))
                findings.append({"source": "cname-pattern", "subdomain": sub, "cname": cname})
                break

    if suspicious:
        out_file.write_text("\n".join(suspicious), encoding="utf-8")

    if verbose:
        print("[+] {}: {} CNAME sospechosos".format(domain, len(findings)))

    return findings


# ---------- Report ---------- #

def build_markdown_report(report_path: Path, summary: Dict[str, Any], verbose: bool) -> None:
    lines: List[str] = []
    lines.append("# Subdomain Takeover Report")
    lines.append("")
    lines.append("Generado: {} UTC".format(datetime.utcnow().isoformat()))
    lines.append("")
    lines.append("## Resumen")
    lines.append("")
    lines.append("- Dominios analizados: **{}**".format(len(summary["domains"])))
    total_subs = sum(len(d.get("subdomains", [])) for d in summary["domains"].values())
    lines.append("- Subdominios descubiertos: **{}**".format(total_subs))
    total_takeovers = sum(len(d.get("potential_takeovers", [])) for d in summary["domains"].values())
    lines.append("- Posibles takeovers: **{}**".format(total_takeovers))
    lines.append("")

    for domain, data in summary["domains"].items():
        lines.append("---")
        lines.append("## Dominio: `{}`".format(domain))
        lines.append("")
        lines.append("- Subdominios: **{}**".format(len(data.get("subdomains", []))))
        lines.append("- Resueltos: **{}**".format(len(data.get("resolved", []))))
        lines.append("- Posibles takeovers: **{}**".format(len(data.get("potential_takeovers", []))))
        lines.append("")

        if data.get("potential_takeovers"):
            lines.append("### Posibles takeovers")
            lines.append("")
            for f in data["potential_takeovers"]:
                src  = f.get("source", "unknown")
                raw  = f.get("raw") or ""
                sub  = f.get("subdomain") or ""
                cname = f.get("cname") or ""
                if raw:
                    lines.append("- **[{}]** {}".format(src, raw))
                else:
                    lines.append("- **[{}]** `{}` -> `{}`".format(src, sub, cname))
            lines.append("")

        if data.get("httpx"):
            lines.append("### Servicios HTTP")
            lines.append("")
            for entry in data["httpx"][:50]:
                lines.append("- `{}`".format(entry.get("raw", "")))
            if len(data["httpx"]) > 50:
                lines.append("- ... ({} mas)".format(len(data["httpx"]) - 50))
            lines.append("")

        if data.get("subdomains"):
            lines.append("### Subdominios (primeros 50)")
            lines.append("")
            for s in data["subdomains"][:50]:
                lines.append("- `{}`".format(s))
            if len(data["subdomains"]) > 50:
                lines.append("- ... ({} mas)".format(len(data["subdomains"]) - 50))
            lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    if verbose:
        print("[+] Informe Markdown: {}".format(report_path))


# ---------- Main ---------- #

def main() -> None:
    print_banner()
    args = parse_args()
    validate_args(args)

    available = check_available_tools(verbose=args.verbose)

    discovery_tools = {"subfinder", "assetfinder"}
    if not discovery_tools & available and not args.active_only:
        print("[!] Sin tools de descubrimiento pasivo. Instala subfinder/assetfinder o usa --active-only --subs-file.")

    domains = normalize_domains(args)

    # En active-only sin dominios raiz, usa un placeholder para el label del report
    if args.active_only and not domains:
        domains = ["scope"]

    if args.verbose:
        print("[+] Dominios: {}\n".format(", ".join(domains)))

    tmpdir = Path(tempfile.mkdtemp(prefix="takeovflow_tmp_"))
    summary: Dict[str, Any] = {"tool": "takeovflow", "version": __version__, "domains": {}}

    for domain in domains:
        if args.verbose:
            print("[*] Analizando: {}".format(domain))

        domain_data: Dict[str, Any] = {}
        subs_file: Optional[Path] = None

        # --- Fase pasiva ---
        if args.active_only:
            # Cargar subdominios desde archivo externo
            src = args.subs_file or args.file
            if src:
                subs_file = build_subs_file_from_external(src, domain, tmpdir)
                domain_data["subdomains"] = [
                    l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()
                ]
                if args.verbose:
                    print("[+] {} subdominios cargados desde {}".format(
                        len(domain_data["subdomains"]), src
                    ))
            else:
                print("[!] --active-only requiere --subs-file o --file.")
                sys.exit(1)
        elif not args.passive_only:
            subs_file = discover_subdomains(domain, tmpdir, args.threads, args.verbose, available)
            domain_data["subdomains"] = [
                l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()
            ] if subs_file and subs_file.exists() else []
        else:
            # passive-only: descubrimiento pero sin fase activa
            subs_file = discover_subdomains(domain, tmpdir, args.threads, args.verbose, available)
            domain_data["subdomains"] = [
                l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()
            ] if subs_file and subs_file.exists() else []

        # --- Fase activa ---
        if not args.passive_only and subs_file and subs_file.exists() and subs_file.stat().st_size > 0:
            resolved_info = resolve_subdomains(
                domain, subs_file, tmpdir, args.threads, args.verbose, available
            )
            domain_data["resolved"] = resolved_info["resolved"]
            domain_data["httpx"]    = resolved_info["httpx"]

            takeovers: List[Dict[str, Any]] = []
            takeovers += run_subjack(domain, subs_file, tmpdir, args.verbose, available)
            takeovers += run_nuclei(
                domain, subs_file, tmpdir, args.threads,
                args.nuclei_templates, args.verbose, available
            )
            takeovers += analyze_cname_patterns(domain, subs_file, tmpdir, args.verbose, available)
            domain_data["potential_takeovers"] = takeovers
        else:
            domain_data.setdefault("resolved", [])
            domain_data.setdefault("httpx", [])
            domain_data.setdefault("potential_takeovers", [])

        summary["domains"][domain] = domain_data
        if args.verbose:
            print()

    now = datetime.utcnow().strftime("%Y%m%d_%H%M")
    report_md = Path.cwd() / "takeovflow_report_{}.md".format(now)
    build_markdown_report(report_md, summary, verbose=args.verbose)

    report_json: Optional[Path] = None
    if args.json_output:
        report_json = Path.cwd() / "takeovflow_report_{}.json".format(now)
        report_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        if args.verbose:
            print("[+] Informe JSON: {}".format(report_json))

    print("[OK] Analisis completado.")
    print("     Informe Markdown : {}".format(report_md))
    if report_json:
        print("     Informe JSON     : {}".format(report_json))


if __name__ == "__main__":
    main()
