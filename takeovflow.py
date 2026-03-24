#!/usr/bin/env python3
"""
takeovflow - Advanced Subdomain Takeover Scanner
by TheOffSecGirl
"""

import argparse
import subprocess
import shutil
import sys
import tempfile
import os
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Set


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
]


def print_banner():
    print("=" * 60)
    print(" takeovflow - Subdomain Takeover Scanner")
    print(" by TheOffSecGirl")
    print("=" * 60)
    print()


def check_available_tools(verbose: bool = False) -> Set[str]:
    """
    Comprueba que tools estan disponibles y cuales faltan.
    NO aborta. Devuelve el set de tools disponibles.
    """
    available = set()
    missing = []

    for tool in ALL_TOOLS:
        if shutil.which(tool):
            available.add(tool)
        else:
            missing.append(tool)

    if missing:
        print(f"[!] Tools no encontradas (se omitiran sus fases): {', '.join(missing)}")
    if verbose and available:
        print(f"[+] Tools disponibles: {', '.join(sorted(available))}")
    print()

    return available


def run_cmd(cmd: List[str], verbose: bool = False) -> str:
    if verbose:
        print(f"[cmd] {' '.join(cmd)}")
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return out.decode(errors="ignore")
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="takeovflow - Advanced Subdomain Takeover Scanner"
    )
    parser.add_argument("-d", "--domain", help="Dominio unico a analizar")
    parser.add_argument("-f", "--file", help="Archivo con dominios (uno por linea)")
    parser.add_argument("-l", "--list", help="Lista de dominios separada por comas")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Hilos (default: 50)")
    parser.add_argument("-r", "--rate", type=int, default=2, help="Rate limit aproximado (default: 2)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose")
    parser.add_argument("--passive-only", action="store_true", help="Solo fase pasiva")
    parser.add_argument("--active-only", action="store_true", help="Solo fase activa")
    parser.add_argument("--json-output", action="store_true", help="Generar informe JSON")
    parser.add_argument("--nuclei-templates", help="Ruta a templates personalizados de nuclei")
    return parser.parse_args()


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
    if args.file:
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

    if not clean:
        print("[!] No se han proporcionado dominios validos.")
        sys.exit(1)

    return clean


def discover_subdomains(
    domain: str, tmpdir: Path, threads: int, verbose: bool, available: Set[str]
) -> Path:
    combined_out = tmpdir / f"{domain}_subdomains_all.txt"
    subs: List[str] = []

    # subfinder
    if "subfinder" in available:
        subfinder_out = tmpdir / f"{domain}_subfinder.txt"
        run_cmd(["subfinder", "-d", domain, "-silent", "-o", str(subfinder_out)], verbose=verbose)
        if subfinder_out.exists():
            subs += [l.strip() for l in subfinder_out.read_text(errors="ignore").splitlines() if l.strip()]
    else:
        if verbose:
            print(f"[~] subfinder no disponible, omitiendo.")

    # assetfinder
    if "assetfinder" in available:
        out = run_cmd(["assetfinder", "--subs-only", domain], verbose=verbose)
        subs += [l.strip() for l in out.splitlines() if l.strip()]
    else:
        if verbose:
            print(f"[~] assetfinder no disponible, omitiendo.")

    subs = sorted(set(subs))
    combined_out.write_text("\n".join(subs), encoding="utf-8")

    if verbose:
        print(f"[+] {domain}: {len(subs)} subdominios descubiertos (pasivo)")

    return combined_out


def resolve_subdomains(
    domain: str, subs_file: Path, tmpdir: Path, threads: int, verbose: bool, available: Set[str]
) -> Dict[str, Any]:
    results: Dict[str, Any] = {"resolved": [], "httpx": []}
    if not subs_file.exists() or subs_file.stat().st_size == 0:
        return results

    # dnsx
    if "dnsx" in available:
        dnsx_out = tmpdir / f"{domain}_dnsx.txt"
        run_cmd(["dnsx", "-silent", "-resp", "-l", str(subs_file), "-o", str(dnsx_out)], verbose=verbose)
        if dnsx_out.exists():
            resolved = [l.split()[0].strip() for l in dnsx_out.read_text(errors="ignore").splitlines() if l.strip()]
            results["resolved"] = sorted(set(resolved))
    else:
        if verbose:
            print(f"[~] dnsx no disponible, usando lista de subdominios sin resolver.")
        results["resolved"] = [l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()]

    # httpx
    if "httpx" in available:
        httpx_out = tmpdir / f"{domain}_httpx.txt"
        run_cmd([
            "httpx", "-silent", "-status-code", "-title", "-follow-redirects",
            "-threads", str(threads), "-l", str(subs_file), "-o", str(httpx_out)
        ], verbose=verbose)
        if httpx_out.exists():
            results["httpx"] = [{"raw": l.strip()} for l in httpx_out.read_text(errors="ignore").splitlines() if l.strip()]
    else:
        if verbose:
            print(f"[~] httpx no disponible, omitiendo deteccion de servicios HTTP.")

    if verbose:
        print(f"[+] {domain}: {len(results['resolved'])} subdominios resueltos")
        print(f"[+] {domain}: {len(results['httpx'])} servicios HTTP detectados")

    return results


def run_subjack(
    domain: str, subs_file: Path, tmpdir: Path, verbose: bool, available: Set[str]
) -> List[Dict[str, Any]]:
    if "subjack" not in available:
        if verbose:
            print(f"[~] subjack no disponible, omitiendo.")
        return []
    if not subs_file.exists() or subs_file.stat().st_size == 0:
        return []

    out_file = tmpdir / f"{domain}_subjack.txt"
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
    domain: str, subs_file: Path, tmpdir: Path, threads: int,
    templates: Optional[str], verbose: bool, available: Set[str]
) -> List[Dict[str, Any]]:
    if "nuclei" not in available:
        if verbose:
            print(f"[~] nuclei no disponible, omitiendo.")
        return []
    if not subs_file.exists() or subs_file.stat().st_size == 0:
        return []

    out_file = tmpdir / f"{domain}_nuclei.txt"
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
    domain: str, subs_file: Path, tmpdir: Path, verbose: bool, available: Set[str]
) -> List[Dict[str, Any]]:
    if "dig" not in available:
        if verbose:
            print(f"[~] dig no disponible, omitiendo analisis CNAME.")
        return []
    if not subs_file.exists() or subs_file.stat().st_size == 0:
        return []

    out_file = tmpdir / f"{domain}_cname_patterns.txt"
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
                suspicious.append(f"{sub} -> {cname}")
                findings.append({"source": "cname-pattern", "subdomain": sub, "cname": cname})
                break

    if suspicious:
        out_file.write_text("\n".join(suspicious), encoding="utf-8")

    if verbose:
        print(f"[+] {domain}: {len(findings)} CNAME sospechosos detectados")

    return findings


def build_markdown_report(report_path: Path, summary: Dict[str, Any], verbose: bool):
    lines: List[str] = []
    lines.append("# Subdomain Takeover Report")
    lines.append("")
    lines.append(f"Generado: {datetime.utcnow().isoformat()} UTC")
    lines.append("")
    lines.append("## Resumen")
    lines.append("")
    lines.append(f"- Dominios analizados: **{len(summary['domains'])}**")
    total_subs = sum(len(d.get("subdomains", [])) for d in summary["domains"].values())
    lines.append(f"- Subdominios descubiertos: **{total_subs}**")
    total_takeovers = sum(len(d.get("potential_takeovers", [])) for d in summary["domains"].values())
    lines.append(f"- Posibles takeovers: **{total_takeovers}**")
    lines.append("")

    for domain, data in summary["domains"].items():
        lines.append("---")
        lines.append(f"## Dominio: `{domain}`")
        lines.append("")
        lines.append(f"- Subdominios descubiertos: **{len(data.get('subdomains', []))}**")
        lines.append(f"- Subdominios resueltos: **{len(data.get('resolved', []))}**")
        lines.append(f"- Posibles takeovers: **{len(data.get('potential_takeovers', []))}**")
        lines.append("")

        if data.get("potential_takeovers"):
            lines.append("### Posibles takeovers")
            lines.append("")
            for f in data["potential_takeovers"]:
                src = f.get("source", "unknown")
                raw = f.get("raw") or ""
                sub = f.get("subdomain") or ""
                cname = f.get("cname") or ""
                if raw:
                    lines.append(f"- **[{src}]** {raw}")
                else:
                    lines.append(f"- **[{src}]** `{sub}` -> `{cname}`")
            lines.append("")

        if data.get("httpx"):
            lines.append("### Servicios HTTP (httpx)")
            lines.append("")
            for entry in data["httpx"][:50]:
                lines.append(f"- `{entry.get('raw', '')}`")
            if len(data["httpx"]) > 50:
                lines.append(f"- ... ({len(data['httpx']) - 50} mas)")
            lines.append("")

        if data.get("subdomains"):
            lines.append("### Subdominios (primeros 50)")
            lines.append("")
            for s in data["subdomains"][:50]:
                lines.append(f"- `{s}`")
            if len(data["subdomains"]) > 50:
                lines.append(f"- ... ({len(data['subdomains']) - 50} mas)")
            lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    if verbose:
        print(f"[+] Informe Markdown: {report_path}")


def main():
    print_banner()
    args = parse_args()

    available = check_available_tools(verbose=args.verbose)

    # Si no hay ninguna tool de descubrimiento, avisa pero no aborta
    discovery_tools = {"subfinder", "assetfinder"}
    if not discovery_tools & available and not args.active_only:
        print("[!] No hay tools de descubrimiento pasivo disponibles (subfinder, assetfinder).")
        print("    Instala al menos una o usa --active-only con un archivo de subdominios.")

    domains = normalize_domains(args)
    if args.verbose:
        print(f"[+] Dominios a analizar: {', '.join(domains)}\n")

    tmpdir = Path(tempfile.mkdtemp(prefix="takeovflow_tmp_"))
    summary: Dict[str, Any] = {"domains": {}}

    for domain in domains:
        if args.verbose:
            print(f"[*] Analizando: {domain}")

        domain_data: Dict[str, Any] = {}
        subs_file: Optional[Path] = None

        if not args.active_only:
            subs_file = discover_subdomains(domain, tmpdir, args.threads, args.verbose, available)
            domain_data["subdomains"] = [
                l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()
            ] if subs_file.exists() else []
        else:
            if args.verbose:
                print("[!] --active-only: fase pasiva omitida.")

        if not args.passive_only and subs_file and subs_file.exists() and subs_file.stat().st_size > 0:
            resolved_info = resolve_subdomains(domain, subs_file, tmpdir, args.threads, args.verbose, available)
            domain_data["resolved"] = resolved_info["resolved"]
            domain_data["httpx"] = resolved_info["httpx"]

            takeovers = []
            takeovers += run_subjack(domain, subs_file, tmpdir, args.verbose, available)
            takeovers += run_nuclei(domain, subs_file, tmpdir, args.threads, args.nuclei_templates, args.verbose, available)
            takeovers += analyze_cname_patterns(domain, subs_file, tmpdir, args.verbose, available)
            domain_data["potential_takeovers"] = takeovers
        else:
            domain_data.setdefault("resolved", [])
            domain_data.setdefault("httpx", [])
            domain_data.setdefault("potential_takeovers", [])

        summary["domains"][domain] = domain_data
        if args.verbose:
            print()

    now = datetime.utcnow().strftime("%Y%m%d")
    report_md = Path.cwd() / f"subdomain_takeover_report_{now}.md"
    build_markdown_report(report_md, summary, verbose=args.verbose)

    report_json = None
    if args.json_output:
        report_json = Path.cwd() / f"subdomain_takeover_report_{now}.json"
        report_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        if args.verbose:
            print(f"[+] Informe JSON: {report_json}")

    print("[OK] Analisis completado.")
    print(f"     Informe Markdown: {report_md}")
    if report_json:
        print(f"     Informe JSON:     {report_json}")


if __name__ == "__main__":
    main()
