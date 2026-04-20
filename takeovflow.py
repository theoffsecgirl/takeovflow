#!/usr/bin/env python3
"""
takeovflow - Advanced Subdomain Takeover Scanner

Flujo:
  [PASIVA]  subfinder + assetfinder -> deduplicacion
  [ACTIVA]  dnsx -> httpx -> subjack -> nuclei -> CNAME patterns (concurrente)
  [OUTPUT]  Markdown + JSON + normalized JSON/JSONL (opcional)
"""

__version__ = "1.6.1"

import argparse
import json
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

_QUIET: bool = False


def log(msg: str, force: bool = False) -> None:
    if not _QUIET or force:
        print(msg, file=sys.stderr)


def signal_handler(sig, frame):  # type: ignore
    log("[!] Interrumpido por el usuario.", force=True)
    sys.exit(130)


signal.signal(signal.SIGINT, signal_handler)

ALL_TOOLS = [
    "subfinder", "assetfinder", "subjack", "dnsx", "httpx",
    "nuclei", "dig", "jq", "curl",
]

CNAME_SERVICES: List[Tuple[str, str, str]] = [
    ("amazonaws.com", "AWS S3 / Elastic Beanstalk", "HIGH"),
    ("cloudfront.net", "AWS CloudFront", "MEDIUM"),
    ("elasticbeanstalk.com", "AWS Elastic Beanstalk", "HIGH"),
    ("azurewebsites.net", "Azure Web Apps", "HIGH"),
    ("trafficmanager.net", "Azure Traffic Manager", "HIGH"),
    ("blob.core.windows.net", "Azure Blob Storage", "HIGH"),
    ("azure-api.net", "Azure API Management", "MEDIUM"),
    ("cloudapp.net", "Azure Cloud App", "MEDIUM"),
    ("herokudns.com", "Heroku", "HIGH"),
    ("herokuapp.com", "Heroku", "HIGH"),
    ("github.io", "GitHub Pages", "HIGH"),
    ("githubusercontent.com", "GitHub Raw", "MEDIUM"),
    ("fastly.net", "Fastly CDN", "HIGH"),
    ("edgesuite.net", "Akamai", "MEDIUM"),
    ("akamai.net", "Akamai", "MEDIUM"),
    ("akamaized.net", "Akamai", "MEDIUM"),
    ("unbouncepages.com", "Unbounce", "HIGH"),
    ("wordpress.com", "WordPress.com", "HIGH"),
    ("zendesk.com", "Zendesk", "HIGH"),
    ("shopify.com", "Shopify", "HIGH"),
    ("helpjuice.com", "HelpJuice", "HIGH"),
    ("helpscoutdocs.com", "HelpScout Docs", "HIGH"),
    ("ghost.io", "Ghost", "HIGH"),
    ("readme.io", "ReadMe.io", "HIGH"),
    ("surge.sh", "Surge.sh", "HIGH"),
    ("strikingly.com", "Strikingly", "HIGH"),
    ("squarespace.com", "Squarespace", "MEDIUM"),
    ("wixdns.net", "Wix", "MEDIUM"),
    ("weebly.com", "Weebly", "HIGH"),
    ("tilda.ws", "Tilda", "HIGH"),
    ("webflow.io", "Webflow", "HIGH"),
    ("netlify.app", "Netlify", "HIGH"),
    ("netlify.com", "Netlify", "HIGH"),
    ("vercel.app", "Vercel", "HIGH"),
    ("gitbook.io", "GitBook", "HIGH"),
    ("gitbook.com", "GitBook", "HIGH"),
    ("statuspage.io", "Atlassian Statuspage", "HIGH"),
    ("uservoice.com", "UserVoice", "HIGH"),
    ("desk.com", "Salesforce Desk", "HIGH"),
    ("freshdesk.com", "Freshdesk", "HIGH"),
    ("intercom.help", "Intercom", "HIGH"),
    ("cargo.site", "Cargo", "HIGH"),
    ("pantheonsite.io", "Pantheon", "HIGH"),
    ("kinsta.cloud", "Kinsta", "HIGH"),
    ("flywheel.io", "Flywheel", "HIGH"),
    ("myshopify.com", "Shopify", "HIGH"),
    ("hubspot.com", "HubSpot", "MEDIUM"),
    ("hs-sites.com", "HubSpot Sites", "HIGH"),
    ("bitbucket.io", "Bitbucket Pages", "HIGH"),
    ("smartling.com", "Smartling", "HIGH"),
    ("launchrock.com", "Launchrock", "HIGH"),
    ("aftership.com", "AfterShip", "HIGH"),
    ("sprintful.com", "Sprintful", "HIGH"),
    ("bigcartel.com", "Big Cartel", "HIGH"),
    ("feedpress.me", "FeedPress", "HIGH"),
    ("cargocollective.com", "Cargo Collective", "HIGH"),
    ("simplebooklet.com", "SimpleBooklet", "HIGH"),
    ("acquia-sites.com", "Acquia", "HIGH"),
]

SEVERITY_COLOR = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "INFO"}
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    source = finding.get("source", "unknown")
    sub = finding.get("subdomain") or (finding.get("raw", "").split()[0] if finding.get("raw") else "")
    service = finding.get("service") or "unknown"
    severity = finding.get("severity", "INFO").lower()

    confidence = "low"
    reason = "generic takeover signal"
    evidence: List[str] = []
    tags = ["takeover"]

    if source == "cname-pattern":
        confidence = "medium"
        reason = f"CNAME points to a known takeover-prone provider ({service})"
        evidence = [f"cname match: {finding.get('cname', '')}", f"provider fingerprint: {service}"]
        tags += ["cname-pattern", service.lower().replace(" ", "-")]
    elif source == "subjack":
        confidence = "high"
        reason = "subjack reported a likely takeover"
        evidence = [finding.get("raw", "")]
        tags.append("subjack")
    elif source == "nuclei":
        confidence = "high" if finding.get("severity") in ["CRITICAL", "HIGH"] else "medium"
        reason = "nuclei takeover template matched"
        evidence = [finding.get("raw", "")]
        tags.append("nuclei")

    return {
        "type": "candidate",
        "vector": "subdomain_takeover",
        "target": sub,
        "host": sub,
        "method": "DNS/HTTP",
        "param": None,
        "severity": severity,
        "confidence": confidence,
        "reason": reason,
        "evidence": evidence,
        "tags": tags,
        "raw": finding,
    }


def serialize_findings(findings: List[Dict[str, Any]], fmt: str) -> str:
    if fmt == "jsonl":
        return "\n".join(json.dumps(f, ensure_ascii=False) for f in findings)
    return json.dumps(findings, indent=2, ensure_ascii=False)


def write_normalized_output(findings: List[Dict[str, Any]], fmt: str, stdout: bool = False, output_path: Optional[Path] = None) -> None:
    payload = serialize_findings(findings, fmt)
    if stdout:
        print(payload)
    if output_path:
        output_path.write_text(payload, encoding="utf-8")
        log(f"[+] Findings normalizados: {output_path}")


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
    return available


def _subjack_supports_flag(flag: str) -> bool:
    try:
        result = subprocess.run(["subjack"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        output = (result.stdout + result.stderr).decode(errors="ignore")
        return flag in output
    except Exception:
        return False


def run_cmd(cmd: List[str], verbose: bool = False, capture_stderr: bool = False, timeout: int = 300, retries: int = 1) -> str:
    if verbose:
        log("[cmd] {}".format(" ".join(cmd)))
    stderr_pipe = subprocess.PIPE if capture_stderr else subprocess.DEVNULL
    for attempt in range(max(retries, 1)):
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=stderr_pipe, timeout=timeout)
            if capture_stderr and result.returncode != 0 and verbose:
                err = result.stderr.decode(errors="ignore").strip()
                if err:
                    log("[stderr] {}".format(err[:400]))
            return result.stdout.decode(errors="ignore")
        except subprocess.TimeoutExpired:
            if verbose:
                log("[!] Timeout ({} s) intento {}/{}: {}".format(timeout, attempt + 1, retries, " ".join(cmd[:3])))
        except FileNotFoundError:
            return ""
        except Exception as exc:
            if verbose:
                log("[!] Error inesperado (intento {}/{}): {}".format(attempt + 1, retries, exc))
    return ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="takeovflow v{} - Advanced Subdomain Takeover Scanner".format(__version__))
    target = parser.add_argument_group("targets")
    target.add_argument("-d", "--domain", help="Dominio único a analizar")
    target.add_argument("-f", "--file", help="Archivo con dominios (uno por línea)")
    target.add_argument("-l", "--list", help="Lista de dominios separada por comas")

    mode = parser.add_argument_group("mode")
    mode.add_argument("--passive-only", action="store_true")
    mode.add_argument("--active-only", action="store_true")
    mode.add_argument("--subs-file", metavar="PATH")

    scan = parser.add_argument_group("scan options")
    scan.add_argument("-t", "--threads", type=int, default=50)
    scan.add_argument("-r", "--rate", type=int, default=150)
    scan.add_argument("--timeout", type=int, default=30)
    scan.add_argument("--retries", type=int, default=2)
    scan.add_argument("--resolvers", metavar="FILE")
    scan.add_argument("-v", "--verbose", action="store_true")
    scan.add_argument("-q", "--quiet", action="store_true")
    scan.add_argument("--no-color", action="store_true")
    scan.add_argument("--json-output", action="store_true", help="Generar informe JSON clásico y findings normalizados")
    scan.add_argument("--output-dir", metavar="DIR")
    scan.add_argument("--nuclei-templates")
    scan.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], default="INFO")
    scan.add_argument("--format", choices=["json", "jsonl"], default="json", help="Formato de findings normalizados")
    scan.add_argument("--stdout", action="store_true", help="Enviar findings normalizados a stdout")
    parser.add_argument("--version", action="version", version="takeovflow {}".format(__version__))
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
        log("[!] No se han proporcionado dominios válidos.", force=True)
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


def discover_subdomains(domain: str, tmpdir: Path, threads: int, verbose: bool, available: Set[str], timeout: int = 120) -> Path:
    combined_out = tmpdir / "{}_subdomains_all.txt".format(domain)
    subs: List[str] = []
    if "subfinder" in available:
        subfinder_out = tmpdir / "{}_subfinder.txt".format(domain)
        run_cmd(["subfinder", "-d", domain, "-silent", "-o", str(subfinder_out)], verbose=verbose, timeout=timeout)
        if subfinder_out.exists():
            subs += [l.strip() for l in subfinder_out.read_text(errors="ignore").splitlines() if l.strip()]
    if "assetfinder" in available:
        out = run_cmd(["assetfinder", "--subs-only", domain], verbose=verbose, timeout=timeout)
        subs += [l.strip() for l in out.splitlines() if l.strip()]
    subs = sorted(set(s for s in subs if s and "." in s))
    combined_out.write_text("\n".join(subs), encoding="utf-8")
    log("[+] {}: {} subdominios (pasivo)".format(domain, len(subs)))
    return combined_out


def resolve_subdomains(domain: str, subs_file: Path, tmpdir: Path, threads: int, rate: int, verbose: bool, available: Set[str], resolvers: Optional[str] = None, timeout: int = 60, retries: int = 2) -> Dict[str, Any]:
    results: Dict[str, Any] = {"resolved": [], "httpx": []}
    if not subs_file.exists() or subs_file.stat().st_size == 0:
        return results
    if "dnsx" in available:
        dnsx_out = tmpdir / "{}_dnsx.txt".format(domain)
        cmd = ["dnsx", "-silent", "-resp", "-l", str(subs_file), "-o", str(dnsx_out), "-t", str(threads), "-rl", str(rate)]
        if resolvers:
            cmd += ["-r", resolvers]
        run_cmd(cmd, verbose=verbose, capture_stderr=verbose, timeout=timeout, retries=retries)
        if dnsx_out.exists():
            resolved = [l.split()[0].strip() for l in dnsx_out.read_text(errors="ignore").splitlines() if l.strip()]
            results["resolved"] = sorted(set(resolved))
    else:
        results["resolved"] = [l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()]
    if "httpx" in available:
        httpx_out = tmpdir / "{}_httpx.txt".format(domain)
        run_cmd(["httpx", "-silent", "-status-code", "-title", "-follow-redirects", "-threads", str(threads), "-rate", str(rate), "-l", str(subs_file), "-o", str(httpx_out)], verbose=verbose, capture_stderr=verbose, timeout=timeout, retries=retries)
        if httpx_out.exists():
            results["httpx"] = [{"raw": l.strip()} for l in httpx_out.read_text(errors="ignore").splitlines() if l.strip()]
    return results


def run_subjack(domain: str, subs_file: Path, tmpdir: Path, verbose: bool, available: Set[str], timeout: int = 120, retries: int = 2) -> List[Dict[str, Any]]:
    if "subjack" not in available or not subs_file.exists() or subs_file.stat().st_size == 0:
        return []
    out_file = tmpdir / "{}_subjack.txt".format(domain)
    fingerprints = tmpdir / "fingerprints.json"
    supports_c = _subjack_supports_flag("-c")
    if supports_c and not fingerprints.exists() and "curl" in available:
        run_cmd(["curl", "-sL", "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json", "-o", str(fingerprints)], verbose=verbose, timeout=30)
    cmd = ["subjack", "-w", str(subs_file), "-t", "100", "-timeout", str(timeout), "-ssl", "-v", "-o", str(out_file)]
    if supports_c and fingerprints.exists():
        cmd += ["-c", str(fingerprints)]
    run_cmd(cmd, verbose=verbose, capture_stderr=verbose, timeout=timeout * 2, retries=retries)
    findings = []
    if out_file.exists():
        for line in out_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line:
                findings.append({"source": "subjack", "severity": "HIGH", "raw": line})
                log("  [subjack] {}".format(line))
    return findings


def run_nuclei(domain: str, subs_file: Path, tmpdir: Path, threads: int, templates: Optional[str], verbose: bool, available: Set[str], timeout: int = 120, retries: int = 2) -> List[Dict[str, Any]]:
    if "nuclei" not in available or not subs_file.exists() or subs_file.stat().st_size == 0:
        return []
    out_file = tmpdir / "{}_nuclei.txt".format(domain)
    if templates:
        cmd = ["nuclei", "-silent", "-l", str(subs_file), "-t", templates, "-o", str(out_file), "-c", str(threads)]
    else:
        cmd = ["nuclei", "-silent", "-l", str(subs_file), "-tags", "takeover", "-o", str(out_file), "-c", str(threads)]
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
                    severity = lvl if lvl in _SEVERITY_ORDER else "HIGH"
                findings.append({"source": "nuclei", "severity": severity, "raw": line})
                log("  [nuclei] {}".format(line))
    return findings


def _check_cname_single(sub: str, verbose: bool, timeout: int = 10) -> Optional[Dict[str, Any]]:
    try:
        result = subprocess.run(["dig", sub, "CNAME", "+short"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
        cname = result.stdout.decode(errors="ignore").strip().lower()
    except Exception:
        return None
    if not cname:
        return None
    for pattern, service, severity in CNAME_SERVICES:
        if pattern in cname:
            return {"source": "cname-pattern", "subdomain": sub, "cname": cname, "service": service, "severity": severity}
    return None


def analyze_cname_patterns(domain: str, subs_file: Path, tmpdir: Path, verbose: bool, available: Set[str], threads: int = 50, dig_timeout: int = 10) -> List[Dict[str, Any]]:
    if "dig" not in available or not subs_file.exists() or subs_file.stat().st_size == 0:
        return []
    subdomains = [l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()]
    findings: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_check_cname_single, sub, verbose, dig_timeout): sub for sub in subdomains}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)
                line = "{} -> {} [{}]".format(result["subdomain"], result["cname"], result["service"])
                log("  [cname] {}".format(line))
    log("[+] {}: {} CNAMEs sospechosos".format(domain, len(findings)))
    return findings


def deduplicate_takeovers(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    unique: List[Dict[str, Any]] = []
    for f in findings:
        sub = f.get("subdomain") or ""
        if not sub and f.get("raw"):
            sub = f["raw"].split()[0]
        key = "{}:{}".format(f.get("source", ""), sub)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def filter_by_severity(findings: List[Dict[str, Any]], min_severity: str) -> List[Dict[str, Any]]:
    threshold = _SEVERITY_ORDER.get(min_severity, 4)
    return [f for f in findings if _SEVERITY_ORDER.get(f.get("severity", "INFO"), 4) <= threshold]


def build_markdown_report(report_path: Path, summary: Dict[str, Any], verbose: bool) -> None:
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
    total_subs = sum(len(d.get("subdomains", [])) for d in summary["domains"].values())
    total_takeovers = sum(len(d.get("potential_takeovers", [])) for d in summary["domains"].values())
    lines.append("| Subdominios descubiertos | **{}** |".format(total_subs))
    lines.append("| Posibles takeovers | **{}** |".format(total_takeovers))
    lines.append("")
    report_path.write_text("\n".join(lines), encoding="utf-8")
    if verbose:
        log("[+] Informe Markdown: {}".format(report_path))


def main() -> None:
    global _QUIET
    args = parse_args()
    _QUIET = args.quiet
    validate_args(args)
    available = check_available_tools(verbose=args.verbose)
    domains = normalize_domains(args)
    if args.active_only and not domains:
        domains = ["scope"]
    output_dir = Path(args.output_dir) if args.output_dir else Path.cwd()

    with tempfile.TemporaryDirectory(prefix="takeovflow_tmp_") as _tmpdir:
        tmpdir = Path(_tmpdir)
        summary: Dict[str, Any] = {"tool": "takeovflow", "version": __version__, "started": datetime.now(timezone.utc).isoformat(timespec="seconds"), "domains": {}}
        normalized_all: List[Dict[str, Any]] = []

        for domain in domains:
            log("[*] Analizando: {}".format(domain))
            domain_data: Dict[str, Any] = {}
            subs_file: Optional[Path] = None

            if args.active_only:
                src = args.subs_file or args.file
                if src:
                    subs_file = build_subs_file_from_external(src, domain, tmpdir)
                    domain_data["subdomains"] = [l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()]
                else:
                    log("[!] --active-only requiere --subs-file o --file.", force=True)
                    sys.exit(1)
            else:
                subs_file = discover_subdomains(domain, tmpdir, args.threads, args.verbose, available, timeout=120)
                domain_data["subdomains"] = [l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()] if subs_file and subs_file.exists() else []

            if not args.passive_only and subs_file and subs_file.exists() and subs_file.stat().st_size > 0:
                resolved_info = resolve_subdomains(domain, subs_file, tmpdir, args.threads, args.rate, args.verbose, available, resolvers=args.resolvers, timeout=args.timeout * 2, retries=args.retries)
                domain_data["resolved"] = resolved_info["resolved"]
                domain_data["httpx"] = resolved_info["httpx"]

                takeovers: List[Dict[str, Any]] = []
                takeovers += run_subjack(domain, subs_file, tmpdir, args.verbose, available, timeout=args.timeout * 4, retries=args.retries)
                takeovers += run_nuclei(domain, subs_file, tmpdir, args.threads, args.nuclei_templates, args.verbose, available, timeout=args.timeout * 4, retries=args.retries)
                takeovers += analyze_cname_patterns(domain, subs_file, tmpdir, args.verbose, available, threads=args.threads, dig_timeout=args.timeout)
                takeovers = filter_by_severity(deduplicate_takeovers(takeovers), args.min_severity)
                domain_data["potential_takeovers"] = takeovers
                normalized_all.extend(normalize_finding(f) for f in takeovers)
            else:
                domain_data.setdefault("resolved", [])
                domain_data.setdefault("httpx", [])
                domain_data.setdefault("potential_takeovers", [])

            summary["domains"][domain] = domain_data

        now = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
        report_md = output_dir / "takeovflow_report_{}.md".format(now)
        report_json: Optional[Path] = None
        findings_out: Optional[Path] = None

        build_markdown_report(report_md, summary, verbose=args.verbose)

        if args.json_output:
            report_json = output_dir / "takeovflow_report_{}.json".format(now)
            summary["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            report_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
            findings_out = output_dir / "takeovflow_findings_{}.{}".format(now, args.format)
            write_normalized_output(normalized_all, fmt=args.format, stdout=False, output_path=findings_out)
            if args.verbose:
                log("[+] Informe JSON: {}".format(report_json))

        if args.stdout:
            write_normalized_output(normalized_all, fmt=args.format, stdout=True, output_path=None)

        log("[OK] Análisis completado.")
        log("     Markdown  : {}".format(report_md))
        if report_json:
            log("     JSON      : {}".format(report_json))
        if findings_out:
            log("     Findings  : {}".format(findings_out))
        total_findings = len(normalized_all)
        if total_findings:
            log("     {} posible(s) takeover(s) encontrado(s)".format(total_findings))
        else:
            log("     Sin takeovers detectados")


if __name__ == "__main__":
    main()
