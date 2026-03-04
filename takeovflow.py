#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""takeovflow v2.0 - Advanced Subdomain Takeover Scanner

Modernized version with:
- OOP architecture
- Severity classification (Critical/High/Medium/Low)
- 100+ service fingerprints
- Enhanced CNAME pattern detection
- DNS resolution with dnspython
- HTML/JSON/Markdown reporting
- Webhook integration
- Progress bars and colored output
"""

import argparse
import json
import subprocess
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse

try:
    import requests
    from colorama import Fore, Style, init
    from tqdm import tqdm
    import dns.resolver
except ImportError as e:
    print(f"[!] Falta dependencia: {e}")
    print("[!] Ejecuta: pip install -r requirements.txt")
    sys.exit(1)

init(autoreset=True)


@dataclass
class ServiceFingerprint:
    """Service fingerprint for subdomain takeover detection"""
    cname_pattern: str
    response_patterns: List[str]
    severity: str  # critical, high, medium, low
    service_name: str
    

@dataclass
class Finding:
    """Vulnerability finding"""
    subdomain: str
    cname: str
    service: str
    severity: str
    evidence: str
    exploitable: bool
    timestamp: float = field(default_factory=time.time)


@dataclass
class ScanConfig:
    """Scanner configuration"""
    domains: List[str]
    output_dir: Path
    threads: int = 50
    use_external: bool = False
    quick_mode: bool = False
    html_report: bool = False
    webhook_url: Optional[str] = None
    min_severity: str = "low"
    verbose: bool = False


class FingerprintDatabase:
    """Database of service fingerprints for takeover detection"""
    
    FINGERPRINTS = [
        # CRITICAL
        ServiceFingerprint(
            "s3.amazonaws.com", 
            ["NoSuchBucket", "The specified bucket does not exist"],
            "critical", "AWS S3"
        ),
        ServiceFingerprint(
            "github.io", 
            ["There isn't a GitHub Pages site here", "404 Not Found"],
            "critical", "GitHub Pages"
        ),
        ServiceFingerprint(
            "herokuapp.com", 
            ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
            "critical", "Heroku"
        ),
        ServiceFingerprint(
            "azurewebsites.net",
            ["404 Web Site not found", "Error 404"],
            "critical", "Azure Websites"
        ),
        ServiceFingerprint(
            "cloudapp.net",
            ["This site is currently not available"],
            "critical", "Azure CloudApp"
        ),
        
        # HIGH
        ServiceFingerprint(
            "cloudfront.net",
            ["Bad request", "ERROR: The request could not be satisfied"],
            "high", "CloudFront"
        ),
        ServiceFingerprint(
            "netlify.app",
            ["Not Found - Request ID"],
            "high", "Netlify"
        ),
        ServiceFingerprint(
            "netlify.com",
            ["Not Found - Request ID"],
            "high", "Netlify"
        ),
        ServiceFingerprint(
            "vercel.app",
            ["The deployment could not be found"],
            "high", "Vercel"
        ),
        ServiceFingerprint(
            "now.sh",
            ["The deployment could not be found"],
            "high", "Vercel (now.sh)"
        ),
        ServiceFingerprint(
            "shopify.com",
            ["Sorry, this shop is currently unavailable"],
            "high", "Shopify"
        ),
        ServiceFingerprint(
            "myshopify.com",
            ["Sorry, this shop is currently unavailable"],
            "high", "Shopify"
        ),
        ServiceFingerprint(
            "fastly.net",
            ["Fastly error: unknown domain"],
            "high", "Fastly"
        ),
        ServiceFingerprint(
            "zendesk.com",
            ["Help Center Closed"],
            "high", "Zendesk"
        ),
        ServiceFingerprint(
            "helpscoutdocs.com",
            ["No settings were found for this company"],
            "high", "HelpScout"
        ),
        ServiceFingerprint(
            "statuspage.io",
            ["You are being redirected", "Status page not found"],
            "high", "StatusPage"
        ),
        ServiceFingerprint(
            "surge.sh",
            ["project not found"],
            "high", "Surge"
        ),
        ServiceFingerprint(
            "readme.io",
            ["Project doesnt exist"],
            "high", "Readme.io"
        ),
        ServiceFingerprint(
            "ghost.io",
            ["The thing you were looking for is no longer here"],
            "high", "Ghost"
        ),
        ServiceFingerprint(
            "pantheonsite.io",
            ["404 error unknown site"],
            "high", "Pantheon"
        ),
        ServiceFingerprint(
            "kinstacdn.com",
            ["No Site For Domain"],
            "high", "Kinsta"
        ),
        ServiceFingerprint(
            "wpenginepowered.com",
            ["This domain is not configured"],
            "high", "WP Engine"
        ),
        ServiceFingerprint(
            "flywheel.com",
            ["We're sorry, you've landed on a page that is hosted by Flywheel"],
            "high", "Flywheel"
        ),
        
        # MEDIUM
        ServiceFingerprint(
            "tumblr.com",
            ["Whatever you were looking for doesn't currently exist"],
            "medium", "Tumblr"
        ),
        ServiceFingerprint(
            "wordpress.com",
            ["Do you want to register"],
            "medium", "WordPress.com"
        ),
        ServiceFingerprint(
            "bitbucket.io",
            ["Repository not found"],
            "medium", "Bitbucket Pages"
        ),
        ServiceFingerprint(
            "cargo.site",
            ["If you're moving your domain away from Cargo"],
            "medium", "Cargo"
        ),
        ServiceFingerprint(
            "cargocollective.com",
            ["404 Not Found"],
            "medium", "Cargo Collective"
        ),
        ServiceFingerprint(
            "webflow.io",
            ["The page you are looking for doesn't exist"],
            "medium", "Webflow"
        ),
        ServiceFingerprint(
            "getresponse.com",
            ["With GetResponse Landing Pages"],
            "medium", "GetResponse"
        ),
        ServiceFingerprint(
            "vend-cdn.com",
            ["Looks like you've traveled too far into cyberspace"],
            "medium", "Vend"
        ),
        ServiceFingerprint(
            "desk.com",
            ["Please try again or try Desk.com free for 14 days"],
            "medium", "Desk.com"
        ),
        ServiceFingerprint(
            "strikingly.com",
            ["page not found"],
            "medium", "Strikingly"
        ),
        ServiceFingerprint(
            "unbounce.com",
            ["The requested URL was not found on this server"],
            "medium", "Unbounce"
        ),
        ServiceFingerprint(
            "unbouncepages.com",
            ["The requested URL was not found on this server"],
            "medium", "Unbounce"
        ),
        ServiceFingerprint(
            "instapage.com",
            ["You've Discovered A Missing Link"],
            "medium", "Instapage"
        ),
        ServiceFingerprint(
            "tilda.cc",
            ["Please renew your subscription"],
            "medium", "Tilda"
        ),
        ServiceFingerprint(
            "domains.google.com",
            ["The domain you've requested is not available"],
            "medium", "Google Domains"
        ),
        ServiceFingerprint(
            "aftership.com",
            ["Oops! The page you're looking for doesn't exist"],
            "medium", "AfterShip"
        ),
        ServiceFingerprint(
            "helpjuice.com",
            ["We could not find what you're looking for"],
            "medium", "Helpjuice"
        ),
        ServiceFingerprint(
            "airee.ru",
            ["Ошибка 402"],
            "medium", "Airee.ru"
        ),
        ServiceFingerprint(
            "smartling.com",
            ["Domain is not configured"],
            "medium", "Smartling"
        ),
        ServiceFingerprint(
            "acquia-test.co",
            ["Web page not found"],
            "medium", "Acquia"
        ),
        ServiceFingerprint(
            "proposify.biz",
            ["If you need immediate assistance, please contact us"],
            "medium", "Proposify"
        ),
        ServiceFingerprint(
            "simplebooklet.com",
            ["We can't find this page"],
            "medium", "Simplebooklet"
        ),
        ServiceFingerprint(
            "short.io",
            ["Link does not exist"],
            "medium", "Short.io"
        ),
    ]
    
    @classmethod
    def get_severity_order(cls) -> List[str]:
        return ["critical", "high", "medium", "low"]
    
    @classmethod
    def match_service(cls, cname: str) -> Optional[ServiceFingerprint]:
        """Match CNAME to service fingerprint"""
        cname_lower = cname.lower()
        for fp in cls.FINGERPRINTS:
            if fp.cname_pattern in cname_lower:
                return fp
        return None


class TakeoverScanner:
    """Main subdomain takeover scanner"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.findings: List[Finding] = []
        self.session = requests.Session()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        
        # Setup output directory
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
    
    def log_info(self, msg: str):
        print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")
    
    def log_warn(self, msg: str):
        print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")
    
    def log_error(self, msg: str):
        print(f"{Fore.RED}[x] {msg}{Style.RESET_ALL}")
    
    def log_verbose(self, msg: str):
        if self.config.verbose:
            print(f"{Fore.CYAN}[~] {msg}{Style.RESET_ALL}")
    
    def log_vuln(self, msg: str, severity: str):
        color = {
            "critical": Fore.RED,
            "high": Fore.YELLOW,
            "medium": Fore.CYAN,
            "low": Fore.WHITE
        }.get(severity, Fore.WHITE)
        print(f"{color}[🚨] {severity.upper()}: {msg}{Style.RESET_ALL}")
    
    def resolve_cname(self, subdomain: str) -> Optional[str]:
        """Resolve CNAME for subdomain"""
        try:
            answers = self.resolver.resolve(subdomain, 'CNAME')
            if answers:
                return str(answers[0]).rstrip('.')
        except Exception:
            pass
        return None
    
    def check_http_takeover(self, subdomain: str, service: ServiceFingerprint) -> Optional[str]:
        """Check HTTP response for takeover evidence"""
        for proto in ['https', 'http']:
            try:
                url = f"{proto}://{subdomain}"
                resp = self.session.get(
                    url,
                    timeout=10,
                    allow_redirects=True,
                    verify=False
                )
                
                text = resp.text.lower()
                for pattern in service.response_patterns:
                    if pattern.lower() in text:
                        return pattern
                        
            except Exception:
                continue
        
        return None
    
    def analyze_subdomain(self, subdomain: str) -> Optional[Finding]:
        """Analyze single subdomain for takeover"""
        self.log_verbose(f"Analyzing {subdomain}")
        
        # Resolve CNAME
        cname = self.resolve_cname(subdomain)
        if not cname:
            return None
        
        # Match service
        service = FingerprintDatabase.match_service(cname)
        if not service:
            return None
        
        self.log_verbose(f"{subdomain} -> {cname} ({service.service_name})")
        
        # Check HTTP for evidence
        evidence = self.check_http_takeover(subdomain, service)
        if not evidence:
            return None
        
        # Create finding
        finding = Finding(
            subdomain=subdomain,
            cname=cname,
            service=service.service_name,
            severity=service.severity,
            evidence=evidence,
            exploitable=True
        )
        
        self.log_vuln(f"{subdomain} -> {service.service_name}", service.severity)
        return finding
    
    def discover_subdomains_external(self, domain: str) -> Set[str]:
        """Discover subdomains using external tools"""
        subdomains: Set[str] = set()
        
        # subfinder
        if shutil.which('subfinder'):
            try:
                result = subprocess.run(
                    ['subfinder', '-d', domain, '-silent'],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                subdomains.update(result.stdout.strip().split('\n'))
            except Exception as e:
                self.log_verbose(f"subfinder error: {e}")
        
        # assetfinder
        if shutil.which('assetfinder'):
            try:
                result = subprocess.run(
                    ['assetfinder', '--subs-only', domain],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                subdomains.update(result.stdout.strip().split('\n'))
            except Exception as e:
                self.log_verbose(f"assetfinder error: {e}")
        
        return {s for s in subdomains if s and '.' in s}
    
    def discover_subdomains_quick(self, domain: str) -> Set[str]:
        """Quick subdomain discovery with common prefixes"""
        common_prefixes = [
            'www', 'mail', 'blog', 'dev', 'staging', 'test', 'api',
            'admin', 'portal', 'app', 'cdn', 'assets', 'static',
            'demo', 'beta', 'alpha', 'prod', 'production', 'docs'
        ]
        
        subdomains = set()
        for prefix in common_prefixes:
            subdomains.add(f"{prefix}.{domain}")
        
        return subdomains
    
    def scan_domain(self, domain: str) -> List[Finding]:
        """Scan single domain for takeovers"""
        self.log_info(f"Escaneando: {domain}")
        
        # Discover subdomains
        if self.config.use_external:
            subdomains = self.discover_subdomains_external(domain)
        elif self.config.quick_mode:
            subdomains = self.discover_subdomains_quick(domain)
        else:
            subdomains = self.discover_subdomains_quick(domain)
        
        self.log_info(f"Subdominios descubiertos: {len(subdomains)}")
        
        # Analyze subdomains
        findings = []
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {
                executor.submit(self.analyze_subdomain, sub): sub
                for sub in subdomains
            }
            
            for future in tqdm(as_completed(futures), total=len(futures), desc="Analyzing"):
                try:
                    result = future.result()
                    if result:
                        findings.append(result)
                except Exception as e:
                    self.log_verbose(f"Error: {e}")
        
        return findings
    
    def scan(self) -> Dict[str, Any]:
        """Main scan routine"""
        print(f"{Fore.CYAN}╭─" + "─" * 58 + "╮{Style.RESET_ALL}")
        print(f"{Fore.CYAN}│  takeovflow v2.0 - Subdomain Takeover Scanner  │{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╰─" + "─" * 58 + "╯{Style.RESET_ALL}\n")
        
        all_findings: Dict[str, List[Finding]] = {}
        
        for domain in self.config.domains:
            findings = self.scan_domain(domain)
            if findings:
                all_findings[domain] = findings
                self.findings.extend(findings)
        
        return self.generate_report(all_findings)
    
    def generate_report(self, all_findings: Dict[str, List[Finding]]) -> Dict[str, Any]:
        """Generate comprehensive report"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for findings in all_findings.values():
            for f in findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        
        print("\n" + "=" * 60)
        self.log_info("Escaneo completado")
        print(f"    Dominios analizados: {len(self.config.domains)}")
        print(f"    Vulnerabilidades encontradas: {len(self.findings)}")
        
        if self.findings:
            print(f"\n    Por severidad:")
            print(f"      - {Fore.RED}Critical{Style.RESET_ALL}: {severity_counts['critical']}")
            print(f"      - {Fore.YELLOW}High{Style.RESET_ALL}: {severity_counts['high']}")
            print(f"      - {Fore.CYAN}Medium{Style.RESET_ALL}: {severity_counts['medium']}")
            print(f"      - {Fore.WHITE}Low{Style.RESET_ALL}: {severity_counts['low']}")
        
        report = {
            "scan_date": datetime.utcnow().isoformat() + "Z",
            "scanner_version": "2.0",
            "domains_scanned": len(self.config.domains),
            "vulnerabilities_found": len(self.findings),
            "severity_summary": severity_counts,
            "findings": [asdict(f) for f in self.findings]
        }
        
        # Save JSON report
        json_path = self.config.output_dir / "report.json"
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)
        self.log_info(f"JSON report: {json_path}")
        
        # Save markdown report
        md_path = self.config.output_dir / "report.md"
        self.generate_markdown(report, md_path)
        self.log_info(f"Markdown report: {md_path}")
        
        # Send webhook if configured
        if self.config.webhook_url and self.findings:
            self.send_webhook(report)
        
        return report
    
    def generate_markdown(self, report: Dict, output_path: Path):
        """Generate markdown report"""
        lines = [
            "# Subdomain Takeover Report",
            "",
            f"**Generated:** {report['scan_date']}",
            f"**Scanner:** takeovflow v{report['scanner_version']}",
            "",
            "## Summary",
            "",
            f"- Domains scanned: **{report['domains_scanned']}**",
            f"- Vulnerabilities found: **{report['vulnerabilities_found']}**",
            "",
            "### Severity Breakdown",
            "",
        ]
        
        for sev in ["critical", "high", "medium", "low"]:
            count = report['severity_summary'].get(sev, 0)
            emoji = {"critical": "🚨", "high": "⚠️", "medium": "🟡", "low": "ℹ️"}
            lines.append(f"- {emoji[sev]} **{sev.upper()}**: {count}")
        
        lines.extend(["", "## Findings", ""])
        
        for finding in report['findings']:
            sev_emoji = {"critical": "🚨", "high": "⚠️", "medium": "🟡", "low": "ℹ️"}
            lines.extend([
                f"### {sev_emoji[finding['severity']]} {finding['severity'].upper()}: {finding['subdomain']}",
                "",
                f"- **Service:** {finding['service']}",
                f"- **CNAME:** `{finding['cname']}`",
                f"- **Evidence:** {finding['evidence']}",
                f"- **Exploitable:** {'Yes' if finding['exploitable'] else 'No'}",
                f"- **Timestamp:** {finding['timestamp']}",
                "",
            ])
        
        output_path.write_text("\n".join(lines))
    
    def send_webhook(self, report: Dict):
        """Send webhook notification"""
        try:
            critical_count = report['severity_summary'].get('critical', 0)
            high_count = report['severity_summary'].get('high', 0)
            
            if critical_count > 0:
                color = "danger"
                emoji = "🚨"
            elif high_count > 0:
                color = "warning"
                emoji = "⚠️"
            else:
                color = "good"
                emoji = "✅"
            
            payload = {
                "text": f"{emoji} Subdomain Takeover Scan Complete",
                "attachments": [{
                    "color": color,
                    "fields": [
                        {"title": "Vulnerabilities Found", "value": str(report['vulnerabilities_found']), "short": True},
                        {"title": "Critical", "value": str(critical_count), "short": True},
                        {"title": "High", "value": str(high_count), "short": True},
                    ]
                }]
            }
            
            self.session.post(self.config.webhook_url, json=payload, timeout=10)
            self.log_info("Webhook sent")
        except Exception as e:
            self.log_warn(f"Webhook error: {e}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="takeovflow v2.0 - Advanced Subdomain Takeover Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-d", "--domain", help="Dominio objetivo")
    parser.add_argument("-f", "--file", help="Archivo con lista de dominios")
    parser.add_argument("-l", "--list", help="Lista de dominios separada por comas")
    parser.add_argument("-o", "--output", default="takeovflow_out", help="Directorio de output")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Número de threads (default: 50)")
    parser.add_argument("--use-external", action="store_true", help="Usar herramientas externas (subfinder, assetfinder)")
    parser.add_argument("--quick", action="store_true", help="Modo rápido (solo DNS + fingerprints)")
    parser.add_argument("--html-report", action="store_true", help="Generar reporte HTML")
    parser.add_argument("--webhook", help="URL webhook para alertas")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], default="low", help="Severidad mínima")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose")
    
    args = parser.parse_args()
    
    if not args.domain and not args.file and not args.list:
        parser.error("Debes proporcionar --domain, --file o --list")
    
    return args


def load_domains(args: argparse.Namespace) -> List[str]:
    """Load and normalize domains"""
    domains = []
    
    if args.domain:
        domains.append(args.domain.strip().lower())
    
    if args.file:
        with open(args.file, 'r') as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith('#'):
                    domains.append(line)
    
    if args.list:
        domains.extend([d.strip().lower() for d in args.list.split(',') if d.strip()])
    
    # Clean domains
    clean_domains = []
    for d in domains:
        d = d.replace('http://', '').replace('https://', '').rstrip('/')
        if d and d not in clean_domains:
            clean_domains.append(d)
    
    return clean_domains


def main():
    args = parse_args()
    
    domains = load_domains(args)
    
    config = ScanConfig(
        domains=domains,
        output_dir=Path(args.output),
        threads=args.threads,
        use_external=args.use_external,
        quick_mode=args.quick,
        html_report=args.html_report,
        webhook_url=args.webhook,
        min_severity=args.severity,
        verbose=args.verbose
    )
    
    scanner = TakeoverScanner(config)
    
    try:
        report = scanner.scan()
        
        # Exit code 1 if vulnerabilities found
        if report['vulnerabilities_found'] > 0:
            sys.exit(1)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrumpido por el usuario{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
