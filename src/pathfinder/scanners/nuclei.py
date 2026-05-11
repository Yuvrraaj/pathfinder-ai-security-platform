"""Nuclei wrapper for vulnerability scanning."""
from __future__ import annotations

import json
import subprocess
import tempfile
from typing import TYPE_CHECKING

from rich.console import Console

from pathfinder.config import SAFE_NUCLEI_TAGS, check_tool, get_config
from pathfinder.models import Finding, Severity

if TYPE_CHECKING:
    from pathfinder.models import Session

console = Console()


def severity_from_string(s: str) -> Severity:
    """Convert severity string to Severity enum."""
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return mapping.get(s.lower(), Severity.INFO)


def run_nuclei(hosts: list[str], timeout: int = 300) -> list[dict]:
    """Run nuclei with safe tags only."""
    tool = check_tool("nuclei")
    if not tool.available:
        console.print("[yellow]nuclei not found, using Python fallback checks[/yellow]")
        return run_python_checks(hosts)

    config = get_config()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts))
        hosts_file = f.name

    try:
        cmd = [
            "nuclei",
            "-l", hosts_file,
            "-silent",
            "-json",
            "-tags", ",".join(config.nuclei_tags),
            "-severity", ",".join(config.nuclei_severity),
            "-no-interactsh",
            "-timeout", "10",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        findings = []
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return findings
    except subprocess.TimeoutExpired:
        console.print("[yellow]nuclei timed out[/yellow]")
        return []
    except Exception as e:
        console.print(f"[yellow]nuclei error: {e}[/yellow]")
        return []


def run_python_checks(hosts: list[str]) -> list[dict]:
    """Fallback Python-based security checks."""
    import httpx as httpx_lib

    EXPOSED_PATHS = [
        ("/.env", "Environment file exposed"),
        ("/.git/config", "Git config exposed"),
        ("/admin", "Admin panel accessible"),
        ("/debug", "Debug endpoint accessible"),
        ("/.aws/credentials", "AWS credentials exposed"),
        ("/phpinfo.php", "PHP info exposed"),
        ("/server-status", "Server status exposed"),
        ("/.htpasswd", "htpasswd file exposed"),
        ("/wp-config.php.bak", "WordPress config backup exposed"),
        ("/api/swagger", "Swagger API docs exposed"),
        ("/graphql", "GraphQL endpoint exposed"),
        ("/.DS_Store", "DS_Store file exposed"),
        ("/robots.txt", "Robots.txt (info)"),
    ]

    findings = []

    for host in hosts:
        for scheme in ["https", "http"]:
            base_url = f"{scheme}://{host}"
            try:
                with httpx_lib.Client(timeout=5, verify=False) as client:
                    for path, description in EXPOSED_PATHS:
                        try:
                            resp = client.get(f"{base_url}{path}")
                            if resp.status_code == 200 and len(resp.text) > 0:
                                if path == "/robots.txt":
                                    severity = "info"
                                elif path in ["/.env", "/.git/config", "/.aws/credentials"]:
                                    severity = "critical"
                                elif path in ["/admin", "/debug", "/phpinfo.php"]:
                                    severity = "high"
                                else:
                                    severity = "medium"

                                findings.append({
                                    "host": host,
                                    "template-id": f"python-{path.replace('/', '-').strip('-')}",
                                    "name": description,
                                    "severity": severity,
                                    "matched-at": f"{base_url}{path}",
                                    "description": f"Sensitive path {path} is accessible",
                                })
                        except Exception:
                            continue
                break
            except Exception:
                continue

    return findings


def scan_vulnerabilities(session: Session, timeout: int = 300) -> list[Finding]:
    """Scan for vulnerabilities using nuclei or fallback."""
    live_hosts = [a.hostname for a in session.assets if a.status_code]
    if not live_hosts:
        console.print("[yellow]No live hosts to scan[/yellow]")
        return []

    console.print(f"[bold blue]Scanning {len(live_hosts)} hosts for vulnerabilities...[/bold blue]")
    console.print(f"[dim]Using safe tags only: {', '.join(SAFE_NUCLEI_TAGS)}[/dim]")

    results = run_nuclei(live_hosts, timeout)

    findings = []
    for result in results:
        host = result.get("host", "")
        if "://" in host:
            host = host.split("://")[1].split("/")[0].split(":")[0]

        finding = Finding(
            id=result.get("template-id", "unknown"),
            name=result.get("name", result.get("template-id", "Unknown")),
            severity=severity_from_string(result.get("severity", "info")),
            host=host,
            evidence=result.get("matched-at", ""),
            description=result.get("description", ""),
            source="nuclei" if check_tool("nuclei").available else "python-check",
            template_id=result.get("template-id"),
            tags=result.get("tags", []),
            raw=result,
        )
        findings.append(finding)
        session.add_finding(finding)

    console.print(f"[green]Found {len(findings)} findings[/green]")
    return findings
