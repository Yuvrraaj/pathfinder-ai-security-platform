"""PathFinder CLI - AI-Assisted External Assessment Platform."""
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from pathfinder.config import check_all_tools, get_config
from pathfinder.models import Session

app = typer.Typer(
    name="pathfinder",
    help="AI-Assisted External Assessment Platform",
    add_completion=False,
)
console = Console()


def print_banner() -> None:
    """Print the PathFinder banner."""
    banner = """[bold cyan]
 ██████╗  █████╗ ████████╗██╗  ██╗███████╗██╗███╗   ██╗██████╗ ███████╗██████╗
 ██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
 ██████╔╝███████║   ██║   ███████║█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
 ██╔═══╝ ██╔══██║   ██║   ██╔══██║██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
 ██║     ██║  ██║   ██║   ██║  ██║██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
 ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
[/bold cyan][dim]AI-Assisted External Assessment Platform • See the attack before it happens[/dim]
"""
    console.print(banner)


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Target domain to scan"),
    passive_only: bool = typer.Option(False, "--passive-only", "-p", help="Only run passive recon"),
    skip_approval: bool = typer.Option(False, "--yes", "-y", help="Skip approval prompt (use with caution)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Run end-to-end scan on a target domain.

    MODE A: PathFinder runs the full pipeline:
    1. Passive recon (Subfinder/crt.sh)
    2. [Optional] Active probing (httpx + Nuclei) with approval
    3. AI analysis and attack path synthesis
    """
    print_banner()

    from pathfinder.scanners import (
        discover_subdomains,
        probe_hosts,
        request_active_scan_approval,
        scan_vulnerabilities,
    )

    session = Session(domain=domain, mode="e2e")

    console.print(Panel(f"[bold]Target: {domain}[/bold]", title="Scan Configuration"))

    discover_subdomains(session)
    print_asset_table(session)

    if passive_only:
        console.print("\n[yellow]Passive-only mode. Skipping active scanning.[/yellow]")
        print_summary(session)
        return

    if not skip_approval and not request_active_scan_approval(session):
        return

    probe_hosts(session)
    scan_vulnerabilities(session)

    print_findings_table(session)
    print_summary(session)

    saved_path = save_session(session, output)
    console.print(f"\n[dim]Session saved to {saved_path}[/dim]")

    console.print("\n[bold cyan]Run 'pathfinder analyze' to generate attack paths[/bold cyan]")


@app.command()
def ingest(
    file: str = typer.Argument(..., help="Input file to ingest"),
    format: str = typer.Option("auto", "--format", "-f", help="Input format: nuclei, httpx, nessus, auto"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Target domain (for session context)"),
) -> None:
    """Ingest scanner output from external tools.

    MODE B: Plugin mode - import findings from any scanner:
    - nuclei: Nuclei JSON output
    - httpx: httpx JSON output
    - nessus: Nessus CSV export
    - auto: Auto-detect format
    """
    print_banner()
    console.print(f"[bold blue]Ingesting {file} (format: {format})...[/bold blue]")

    from pathfinder.ingestors import ingest_file

    session = ingest_file(file, format, domain)

    print_asset_table(session)
    print_findings_table(session)
    print_summary(session)

    saved_path = save_session(session)
    console.print(f"\n[dim]Session saved to {saved_path}[/dim]")

    console.print("\n[bold cyan]Run 'pathfinder analyze' to generate attack paths[/bold cyan]")


@app.command()
def analyze(
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Domain to analyze"),
    session_file: Optional[str] = typer.Option(None, "--session", "-s", help="Session file to load"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file (supports .json, .html)"),
) -> None:
    """Analyze findings and generate attack paths.

    Uses AI to:
    - Correlate findings across assets
    - Synthesize attack paths
    - Score business impact
    - Generate executive narrative
    """
    print_banner()

    from pathfinder.core import analyze_sync, generate_html_report, print_full_analysis

    session: Optional[Session] = None

    if session_file:
        session = load_session(session_file)
        if not session:
            console.print(f"[red]Failed to load session from {session_file}[/red]")
            raise typer.Exit(1)
    else:
        config = get_config()
        latest_session = find_latest_session(config.data_dir, domain)
        if latest_session:
            session = load_session(str(latest_session))

    if not session:
        console.print("[yellow]No session found. Run 'pathfinder scan' or 'pathfinder ingest' first.[/yellow]")
        raise typer.Exit(1)

    if not session.findings:
        console.print("[yellow]No findings in session. Nothing to analyze.[/yellow]")
        raise typer.Exit(0)

    console.print(f"[bold]Analyzing {len(session.findings)} findings across {len(session.assets)} assets...[/bold]")

    analysis = analyze_sync(session)

    print_full_analysis(analysis, session)

    if output:
        if output.endswith(".html"):
            html = generate_html_report(analysis, session)
            with open(output, "w") as f:
                f.write(html)
            console.print(f"\n[green]HTML report saved to {output}[/green]")
        else:
            import json
            with open(output, "w") as f:
                json.dump(analysis, f, indent=2)
            console.print(f"\n[green]Analysis saved to {output}[/green]")


def load_session(path: str) -> Optional[Session]:
    """Load a session from a JSON file."""
    import json
    from pathlib import Path
    from datetime import datetime

    try:
        with open(path) as f:
            data = json.load(f)

        session = Session(
            domain=data.get("domain", "unknown"),
            mode=data.get("mode", "loaded"),
        )

        from pathfinder.models import Asset, Finding, Severity

        for a in data.get("assets", []):
            asset = Asset(
                hostname=a.get("hostname", ""),
                source=a.get("source", "loaded"),
                ip=a.get("ip"),
                ports=a.get("ports", []),
                tech_stack=a.get("tech_stack", []),
                status_code=a.get("status_code"),
                title=a.get("title"),
            )
            session.assets.append(asset)

        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        for f in data.get("findings", []):
            finding = Finding(
                id=f.get("id", "unknown"),
                name=f.get("name", "Unknown"),
                severity=severity_map.get(f.get("severity", "info"), Severity.INFO),
                host=f.get("host", ""),
                evidence=f.get("evidence", ""),
                description=f.get("description", ""),
                source=f.get("source", "loaded"),
                template_id=f.get("template_id"),
                tags=f.get("tags", []),
            )
            session.add_finding(finding)

        return session
    except Exception as e:
        console.print(f"[red]Error loading session: {e}[/red]")
        return None


def find_latest_session(data_dir, domain: Optional[str] = None):
    """Find the most recent session file."""
    from pathlib import Path

    sessions_dir = data_dir / "sessions"
    if not sessions_dir.exists():
        return None

    pattern = f"*{domain}*.json" if domain else "*.json"
    sessions = list(sessions_dir.glob(pattern))

    if not sessions:
        return None

    return max(sessions, key=lambda p: p.stat().st_mtime)


@app.command()
def run(
    domain: str = typer.Argument(..., help="Target domain to assess"),
    passive_only: bool = typer.Option(False, "--passive-only", "-p", help="Only run passive recon"),
    skip_approval: bool = typer.Option(False, "--yes", "-y", help="Skip approval prompt"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file (.json or .html)"),
    demo: bool = typer.Option(False, "--demo", help="Use synthetic demo data (no real scanning)"),
) -> None:
    """Run full assessment: scan + analyze in one command.

    This is the recommended way to use PathFinder for a complete assessment.
    """
    print_banner()

    from pathfinder.core import analyze_sync, generate_html_report, print_full_analysis
    from pathfinder.scanners import (
        discover_subdomains,
        probe_hosts,
        request_active_scan_approval,
        scan_vulnerabilities,
    )

    if demo:
        console.print("[bold yellow]DEMO MODE[/bold yellow] — Using synthetic data\n")
        session = generate_demo_session(domain)
    else:
        session = Session(domain=domain, mode="e2e")
        console.print(Panel(f"[bold]Target: {domain}[/bold]", title="Assessment Configuration"))

        discover_subdomains(session)

        if not passive_only:
            if not skip_approval and not request_active_scan_approval(session):
                return
            probe_hosts(session)
            scan_vulnerabilities(session)

    print_asset_table(session)
    print_findings_table(session)

    if not session.findings:
        console.print("[yellow]No findings to analyze.[/yellow]")
        print_summary(session)
        return

    console.print("\n[bold blue]Generating AI analysis...[/bold blue]\n")
    analysis = analyze_sync(session)

    print_full_analysis(analysis, session)

    if output:
        if output.endswith(".html"):
            html = generate_html_report(analysis, session)
            with open(output, "w") as f:
                f.write(html)
            console.print(f"\n[green]HTML report saved to {output}[/green]")
        else:
            import json
            full_output = {
                "session": {
                    "domain": session.domain,
                    "assets": [a.to_dict() for a in session.assets],
                    "findings": [f.to_dict() for f in session.findings],
                },
                "analysis": analysis,
            }
            with open(output, "w") as f:
                json.dump(full_output, f, indent=2)
            console.print(f"\n[green]Full report saved to {output}[/green]")
    else:
        saved_path = save_session(session)
        console.print(f"\n[dim]Session saved to {saved_path}[/dim]")


def generate_demo_session(domain: str) -> Session:
    """Generate a realistic demo session with synthetic data."""
    from pathfinder.models import Asset, Finding, Severity

    session = Session(domain=domain, mode="demo")

    demo_assets = [
        Asset(hostname=f"www.{domain}", source="demo", status_code=200, title="Welcome", tech_stack=["nginx", "react"]),
        Asset(hostname=f"api.{domain}", source="demo", status_code=200, title="API Gateway", tech_stack=["nginx", "nodejs", "express"]),
        Asset(hostname=f"admin.{domain}", source="demo", status_code=200, title="Admin Portal", tech_stack=["apache", "php"]),
        Asset(hostname=f"dev.{domain}", source="demo", status_code=200, title="Development", tech_stack=["nginx", "python", "flask"]),
        Asset(hostname=f"staging.{domain}", source="demo", status_code=200, title="Staging Environment", tech_stack=["nginx", "nodejs"]),
        Asset(hostname=f"old.{domain}", source="demo", status_code=200, title="Legacy Portal", tech_stack=["iis", "asp.net"]),
        Asset(hostname=f"mail.{domain}", source="demo", status_code=301, title="Mail Server", tech_stack=["postfix"]),
        Asset(hostname=f"vpn.{domain}", source="demo", status_code=200, title="VPN Gateway", tech_stack=["openvpn"]),
    ]

    demo_findings = [
        Finding(
            id="exposed-panels/admin-login",
            name="Admin Panel Accessible Without Network Restriction",
            severity=Severity.CRITICAL,
            host=f"admin.{domain}",
            evidence=f"https://admin.{domain}/admin/login returns 200 OK from public internet",
            description="Administrative interface is publicly accessible without IP restrictions or VPN requirement",
            source="demo",
            tags=["panel", "admin", "exposure"],
        ),
        Finding(
            id="exposures/configs/env-file",
            name="Environment File Exposure (.env)",
            severity=Severity.CRITICAL,
            host=f"api.{domain}",
            evidence=f"https://api.{domain}/.env contains DB_PASSWORD, JWT_SECRET",
            description="Environment file with database credentials and API keys is publicly accessible",
            source="demo",
            tags=["exposure", "config", "credentials"],
        ),
        Finding(
            id="misconfiguration/verbose-errors",
            name="API Returns Full Stack Traces on Error",
            severity=Severity.HIGH,
            host=f"api.{domain}",
            evidence=f"https://api.{domain}/v1/users/invalid returns stack trace with internal paths",
            description="Error responses include full stack traces exposing internal file paths and framework versions",
            source="demo",
            tags=["misconfig", "info-disclosure"],
        ),
        Finding(
            id="exposures/configs/git-config",
            name="Git Configuration Exposed",
            severity=Severity.HIGH,
            host=f"dev.{domain}",
            evidence=f"https://dev.{domain}/.git/config exposes repository URL and branch info",
            description="Git configuration file is publicly accessible, potentially exposing repository structure",
            source="demo",
            tags=["exposure", "git", "config"],
        ),
        Finding(
            id="tech/eol-software",
            name="End-of-Life Software Detected (IIS 7.5 / ASP.NET 2.0)",
            severity=Severity.HIGH,
            host=f"old.{domain}",
            evidence="Server: Microsoft-IIS/7.5, X-Powered-By: ASP.NET 2.0",
            description="Server is running end-of-life software with known unpatched vulnerabilities",
            source="demo",
            tags=["tech", "eol", "outdated"],
        ),
        Finding(
            id="misconfiguration/missing-headers",
            name="Missing Security Headers (HSTS, CSP, X-Frame-Options)",
            severity=Severity.MEDIUM,
            host=f"staging.{domain}",
            evidence=f"https://staging.{domain}/ missing Strict-Transport-Security, Content-Security-Policy",
            description="Security headers are not configured, increasing risk of XSS and clickjacking attacks",
            source="demo",
            tags=["misconfig", "headers"],
        ),
        Finding(
            id="misconfiguration/cors-wildcard",
            name="CORS Wildcard Origin Accepted",
            severity=Severity.MEDIUM,
            host=f"api.{domain}",
            evidence="Access-Control-Allow-Origin: * returned for cross-origin requests",
            description="API accepts requests from any origin, enabling potential data exfiltration via malicious sites",
            source="demo",
            tags=["misconfig", "cors"],
        ),
        Finding(
            id="misconfiguration/http-no-redirect",
            name="HTTP to HTTPS Redirect Not Enforced",
            severity=Severity.LOW,
            host=f"www.{domain}",
            evidence=f"http://www.{domain}/ returns 200 instead of 301 redirect to HTTPS",
            description="Plain HTTP requests are served instead of redirecting to HTTPS",
            source="demo",
            tags=["misconfig", "tls"],
        ),
    ]

    for asset in demo_assets:
        session.add_asset(asset)

    for finding in demo_findings:
        session.add_finding(finding)

    return session


@app.command()
def demo(
    domain: str = typer.Option("acme-corp.com", "--domain", "-d", help="Demo domain name"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file (.html recommended)"),
) -> None:
    """Run a demo with synthetic data to showcase PathFinder capabilities.

    No real scanning is performed. Uses realistic synthetic findings
    to demonstrate the attack path analysis.
    """
    from pathfinder.core import analyze_sync, generate_html_report, print_full_analysis

    print_banner()
    console.print("[bold yellow]PATHFINDER DEMO[/bold yellow]")
    console.print("[dim]Using synthetic data — no real scanning performed[/dim]\n")

    session = generate_demo_session(domain)

    print_asset_table(session)
    print_findings_table(session)

    console.print("\n[bold blue]Generating AI analysis...[/bold blue]\n")
    analysis = analyze_sync(session)

    print_full_analysis(analysis, session)

    if output:
        if output.endswith(".html"):
            html = generate_html_report(analysis, session)
            with open(output, "w") as f:
                f.write(html)
            console.print(f"\n[green]HTML report saved to {output}[/green]")
        else:
            import json
            with open(output, "w") as f:
                json.dump(analysis, f, indent=2)
            console.print(f"\n[green]Analysis saved to {output}[/green]")


@app.command()
def status() -> None:
    """Check tool availability and configuration."""
    print_banner()

    console.print("[bold]Tool Status:[/bold]\n")

    tools = check_all_tools()
    table = Table(show_header=True, header_style="bold")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Path")

    for name, tool in tools.items():
        status = "[green]Available[/green]" if tool.available else "[red]Not Found[/red]"
        path = tool.path or "-"
        table.add_row(name, status, path)

    console.print(table)

    config = get_config()
    console.print("\n[bold]API Configuration:[/bold]\n")

    api_table = Table(show_header=True, header_style="bold")
    api_table.add_column("Setting")
    api_table.add_column("Value")

    api_table.add_row(
        "Anthropic API Key",
        "[green]Set[/green]" if config.anthropic_api_key else "[red]Not Set[/red]",
    )
    api_table.add_row(
        "Groq API Key",
        "[green]Set[/green]" if config.groq_api_key else "[dim]Not Set[/dim]",
    )
    api_table.add_row("Model", config.model)
    api_table.add_row("Data Directory", str(config.data_dir))

    console.print(api_table)


def print_asset_table(session: Session) -> None:
    """Print table of discovered assets."""
    if not session.assets:
        return

    table = Table(title="Discovered Assets", show_header=True, header_style="bold")
    table.add_column("Host", style="cyan")
    table.add_column("Status")
    table.add_column("Title")
    table.add_column("Tech Stack")
    table.add_column("Source")

    for asset in session.assets[:20]:
        status = str(asset.status_code) if asset.status_code else "-"
        title = (asset.title[:30] + "...") if asset.title and len(asset.title) > 30 else (asset.title or "-")
        tech = ", ".join(asset.tech_stack[:3]) if asset.tech_stack else "-"
        table.add_row(asset.hostname, status, title, tech, asset.source)

    if len(session.assets) > 20:
        table.add_row(f"... and {len(session.assets) - 20} more", "", "", "", "")

    console.print("\n")
    console.print(table)


def print_findings_table(session: Session) -> None:
    """Print table of findings."""
    if not session.findings:
        return

    table = Table(title="Findings", show_header=True, header_style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Finding")
    table.add_column("Host")
    table.add_column("Source")

    severity_colors = {
        "critical": "red",
        "high": "orange3",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for finding in sorted(session.findings, key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value)):
        color = severity_colors.get(finding.severity.value, "white")
        table.add_row(
            f"[{color}]{finding.severity.value.upper()}[/{color}]",
            finding.name[:50],
            finding.host,
            finding.source,
        )

    console.print("\n")
    console.print(table)


def print_summary(session: Session) -> None:
    """Print session summary."""
    summary = session.summary()

    panel_content = f"""
[bold]Domain:[/bold] {summary['domain']}
[bold]Mode:[/bold] {summary['mode']}
[bold]Assets:[/bold] {summary['asset_count']}
[bold]Findings:[/bold] {summary['finding_count']}

[bold]Severity Breakdown:[/bold]
  [red]Critical:[/red] {summary['severity_breakdown']['critical']}
  [orange3]High:[/orange3] {summary['severity_breakdown']['high']}
  [yellow]Medium:[/yellow] {summary['severity_breakdown']['medium']}
  [blue]Low:[/blue] {summary['severity_breakdown']['low']}
  [dim]Info:[/dim] {summary['severity_breakdown']['info']}
"""

    console.print(Panel(panel_content, title="[bold]Scan Summary[/bold]", border_style="green"))


def save_session(session: Session, path: str | None = None) -> str:
    """Save session to JSON file."""
    import json
    from datetime import datetime
    from pathlib import Path

    if path is None:
        config = get_config()
        sessions_dir = config.data_dir / "sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(sessions_dir / f"{session.domain}_{timestamp}.json")

    data = {
        "domain": session.domain,
        "mode": session.mode,
        "created_at": session.created_at.isoformat(),
        "assets": [a.to_dict() for a in session.assets],
        "findings": [f.to_dict() for f in session.findings],
        "attack_paths": [p.to_dict() for p in session.attack_paths],
    }

    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    return path


if __name__ == "__main__":
    app()
