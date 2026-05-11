"""Subfinder wrapper for passive subdomain enumeration."""
from __future__ import annotations

import json
import subprocess
import urllib.request
import urllib.error
from typing import TYPE_CHECKING

from rich.console import Console

from pathfinder.config import check_tool
from pathfinder.models import Asset

if TYPE_CHECKING:
    from pathfinder.models import Session

console = Console()


def run_subfinder(domain: str, timeout: int = 60) -> list[str]:
    """Run subfinder to discover subdomains."""
    tool = check_tool("subfinder")
    if not tool.available:
        console.print("[yellow]subfinder not found, falling back to crt.sh[/yellow]")
        return run_crtsh_fallback(domain)

    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-timeout", str(timeout)],
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return list(set(subdomains))
    except subprocess.TimeoutExpired:
        console.print("[yellow]subfinder timed out, falling back to crt.sh[/yellow]")
        return run_crtsh_fallback(domain)
    except Exception as e:
        console.print(f"[yellow]subfinder error: {e}, falling back to crt.sh[/yellow]")
        return run_crtsh_fallback(domain)


def run_crtsh_fallback(domain: str) -> list[str]:
    """Query crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PathFinder/1.0"})
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))

        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*") and domain in name:
                    subdomains.add(name)

        return list(subdomains)
    except Exception as e:
        console.print(f"[red]crt.sh fallback failed: {e}[/red]")
        return []


def discover_subdomains(session: Session) -> list[Asset]:
    """Discover subdomains and create Asset objects."""
    console.print(f"[bold blue]Discovering subdomains for {session.domain}...[/bold blue]")

    subdomains = run_subfinder(session.domain)

    if session.domain not in subdomains:
        subdomains.append(session.domain)

    assets = []
    for subdomain in sorted(subdomains):
        asset = Asset(
            hostname=subdomain,
            source="subfinder" if check_tool("subfinder").available else "crt.sh",
        )
        assets.append(asset)
        session.add_asset(asset)

    console.print(f"[green]Found {len(assets)} subdomains[/green]")
    return assets
