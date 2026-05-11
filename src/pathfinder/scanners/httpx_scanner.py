"""httpx wrapper for HTTP probing and tech detection."""
from __future__ import annotations

import json
import subprocess
import tempfile
from typing import TYPE_CHECKING

import httpx as httpx_lib
from rich.console import Console

from pathfinder.config import check_tool
from pathfinder.models import Asset

if TYPE_CHECKING:
    from pathfinder.models import Session

console = Console()


def run_httpx_binary(hosts: list[str], timeout: int = 30) -> list[dict]:
    """Run httpx binary for HTTP probing."""
    tool = check_tool("httpx")
    if not tool.available:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts))
        hosts_file = f.name

    try:
        result = subprocess.run(
            [
                "httpx",
                "-l", hosts_file,
                "-silent",
                "-json",
                "-title",
                "-tech-detect",
                "-status-code",
                "-timeout", str(timeout),
            ],
            capture_output=True,
            text=True,
            timeout=timeout * len(hosts) + 60,
        )

        results = []
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results
    except Exception as e:
        console.print(f"[yellow]httpx binary error: {e}[/yellow]")
        return []


def run_httpx_fallback(hosts: list[str], timeout: int = 10) -> list[dict]:
    """Fallback HTTP probing using Python httpx library."""
    results = []

    for host in hosts:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{host}"
            try:
                with httpx_lib.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
                    response = client.get(url)

                tech_stack = detect_tech_from_response(response)
                title = extract_title(response.text)

                results.append({
                    "url": str(response.url),
                    "host": host,
                    "status_code": response.status_code,
                    "title": title,
                    "tech": tech_stack,
                    "headers": dict(response.headers),
                })
                break
            except Exception:
                continue

    return results


def detect_tech_from_response(response: httpx_lib.Response) -> list[str]:
    """Detect technologies from HTTP response."""
    tech = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    body = response.text.lower()

    server = headers.get("server", "")
    if "nginx" in server.lower():
        tech.append("nginx")
    if "apache" in server.lower():
        tech.append("apache")
    if "iis" in server.lower():
        tech.append("iis")

    powered_by = headers.get("x-powered-by", "")
    if "php" in powered_by.lower():
        tech.append("php")
    if "express" in powered_by.lower():
        tech.append("express")
    if "asp.net" in powered_by.lower():
        tech.append("asp.net")

    if "react" in body or "reactdom" in body:
        tech.append("react")
    if "next" in body or "_next" in body:
        tech.append("nextjs")
    if "vue" in body:
        tech.append("vue")
    if "angular" in body:
        tech.append("angular")
    if "wordpress" in body or "wp-content" in body:
        tech.append("wordpress")

    return tech


def extract_title(html: str) -> str | None:
    """Extract page title from HTML."""
    import re
    match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    return match.group(1).strip() if match else None


def probe_hosts(session: Session, timeout: int = 30) -> list[Asset]:
    """Probe discovered hosts for HTTP services."""
    hosts = [asset.hostname for asset in session.assets]
    if not hosts:
        console.print("[yellow]No hosts to probe[/yellow]")
        return []

    console.print(f"[bold blue]Probing {len(hosts)} hosts...[/bold blue]")

    if check_tool("httpx").available:
        results = run_httpx_binary(hosts, timeout)
    else:
        console.print("[yellow]httpx binary not found, using Python fallback (slower)[/yellow]")
        results = run_httpx_fallback(hosts, timeout)

    live_assets = []
    for result in results:
        hostname = result.get("host") or result.get("url", "").split("://")[-1].split("/")[0]

        for asset in session.assets:
            if asset.hostname == hostname:
                asset.status_code = result.get("status_code")
                asset.title = result.get("title")
                asset.tech_stack = result.get("tech", [])
                if isinstance(asset.tech_stack, str):
                    asset.tech_stack = [asset.tech_stack]
                asset.headers = result.get("headers", {})
                live_assets.append(asset)
                break

    console.print(f"[green]{len(live_assets)} hosts are live[/green]")
    return live_assets
