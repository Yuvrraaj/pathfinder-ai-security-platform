"""Ingestors for external scanner output."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from rich.console import Console

from pathfinder.models import Asset, Finding, Session, Severity

console = Console()


def ingest_file(file_path: str, format: str = "auto", domain: Optional[str] = None) -> Session:
    """Ingest scanner output from a file."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    content = path.read_text()

    if format == "auto":
        format = detect_format(content, path.suffix)

    console.print(f"[dim]Detected format: {format}[/dim]")

    if format == "nuclei":
        return ingest_nuclei(content, domain)
    elif format == "httpx":
        return ingest_httpx(content, domain)
    elif format == "nessus":
        return ingest_nessus(content, domain)
    else:
        raise ValueError(f"Unknown format: {format}")


def detect_format(content: str, suffix: str) -> str:
    """Auto-detect scanner output format."""
    if suffix == ".csv":
        return "nessus"

    try:
        first_line = content.strip().split("\n")[0]
        data = json.loads(first_line)

        if "template-id" in data or "template" in data:
            return "nuclei"
        elif "tech" in data or "status_code" in data:
            return "httpx"
    except (json.JSONDecodeError, IndexError):
        pass

    return "nuclei"


def ingest_nuclei(content: str, domain: Optional[str] = None) -> Session:
    """Ingest Nuclei JSON output."""
    session = Session(domain=domain or "unknown", mode="plugin")

    for line in content.strip().split("\n"):
        if not line.strip():
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        host = data.get("host", "")
        if "://" in host:
            host = host.split("://")[1].split("/")[0].split(":")[0]

        if not domain:
            parts = host.split(".")
            if len(parts) >= 2:
                session.domain = ".".join(parts[-2:])

        asset = Asset(hostname=host, source="nuclei-import")
        session.add_asset(asset)

        severity_str = data.get("severity", "info").lower()
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        finding = Finding(
            id=data.get("template-id", "unknown"),
            name=data.get("name", data.get("template-id", "Unknown")),
            severity=severity_map.get(severity_str, Severity.INFO),
            host=host,
            evidence=data.get("matched-at", ""),
            description=data.get("description", ""),
            source="nuclei-import",
            template_id=data.get("template-id"),
            tags=data.get("tags", []),
            raw=data,
        )
        session.add_finding(finding)

    console.print(f"[green]Ingested {len(session.findings)} findings from Nuclei output[/green]")
    return session


def ingest_httpx(content: str, domain: Optional[str] = None) -> Session:
    """Ingest httpx JSON output."""
    session = Session(domain=domain or "unknown", mode="plugin")

    for line in content.strip().split("\n"):
        if not line.strip():
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        host = data.get("host", data.get("input", ""))
        if "://" in host:
            host = host.split("://")[1].split("/")[0].split(":")[0]

        if not domain:
            parts = host.split(".")
            if len(parts) >= 2:
                session.domain = ".".join(parts[-2:])

        tech = data.get("tech", [])
        if isinstance(tech, str):
            tech = [tech]

        asset = Asset(
            hostname=host,
            source="httpx-import",
            status_code=data.get("status_code"),
            title=data.get("title"),
            tech_stack=tech,
        )
        session.add_asset(asset)

    console.print(f"[green]Ingested {len(session.assets)} assets from httpx output[/green]")
    return session


def ingest_nessus(content: str, domain: Optional[str] = None) -> Session:
    """Ingest Nessus CSV export."""
    import csv
    from io import StringIO

    session = Session(domain=domain or "unknown", mode="plugin")

    reader = csv.DictReader(StringIO(content))

    for row in reader:
        host = row.get("Host", row.get("IP Address", "unknown"))

        if not domain:
            parts = host.split(".")
            if len(parts) >= 2:
                session.domain = ".".join(parts[-2:])

        asset = Asset(hostname=host, source="nessus-import")
        session.add_asset(asset)

        risk = row.get("Risk", "None").lower()
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "none": Severity.INFO,
        }

        plugin_id = row.get("Plugin ID", "unknown")

        finding = Finding(
            id=f"nessus-{plugin_id}",
            name=row.get("Name", "Unknown"),
            severity=severity_map.get(risk, Severity.INFO),
            host=host,
            port=int(row.get("Port", 0)) or None,
            evidence=row.get("Plugin Output", "")[:500],
            description=row.get("Synopsis", ""),
            source="nessus-import",
            template_id=plugin_id,
            raw=dict(row),
        )
        session.add_finding(finding)

    console.print(f"[green]Ingested {len(session.findings)} findings from Nessus export[/green]")
    return session


__all__ = ["ingest_file"]
