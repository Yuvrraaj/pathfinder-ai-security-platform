"""Human-in-the-loop approval gate for active scanning."""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

if TYPE_CHECKING:
    from pathfinder.models import Session

console = Console()


def request_active_scan_approval(session: Session) -> bool:
    """Request user approval before active scanning.

    Returns True if approved, False otherwise.
    """
    host_count = len(session.assets)

    panel_content = f"""
[bold]Target Domain:[/bold] {session.domain}
[bold]Hosts to Probe:[/bold] {host_count} subdomains

[bold green]What this WILL do:[/bold green]
  • HTTP/HTTPS status checks
  • Technology fingerprinting
  • Header analysis
  • Nuclei templates (misconfig, exposure, info only)

[bold red]What this will NOT do:[/bold red]
  • No exploitation attempts
  • No credential brute-forcing
  • No payload injection
  • No destructive actions
  • No testing without your approval

[dim]All actions are logged and auditable.[/dim]
"""

    console.print(Panel(
        panel_content,
        title="[bold yellow]ACTIVE SCAN AUTHORIZATION REQUIRED[/bold yellow]",
        border_style="yellow",
    ))

    approved = Confirm.ask("\n[bold]Proceed with active scanning?[/bold]", default=False)

    if approved:
        log_approval(session, "active_scan", approved=True)
        console.print("[green]Authorization granted. Starting active scan...[/green]\n")
    else:
        log_approval(session, "active_scan", approved=False)
        console.print("[yellow]Active scan declined. Exiting.[/yellow]")

    return approved


def log_approval(session: Session, action: str, approved: bool) -> None:
    """Log approval decision for audit trail."""
    from pathfinder.config import get_config

    config = get_config()
    log_file = config.data_dir / "audit.log"

    entry = {
        "timestamp": datetime.now().isoformat(),
        "domain": session.domain,
        "action": action,
        "approved": approved,
        "host_count": len(session.assets),
    }

    with open(log_file, "a") as f:
        import json
        f.write(json.dumps(entry) + "\n")
