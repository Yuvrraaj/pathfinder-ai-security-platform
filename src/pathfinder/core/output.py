"""Output formatting and visualization for PathFinder.

Generates ASCII attack path visualizations and executive reports.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

if TYPE_CHECKING:
    from pathfinder.models import AttackPath, Session

console = Console()


def print_attack_path_ascii(path: AttackPath) -> None:
    """Print an ASCII visualization of an attack path."""
    impact_colors = {
        "critical": "red",
        "high": "orange3",
        "medium": "yellow",
        "low": "blue",
    }

    confidence_icons = {
        "high": "[green]●●●[/green]",
        "medium": "[yellow]●●○[/yellow]",
        "low": "[red]●○○[/red]",
    }

    color = impact_colors.get(path.business_impact.value, "white")
    conf_icon = confidence_icons.get(path.confidence.value, "●●○")

    header = f"[bold {color}]ATTACK PATH: {path.name}[/bold {color}]"
    subheader = f"[dim]ID: {path.id} | Confidence: {conf_icon} {path.confidence.value.upper()} | Impact: [{color}]{path.business_impact.value.upper()}[/{color}][/dim]"

    console.print()
    console.print(header)
    console.print(subheader)
    console.print()

    console.print("[bold cyan]Attack Flow:[/bold cyan]")
    console.print()

    for i, step in enumerate(path.steps):
        is_last = i == len(path.steps) - 1

        if i == 0:
            prefix = "┌──"
            connector = "│"
        elif is_last:
            prefix = "└──"
            connector = " "
        else:
            prefix = "├──"
            connector = "│"

        box_top = f"  {prefix}{'─' * 50}┐"
        box_mid = f"  {connector}  [bold]Step {step.step_number}:[/bold] {step.action[:45]}"
        box_asset = f"  {connector}  [cyan]Asset:[/cyan] {step.asset}"
        box_finding = f"  {connector}  [dim]Finding:[/dim] {step.finding_id or 'N/A'}"
        box_desc = f"  {connector}  {step.description[:60]}"
        box_bottom = f"  {connector}{'─' * 52}┘"

        console.print(box_top)
        console.print(box_mid)
        console.print(box_asset)
        console.print(box_finding)
        if step.description:
            console.print(box_desc)
        console.print(box_bottom)

        if not is_last:
            console.print(f"  │")
            console.print(f"  │  [dim]↓[/dim]")
            console.print(f"  │")

    console.print()
    console.print(f"[bold]Entry Point:[/bold] {path.entry_point}")
    console.print(f"[bold]Target:[/bold] {path.target}")
    console.print()

    console.print("[bold]Narrative:[/bold]")
    console.print(Panel(path.narrative, border_style="dim"))

    if path.mitigations:
        console.print("[bold green]Mitigations:[/bold green]")
        for i, mitigation in enumerate(path.mitigations, 1):
            console.print(f"  {i}. {mitigation}")
    console.print()


def print_attack_path_graph(path: AttackPath) -> None:
    """Print a tree-style visualization of an attack path."""
    tree = Tree(f"[bold red]🎯 {path.name}[/bold red]")

    entry_branch = tree.add(f"[cyan]Entry: {path.entry_point}[/cyan]")

    current = entry_branch
    for step in path.steps:
        step_text = f"[bold]Step {step.step_number}:[/bold] {step.action}"
        step_branch = current.add(step_text)
        step_branch.add(f"[dim]Asset:[/dim] {step.asset}")
        if step.finding_id:
            step_branch.add(f"[dim]Finding:[/dim] {step.finding_id}")
        current = step_branch

    current.add(f"[bold red]🏁 Target: {path.target}[/bold red]")

    console.print(tree)


def print_executive_summary(analysis: dict, session: Session) -> None:
    """Print the executive summary."""
    risk_score = analysis.get("risk_score", 0)

    if risk_score >= 80:
        risk_color = "red"
        risk_label = "CRITICAL"
    elif risk_score >= 60:
        risk_color = "orange3"
        risk_label = "HIGH"
    elif risk_score >= 40:
        risk_color = "yellow"
        risk_label = "MEDIUM"
    else:
        risk_color = "green"
        risk_label = "LOW"

    summary_text = f"""
[bold]Risk Score:[/bold] [{risk_color}]{risk_score}/100 ({risk_label})[/{risk_color}]

[bold]Executive Summary:[/bold]
{analysis.get('executive_summary', 'No summary available.')}

[bold]Key Statistics:[/bold]
  • Assets Discovered: {len(session.assets)}
  • Findings Identified: {len(session.findings)}
  • Attack Paths Synthesized: {len(analysis.get('attack_paths', []))}
"""

    console.print(Panel(
        summary_text,
        title="[bold]PathFinder Analysis Report[/bold]",
        subtitle=f"[dim]{session.domain}[/dim]",
        border_style=risk_color,
    ))


def print_priority_findings(analysis: dict) -> None:
    """Print priority findings table."""
    priority = analysis.get("priority_findings", [])
    if not priority:
        return

    table = Table(title="Priority Findings", show_header=True, header_style="bold")
    table.add_column("Finding ID", style="cyan")
    table.add_column("Reason")
    table.add_column("Fix Complexity")

    complexity_colors = {"low": "green", "medium": "yellow", "high": "red"}

    for pf in priority[:10]:
        complexity = pf.get("fix_complexity", "medium")
        color = complexity_colors.get(complexity, "white")
        table.add_row(
            pf.get("finding_id", "Unknown"),
            pf.get("reason", "")[:60],
            f"[{color}]{complexity.upper()}[/{color}]",
        )

    console.print(table)


def print_recommendations(analysis: dict) -> None:
    """Print recommendations."""
    recommendations = analysis.get("recommendations", [])
    if not recommendations:
        return

    console.print("\n[bold]Top Recommendations:[/bold]")
    for i, rec in enumerate(recommendations[:5], 1):
        console.print(f"  {i}. {rec}")


def print_full_analysis(analysis: dict, session: Session) -> None:
    """Print the complete analysis output."""
    print_executive_summary(analysis, session)
    console.print()

    attack_paths = analysis.get("attack_paths", [])
    if attack_paths:
        console.print(f"[bold]Attack Paths ({len(attack_paths)}):[/bold]")
        for path_data in attack_paths:
            from pathfinder.core.reasoning import parse_attack_paths
            paths = parse_attack_paths({"attack_paths": [path_data]})
            if paths:
                print_attack_path_ascii(paths[0])

    print_priority_findings(analysis)
    console.print()
    print_recommendations(analysis)


def generate_html_report(analysis: dict, session: Session) -> str:
    """Generate an HTML report."""
    risk_score = analysis.get("risk_score", 0)

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>PathFinder Report - {session.domain}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #0d1117; color: #c9d1d9; }}
        .header {{ border-bottom: 2px solid #30363d; padding-bottom: 20px; margin-bottom: 30px; }}
        .risk-score {{ font-size: 48px; font-weight: bold; }}
        .risk-critical {{ color: #f85149; }}
        .risk-high {{ color: #db6d28; }}
        .risk-medium {{ color: #d29922; }}
        .risk-low {{ color: #3fb950; }}
        .attack-path {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 20px; margin: 20px 0; }}
        .attack-path h3 {{ color: #f85149; margin-top: 0; }}
        .step {{ background: #21262d; padding: 15px; margin: 10px 0; border-left: 3px solid #58a6ff; }}
        .step-number {{ color: #58a6ff; font-weight: bold; }}
        .finding-id {{ color: #8b949e; font-size: 12px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #30363d; }}
        th {{ background: #161b22; }}
        .severity-critical {{ color: #f85149; }}
        .severity-high {{ color: #db6d28; }}
        .severity-medium {{ color: #d29922; }}
        .severity-low {{ color: #58a6ff; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>PathFinder Analysis Report</h1>
        <p>Target: <strong>{session.domain}</strong></p>
        <p class="risk-score risk-{'critical' if risk_score >= 80 else 'high' if risk_score >= 60 else 'medium' if risk_score >= 40 else 'low'}">
            Risk Score: {risk_score}/100
        </p>
    </div>

    <h2>Executive Summary</h2>
    <p>{analysis.get('executive_summary', 'No summary available.')}</p>

    <h2>Key Statistics</h2>
    <ul>
        <li>Assets Discovered: {len(session.assets)}</li>
        <li>Findings Identified: {len(session.findings)}</li>
        <li>Attack Paths: {len(analysis.get('attack_paths', []))}</li>
    </ul>

    <h2>Attack Paths</h2>
"""

    for path_data in analysis.get("attack_paths", []):
        html += f"""
    <div class="attack-path">
        <h3>{path_data.get('name', 'Unknown Path')}</h3>
        <p><strong>Entry:</strong> {path_data.get('entry_point', '')} → <strong>Target:</strong> {path_data.get('target', '')}</p>
        <p><strong>Confidence:</strong> {path_data.get('confidence', 'medium').upper()} | <strong>Impact:</strong> {path_data.get('business_impact', 'medium').upper()}</p>
"""
        for step in path_data.get("steps", []):
            html += f"""
        <div class="step">
            <span class="step-number">Step {step.get('step_number', 0)}:</span> {step.get('action', '')}
            <br><small>Asset: {step.get('asset', '')} <span class="finding-id">Finding: {step.get('finding_id', 'N/A')}</span></small>
        </div>
"""
        html += f"""
        <p><strong>Narrative:</strong> {path_data.get('narrative', '')}</p>
    </div>
"""

    html += """
    <h2>Recommendations</h2>
    <ol>
"""
    for rec in analysis.get("recommendations", []):
        html += f"        <li>{rec}</li>\n"

    html += """
    </ol>
    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #30363d; color: #8b949e;">
        Generated by PathFinder • AI-Assisted External Assessment Platform
    </footer>
</body>
</html>
"""
    return html
