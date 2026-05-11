"""AI reasoning engine for attack path synthesis.

Uses Groq (Llama) to analyze findings and synthesize attack paths
with business context and confidence scoring.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from rich.console import Console

from pathfinder.config import get_config
from pathfinder.core.graph import RelationshipGraph, build_relationship_graph
from pathfinder.models import AttackPath, AttackPathStep, Confidence, Severity

if TYPE_CHECKING:
    from pathfinder.models import Session

console = Console()

SYSTEM_PROMPT = """You are an expert penetration tester and security analyst. Your task is to analyze external attack surface findings and synthesize realistic attack paths.

You think like an attacker: you look for chains of vulnerabilities that, when combined, create a path to high-value targets. A critical SQL injection matters less if it's on an isolated test server with no data. A medium-severity misconfiguration on the main API gateway matters more.

Your analysis must be:
1. Evidence-based: Every claim must cite specific findings
2. Realistic: Focus on paths an attacker would actually take
3. Business-aware: Consider what assets are valuable targets
4. Actionable: Prioritize what to fix first and why

Output valid JSON only. No markdown, no explanation outside the JSON."""


def build_analysis_prompt(session: Session, graph: RelationshipGraph) -> str:
    """Build the prompt for AI analysis."""
    assets_summary = []
    for asset in session.assets[:30]:
        assets_summary.append({
            "hostname": asset.hostname,
            "status": asset.status_code,
            "tech": asset.tech_stack[:5],
            "finding_count": len(asset.findings),
        })

    findings_summary = []
    for finding in session.findings[:50]:
        findings_summary.append({
            "id": finding.id,
            "name": finding.name,
            "severity": finding.severity.value,
            "host": finding.host,
            "evidence": finding.evidence[:200] if finding.evidence else "",
            "tags": finding.tags[:5],
        })

    prompt = f"""Analyze this external attack surface assessment and synthesize attack paths.

## Target Domain
{session.domain}

## Discovered Assets ({len(session.assets)} total)
{json.dumps(assets_summary, indent=2)}

## Findings ({len(session.findings)} total)
{json.dumps(findings_summary, indent=2)}

## Detected Relationships
{json.dumps(graph.to_dict(), indent=2)}

## Your Task
1. Identify the most critical attack paths (chains of findings that lead to high-value targets)
2. For each path, explain HOW an attacker would chain these findings
3. Score confidence (high/medium/low) based on evidence quality
4. Score business impact (critical/high/medium/low) based on likely target value
5. Provide specific, actionable mitigations

## Output Format (JSON only)
{{
  "executive_summary": "2-3 sentence summary for non-technical stakeholders",
  "risk_score": 0-100,
  "attack_paths": [
    {{
      "id": "AP-001",
      "name": "Path name (e.g., 'Admin Panel to Database')",
      "entry_point": "hostname where attacker starts",
      "target": "what attacker ultimately reaches",
      "confidence": "high|medium|low",
      "business_impact": "critical|high|medium|low",
      "steps": [
        {{
          "step_number": 1,
          "asset": "hostname",
          "action": "what attacker does",
          "finding_id": "finding ID used",
          "description": "detailed explanation"
        }}
      ],
      "narrative": "Plain English explanation of how this attack works",
      "mitigations": ["specific fix 1", "specific fix 2"]
    }}
  ],
  "priority_findings": [
    {{
      "finding_id": "ID",
      "reason": "why this should be fixed first",
      "fix_complexity": "low|medium|high"
    }}
  ],
  "recommendations": [
    "Top recommendation 1",
    "Top recommendation 2",
    "Top recommendation 3"
  ]
}}

Respond with valid JSON only."""

    return prompt


async def analyze_with_groq(session: Session) -> dict:
    """Analyze session using Groq API (Llama models)."""
    from groq import Groq

    config = get_config()

    if not config.groq_api_key:
        console.print("[yellow]GROQ_API_KEY not set. Using fallback analysis.[/yellow]")
        console.print("[dim]Set it with: export GROQ_API_KEY=your-key[/dim]")
        return generate_fallback_analysis(session)

    graph = build_relationship_graph(session)
    prompt = build_analysis_prompt(session, graph)

    console.print("[bold blue]Analyzing with Groq (Llama 3.3 70B)...[/bold blue]")

    try:
        client = Groq(api_key=config.groq_api_key)

        chat_completion = client.chat.completions.create(
            model=config.model,
            max_tokens=4096,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
        )

        response_text = chat_completion.choices[0].message.content

        response_text = response_text.strip()
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]

        analysis = json.loads(response_text)
        console.print("[green]AI analysis complete[/green]")
        return analysis

    except json.JSONDecodeError as e:
        console.print(f"[yellow]Failed to parse AI response: {e}[/yellow]")
        console.print("[dim]Falling back to heuristic analysis[/dim]")
        return generate_fallback_analysis(session)
    except Exception as e:
        console.print(f"[yellow]AI analysis failed: {e}[/yellow]")
        console.print("[dim]Falling back to heuristic analysis[/dim]")
        return generate_fallback_analysis(session)


def analyze_sync(session: Session) -> dict:
    """Synchronous wrapper for analyze_with_groq."""
    import asyncio
    return asyncio.run(analyze_with_groq(session))


def generate_fallback_analysis(session: Session) -> dict:
    """Generate heuristic-based analysis when AI is unavailable."""
    console.print("[dim]Generating heuristic analysis...[/dim]")

    graph = build_relationship_graph(session)

    critical_findings = [f for f in session.findings if f.severity == Severity.CRITICAL]
    high_findings = [f for f in session.findings if f.severity == Severity.HIGH]

    attack_paths = []
    path_id = 1

    admin_findings = [f for f in session.findings if "admin" in f.host.lower() or "admin" in f.name.lower()]
    if admin_findings:
        steps = []
        for i, f in enumerate(admin_findings[:3], 1):
            steps.append({
                "step_number": i,
                "asset": f.host,
                "action": f"Exploit {f.name}",
                "finding_id": f.id,
                "description": f.description or f"Leverage {f.name} on {f.host}",
            })

        attack_paths.append({
            "id": f"AP-{path_id:03d}",
            "name": "Admin Panel Compromise",
            "entry_point": admin_findings[0].host,
            "target": "Administrative access",
            "confidence": "high" if len(admin_findings) > 1 else "medium",
            "business_impact": "critical",
            "steps": steps,
            "narrative": f"An attacker could gain administrative access through {admin_findings[0].host} by exploiting {admin_findings[0].name}.",
            "mitigations": [
                "Restrict admin panel access to internal networks or VPN",
                "Implement multi-factor authentication",
                "Enable IP allowlisting for administrative endpoints",
            ],
        })
        path_id += 1

    sensitive_paths = [f for f in session.findings if any(p in f.evidence.lower() for p in [".env", ".git", "config", "credentials", "secret"])]
    if sensitive_paths:
        steps = []
        for i, f in enumerate(sensitive_paths[:3], 1):
            steps.append({
                "step_number": i,
                "asset": f.host,
                "action": f"Access {f.name}",
                "finding_id": f.id,
                "description": f"Retrieve sensitive data from {f.evidence[:100]}",
            })

        attack_paths.append({
            "id": f"AP-{path_id:03d}",
            "name": "Sensitive Data Exposure",
            "entry_point": sensitive_paths[0].host,
            "target": "Credentials and configuration",
            "confidence": "high",
            "business_impact": "critical",
            "steps": steps,
            "narrative": f"Sensitive files are publicly accessible at {sensitive_paths[0].host}, potentially exposing credentials and internal configuration.",
            "mitigations": [
                "Remove sensitive files from web-accessible directories",
                "Implement proper access controls",
                "Rotate any exposed credentials immediately",
            ],
        })
        path_id += 1

    if critical_findings and not attack_paths:
        f = critical_findings[0]
        attack_paths.append({
            "id": f"AP-{path_id:03d}",
            "name": f"Critical: {f.name}",
            "entry_point": f.host,
            "target": "System compromise",
            "confidence": "high",
            "business_impact": "critical",
            "steps": [{
                "step_number": 1,
                "asset": f.host,
                "action": f"Exploit {f.name}",
                "finding_id": f.id,
                "description": f.description or f"Critical vulnerability on {f.host}",
            }],
            "narrative": f"A critical vulnerability ({f.name}) exists on {f.host} that could lead to system compromise.",
            "mitigations": ["Address this finding immediately as highest priority"],
        })

    total = len(session.findings)
    crit = len(critical_findings)
    high = len(high_findings)
    risk_score = min(100, (crit * 25) + (high * 10) + (total * 2))

    priority_findings = []
    for f in (critical_findings + high_findings)[:5]:
        priority_findings.append({
            "finding_id": f.id,
            "reason": f"{f.severity.value.upper()} severity: {f.name}",
            "fix_complexity": "medium",
        })

    return {
        "executive_summary": f"External assessment of {session.domain} identified {total} findings across {len(session.assets)} assets. {crit} critical and {high} high severity issues require immediate attention.",
        "risk_score": risk_score,
        "attack_paths": attack_paths,
        "priority_findings": priority_findings,
        "recommendations": [
            "Address all critical and high severity findings within 7 days",
            "Implement network segmentation for administrative interfaces",
            "Enable security headers across all web applications",
        ],
    }


def parse_attack_paths(analysis: dict) -> list[AttackPath]:
    """Parse AI analysis into AttackPath objects."""
    paths = []

    for ap_data in analysis.get("attack_paths", []):
        steps = []
        for step_data in ap_data.get("steps", []):
            steps.append(AttackPathStep(
                step_number=step_data.get("step_number", 0),
                asset=step_data.get("asset", ""),
                action=step_data.get("action", ""),
                finding_id=step_data.get("finding_id"),
                description=step_data.get("description", ""),
            ))

        confidence_map = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}
        impact_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}

        paths.append(AttackPath(
            id=ap_data.get("id", "AP-000"),
            name=ap_data.get("name", "Unknown Path"),
            steps=steps,
            entry_point=ap_data.get("entry_point", ""),
            target=ap_data.get("target", ""),
            confidence=confidence_map.get(ap_data.get("confidence", "medium"), Confidence.MEDIUM),
            business_impact=impact_map.get(ap_data.get("business_impact", "medium"), Severity.MEDIUM),
            narrative=ap_data.get("narrative", ""),
            evidence_ids=[s.finding_id for s in steps if s.finding_id],
            mitigations=ap_data.get("mitigations", []),
        ))

    return paths
