"""Normalized data models for PathFinder.

All scanner outputs normalize to these schemas, enabling the AI reasoning
layer to work with any input source.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    """A normalized vulnerability or misconfiguration finding."""

    id: str
    name: str
    severity: Severity
    host: str
    evidence: str
    description: str
    source: str
    port: int | None = None
    template_id: str | None = None
    tags: list[str] = field(default_factory=list)
    cwe: str | None = None
    cvss: float | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity.value,
            "host": self.host,
            "port": self.port,
            "evidence": self.evidence,
            "description": self.description,
            "source": self.source,
            "template_id": self.template_id,
            "tags": self.tags,
            "cwe": self.cwe,
            "cvss": self.cvss,
        }


@dataclass
class Asset:
    """A discovered asset (subdomain, host, service)."""

    hostname: str
    source: str
    ip: str | None = None
    ports: list[int] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    status_code: int | None = None
    title: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cert_info: dict[str, Any] | None = None
    findings: list[Finding] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "ip": self.ip,
            "ports": self.ports,
            "tech_stack": self.tech_stack,
            "status_code": self.status_code,
            "title": self.title,
            "source": self.source,
            "finding_count": len(self.findings),
        }


@dataclass
class AttackPathStep:
    """A single step in an attack path."""

    step_number: int
    asset: str
    action: str
    finding_id: str | None
    description: str


@dataclass
class AttackPath:
    """A synthesized attack path showing how findings chain together."""

    id: str
    name: str
    steps: list[AttackPathStep]
    entry_point: str
    target: str
    confidence: Confidence
    business_impact: Severity
    narrative: str
    evidence_ids: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "steps": [
                {
                    "step": s.step_number,
                    "asset": s.asset,
                    "action": s.action,
                    "finding_id": s.finding_id,
                    "description": s.description,
                }
                for s in self.steps
            ],
            "entry_point": self.entry_point,
            "target": self.target,
            "confidence": self.confidence.value,
            "business_impact": self.business_impact.value,
            "narrative": self.narrative,
            "evidence_ids": self.evidence_ids,
            "mitigations": self.mitigations,
        }


@dataclass
class Session:
    """A PathFinder session containing all discovered data."""

    domain: str
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    mode: str = "e2e"  # "e2e" or "plugin"

    def add_asset(self, asset: Asset) -> None:
        existing = next((a for a in self.assets if a.hostname == asset.hostname), None)
        if existing:
            existing.tech_stack = list(set(existing.tech_stack + asset.tech_stack))
            existing.ports = list(set(existing.ports + asset.ports))
            if asset.status_code:
                existing.status_code = asset.status_code
            if asset.title:
                existing.title = asset.title
        else:
            self.assets.append(asset)

    def add_finding(self, finding: Finding) -> None:
        if not any(f.id == finding.id and f.host == finding.host for f in self.findings):
            self.findings.append(finding)
            for asset in self.assets:
                if asset.hostname == finding.host:
                    asset.findings.append(finding)
                    break

    def summary(self) -> dict[str, Any]:
        severity_counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            severity_counts[f.severity.value] += 1

        return {
            "domain": self.domain,
            "mode": self.mode,
            "asset_count": len(self.assets),
            "finding_count": len(self.findings),
            "attack_path_count": len(self.attack_paths),
            "severity_breakdown": severity_counts,
        }
