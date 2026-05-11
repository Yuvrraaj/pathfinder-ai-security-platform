"""Relationship graph builder for PathFinder.

Detects relationships between assets and findings to enable
attack path synthesis.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from pathfinder.models import Session

console = Console()


@dataclass
class Relationship:
    """A relationship between two assets or findings."""

    source: str
    target: str
    relationship_type: str
    confidence: float
    evidence: str


@dataclass
class RelationshipGraph:
    """Graph of relationships between assets and findings."""

    relationships: list[Relationship] = field(default_factory=list)
    clusters: dict[str, list[str]] = field(default_factory=dict)

    def add_relationship(self, rel: Relationship) -> None:
        if not any(
            r.source == rel.source and r.target == rel.target and r.relationship_type == rel.relationship_type
            for r in self.relationships
        ):
            self.relationships.append(rel)

    def get_relationships_for(self, entity: str) -> list[Relationship]:
        return [r for r in self.relationships if r.source == entity or r.target == entity]

    def to_dict(self) -> dict:
        return {
            "relationships": [
                {
                    "source": r.source,
                    "target": r.target,
                    "type": r.relationship_type,
                    "confidence": r.confidence,
                    "evidence": r.evidence,
                }
                for r in self.relationships
            ],
            "clusters": self.clusters,
        }


def build_relationship_graph(session: Session) -> RelationshipGraph:
    """Build a relationship graph from session data."""
    console.print("[bold blue]Building relationship graph...[/bold blue]")

    graph = RelationshipGraph()

    detect_shared_tech(session, graph)
    detect_shared_certificates(session, graph)
    detect_finding_correlations(session, graph)
    detect_subdomain_patterns(session, graph)
    detect_severity_clusters(session, graph)
    detect_credential_exposure_chains(session, graph)
    detect_attack_surface_tiers(session, graph)
    detect_lateral_movement_paths(session, graph)

    console.print(f"[green]Found {len(graph.relationships)} relationships[/green]")
    return graph


def detect_shared_tech(session: Session, graph: RelationshipGraph) -> None:
    """Detect assets sharing the same technology stack."""
    tech_to_assets: dict[str, list[str]] = {}

    for asset in session.assets:
        for tech in asset.tech_stack:
            tech_lower = tech.lower()
            if tech_lower not in tech_to_assets:
                tech_to_assets[tech_lower] = []
            tech_to_assets[tech_lower].append(asset.hostname)

    for tech, assets in tech_to_assets.items():
        if len(assets) > 1:
            graph.clusters[f"tech:{tech}"] = assets
            for i, asset1 in enumerate(assets):
                for asset2 in assets[i + 1:]:
                    graph.add_relationship(Relationship(
                        source=asset1,
                        target=asset2,
                        relationship_type="shared_tech",
                        confidence=0.8,
                        evidence=f"Both run {tech}",
                    ))


def detect_shared_certificates(session: Session, graph: RelationshipGraph) -> None:
    """Detect assets sharing TLS certificates."""
    cert_to_assets: dict[str, list[str]] = {}

    for asset in session.assets:
        if asset.cert_info:
            issuer = asset.cert_info.get("issuer", "")
            if issuer:
                if issuer not in cert_to_assets:
                    cert_to_assets[issuer] = []
                cert_to_assets[issuer].append(asset.hostname)

    for issuer, assets in cert_to_assets.items():
        if len(assets) > 1:
            graph.clusters[f"cert:{issuer[:30]}"] = assets
            for i, asset1 in enumerate(assets):
                for asset2 in assets[i + 1:]:
                    graph.add_relationship(Relationship(
                        source=asset1,
                        target=asset2,
                        relationship_type="shared_certificate",
                        confidence=0.9,
                        evidence=f"Shared certificate issuer: {issuer[:50]}",
                    ))


def detect_finding_correlations(session: Session, graph: RelationshipGraph) -> None:
    """Detect findings that appear across multiple assets."""
    finding_type_to_assets: dict[str, list[str]] = {}

    for finding in session.findings:
        finding_key = finding.template_id or finding.name
        if finding_key not in finding_type_to_assets:
            finding_type_to_assets[finding_key] = []
        if finding.host not in finding_type_to_assets[finding_key]:
            finding_type_to_assets[finding_key].append(finding.host)

    for finding_type, assets in finding_type_to_assets.items():
        if len(assets) > 1:
            graph.clusters[f"vuln:{finding_type[:30]}"] = assets
            for i, asset1 in enumerate(assets):
                for asset2 in assets[i + 1:]:
                    graph.add_relationship(Relationship(
                        source=asset1,
                        target=asset2,
                        relationship_type="same_vulnerability",
                        confidence=0.95,
                        evidence=f"Both have: {finding_type}",
                    ))


def detect_subdomain_patterns(session: Session, graph: RelationshipGraph) -> None:
    """Detect related subdomains based on naming patterns."""
    env_prefixes = ["dev", "staging", "stage", "test", "qa", "uat", "prod", "api", "admin", "internal"]
    env_to_assets: dict[str, list[str]] = {}

    for asset in session.assets:
        hostname = asset.hostname.lower()
        for prefix in env_prefixes:
            if hostname.startswith(f"{prefix}.") or hostname.startswith(f"{prefix}-"):
                if prefix not in env_to_assets:
                    env_to_assets[prefix] = []
                env_to_assets[prefix].append(asset.hostname)
                break

    for env, assets in env_to_assets.items():
        graph.clusters[f"env:{env}"] = assets

    dev_envs = ["dev", "staging", "stage", "test", "qa", "uat"]
    prod_envs = ["prod", "api", "admin"]

    dev_assets = [a for env in dev_envs for a in env_to_assets.get(env, [])]
    prod_assets = [a for env in prod_envs for a in env_to_assets.get(env, [])]

    for dev_asset in dev_assets:
        for prod_asset in prod_assets:
            graph.add_relationship(Relationship(
                source=dev_asset,
                target=prod_asset,
                relationship_type="dev_prod_pair",
                confidence=0.7,
                evidence="Development and production environment pair",
            ))


def detect_severity_clusters(session: Session, graph: RelationshipGraph) -> None:
    """Group assets by finding severity."""
    severity_to_assets: dict[str, list[str]] = {}

    for finding in session.findings:
        sev = finding.severity.value
        if sev not in severity_to_assets:
            severity_to_assets[sev] = []
        if finding.host not in severity_to_assets[sev]:
            severity_to_assets[sev].append(finding.host)

    for severity, assets in severity_to_assets.items():
        graph.clusters[f"severity:{severity}"] = assets


def detect_credential_exposure_chains(session: Session, graph: RelationshipGraph) -> None:
    """Detect chains where credentials exposed on one host could grant access to another."""
    credential_findings = [
        f for f in session.findings
        if any(kw in f.name.lower() or kw in f.evidence.lower()
               for kw in ["credential", "password", "secret", "key", "token", ".env", "config"])
    ]

    admin_findings = [
        f for f in session.findings
        if any(kw in f.name.lower() or kw in f.host.lower()
               for kw in ["admin", "login", "auth", "panel"])
    ]

    for cred_finding in credential_findings:
        for admin_finding in admin_findings:
            if cred_finding.host != admin_finding.host:
                graph.add_relationship(Relationship(
                    source=cred_finding.host,
                    target=admin_finding.host,
                    relationship_type="credential_to_access",
                    confidence=0.85,
                    evidence=f"Credentials from {cred_finding.host} may grant access to {admin_finding.host}",
                ))


def detect_attack_surface_tiers(session: Session, graph: RelationshipGraph) -> None:
    """Detect tiered attack surface (external -> dmz -> internal patterns)."""
    external_indicators = ["www", "api", "cdn", "static", "public"]
    dmz_indicators = ["gateway", "proxy", "lb", "edge", "ingress"]
    internal_indicators = ["internal", "private", "corp", "intra", "admin", "mgmt"]

    external_assets = []
    dmz_assets = []
    internal_assets = []

    for asset in session.assets:
        hostname_lower = asset.hostname.lower()
        if any(ind in hostname_lower for ind in internal_indicators):
            internal_assets.append(asset.hostname)
        elif any(ind in hostname_lower for ind in dmz_indicators):
            dmz_assets.append(asset.hostname)
        elif any(ind in hostname_lower for ind in external_indicators):
            external_assets.append(asset.hostname)

    for ext in external_assets:
        for dmz in dmz_assets:
            graph.add_relationship(Relationship(
                source=ext,
                target=dmz,
                relationship_type="external_to_dmz",
                confidence=0.6,
                evidence="External asset may route through DMZ",
            ))

    for dmz in dmz_assets:
        for internal in internal_assets:
            graph.add_relationship(Relationship(
                source=dmz,
                target=internal,
                relationship_type="dmz_to_internal",
                confidence=0.6,
                evidence="DMZ asset may have access to internal resources",
            ))


def detect_lateral_movement_paths(session: Session, graph: RelationshipGraph) -> None:
    """Detect potential lateral movement paths based on findings."""
    high_value_findings = [f for f in session.findings if f.severity.value in ["critical", "high"]]

    high_value_hosts = list(set(f.host for f in high_value_findings))

    for i, host1 in enumerate(high_value_hosts):
        host1_findings = [f for f in high_value_findings if f.host == host1]
        for host2 in high_value_hosts[i + 1:]:
            host2_findings = [f for f in high_value_findings if f.host == host2]

            shared_tags = set()
            for f1 in host1_findings:
                for f2 in host2_findings:
                    shared_tags.update(set(f1.tags) & set(f2.tags))

            if shared_tags:
                graph.add_relationship(Relationship(
                    source=host1,
                    target=host2,
                    relationship_type="lateral_movement_candidate",
                    confidence=0.7,
                    evidence=f"Both hosts have high-severity findings with shared tags: {', '.join(list(shared_tags)[:3])}",
                ))
