# PathFinder Technical Deep-Dive

**Implementation details and code walkthrough**

---

## Module Overview

```
src/pathfinder/
├── cli.py              # Entry point, 6 commands
├── config.py           # Configuration management
├── models/
│   └── schema.py       # Data structures
├── scanners/
│   ├── subfinder.py    # Subdomain enumeration
│   ├── httpx_scanner.py # HTTP probing
│   ├── nuclei.py       # Vulnerability scanning
│   └── approval.py     # Human-in-loop gate
├── ingestors/
│   └── __init__.py     # Universal ingestion
└── core/
    ├── graph.py        # Relationship detection
    ├── reasoning.py    # AI synthesis
    └── output.py       # Visualization
```

---

## 1. The Data Model (`models/schema.py`)

### Why I Chose These Structures

The data model is the foundation. I needed structures that:
1. Represent security concepts accurately
2. Serialize to JSON easily
3. Support the attack path synthesis use case

### The Finding Model

```python
@dataclass
class Finding:
    id: str                    # Unique identifier (template-id for Nuclei)
    name: str                  # Human-readable name
    severity: Severity         # Enum: CRITICAL, HIGH, MEDIUM, LOW, INFO
    host: str                  # Where it was found
    evidence: str              # Proof (URL, matched content, etc.)
    description: str           # What this vulnerability is
    source: str                # Scanner that found it
    template_id: str | None    # Original scanner's ID
    tags: list[str]            # Categories for grouping
    raw: dict                  # Preserve original scanner output
```

**Why `raw: dict`**: I preserve the original scanner output so the AI layer can access scanner-specific fields if needed. This is "lossless" normalization.

**Why `Severity` as Enum**: Using a string would invite bugs (`"High"` vs `"high"`). Enums catch these at definition time.

### The Session Model

```python
@dataclass
class Session:
    domain: str
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    mode: str = "e2e"  # "e2e", "plugin", or "demo"
```

**Why Session exists**: It's the container that flows through the entire pipeline. Instead of passing multiple lists around, functions receive and modify a Session.

**The `add_asset` and `add_finding` methods**: These deduplicate automatically:

```python
def add_asset(self, asset: Asset) -> None:
    existing = next((a for a in self.assets if a.hostname == asset.hostname), None)
    if existing:
        # Merge tech stacks, ports, etc.
        existing.tech_stack = list(set(existing.tech_stack + asset.tech_stack))
    else:
        self.assets.append(asset)
```

---

## 2. Scanner Wrappers (`scanners/`)

### The Pattern

Every scanner wrapper follows the same pattern:

```python
def run_tool(input) -> list[dict]:
    tool = check_tool("toolname")
    if not tool.available:
        return run_fallback(input)
    
    result = subprocess.run([...], capture_output=True)
    return parse_json_output(result.stdout)
```

### Subfinder Implementation

```python
def run_subfinder(domain: str, timeout: int = 60) -> list[str]:
    tool = check_tool("subfinder")
    if not tool.available:
        console.print("[yellow]subfinder not found, falling back to crt.sh[/yellow]")
        return run_crtsh_fallback(domain)

    result = subprocess.run(
        ["subfinder", "-d", domain, "-silent", "-timeout", str(timeout)],
        capture_output=True,
        text=True,
        timeout=timeout + 10,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]
```

**Why `-silent`**: Suppresses banner and progress output. We only want the subdomain list.

**Why `timeout + 10`**: The subprocess timeout should be slightly longer than the tool's internal timeout, so the tool can exit gracefully.

### The crt.sh Fallback

```python
def run_crtsh_fallback(domain: str) -> list[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    
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
```

**Why `%.{domain}`**: The `%` is a SQL wildcard. This queries all certificates ever issued for any subdomain.

**Why filter out `*`**: Wildcard certificates (`*.example.com`) aren't actual subdomains.

---

## 3. Human Approval Gate (`scanners/approval.py`)

### The Implementation

```python
def request_active_scan_approval(session: Session) -> bool:
    panel_content = f"""
[bold green]What this WILL do:[/bold green]
  • HTTP/HTTPS status checks
  • Technology fingerprinting
  • Nuclei templates (misconfig, exposure only)

[bold red]What this will NOT do:[/bold red]
  • No exploitation
  • No credential brute-forcing
  • No payload injection
"""
    console.print(Panel(panel_content, title="ACTIVE SCAN AUTHORIZATION REQUIRED"))
    
    approved = Confirm.ask("Proceed with active scanning?", default=False)
    
    log_approval(session, "active_scan", approved=approved)
    return approved
```

**Why `default=False`**: Active scanning should require explicit consent. Accidental Enter shouldn't trigger a scan.

### Audit Logging

```python
def log_approval(session: Session, action: str, approved: bool) -> None:
    log_file = config.data_dir / "audit.log"
    entry = {
        "timestamp": datetime.now().isoformat(),
        "domain": session.domain,
        "action": action,
        "approved": approved,
        "host_count": len(session.assets),
    }
    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")
```

**Why JSON lines format**: Each line is a complete JSON object. Easy to parse, append-only, no corruption risk.

---

## 4. Universal Ingestion (`ingestors/__init__.py`)

### Format Detection

```python
def detect_format(content: str, suffix: str) -> str:
    if suffix == ".csv":
        return "nessus"
    
    try:
        first_line = content.strip().split("\n")[0]
        data = json.loads(first_line)
        
        if "template-id" in data or "template" in data:
            return "nuclei"
        elif "tech" in data or "status_code" in data:
            return "httpx"
    except:
        pass
    
    return "nuclei"  # Default fallback
```

**Why check first line**: Scanner JSON is usually newline-delimited (one object per line). Checking the first line is efficient.

**Why default to Nuclei**: It's the most common format. If detection fails, assume Nuclei and let parsing fail gracefully.

### Nuclei Ingestion

```python
def ingest_nuclei(content: str, domain: Optional[str] = None) -> Session:
    session = Session(domain=domain or "unknown", mode="plugin")
    
    for line in content.strip().split("\n"):
        if not line.strip():
            continue
        
        data = json.loads(line)
        host = data.get("host", "")
        if "://" in host:
            host = host.split("://")[1].split("/")[0].split(":")[0]
        
        finding = Finding(
            id=data.get("template-id", "unknown"),
            name=data.get("name", data.get("template-id", "Unknown")),
            severity=severity_map.get(data.get("severity", "info").lower(), Severity.INFO),
            host=host,
            evidence=data.get("matched-at", ""),
            ...
        )
        session.add_finding(finding)
    
    return session
```

**Why strip protocol from host**: Nuclei sometimes returns `https://host/path`. We want just `host`.

**Why double fallback for name**: `data.get("name", data.get("template-id", "Unknown"))` — some findings have name, some only have template-id.

---

## 5. Relationship Graph (`core/graph.py`)

### The Graph Structure

```python
@dataclass
class Relationship:
    source: str              # Entity A
    target: str              # Entity B
    relationship_type: str   # What connects them
    confidence: float        # How sure are we (0-1)
    evidence: str            # Why we think this

@dataclass
class RelationshipGraph:
    relationships: list[Relationship]
    clusters: dict[str, list[str]]  # Named groups of entities
```

### Detection: Shared Technology

```python
def detect_shared_tech(session: Session, graph: RelationshipGraph) -> None:
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
```

**Why `tech.lower()`**: Normalize case (`Nginx` vs `nginx`).

**Why confidence 0.8**: Shared technology is a moderate signal. Many sites run nginx; doesn't necessarily mean shared infrastructure.

### Detection: Credential Chains

```python
def detect_credential_exposure_chains(session: Session, graph: RelationshipGraph) -> None:
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
    
    for cred in credential_findings:
        for admin in admin_findings:
            if cred.host != admin.host:
                graph.add_relationship(Relationship(
                    source=cred.host,
                    target=admin.host,
                    relationship_type="credential_to_access",
                    confidence=0.85,
                    evidence=f"Credentials from {cred.host} may grant access to {admin.host}",
                ))
```

**Why cross-host only**: If credentials and admin panel are on the same host, that's obvious. Cross-host chains are the interesting ones.

---

## 6. AI Reasoning Engine (`core/reasoning.py`)

The reasoning engine uses **Groq** with **Llama 3.3 70B** for fast, free AI analysis.

### The System Prompt

```python
SYSTEM_PROMPT = """You are an expert penetration tester and security analyst. 
Your task is to analyze external attack surface findings and synthesize realistic attack paths.

You think like an attacker: you look for chains of vulnerabilities that, when combined, 
create a path to high-value targets. A critical SQL injection matters less if it's on 
an isolated test server with no data. A medium-severity misconfiguration on the main 
API gateway matters more.

Your analysis must be:
1. Evidence-based: Every claim must cite specific findings
2. Realistic: Focus on paths an attacker would actually take
3. Business-aware: Consider what assets are valuable targets
4. Actionable: Prioritize what to fix first and why

Output valid JSON only. No markdown, no explanation outside the JSON."""
```

**Why "think like an attacker"**: This framing produces more realistic attack paths than generic vulnerability analysis.

**Why "JSON only"**: Prevents the LLM from adding explanatory text that breaks parsing.

### The User Prompt Structure

```python
prompt = f"""Analyze this external attack surface assessment...

## Target Domain
{session.domain}

## Discovered Assets ({len(session.assets)} total)
{json.dumps(assets_summary, indent=2)}

## Findings ({len(session.findings)} total)
{json.dumps(findings_summary, indent=2)}

## Detected Relationships
{json.dumps(graph.to_dict(), indent=2)}

## Output Format (JSON only)
{{
  "executive_summary": "...",
  "risk_score": 0-100,
  "attack_paths": [...],
  ...
}}
"""
```

**Why include relationship graph**: The AI can use detected relationships (shared tech, credential chains) to build more sophisticated attack paths.

**Why JSON schema in prompt**: Shows the LLM exactly what structure to produce. Reduces parsing errors.

### Response Parsing

```python
response_text = chat_completion.choices[0].message.content

# Strip markdown code blocks if present
if response_text.startswith("```json"):
    response_text = response_text[7:]
if response_text.endswith("```"):
    response_text = response_text[:-3]

analysis = json.loads(response_text)
```

**Why strip markdown**: LLMs sometimes wrap JSON in code blocks despite instructions.

---

## 7. Output Layer (`core/output.py`)

### ASCII Attack Path Visualization

```python
def print_attack_path_ascii(path: AttackPath) -> None:
    for i, step in enumerate(path.steps):
        is_last = i == len(path.steps) - 1
        
        if i == 0:
            prefix = "┌──"
        elif is_last:
            prefix = "└──"
        else:
            prefix = "├──"
        
        box_top = f"  {prefix}{'─' * 50}┐"
        box_mid = f"  │  [bold]Step {step.step_number}:[/bold] {step.action}"
        # ...
```

**Why box-drawing characters**: `┌`, `│`, `└`, `├` create clean visual hierarchy. More readable than ASCII dashes.

**Why Rich markup**: `[bold]` and `[cyan]` create visual emphasis without ANSI escape codes in the source.

### HTML Report Generation

```python
def generate_html_report(analysis: dict, session: Session) -> str:
    risk_color = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else ...
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>PathFinder Report - {session.domain}</title>
    <style>
        body {{ background: #0d1117; color: #c9d1d9; ... }}
        .risk-critical {{ color: #f85149; }}
        .attack-path {{ background: #161b22; ... }}
    </style>
</head>
...
"""
```

**Why inline CSS**: No external dependencies. Single file that can be emailed, shared, or uploaded.

**Why GitHub dark mode colors**: Familiar aesthetic for developers. Professional appearance.

---

## 8. CLI Implementation (`cli.py`)

### The `run` Command

```python
@app.command()
def run(
    domain: str = typer.Argument(..., help="Target domain"),
    passive_only: bool = typer.Option(False, "--passive-only", "-p"),
    skip_approval: bool = typer.Option(False, "--yes", "-y"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
    demo: bool = typer.Option(False, "--demo"),
) -> None:
    if demo:
        session = generate_demo_session(domain)
    else:
        session = Session(domain=domain)
        discover_subdomains(session)
        
        if not passive_only:
            if not skip_approval and not request_active_scan_approval(session):
                return
            probe_hosts(session)
            scan_vulnerabilities(session)
    
    analysis = analyze_sync(session)
    print_full_analysis(analysis, session)
```

**Why `--demo` flag on `run`**: Users can see the full flow with fake data without a separate command.

**Why `--yes` flag**: For scripted usage (CI/CD). Skips interactive prompt.

### Demo Data Generation

```python
def generate_demo_session(domain: str) -> Session:
    demo_assets = [
        Asset(hostname=f"www.{domain}", tech_stack=["nginx", "react"], ...),
        Asset(hostname=f"api.{domain}", tech_stack=["nginx", "nodejs"], ...),
        Asset(hostname=f"admin.{domain}", tech_stack=["apache", "php"], ...),
        ...
    ]
    
    demo_findings = [
        Finding(
            id="exposed-panels/admin-login",
            name="Admin Panel Accessible Without Network Restriction",
            severity=Severity.CRITICAL,
            host=f"admin.{domain}",
            ...
        ),
        ...
    ]
```

**Why realistic demo data**: The demo should look like a real assessment. Generic "Test Finding 1" wouldn't showcase the product properly.

---

## Performance Considerations

### What I Optimized

1. **Parallel relationship detection**: Each detector runs independently
2. **Lazy loading**: Scanner wrappers only import when called
3. **Early termination**: If passive-only mode, skip active scanning imports

### What I Didn't Optimize (Prototype Scope)

1. **Async I/O**: Scanner calls are sequential (could be parallel)
2. **Caching**: No caching of API responses
3. **Large scale**: Not tested beyond ~100 assets

---

## Security Considerations

### What I Hardened

1. **No shell injection**: All subprocess calls use list arguments, not shell strings
2. **Input validation**: Hostnames extracted with defensive parsing
3. **Audit logging**: All approval decisions logged

### What Would Need Hardening for Production

1. **API key storage**: Currently uses environment variables
2. **Session file permissions**: Currently default umask
3. **Rate limiting**: No protection against API abuse

---

## Testing Approach

### What I Tested

1. **Demo mode**: Full pipeline with synthetic data
2. **Fallback paths**: Ran without external tools
3. **Edge cases**: Empty findings, missing fields

### What Would Need More Testing

1. **Real scanner output**: Various Nuclei/Nessus formats
2. **Large datasets**: 1000+ findings
3. **AI edge cases**: Malformed responses

---

*Technical Deep-Dive • PathFinder v0.1.0 • May 2026*
