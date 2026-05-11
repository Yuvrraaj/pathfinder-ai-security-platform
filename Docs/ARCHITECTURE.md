# PathFinder Architecture & Design Decisions

**Author**: Yuvraj  
**Date**: May 2026  
**Document Type**: Engineering Decision Record

---

## Overview

This document captures the architectural decisions, design philosophy, and reasoning behind PathFinder. It's written as a first-person narrative to explain not just *what* was built, but *why* each decision was made.

---

## 1. The Core Insight: Why I Built This

### The Problem I Observed

When I started researching the AI pentesting landscape, I noticed a pattern:

> "Everyone is building autonomous hackers. Nobody is building analyst augmentation."

Shannon scores 96% on benchmarks. PentAGI has 14,700 GitHub stars. XBOW reached #1 on HackerOne. These are impressive technical achievements. But when I talked to practitioners (and researched their pain points), I heard something different:

> "We ran Nuclei and got 347 findings. I spent two days just figuring out which 10 mattered."

The problem isn't *finding* vulnerabilities. Scanners are excellent at that. The problem is *making sense* of what you found.

### Why I Chose Intelligence Over Automation

I could have built another autonomous scanner. The technology exists. But I asked myself:

1. **What do enterprises actually want?** Not full autonomy (trust concerns, Cisco Talos flagged this). They want *augmentation*.

2. **What's the real bottleneck?** Not detection. It's triage, prioritization, and communication.

3. **Where can AI add unique value?** Not in running Nmap faster. In *reasoning about findings*.

Therefore, I built PathFinder as an **intelligence layer**, not another scanner.

---

## 2. Dual-Mode Architecture: The Key Design Decision

### The Insight That Shaped Everything

A security practitioner told me:

> "Nuclei, httpx, Subfinder — they're industry standard. We're not switching."

This was the pivotal insight. Instead of competing with established tools, I decided to **complement them**.

### Why Dual-Mode?

**Mode A (E2E)**: For users who want a complete solution
- Run `pathfinder run domain.com` and get everything
- Good for demos, quick assessments, smaller teams

**Mode B (Plugin)**: For users with existing tooling
- Import Nuclei JSON, Nessus CSV, or httpx output
- Add intelligence without changing workflows
- Enterprise-friendly (no tool replacement)

### Why This Matters for RedHold

If RedHold internalizes this approach:
- **No tool replacement asks** — customers keep their scanners
- **Value-add layer** — PathFinder is the "brain" on top
- **Lower adoption friction** — just add a layer, don't rip and replace

I specifically avoided building "a better Nuclei" because that's a losing proposition. Nuclei has 9,000+ templates and massive community investment. My competitive advantage isn't in template coverage — it's in reasoning.

---

## 3. The Normalized Schema: Why I Invested Here First

### The Problem

Every scanner has different output formats:
- Nuclei: JSON with `template-id`, `matched-at`, `severity`
- Nessus: CSV with `Plugin ID`, `Risk`, `Synopsis`
- httpx: JSON with `tech`, `status_code`, `title`

If PathFinder is tightly coupled to one format, it can't be a universal intelligence layer.

### My Solution

I created a **normalized schema** as the foundation:

```python
@dataclass
class Finding:
    id: str
    name: str
    severity: Severity  # Enum: CRITICAL, HIGH, MEDIUM, LOW, INFO
    host: str
    evidence: str
    description: str
    source: str         # "nuclei", "nessus", "httpx", etc.
    raw: dict           # Preserve original data
```

### Why This Design

1. **Common denominator**: Every scanner produces findings with severity, host, and evidence. I normalized to these.

2. **Preserve original data**: The `raw` field keeps the original scanner output. Nothing is lost.

3. **Source tracking**: I track where each finding came from. This enables "which scanner found what" analysis.

4. **Enum-based severity**: Using an enum prevents string comparison bugs (`"High"` vs `"high"` vs `"HIGH"`).

### The Trade-off I Accepted

Normalization loses some scanner-specific nuance. A Nessus `Plugin Output` field has more detail than my `evidence` field can capture. I accepted this trade-off because:

- The AI reasoning layer can still access `raw` data
- Most attack path logic only needs the normalized fields
- Simplicity of the core schema enables easier plugin development

---

## 4. Scanner Wrappers with Fallbacks: Defensive Design

### The Problem

External tools (subfinder, httpx, nuclei) may not be installed. If PathFinder fails when tools are missing, it's not useful for demos or environments without Go tooling.

### My Solution

Every scanner wrapper has a Python fallback:

| Tool | Primary | Fallback |
|------|---------|----------|
| Subfinder | Go binary | crt.sh API (Python urllib) |
| httpx | Go binary | Python httpx library |
| Nuclei | Go binary | 13 exposed path checks (Python) |

### Why I Did This

1. **Demo capability**: `pathfinder demo` works anywhere with just Python.

2. **Graceful degradation**: Missing tools don't crash the system; they reduce capability.

3. **CI/CD friendly**: Can run in containers without installing Go toolchain.

### The Code Pattern

```python
def run_subfinder(domain: str) -> list[str]:
    tool = check_tool("subfinder")
    if not tool.available:
        console.print("[yellow]subfinder not found, falling back to crt.sh[/yellow]")
        return run_crtsh_fallback(domain)
    # ... run subprocess
```

I made the fallback visible to users (`[yellow]` warning) so they know they're getting reduced capability, not silent failure.

---

## 5. Human-in-the-Loop: Safety as a Feature

### The Problem

Autonomous security tools raise trust concerns. Cisco Talos wrote about Shannon:

> "If the platform itself is compromised, misconfigured, or stores data insecurely, attackers could gain access to highly sensitive internal assets."

Enterprises don't want tools that "just do things" without oversight.

### My Solution

Explicit approval gate before any active scanning:

```
┌─────────────────────────────────────────────────────────┐
│  ACTIVE SCAN AUTHORIZATION REQUIRED                     │
│                                                         │
│  What this WILL do:                                     │
│    • HTTP/HTTPS status checks                           │
│    • Technology fingerprinting                          │
│    • Nuclei templates (misconfig, exposure only)        │
│                                                         │
│  What this will NOT do:                                 │
│    • No exploitation                                    │
│    • No credential brute-forcing                        │
│    • No payload injection                               │
│                                                         │
│  Proceed? [y/N]                                         │
└─────────────────────────────────────────────────────────┘
```

### Why This Design

1. **Transparency**: Users see exactly what will happen before it happens.

2. **Audit trail**: Every approval is logged with timestamp to `~/.pathfinder/audit.log`.

3. **Safe defaults**: Default answer is `N` (no). Active scanning requires explicit consent.

4. **Scope limitation**: I explicitly list what PathFinder will NOT do. This is reassuring.

### The Framing Matters

I framed human-in-the-loop as a **feature**, not a limitation:

> "PathFinder keeps humans in control. AI assists; humans decide."

This is enterprise-friendly positioning that addresses the trust concerns raised about autonomous tools.

---

## 6. Relationship Graph: Enabling Attack Path Synthesis

### The Problem

Individual findings are atoms. Attack paths are molecules. To synthesize paths, I need to understand *relationships* between assets and findings.

### My Solution

A relationship graph with 8 detection methods:

1. **Shared Technology**: Assets running the same tech stack
2. **Shared Certificates**: Assets with common TLS certificate issuers
3. **Finding Correlations**: Same vulnerability type across multiple assets
4. **Subdomain Patterns**: dev/staging/prod environment groupings
5. **Severity Clusters**: Assets grouped by finding severity
6. **Credential Exposure Chains**: Credentials on one host → access on another
7. **Attack Surface Tiers**: External → DMZ → internal patterns
8. **Lateral Movement Candidates**: High-severity findings with shared tags

### Why These Specific Detectors

I chose detectors that map to **real attacker behavior**:

- Attackers look for shared credentials (detector #6)
- Attackers pivot from external to internal (detector #7)
- Attackers chain findings with similar characteristics (detector #8)

Each detector produces a `Relationship` with:
- Source and target entities
- Relationship type
- Confidence score (0-1)
- Evidence string

### The Confidence Scoring

I assign confidence scores based on how certain the relationship is:

| Relationship | Confidence | Reasoning |
|--------------|------------|-----------|
| Same vulnerability | 0.95 | Nearly certain — same CVE on different hosts |
| Shared certificate | 0.90 | Strong signal — implies shared infrastructure |
| Credential to access | 0.85 | Likely — but credentials might be rotated |
| Shared technology | 0.80 | Moderate — common tech doesn't mean shared |
| Dev/prod pair | 0.70 | Heuristic — naming convention might be wrong |
| Attack surface tier | 0.60 | Weak — based on hostname patterns only |

---

## 7. AI Reasoning Engine: The Core Differentiator

### The Problem

Raw findings + relationships still don't tell a story. I need AI to:
1. Chain findings into attack paths
2. Score business impact
3. Generate narrative explanations

### My Solution

A prompt-engineered Groq integration with Llama 3.3 70B:

```python
SYSTEM_PROMPT = """You are an expert penetration tester and security analyst...
You think like an attacker: you look for chains of vulnerabilities that,
when combined, create a path to high-value targets..."""
```

### Why Groq + Llama 3.3 70B

1. **Free tier**: Groq offers a generous free API tier (get key at console.groq.com)
2. **Fast inference**: Groq's LPU architecture delivers sub-second responses
3. **Structured output**: Llama 3.3 70B follows JSON schemas reliably
4. **Reasoning quality**: 70B parameter model handles security domain reasoning well

### Why I Included a Fallback

Not everyone has `GROQ_API_KEY` set. For demos and testing, I built a **heuristic fallback** that:

- Looks for admin panel findings
- Looks for credential exposure findings
- Generates basic attack paths based on finding patterns

The fallback is less sophisticated but ensures PathFinder always produces *something*.

### The Prompt Design

I structured the prompt to:

1. **Provide full context**: Assets, findings, relationships as JSON
2. **Request specific output**: Attack paths with steps, confidence, business impact
3. **Enforce structure**: JSON schema in the prompt ensures parseable output
4. **Inject domain expertise**: "Think like an attacker" framing

---

## 8. Output Layer: The "Wow Moment"

### The Problem

Attack paths are data structures. Users need visualization.

### My Solution

ASCII art attack flow visualization:

```
  ┌────────────────────────────────────────────────────┐
  │  Step 1: Access Environment File Exposure
  │  Asset: api.example.com
  │  Finding: exposures/configs/env-file
  │────────────────────────────────────────────────────┘
  │
  │  ↓
  │
  └────────────────────────────────────────────────────┐
     Step 2: Use Credentials on Admin Panel
     Asset: admin.example.com
   ────────────────────────────────────────────────────┘
```

### Why ASCII Instead of a Web UI

1. **Terminal-native**: Security practitioners live in terminals
2. **Copy-pasteable**: Can share in Slack, tickets, docs
3. **No dependencies**: No React, no browser, no server
4. **Demo-friendly**: Works in any screen recording

### Why I Also Built HTML Output

For executive stakeholders who need polished reports:

```bash
pathfinder run example.com --output report.html
```

The HTML report has:
- Dark mode styling (GitHub-inspired)
- Risk score with color coding
- Attack path cards
- Recommendations list

This covers both technical (terminal) and executive (HTML) audiences.

---

## 9. CLI Design: Opinionated Simplicity

### The Problem

Too many options paralyze users. Too few options frustrate power users.

### My Solution

**6 commands**, each with a clear job:

| Command | Job |
|---------|-----|
| `run` | Full assessment in one command |
| `scan` | Just scanning, no analysis |
| `ingest` | Import external scanner output |
| `analyze` | Generate attack paths from session |
| `demo` | Showcase with synthetic data |
| `status` | Check configuration |

### Why `run` Is the Hero Command

Most users want: "Scan this domain and tell me what's wrong."

`pathfinder run example.com` does exactly that — scan + analyze + output.

I added `scan` and `analyze` as separate commands for users who want finer control, but `run` is the recommended path.

### Why `demo` Exists

For interviews, sales demos, and testing without real targets:

```bash
pathfinder demo --output report.html
```

Generates realistic synthetic data so you can showcase the full capability without scanning anything real.

---

## 10. What I Explicitly Avoided

### Things I Could Have Built But Didn't

1. **Web UI**: Would add scope, dependencies, and deployment complexity
2. **Database**: In-memory is sufficient for prototype; files for persistence
3. **Kubernetes deployment**: Out of scope for assignment
4. **Multi-tenancy**: MSSP feature, deferred to future
5. **Remediation code generation**: Good idea, but adds significant complexity

### Why I Made These Cuts

The assignment said:

> "A narrow, thoughtful, working prototype is better than a broad but shallow one."

I prioritized **depth in attack path synthesis** over breadth in features. Every feature I added directly supports the core value proposition: turning scanner output into actionable intelligence.

---

## 11. Trade-offs I Accepted

| Decision | Trade-off | Why I Accepted It |
|----------|-----------|-------------------|
| Python-only | Slower than Go tools | Simpler deployment, better AI integration |
| In-memory graph | No persistence across runs | Prototype scope; files handle session persistence |
| Heuristic fallback | Less accurate without AI | Ensures demos work without API key |
| ASCII visualization | Less pretty than D3.js | Terminal-native, no dependencies |
| 13 fallback path checks | Fewer than Nuclei's 9000 | Sufficient for demo; real usage should have Nuclei installed |

---

## 12. What I Would Do Next

### With 1 More Week

1. **Remediation code generation**: Generate IaC patches for common findings
2. **More ingestor formats**: Burp, OWASP ZAP, Qualys XML
3. **Continuous delta monitoring**: "What changed since yesterday?"

### With 1 More Month

1. **Web dashboard**: Real-time visualization, team collaboration
2. **SIEM integration**: Export to Splunk, Elastic
3. **Multi-tenant**: MSSP support with client isolation

### With Unlimited Time

1. **Fine-tuned security model**: Train on pentest reports for better reasoning
2. **Automated remediation**: PR creation, WAF rule deployment
3. **Threat intelligence integration**: Correlate with active exploitation data

---

## Conclusion

PathFinder exists because I observed a gap: scanners find vulnerabilities, but humans struggle to prioritize them. Instead of building a better scanner (crowded market, hard to differentiate), I built an intelligence layer that makes *any* scanner smarter.

The key decisions:
1. **Dual-mode architecture** — work with existing tools, don't replace them
2. **Normalized schema** — enable universal ingestion
3. **Human-in-the-loop** — safety as a feature, not a limitation
4. **Relationship graph** — enable attack path reasoning
5. **AI synthesis** — turn data into narrative

Every decision traced back to one question: *What helps the security analyst do their job better?*

---

*Architecture Document • PathFinder v0.1.0 • May 2026*
