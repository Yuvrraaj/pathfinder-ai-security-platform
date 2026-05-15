# PathFinder

**AI-Assisted External Assessment Platform**

> "Scanners tell you WHAT's wrong. PathFinder tells you WHY it matters and HOW an attacker would chain it."

## What It Is

PathFinder is an intelligence layer that transforms raw security scanner output into actionable attack paths. It works in two modes:

- **E2E Mode**: Run the full pipeline (Subfinder → httpx → Nuclei → AI Analysis)
- **Plugin Mode**: Ingest output from scanners you already use (Nuclei, Nessus, Qualys, Burp)

Either way, you get:
- Attack path synthesis with confidence scoring
- Business impact assessment
- Executive-ready narratives
- Prioritized remediation guidance

## The Problem

Security teams drown in scanner output:
- **112,000+ open vulnerabilities** per organization (average)
- **CVSS doesn't know your business**: A 9.8 on an air-gapped server ≠ 7.5 on internet-facing admin panel
- **Atomic findings**: CVEs listed individually, no attack chain context
- **No prioritization**: Which 5 of these 500 findings actually matter?

## The Solution

PathFinder adds the missing intelligence layer:

```
Scanner Output → PathFinder → Attack Paths + Priorities + Narrative
```

Instead of:
```
CRITICAL: CVE-2024-1234 on api.example.com
HIGH: Exposed admin panel on admin.example.com
HIGH: .env file accessible on api.example.com
```

You get:
```
ATTACK PATH: API to Database Compromise
Confidence: HIGH | Impact: CRITICAL

Step 1: Access exposed .env file on api.example.com
        → Contains database credentials

Step 2: Use credentials to access admin panel on admin.example.com
        → No MFA, accepts any source IP

Step 3: Admin panel has direct database access
        → Full PII exposure

FIX FIRST: Remove .env from web root, rotate credentials
```

## Quick Start

### Docker (Recommended)

```bash
# Build and run
make build
make demo

# With AI analysis (free Groq API)
export GROQ_API_KEY=gsk_your_key  # Get free key at console.groq.com
make demo

# Scan vulnerable labs
make labs-up
make scan TARGET="http://juice-shop:3000"
```

### Local Install

```bash
# Install
uv pip install -e .

# Check tool availability
pathfinder status

# Run a demo (no real scanning)
pathfinder demo --output report.html

# Full assessment (E2E mode)
pathfinder run example.com

# Or ingest existing scanner output (Plugin mode)
pathfinder ingest nuclei-output.json
pathfinder analyze
```

## Commands

| Command | Description |
|---------|-------------|
| `pathfinder run <domain>` | Full E2E assessment with AI analysis |
| `pathfinder scan <domain>` | Scan only (passive + active recon) |
| `pathfinder ingest <file>` | Import scanner output (Nuclei, Nessus, httpx) |
| `pathfinder analyze` | Generate attack paths from session data |
| `pathfinder demo` | Run with synthetic data to showcase capabilities |
| `pathfinder status` | Check tool availability and API configuration |

## Configuration

```bash
# AI analysis with Groq (FREE - get key at console.groq.com)
export GROQ_API_KEY=gsk_your_key

# Optional external tools (PathFinder has built-in fallbacks)
# - subfinder: Passive subdomain enumeration
# - httpx: HTTP probing and tech detection  
# - nuclei: Vulnerability scanning

# Without API key, PathFinder uses heuristic analysis (still useful!)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     PATHFINDER — DUAL MODE                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  MODE A: E2E                           MODE B: PLUGIN                   │
│  pathfinder run domain                 pathfinder ingest file           │
│                                                                         │
│  ┌─────────────────────────┐           ┌─────────────────────────┐      │
│  │  Subfinder / crt.sh     │           │  Nuclei JSON            │      │
│  │  httpx / Python probe   │           │  Nessus CSV             │      │
│  │  Nuclei / Python checks │           │  httpx JSON             │      │
│  └───────────┬─────────────┘           └───────────┬─────────────┘      │
│              │                                     │                    │
│              └──────────────┬──────────────────────┘                    │
│                             ▼                                           │
│              ┌─────────────────────────────────────┐                    │
│              │      UNIVERSAL INGESTION LAYER      │                    │
│              │   (normalize to PathFinder schema)  │                    │
│              └───────────────┬─────────────────────┘                    │
│                              ▼                                          │
│              ┌─────────────────────────────────────┐                    │
│              │       AI REASONING ENGINE           │                    │
│              │  • Relationship graph               │                    │
│              │  • Attack path synthesis            │                    │
│              │  • Business impact scoring          │                    │
│              │  • Narrative generation             │                    │
│              └───────────────┬─────────────────────┘                    │
│                              ▼                                          │
│              ┌─────────────────────────────────────┐                    │
│              │           OUTPUT LAYER              │                    │
│              │  • ASCII attack path visualization  │                    │
│              │  • Executive summary                │                    │
│              │  • HTML reports                     │                    │
│              │  • Prioritized actions              │                    │
│              └─────────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────────────────────┘
```

## Safety Design

PathFinder is designed for safe, authorized assessment:

### What It Does
- Passive subdomain enumeration (certificate transparency, DNS)
- HTTP probing (status codes, headers, tech detection)
- Safe vulnerability templates (misconfig, exposure, info only)
- AI analysis and reporting

### What It Does NOT Do
- No exploitation
- No credential brute-forcing
- No payload injection
- No destructive actions

### Human Approval Gate
Active scanning requires explicit approval:
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

## Example Output

### Attack Path Visualization
```
ATTACK PATH: Sensitive Data Exposure
ID: AP-002 | Confidence: ●●● HIGH | Impact: CRITICAL

Attack Flow:

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
     Finding: exposed-panels/admin-login
   ────────────────────────────────────────────────────┘

Narrative:
╭──────────────────────────────────────────────────────╮
│ Sensitive files are publicly accessible at           │
│ api.example.com, potentially exposing credentials    │
│ that grant access to the admin panel.                │
╰──────────────────────────────────────────────────────╯
```

### HTML Report
PathFinder generates dark-mode HTML reports suitable for executive presentation:
```bash
pathfinder run example.com --output report.html
```

## Why This Approach

### Research Finding
> "I asked security practitioners why they don't build a better scanner. They said: 'Nuclei, httpx, Subfinder are industry standard — they're not going anywhere.' So instead of replacing them, PathFinder works WITH them."

### Differentiation
| Tool | Strength | Gap PathFinder Fills |
|------|----------|---------------------|
| Nuclei | 9000+ templates | No attack chain reasoning |
| Nessus | Enterprise coverage | No AI-powered prioritization |
| Shannon | Autonomous exploitation | Requires source access, trust concerns |
| EASM tools | Asset discovery | Inventory, not intelligence |

PathFinder's positioning:
> "Industry-standard scanners aren't going anywhere. PathFinder doesn't replace them — it makes them smarter."

## Limitations

- AI analysis requires GROQ_API_KEY (falls back to heuristics without it)
- Attack path synthesis quality depends on finding density
- External tools (subfinder, httpx, nuclei) provide better results but have fallbacks
- Tested primarily against web application attack surfaces

## What's Next

With more time, PathFinder would add:
- More ingestor formats (Burp, OWASP ZAP, Qualys XML)
- Remediation code generation (IaC patches, WAF rules)
- Continuous monitoring with delta detection
- Integration with ticketing systems (Jira, Linear)
- Multi-tenant support for MSSPs

## License

MIT

---

Built for RedHold Engineering Assignment • May 2026
