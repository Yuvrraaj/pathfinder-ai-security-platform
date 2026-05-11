# PathFinder Decision Log

**A chronological record of key decisions made during development**

---

## Decision 1: Direction Selection

**Date**: Day 0 (Research Phase)  
**Decision**: Build an "AI Recon Analyst" instead of autonomous pentester  
**Context**: 
- Evaluated 6 directions: MSP Portfolio, Remediation-First, Context Injection, Compliance Evidence, Attack Path Validation, Delta-First
- Scored each on differentiation, pain clarity, prototype feasibility, technical impressiveness, business viability

**Alternatives Considered**:
1. **Remediation-First**: Generate code fixes for findings
   - Rejected because: High demo risk (code gen can fail), Snyk already in this space
2. **Autonomous Pentester**: Full Shannon/PentAGI clone
   - Rejected because: Already crowded, trust concerns, assignment explicitly warned against "thin forks"

**Why I Chose This**:
- Practitioners told me: "The problem isn't finding vulns, it's making sense of them"
- "Intelligence layer" positioning is unique — no direct competitor
- Human-in-loop addresses enterprise trust concerns
- Attack path visualization is a compelling demo moment

**Outcome**: This decision shaped the entire architecture. Every subsequent choice flowed from "we're an intelligence layer, not a scanner."

---

## Decision 2: Dual-Mode Architecture

**Date**: Day 0 (Architecture Phase)  
**Decision**: Support both E2E scanning and plugin ingestion  
**Context**: A practitioner said "Nuclei, httpx, Subfinder are industry standard — we're not switching."

**Alternatives Considered**:
1. **E2E Only**: Run our own scanners, ignore external output
   - Rejected because: Forces tool replacement, higher adoption friction
2. **Plugin Only**: Only ingest external output, no built-in scanning
   - Rejected because: Can't demo without existing scan data, less impressive

**Why I Chose This**:
- E2E mode enables standalone demos and quick assessments
- Plugin mode enables enterprise adoption without workflow disruption
- Both converge to the same intelligence layer (normalized schema)
- If RedHold internalizes this: "keep your tools, add our intelligence"

**Outcome**: Implemented universal ingestion layer with Nuclei, Nessus, httpx parsers.

---

## Decision 3: Python Over Go

**Date**: Day 1  
**Decision**: Write everything in Python, not Go  
**Context**: Most security tools (Nuclei, httpx, Subfinder) are written in Go for performance.

**Alternatives Considered**:
1. **Go**: Faster execution, same ecosystem as tools we integrate
   - Rejected because: Slower development, harder AI integration
2. **Hybrid**: Go for scanning, Python for AI
   - Rejected because: Two codebases, complex deployment

**Why I Chose This**:
- Python has better AI/ML ecosystem (Anthropic SDK, data processing)
- Faster development for a 5-day prototype
- Can shell out to Go binaries when needed (subprocess)
- Performance isn't critical for an intelligence layer

**Trade-off Accepted**: Slower than native Go tools. Mitigated by using Go binaries for scanning when available.

---

## Decision 4: Dataclasses Over Pydantic for Models

**Date**: Day 1  
**Decision**: Use Python dataclasses with manual validation, not full Pydantic models  
**Context**: Need structured data models for Asset, Finding, AttackPath.

**Alternatives Considered**:
1. **Pydantic v2**: Full validation, JSON schema generation
   - Rejected because: Adds complexity, validation errors can be confusing
2. **Plain dicts**: No structure at all
   - Rejected because: Type safety helps during development

**Why I Chose This**:
- Dataclasses are stdlib (no extra dependency for core models)
- `@dataclass` with type hints gives IDE support
- `to_dict()` methods handle serialization explicitly
- Pydantic is installed anyway (via Anthropic SDK), but not required for models

**Outcome**: Clean, simple models that are easy to understand and modify.

---

## Decision 5: Typer Over Click for CLI

**Date**: Day 1  
**Decision**: Use Typer for CLI framework  
**Context**: Need a CLI with multiple commands, help text, and options.

**Alternatives Considered**:
1. **Click**: More established, more control
   - Rejected because: More verbose, less automatic help generation
2. **argparse**: Stdlib, no dependencies
   - Rejected because: Subcommand handling is clunky
3. **Fire**: Auto-generates CLI from functions
   - Rejected because: Less control over help text and validation

**Why I Chose This**:
- Typer builds on Click with less boilerplate
- Automatic help generation from docstrings
- Type hints become CLI argument types
- Rich integration for beautiful output

**Outcome**: Clean CLI with 6 commands, good help text, minimal code.

---

## Decision 6: Rich for Terminal Output

**Date**: Day 1  
**Decision**: Use Rich library for all terminal output  
**Context**: Need tables, panels, colored text, and ASCII art.

**Why I Chose This**:
- Single library for all formatting needs
- Tables, panels, trees, progress bars
- Markdown rendering
- Works in all terminals

**Alternative Considered**: Plain print() with ANSI codes. Rejected because Rich is cleaner and more maintainable.

**Outcome**: Beautiful terminal output with minimal effort.

---

## Decision 7: Subprocess for External Tools

**Date**: Day 1  
**Decision**: Call external tools via subprocess, not as libraries  
**Context**: Need to run Subfinder, httpx, Nuclei.

**Alternatives Considered**:
1. **Go bindings**: Import Go packages from Python
   - Rejected because: Complex, requires CGO
2. **Reimplement in Python**: Write our own subdomain enumeration
   - Rejected because: Why rebuild what already exists?

**Why I Chose This**:
- Subprocess is simple and reliable
- External tools handle their own complexity
- Can easily add new tools later
- Fallback to Python when tools unavailable

**Outcome**: `subprocess.run()` with JSON parsing for each tool.

---

## Decision 8: crt.sh as Subfinder Fallback

**Date**: Day 1  
**Decision**: Query crt.sh API when Subfinder not installed  
**Context**: Need subdomain enumeration to work without Go tools.

**Why I Chose This**:
- crt.sh is the highest-signal source Subfinder queries anyway
- Free, no API key required
- Simple REST API with JSON output
- Covers the most important passive data source

**Trade-off Accepted**: crt.sh returns fewer subdomains than Subfinder's 40+ sources. Acceptable for demos and fallback scenarios.

---

## Decision 9: Human Approval as Explicit Gate

**Date**: Day 1  
**Decision**: Require explicit Y/N confirmation before active scanning  
**Context**: Active scanning sends packets to target systems — need user consent.

**Alternatives Considered**:
1. **Auto-proceed**: Just scan after showing what will happen
   - Rejected because: Violates principle of least surprise
2. **Config flag**: Set in config file to auto-approve
   - Rejected because: Too easy to forget, less safe

**Why I Chose This**:
- Safety as a feature, not a limitation
- Addresses Cisco Talos concerns about autonomous tools
- Creates audit trail
- Enterprise-friendly positioning

**Implementation Detail**: Default answer is `N` (no). User must explicitly type `y`.

---

## Decision 10: 8 Relationship Detectors

**Date**: Day 2  
**Decision**: Build 8 specific relationship detection methods  
**Context**: Need to understand connections between assets/findings for attack path synthesis.

**Detectors Built**:
1. Shared technology (same tech stack)
2. Shared certificates (common TLS issuer)
3. Finding correlations (same vuln across hosts)
4. Subdomain patterns (dev/staging/prod)
5. Severity clusters (grouped by severity)
6. Credential exposure chains (creds → access)
7. Attack surface tiers (external → dmz → internal)
8. Lateral movement candidates (high-severity with shared tags)

**Why These Specific 8**:
- Each maps to real attacker behavior
- Each produces actionable intelligence
- Diminishing returns after ~8 (would need real pentest data to tune more)

**Outcome**: 15 relationships detected in demo data (up from 2 with basic detectors).

---

## Decision 11: Heuristic Fallback for AI

**Date**: Day 2  
**Decision**: Build heuristic analysis when Claude API unavailable  
**Context**: Not everyone has ANTHROPIC_API_KEY set.

**What the Fallback Does**:
- Finds admin panel findings → creates "Admin Compromise" path
- Finds credential exposure → creates "Data Exposure" path
- Calculates risk score from severity counts
- Generates basic recommendations

**Why I Chose This**:
- Ensures demos work without API key
- Shows the *structure* of analysis even without AI
- Can compare heuristic vs AI quality

**Trade-off Accepted**: Heuristic analysis is less sophisticated. Clear warning shown to user.

---

## Decision 12: ASCII Over D3.js for Visualization

**Date**: Day 2  
**Decision**: Build ASCII attack flow visualization, not web-based graphs  
**Context**: Need to visualize attack paths.

**Alternatives Considered**:
1. **D3.js / Web UI**: Beautiful interactive graphs
   - Rejected because: Requires server, browser, deployment complexity
2. **Graphviz**: Generate PNG images
   - Rejected because: External dependency, not terminal-native
3. **Mermaid**: Generate diagrams
   - Rejected because: Still requires rendering

**Why I Chose This**:
- Terminal-native (security practitioners live in terminals)
- Copy-pasteable (can share in Slack, tickets)
- No dependencies
- Demo-friendly (works in any screen recording)

**Outcome**: Box-drawing characters create clear flow visualization:
```
  ┌────────────────────────────────┐
  │  Step 1: ...                   │
  │────────────────────────────────┘
  │
  │  ↓
```

---

## Decision 13: Session Persistence via JSON Files

**Date**: Day 2  
**Decision**: Save sessions to JSON files in `~/.pathfinder/sessions/`  
**Context**: Need to persist scan results for later analysis.

**Alternatives Considered**:
1. **SQLite**: Relational database
   - Rejected because: Overkill for prototype, adds complexity
2. **Redis**: In-memory with persistence
   - Rejected because: External dependency
3. **No persistence**: In-memory only
   - Rejected because: Can't analyze past scans

**Why I Chose This**:
- JSON is human-readable (can inspect with `cat`)
- No external dependencies
- Easy to backup, share, version control
- Sufficient for prototype scope

**File naming**: `{domain}_{timestamp}.json` for easy identification.

---

## Decision 14: Demo Mode with Synthetic Data

**Date**: Day 3  
**Decision**: Add `pathfinder demo` command with realistic fake data  
**Context**: Need to demo without scanning real systems.

**What Demo Mode Does**:
- Creates 8 realistic assets (www, api, admin, dev, staging, old, mail, vpn)
- Creates 8 findings (2 critical, 3 high, 2 medium, 1 low)
- Runs full analysis pipeline
- Outputs to terminal or HTML

**Why I Chose This**:
- Interview demos without legal concerns
- Sales presentations without customer data
- Testing analysis pipeline without network access
- Documentation examples

**Outcome**: `pathfinder demo --output report.html` produces a complete demo in seconds.

---

## Decision 15: HTML Report with Dark Mode

**Date**: Day 3  
**Decision**: Generate GitHub-style dark mode HTML reports  
**Context**: Need executive-friendly output format.

**Styling Choices**:
- Dark background (#0d1117) — GitHub dark mode
- Accent colors for severity (red, orange, yellow, green)
- Card-based layout for attack paths
- Monospace for evidence

**Why Dark Mode**:
- Security practitioners prefer dark themes
- Looks professional in presentations
- Consistent with terminal aesthetic
- Less eye strain

**Outcome**: Clean, professional HTML that can be shared with stakeholders.

---

## Summary

These 15 decisions shaped PathFinder from concept to working prototype:

1. **Strategic**: Intelligence layer > autonomous scanner
2. **Architectural**: Dual-mode, normalized schema
3. **Technical**: Python, subprocess, fallbacks
4. **UX**: Human approval, ASCII visualization, demo mode
5. **Practical**: Session persistence, HTML reports

Every decision traced back to one question: *What helps the security analyst do their job better?*

---

*Decision Log • PathFinder v0.1.0 • May 2026*
