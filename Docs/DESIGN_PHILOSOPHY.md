# PathFinder Design Philosophy

**The principles that guided every decision**

---

## The One-Liner

> "Scanners tell you WHAT's wrong. PathFinder tells you WHY it matters and HOW an attacker would chain it."

This sentence captures the entire value proposition. Every feature, every design decision, every line of code serves this goal.

---

## Core Principles

### 1. Intelligence Over Automation

**The temptation**: Build an autonomous AI hacker that runs everything end-to-end.

**The reality**: Enterprises don't trust autonomous security tools. They want assistance, not replacement.

**My choice**: Build an intelligence layer that makes *humans* smarter, not a robot that replaces them.

**How this manifests**:
- Human approval required for active scanning
- AI suggests attack paths; humans validate
- Output is designed for human consumption (narrative, not just data)

---

### 2. Complement, Don't Compete

**The temptation**: Build a better Nuclei with more templates and faster scanning.

**The reality**: Nuclei has 9,000+ templates and massive community investment. That's not a winnable fight.

**My choice**: Work WITH existing tools. Accept their output. Add intelligence on top.

**How this manifests**:
- Dual-mode architecture (E2E + Plugin)
- Universal ingestion layer
- "Keep your tools, add our brain" positioning

---

### 3. Graceful Degradation

**The temptation**: Require all dependencies to be perfectly installed.

**The reality**: Users will try PathFinder in environments where Go tools aren't available, or API keys aren't set.

**My choice**: Always produce *something*. Fallbacks for every external dependency.

**How this manifests**:
- crt.sh fallback when Subfinder unavailable
- Python httpx when binary not installed
- 13 path checks when Nuclei not installed
- Heuristic analysis when Claude API unavailable

---

### 4. Terminal-Native UX

**The temptation**: Build a beautiful React dashboard with D3.js visualizations.

**The reality**: Security practitioners live in terminals. They copy-paste to Slack. They don't want to open a browser.

**My choice**: ASCII-first design. Everything works in a terminal.

**How this manifests**:
- Box-drawing attack path visualization
- Rich library for tables and panels
- Copy-pasteable output
- HTML as optional export, not primary interface

---

### 5. Safety as a Feature

**The temptation**: "Just run it" with maximum automation.

**The reality**: Security tools that act without consent create legal and trust problems.

**My choice**: Explicit consent before any active action. Clear communication about what will (and won't) happen.

**How this manifests**:
- Human approval gate with full disclosure
- Audit logging of all decisions
- Explicit listing of prohibited actions
- Default to passive-only mode

---

### 6. Depth Over Breadth

**The temptation**: Add every feature imaginable. Multi-tenant! Continuous monitoring! Slack integration!

**The reality**: The assignment said "narrow, thoughtful prototype is better than broad but shallow."

**My choice**: Do one thing extremely well: attack path synthesis.

**How this manifests**:
- 8 relationship detectors (deep investment in graph building)
- Detailed AI prompt engineering
- Rich output formatting
- Everything serves the core use case

---

### 7. Show Your Work

**The temptation**: Hide complexity behind "AI magic."

**The reality**: Security professionals are skeptical. They want to understand *why* something is flagged.

**My choice**: Every conclusion includes evidence. Every attack path cites specific findings.

**How this manifests**:
- Finding IDs in attack path steps
- Confidence scores with reasoning
- Narrative explanations in plain English
- Evidence field in every finding

---

## Design Anti-Patterns I Avoided

### Anti-Pattern 1: The Thin Wrapper

> "Take Nuclei output, pass to GPT, return summary."

Why this fails: No value add. Anyone can pipe to an LLM.

What I did instead: Relationship graph, attack path synthesis, structured prompting, confidence scoring.

### Anti-Pattern 2: The Kitchen Sink

> "We do scanning AND remediation AND compliance AND monitoring AND..."

Why this fails: Nothing is done well. Users confused about value prop.

What I did instead: Clear focus on intelligence layer. Other features explicitly deferred.

### Anti-Pattern 3: The Black Box

> "Our AI found these issues. Trust us."

Why this fails: Security professionals don't trust black boxes.

What I did instead: Every conclusion traceable to evidence. Transparent reasoning.

### Anti-Pattern 4: The Demo-Only Product

> "Works great in demos, falls apart in production."

Why this fails: Can't handle edge cases, missing tools, bad data.

What I did instead: Fallbacks for every dependency. Graceful error handling. Works with partial data.

---

## The User Journey I Designed For

### Happy Path

```
1. User runs: pathfinder run example.com
2. PathFinder discovers subdomains
3. User approves active scanning (Y/N)
4. PathFinder probes and scans
5. AI synthesizes attack paths
6. User sees prioritized findings with narrative
7. User exports HTML report for stakeholders
```

### Fallback Path

```
1. User runs: pathfinder run example.com
2. Subfinder not installed → fallback to crt.sh
3. User approves active scanning
4. Nuclei not installed → fallback to Python checks
5. ANTHROPIC_API_KEY not set → fallback to heuristics
6. User still sees attack paths (lower quality, but works)
7. User knows exactly what was limited (warnings shown)
```

### Plugin Path

```
1. User already ran Nuclei externally
2. User runs: pathfinder ingest nuclei-output.json
3. PathFinder normalizes findings
4. pathfinder analyze
5. AI synthesizes attack paths from imported data
6. No scanning needed — pure intelligence layer
```

---

## Questions I Asked Myself

Before every major decision, I asked:

1. **Does this help the analyst?** If not, cut it.

2. **Does this require tool replacement?** If yes, reconsider.

3. **Does this work without dependencies?** If not, add fallback.

4. **Is this explainable?** If black box, add transparency.

5. **Would I use this?** If not, redesign.

---

## The North Star Metric

If I had to pick ONE metric to measure PathFinder's success:

> **Time from scanner output to actionable prioritized list**

Before PathFinder: Hours of manual triage
After PathFinder: Minutes

That's the value.

---

## What I Would Tell My Past Self

If I could go back to Day 0:

1. **Start with the output, work backwards.** I designed the attack path visualization first, then figured out what data I needed to produce it.

2. **Build the demo first.** `pathfinder demo` existed before real scanning worked. This let me refine the output format without waiting for network operations.

3. **Fallbacks are features, not afterthoughts.** Every fallback I built made the product more robust. Don't treat them as edge cases.

4. **The prompt is the product.** For AI features, prompt engineering is 80% of the work. Invest time here.

5. **Positioning matters more than features.** "Intelligence layer" is a better position than "better scanner." The framing shapes everything.

---

## Closing Thought

PathFinder isn't the most technically complex project I could have built. It's not the most feature-rich. It's not the most impressive from a pure engineering standpoint.

But it solves a real problem that real practitioners have:

> "I have 500 findings. What do I actually do?"

Every design decision serves that answer.

---

*Design Philosophy • PathFinder v0.1.0 • May 2026*
