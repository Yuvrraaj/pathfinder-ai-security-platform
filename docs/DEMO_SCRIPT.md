# PathFinder Demo Recording Script

**Duration**: 3-5 minutes  
**Format**: Screen recording with voiceover (Loom recommended)

---

## Opening (30 seconds)

**[Screen: Terminal with PathFinder banner]**

> "Hi, I'm Yuvraj, and this is PathFinder - an AI-assisted external assessment platform I built for RedHold's take-home assignment."

**[Show the problem]**

> "Here's the problem PathFinder solves: security scanners like Nuclei generate hundreds of findings, but they don't tell you which ones actually matter. A junior analyst spends days triaging. PathFinder does that in minutes."

---

## Why This Isn't Just a Prompt Wrapper (45 seconds)

**[Screen: Show the architecture diagram or code structure]**

> "Before I demo, let me explain why this isn't just 'pipe scanner output to an LLM and pray.'"

**Key differentiators to mention:**

1. **Relationship Graph Engine** (`core/graph.py`)
   > "I built 8 relationship detectors that identify connections between findings - shared technology, credential chains, lateral movement paths. This context is what makes the AI analysis actually useful."

2. **Dual-Mode Architecture**
   > "PathFinder works two ways: run your own scans OR import existing Nuclei/Nessus output. This means teams don't have to replace their tools - PathFinder adds intelligence on top."

3. **Attack Path Visualization**
   > "The ASCII attack flow visualization shows exactly how an attacker would chain findings. Every step cites specific evidence. No black box."

4. **Human-in-the-Loop**
   > "Active scanning requires explicit approval with full disclosure. This isn't an autonomous hacker - it's an analyst augmentation tool."

5. **Graceful Degradation**
   > "Every external dependency has a fallback. No Nuclei? Python checks. No API key? Heuristic analysis. PathFinder always produces something."

---

## Live Demo (2-3 minutes)

### Demo 1: Quick Demo Mode (60 seconds)

**[Run the demo command]**

```bash
pathfinder demo --output reports/demo.html
```

> "Let's start with demo mode - this uses synthetic data so I don't need to scan anything real."

**[Walk through the output]**

- Point out the **discovered assets** (8 hosts with tech stacks)
- Point out the **findings by severity** (critical, high, medium)
- Point out the **relationship detection** ("15 relationships across 8 hosts")
- Point out the **AI analysis** (or heuristic fallback if no key)
- Point out the **attack paths** with step-by-step chains
- Point out the **executive summary** and **risk score**

> "Notice how the attack path cites specific findings at each step. This isn't hallucinated - it's traceable."

### Demo 2: HTML Report (30 seconds)

**[Open the generated HTML report in browser]**

```bash
open reports/demo.html
```

> "PathFinder generates executive-ready HTML reports. Dark mode, because security people have taste."

- Show the **risk score visualization**
- Show the **attack path cards**
- Show the **recommendations list**

> "This is what you'd send to a CISO - not a 500-line JSON dump."

### Demo 3: Plugin Mode (Optional, 30 seconds)

**[Show ingesting external output]**

```bash
# If you have Nuclei output from a previous scan:
pathfinder ingest nuclei-output.json
pathfinder analyze
```

> "Teams with existing tooling can ingest Nuclei or Nessus output directly. PathFinder adds intelligence without changing workflows."

---

## Architecture Highlights (30 seconds)

**[Quick code walkthrough if time permits]**

- `models/schema.py`: Normalized finding model works with any scanner
- `core/graph.py`: 8 relationship detectors (shared tech, creds, lateral movement)
- `core/reasoning.py`: Structured AI prompting with fallback
- `core/output.py`: ASCII visualization + HTML reports
- `scanners/approval.py`: Human approval gate with audit logging

---

## Closing (30 seconds)

> "PathFinder took about a week to build. The key insight was: don't compete with scanners - complement them."

> "I chose to build an intelligence layer because that's the real bottleneck. Finding vulnerabilities is solved. Making sense of them isn't."

> "The codebase is fully documented with decision logs explaining every architectural choice. Thanks for watching!"

---

## Recording Tips

1. **Terminal**: Use a clean terminal with large font (14-16pt)
2. **Speed**: Don't rush - pause on important outputs
3. **Highlight**: Use terminal zoom or annotation to highlight key areas
4. **Mistakes**: If something fails, show the graceful degradation (it's a feature!)
5. **Tone**: Confident but not salesy - you're showing engineering work

---

## Commands Quick Reference

```bash
# Build Docker image
make build

# Check status
make status

# Run demo (no API key needed for heuristics)
make demo

# Run demo with AI (requires GROQ_API_KEY)
GROQ_API_KEY=gsk_xxx make demo

# Start vulnerable labs
make labs-up

# Scan Juice Shop
make scan TARGET="http://juice-shop:3000"

# Interactive shell
make shell
```

---

## Talking Points if Asked

**"Why Groq/Llama instead of OpenAI/Claude?"**
> "Groq offers free tier with fast inference. For a prototype, it reduces friction for evaluators to test it themselves."

**"Why not build a web UI?"**
> "Security practitioners live in terminals. ASCII-first means it works in any environment, can be copy-pasted to Slack/tickets, and has zero deployment complexity."

**"What would you add with more time?"**
> "Remediation code generation, continuous delta monitoring, and SIEM integration. But I focused on depth in attack path synthesis rather than breadth."

**"How does this compare to existing tools?"**
> "Shannon and PentAGI are autonomous pentesters - they replace the analyst. PathFinder augments the analyst. Different philosophy, different trust model, different market."

---

*Demo Script v1.0 - PathFinder*
