# PathFinder Documentation

**Complete documentation for the PathFinder project**

---

## Documents

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](./ARCHITECTURE.md) | High-level architecture and design decisions with rationale |
| [DECISION_LOG.md](./DECISION_LOG.md) | Chronological record of 15 key decisions |
| [DESIGN_PHILOSOPHY.md](./DESIGN_PHILOSOPHY.md) | Core principles that guided development |
| [TECHNICAL_DEEPDIVE.md](./TECHNICAL_DEEPDIVE.md) | Implementation details and code walkthrough |

---

## Quick Links

### For Evaluators
Start with **ARCHITECTURE.md** for the big picture, then **DECISION_LOG.md** to understand specific choices.

### For Developers
Start with **TECHNICAL_DEEPDIVE.md** for implementation details.

### For Understanding the "Why"
Read **DESIGN_PHILOSOPHY.md** to understand the principles behind every decision.

---

## Document Summaries

### ARCHITECTURE.md
- Why I built an intelligence layer instead of an autonomous scanner
- The dual-mode architecture (E2E + Plugin)
- Why the normalized schema exists
- How relationship detection enables attack paths
- What I avoided and why

### DECISION_LOG.md
15 decisions documented with:
- Date and context
- Alternatives considered
- Why I chose this approach
- Outcome

### DESIGN_PHILOSOPHY.md
Core principles:
1. Intelligence over automation
2. Complement, don't compete
3. Graceful degradation
4. Terminal-native UX
5. Safety as a feature
6. Depth over breadth
7. Show your work

### TECHNICAL_DEEPDIVE.md
- Module-by-module code walkthrough
- Data model design
- Scanner wrapper patterns
- AI prompt engineering
- Output visualization implementation

---

## Reading Order

For the RedHold interview:

1. **README.md** (root) - What was built
2. **LANDSCAPE_REVIEW.md** (root) - Market research
3. **docs/ARCHITECTURE.md** - Why it was built this way
4. **docs/DECISION_LOG.md** - Specific choices

For a technical deep-dive:

1. **docs/TECHNICAL_DEEPDIVE.md** - Implementation details
2. **Source code** in `src/pathfinder/`

---

*PathFinder Documentation Index • May 2026*
