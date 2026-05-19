# Part 2 — Emulation Plan Generation Context
# Project: Automating Adversary Emulation: Knowledge Graphs and LLMs for CTI Analysis

> **IMPORTANT**: Before reading this file, read the KG construction context first:
> `project_context.md` — This file assumes the LockBit CTI Knowledge Graph is already
> built and populated in Neo4j as described there.

---

## Goal of This Phase

Use the constructed LockBit CTI Knowledge Graph (Neo4j) as a structured ground truth to
automatically generate **logically valid, ordered Adversary Emulation Plans (AEPs)** that
mimic real-world LockBit attack behaviors.

The core problem this solves: LLMs alone hallucinate attack steps and produce invalid chains.
By grounding the LLM in a structured KG (GraphRAG), the output is constrained to only
known, validated TTPs linked to LockBit.

---

## Research Question Addressed

**RQ2**: Can the constructed Knowledge Graph be utilized to automatically generate a
logically valid sequence of actions (an emulation plan) for a specific threat scenario?

---

## System Architecture (Three Components)

### Component 1 — GraphRAG Retrieval

Query the Neo4j KG to extract a LockBit-specific subgraph relevant to the emulation request.

**Input**: Emulation request (e.g., "Emulate LockBit 3.0 ransomware attack on Windows AD")
**Output**: A structured subgraph — ordered list of techniques, procedures, preconditions, effects

Steps:
1. Parse the request to extract: target environment (Windows/Linux/cloud), LockBit version (2.0/3.0), objective
2. Query Neo4j for all Technique and EmulationStep nodes linked to the requested Malware node
3. Filter by environment compatibility
4. Order steps by tactic phase (Reconnaissance → Initial Access → Execution → ... → Impact)
5. Serialize the subgraph into a structured prompt context

**Cypher query pattern:**
```cypher
MATCH (m:Malware {attack_id: "S1202"})-[:USES]->(t:Technique)
OPTIONAL MATCH (e:EmulationStep)-[:IMPLEMENTS]->(t)
RETURN m.name, t.attack_id, t.name, t.tactics, e.step_id, e.description
ORDER BY t.tactics
```

### Component 2 — LLM Plan Generation

Use an LLM to generate the emulation plan from the retrieved subgraph context.

**LLM Options (to be decided):**
- GPT-4o mini (OpenAI API) — cost-efficient, strong instruction following
- Llama-3 8B (self-hosted or via AI-LAB) — open source, no API cost
- Claude Haiku (Anthropic API) — fast, good structured output

**Prompt structure:**
```
SYSTEM:
You are an adversary emulation planner. You must ONLY use the techniques and steps
provided in the context below. Output a structured JSON emulation plan with phases
and ordered steps. Each step must reference an ATT&CK technique ID.
Assume a lab/sandbox environment.

USER:
Target: [environment description]
Adversary: LockBit [version]
Objective: [e.g., encrypt files and exfiltrate data]

Context (retrieved from Knowledge Graph):
[serialized subgraph — techniques, procedures, preconditions, effects]

Output schema:
{
  "adversary": "LockBit 3.0",
  "environment": "Windows AD on-prem",
  "phases": [
    {
      "tactic": "Initial Access",
      "steps": [
        {
          "step_id": 1,
          "technique_id": "T1566.001",
          "technique_name": "Spearphishing Attachment",
          "description": "...",
          "preconditions": ["email access to target"],
          "effects": ["foothold on endpoint"]
        }
      ]
    }
  ]
}
```

### Component 3 — Graph-Based Validation

Before outputting the plan, validate every step against the KG to prevent hallucinations.

**Validation checks:**
1. **Technique membership**: Every technique ID in the plan must exist in Neo4j linked to LockBit
2. **Precondition check**: Preconditions for step N must be satisfied by effects of steps 1..N-1
3. **Sequence feasibility**: Step order must follow tactic phase ordering (ATT&CK kill chain)
4. **Environment filter**: Techniques flagged as Linux-only must not appear in a Windows plan

**Validation loop:**
```
Generate plan → validate against KG → if invalid: construct feedback → re-prompt LLM → repeat
```

---

## Output Format

The final emulation plan is a **JSON/YAML document** with:
- Adversary name and version
- Target environment
- Ordered phases (matching ATT&CK tactic order)
- Each step: technique ID, name, description, preconditions, effects, optional commands
- Provenance: which KG sources informed each step

---

## Infrastructure for This Phase

- **GraphRAG retrieval**: Python + Neo4j driver (runs locally or AI-LAB)
- **LLM API calls**: OpenAI/Anthropic API — runs on AI-LAB via Slurm (rate limit friendly)
- **Validation module**: Python — queries Neo4j, checks plan JSON against graph constraints
- **Same two-stage pattern** from Part 1: heavy LLM calls on AI-LAB, Neo4j access locally

---

## What Needs to Be Built

| Component | Status | Notes |
|---|---|---|
| GraphRAG retrieval module | ⏳ To build | Cypher queries + subgraph serializer |
| Prompt construction function | ⏳ To build | Takes (version, environment, subgraph) → prompt |
| LLM API integration | ⏳ To build | LLM not yet decided |
| Plan parser (JSON output) | ⏳ To build | Parse and validate LLM JSON output |
| Validation module | ⏳ To build | Check each step against KG |
| Feedback/refinement loop | ⏳ To build | Re-prompt on validation failure |

---

## Dependencies

- KG must be fully populated (Parts 1.5.1a, 1.5.1b, 1.5.3, 1.5.4 complete) before this runs
- Neo4j running with LockBit Malware, Technique, EmulationStep, Procedure nodes populated
- LLM API key (OpenAI or Anthropic) set as environment variable
- `openai` Python package already installed in venv

---

## Key References (From Proposal)

1. Loevenich et al. — "Automating Cyber Threat Intelligence and Attack Chain Generation using Cyber Security Knowledge Graphs and LLMs"
2. Branzan et al. — "The Synthesis of Large Language Models and Knowledge Graphs for Autonomous Adversary Emulation"
3. Yang et al. — "Knowledge Graph and LLM Co-learning via Structure-oriented RAG"
