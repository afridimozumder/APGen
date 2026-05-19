# Part 3 — Emulation Plan Evaluation Context
# Project: Automating Adversary Emulation: Knowledge Graphs and LLMs for CTI Analysis

> **IMPORTANT**: Before reading this file, read both preceding context files:
> 1. `project_context.md` — LockBit CTI Knowledge Graph construction
> 2. `part2_emulation_generation_context.md` — Emulation plan generation with LLM + GraphRAG
>
> This phase evaluates the quality of plans produced in Part 2.

---

## Goal of This Phase

Assess whether the automatically generated emulation plans are:
- **Logically complete** — do they cover the full attack lifecycle?
- **Tactically correct** — do steps match known LockBit TTP behavior?
- **Capable of achieving the intended malicious goal** — does the chain lead to the objective?

---

## Research Question Addressed

**RQ3**: To what extent are the automatically generated emulation plans logically complete
and tactically correct and capable of achieving the intended malicious goal?

---

## Evaluation Methodology (To Be Finalized — Research Needed)

This section outlines the current thinking. The exact metrics and comparison baselines
need further literature research before finalizing.

### Dimension 1 — Structural / Logical Correctness

Evaluate whether the plan is internally consistent and follows ATT&CK logic.

**Metrics (proposed):**
- **Technique coverage rate**: % of LockBit-linked techniques in KG that appear in the plan
- **Precondition satisfaction rate**: % of steps whose preconditions are met by prior steps
- **Tactic ordering compliance**: % of step transitions that follow ATT&CK kill chain order
- **Hallucination rate**: % of technique IDs in the plan that do NOT exist in the KG

**Method**: Automated — run validation module from Part 2 against the generated plan, compute scores.

### Dimension 2 — Comparison Against Reference Plans

Compare generated plans against known ground-truth LockBit emulation plans.

**Reference baselines (available):**
| Baseline | Source | Notes |
|---|---|---|
| ATT&CK Evaluations 2024 LockBit plan | MITRE ATT&CK Evaluations GitHub | Gold standard — already loaded in KG as EmulationStep nodes (Step 1.5.1b) |
| MITRE CTI LockBit techniques | github.com/mitre/cti | Already in KG from Step 1.5.1a |
| IEEE 2025 "Inside LockBit" TTP table | Academic paper | Version-differentiated, loaded in Step 1.5.4 |
| Vendor reports (Sophos, Kaspersky, Picus) | CTI reports | Loaded in Step 1.5.3 |

**Comparison factors (proposed):**
- **TTP overlap (Jaccard similarity)**: Intersection / Union of technique IDs between generated plan and reference plan
- **Phase coverage**: How many ATT&CK tactic phases are covered vs. reference
- **Step ordering similarity**: Edit distance or sequence alignment between generated and reference step order
- **Missing critical steps**: Steps present in reference but absent from generated plan

### Dimension 3 — Goal Achievement Analysis

Does the attack chain logically lead to the stated objective (e.g., file encryption + exfiltration)?

**Method (proposed):**
- Define success criteria as specific ATT&CK techniques that MUST be present (e.g., T1486 Data Encrypted for Impact for ransomware)
- Compute **goal completion rate**: % of mandatory objective techniques present in plan
- Check causal chain: can you trace a path from Initial Access to the final objective through the plan steps?

### Dimension 4 — Quantitative Success Rate (To Research Further)

Options under consideration — needs literature review to decide:
- **Plan executability score**: Proportion of steps that could theoretically execute given the preconditions
- **Atomic Red Team coverage**: % of plan steps that have a corresponding Atomic Red Team test (validates real-world feasibility)
- **CALDERA operator score**: If plan is translated to CALDERA, what % of steps execute successfully in lab

---

## Evaluation Tools / Framework Options (To Decide)

| Tool | Purpose | Notes |
|---|---|---|
| Automated KG validator (from Part 2) | Logical correctness | Already built as part of validation module |
| Python `difflib` / sequence alignment | Step ordering comparison | Simple, no extra install |
| NetworkX | Graph-based path analysis | Check causal chains in plan graph |
| CALDERA | Live execution scoring | Requires lab setup — optional stretch goal |
| Atomic Red Team | Feasibility check | Map steps to existing test library |

---

## Output of Evaluation

For each generated plan, produce an evaluation report containing:

```json
{
  "plan_id": "lockbit_3.0_windows_ad_001",
  "technique_coverage_rate": 0.78,
  "precondition_satisfaction_rate": 0.91,
  "hallucination_rate": 0.02,
  "jaccard_similarity_vs_att&ck_eval": 0.65,
  "goal_completion_rate": 1.0,
  "missing_critical_steps": ["T1078", "T1562.001"],
  "tactic_ordering_compliance": 0.88,
  "verdict": "PASS"
}
```

---

## What Needs to Be Researched / Decided

- [ ] Final choice of metrics — review related work (Branzan, Loevenich) for precedent
- [ ] Whether to include live execution (CALDERA) or keep evaluation graph-only
- [ ] Scoring thresholds: what score constitutes a "valid" plan?
- [ ] Whether to evaluate per-version (LockBit 2.0 vs 3.0 plans separately)
- [ ] Human expert review as a qualitative validation layer (optional)

---

## Dependencies

- Completed generated plans from Part 2 (JSON format)
- KG fully populated with EmulationStep nodes from Step 1.5.1b (ATT&CK Evaluations reference)
- Neo4j running locally with all LockBit data

---

## Key References (From Proposal)

1. Branzan et al. — "The Synthesis of LLMs and Knowledge Graphs for Autonomous Adversary Emulation" — likely contains evaluation metrics
2. Loevenich et al. — "Automating CTI and Attack Chain Generation using KGs and LLMs"
3. MITRE ATT&CK Evaluations methodology — structured scoring of emulation plan coverage
