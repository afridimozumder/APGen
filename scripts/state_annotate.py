#!/usr/bin/env python3
"""
Step 1.5.5 — Annotate the graph with preconditions and effects.

Two things happen here, both about giving the graph the state information that
Part 2's validator and Part 3's precondition-satisfaction metric need:

  1. Every Technique/SubTechnique gets `preconditions` and `effects` from the
     authored tactic-state rules in attack_state.py.
  2. The MITRE ATT&CK Evaluations ER6 LockBit plan is loaded as an ordered
     chain of EmulationStep nodes — the "spine". This is an authoritative,
     published, ordered plan, so it serves as (a) the Part 3 gold-standard
     reference and (b) a self-test of the tactic rules: replaying the rules
     over its real ordering must leave every step's preconditions satisfied.

The advisory/plan publishes as Markdown, so the extract stage parses the
scenario file; the load stage writes to Neo4j.

TWO-STAGE APPROACH:
  Stage A (AI-LAB): Download + parse the ER6 plan -> save to evals_lockbit.json
  Stage B (local):  Annotate techniques + load the reference chain -> Neo4j

Usage:
  python3 state_annotate.py --stage extract --output outputs/evals_lockbit.json
  python3 state_annotate.py --stage load    --input  outputs/evals_lockbit.json
"""

import os
import re
import sys
import json
import argparse
import requests
from neo4j import GraphDatabase

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attack_tactics import normalize_tactic
from attack_state import technique_state, unmet_preconditions, TACTIC_STATE

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
NEO4J_URI  = os.getenv("NEO4J_URI",  "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "LockBit2025!")

STATE_MODEL = "tactic-rules-v1"  # stamps authored preconditions/effects for provenance

PLAN_ID   = "attackevals-er6-lockbit"
PLAN_NAME = "MITRE ATT&CK Evaluations ER6 — LockBit"
PLAN_URL  = ("https://raw.githubusercontent.com/attackevals/ael/main/"
             "Enterprise/lockbit/Emulation_Plan/ER6_LockBit_Scenario.md")
PLAN_SOURCE = "MITRE ATT&CK Evaluations ER6"

STEP_HEADING_RE = re.compile(r"^Step\s+(\d+)\s*-\s*(.+?)\s*\(Evaluation Step\s+(\d+)\)")
TECHNIQUE_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

# ATT&CK tactic display names, longest first so "command and control" is matched
# before any shorter fragment. A step heading may name more than one tactic
# (e.g. "Privilege Escalation and Command & Control") or add scenery
# ("Lateral Movement to Linux Server"), so tactics are found by substring.
TACTIC_DISPLAY = [
    ("command and control",  "command-and-control"),
    ("privilege escalation", "privilege-escalation"),
    ("credential access",    "credential-access"),
    ("lateral movement",     "lateral-movement"),
    ("defense evasion",      "defense-evasion"),
    ("initial access",       "initial-access"),
    ("exfiltration",         "exfiltration"),
    ("persistence",          "persistence"),
    ("collection",           "collection"),
    ("discovery",            "discovery"),
    ("execution",            "execution"),
    ("impact",               "impact"),
]


# ─────────────────────────────────────────────
# HELPERS (parsing)
# ─────────────────────────────────────────────
def tactics_in_heading(text: str) -> list:
    """Canonical tactics named in a step heading, in kill-chain reading order."""
    norm = text.lower().replace("&", "and")
    found = []
    for display, canonical in TACTIC_DISPLAY:
        if display in norm and canonical not in found:
            found.append(canonical)
    return found


def extract_voice_track(chunk: str) -> str:
    """The step's Voice Track narrative (the section before the first other one)."""
    match = re.search(r"Voice Track\s*(.*?)(?:\n#{2,4}\s|\Z)", chunk, re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()


def dedupe(seq):
    """Order-preserving de-duplication."""
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def parse_plan(markdown: str) -> list:
    """
    Ordered attack steps from the ER6 scenario Markdown.

    Splitting on "## " gives one chunk per section; only chunks whose heading
    matches "Step N - <tactics> (Evaluation Step M)" are attack steps, which
    naturally drops the two "Step 0" setup sections that have no evaluation
    number. Technique IDs are read from the ATT&CK-technique column of each
    step's reference table (the only place T-codes appear).
    """
    steps = []
    for chunk in markdown.split("\n## "):
        heading = chunk.splitlines()[0] if chunk else ""
        m = STEP_HEADING_RE.match(heading)
        if not m:
            continue
        step_number, title, eval_step = int(m.group(1)), m.group(2).strip(), int(m.group(3))
        tactics = tactics_in_heading(title)
        steps.append({
            "step_number":   step_number,
            "eval_step":     eval_step,
            "name":          title,
            "tactics":       tactics,
            "technique_ids": dedupe(TECHNIQUE_ID_RE.findall(chunk)),
            "description":   extract_voice_track(chunk)[:500],
        })
    steps.sort(key=lambda s: s["step_number"])
    return steps


# ─────────────────────────────────────────────
# STAGE A — Download + parse → Save JSON
# ─────────────────────────────────────────────
def stage_extract(output_path):
    print(f"[1/3] Downloading MITRE ATT&CK Evaluations ER6 LockBit plan ...")
    response = requests.get(PLAN_URL, timeout=60)
    response.raise_for_status()
    response.encoding = "utf-8"
    print(f"      ✅ Downloaded {len(response.text)} characters")

    print("[2/3] Parsing ordered steps ...")
    steps = parse_plan(response.text)
    if not steps:
        raise ValueError("❌ No attack steps found — the plan layout changed.")
    for s in steps:
        print(f"      ✅ Step {s['step_number']}: {s['name']}  "
              f"[{', '.join(s['tactics']) or '?'}]  ({len(s['technique_ids'])} techniques)")

    result = {
        "plan_id":    PLAN_ID,
        "plan_name":  PLAN_NAME,
        "source_url": PLAN_URL,
        "steps":      steps,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"[3/3] ✅ Saved to {output_path}")


# ─────────────────────────────────────────────
# STAGE B — Annotate + load → Neo4j (run locally)
# ─────────────────────────────────────────────
def annotate_techniques(session):
    """Write authored preconditions/effects onto every technique from its tactics."""
    techniques = session.run(
        "MATCH (t) WHERE t:Technique OR t:SubTechnique "
        "RETURN t.attack_id AS id, t.tactics AS tactics"
    ).data()
    for t in techniques:
        pre, eff = technique_state(t["tactics"] or [])
        session.run("""
            MATCH (t {attack_id: $id})
            SET t.preconditions = $pre, t.effects = $eff, t.state_model = $model
        """, {"id": t["id"], "pre": pre, "eff": eff, "model": STATE_MODEL})
    return len(techniques)


def step_state(tactics):
    """(preconditions, effects) for a whole step, unioned over its tactics."""
    pre, eff = set(), set()
    for tactic in tactics:
        norm = normalize_tactic(tactic)
        if norm in TACTIC_STATE:
            p, e = TACTIC_STATE[norm]
            pre.update(p)
            eff.update(e)
    return sorted(pre - eff), sorted(eff)


def load_reference_plan(session, plan):
    """Create the ordered EmulationStep chain and link each step to its techniques."""
    prov = {"source": PLAN_SOURCE, "url": plan["source_url"]}
    previous_key = None
    linked = 0
    for step in plan["steps"]:
        pre, eff = step_state(step["tactics"])
        key = f"{plan['plan_id']}#{step['step_number']}"
        session.run("""
            MERGE (s:EmulationStep {step_key: $key})
            SET s.plan_id       = $plan_id,
                s.plan_name      = $plan_name,
                s.step_number    = $step_number,
                s.eval_step      = $eval_step,
                s.name           = $name,
                s.description    = $description,
                s.tactics        = $tactics,
                s.preconditions  = $pre,
                s.effects        = $eff,
                s.state_model    = $model,
                s.source         = $source,
                s.source_url     = $url,
                s.confidence     = 1.0
        """, {"key": key, "plan_id": plan["plan_id"], "plan_name": plan["plan_name"],
              "step_number": step["step_number"], "eval_step": step["eval_step"],
              "name": step["name"], "description": step["description"],
              "tactics": step["tactics"], "pre": pre, "eff": eff,
              "model": STATE_MODEL, **prov})

        # Link this step to the LockBit techniques it performs that we already hold.
        for tid in step["technique_ids"]:
            res = session.run("""
                MATCH (s:EmulationStep {step_key: $key})
                MATCH (t {attack_id: $tid}) WHERE t:Technique OR t:SubTechnique
                MERGE (s)-[r:PERFORMS]->(t)
                SET r.source = $source, r.source_url = $url, r.confidence = 1.0
                RETURN t
            """, {"key": key, "tid": tid, **prov})
            if res.single():
                linked += 1

        if previous_key is not None:
            session.run("""
                MATCH (a:EmulationStep {step_key: $a})
                MATCH (b:EmulationStep {step_key: $b})
                MERGE (a)-[r:NEXT]->(b)
                SET r.source = $source, r.source_url = $url, r.confidence = 1.0
            """, {"a": previous_key, "b": key, **prov})
        previous_key = key
    return linked


def check_spine(plan):
    """
    Replay the tactic rules over the plan's real order. Every step's
    preconditions must be met by the accumulated effects of prior steps, or the
    authored rules cannot even reproduce MITRE's own published plan.
    """
    ordered = [(f"step {s['step_number']} ({s['name']})", tactic)
               for s in plan["steps"] for tactic in s["tactics"]]
    failures = unmet_preconditions(ordered)
    return failures


def stage_load(input_path):
    print(f"[1/4] Reading {input_path} ...")
    with open(input_path, encoding="utf-8") as f:
        plan = json.load(f)
    print(f"      Plan: {plan['plan_name']} ({len(plan['steps'])} steps)")

    print("\n[2/4] Validating the tactic rules against the published plan ...")
    failures = check_spine(plan)
    if failures:
        for label, missing in failures:
            print(f"      ❌ {label}: unmet preconditions {missing}")
        raise SystemExit("Spine self-check failed — tactic rules are inconsistent "
                         "with the MITRE Evaluations plan; fix attack_state.py.")
    print("      ✅ Every step's preconditions satisfied by prior effects")

    print(f"\n[3/4] Connecting to Neo4j at {NEO4J_URI} ...")
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    with driver.session() as session:
        n = annotate_techniques(session)
        print(f"      ✅ Annotated {n} techniques with preconditions/effects")
        linked = load_reference_plan(session, plan)
        print(f"      ✅ Loaded {len(plan['steps'])} EmulationStep nodes, "
              f"{linked} links to known techniques")

    print("\n[4/4] Verifying ...")
    with driver.session() as session:
        no_pre = session.run(
            "MATCH (t) WHERE (t:Technique OR t:SubTechnique) AND t.effects IS NULL "
            "RETURN count(*) AS c").single()["c"]
        steps = session.run("MATCH (s:EmulationStep) RETURN count(*) AS c").single()["c"]
        print(f"      Techniques without effects : {no_pre}")
        print(f"      EmulationStep nodes         : {steps}")
    driver.close()
    print("\n✅ Step 1.5.5 complete — preconditions/effects annotated and spine loaded!")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage",  choices=["extract", "load"], required=True)
    parser.add_argument("--input",  default="outputs/evals_lockbit.json")
    parser.add_argument("--output", default="outputs/evals_lockbit.json")
    args = parser.parse_args()

    if args.stage == "extract":
        stage_extract(args.output)
    elif args.stage == "load":
        stage_load(args.input)
