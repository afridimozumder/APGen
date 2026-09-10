#!/usr/bin/env python3
"""
Part 2, Phase B — GraphRAG retrieval over the LockBit CTI knowledge graph.

Given an emulation request (LockBit version, target platforms, objective), this
returns the LockBit-specific subgraph the Part 2 generator will be prompted with:
techniques grouped into ATT&CK kill-chain phases, each carrying the authored
preconditions/effects and the tools that implement it.

WHY NO --stage extract / --stage load: that rule exists because the HPC cannot
reach the local Neo4j when *writing*. This module only *reads*, and it runs
locally against Docker Neo4j, so the two-stage split does not apply. The optional
--out dump is a cache of a read, not an extract stage.

TWO SOURCES, TWO LEGS. A technique counts as LockBit's if either:
  * MITRE attributes it to the requested payload version — (:Malware {attack_id})
    -[:USES]->(t). This leg is version-specific: S1199 (2.0) vs S1202 (3.0).
  * CISA AA23-165A attributes it to the affiliates — (:ThreatActor)-[:USES]->(t).
    This leg is version-AGNOSTIC, and that is a real limitation worth stating in
    the thesis: the advisory describes affiliate tradecraft, not one payload
    build, so 2.0 and 3.0 requests inherit the same affiliate techniques. Without
    this leg the plan has no credential-access, collection or exfiltration stage
    at all, which is the whole reason the advisory was ingested.

Techniques pulled into the graph only for their platform data (the --enrich pass
in stix_ingest.py) carry no USES edge, so they are excluded here automatically —
which is correct: MITRE defines them but does not attribute them to LockBit.

DELIBERATELY NOT RETRIEVED: the EmulationStep reference spine (MITRE ATT&CK
Evaluations ER6). That published, ordered plan is Part 3's gold standard. Feeding
it into the generation context would be teaching to the test and would invalidate
the KG-grounded-vs-baseline comparison.

Usage:
  python3 graphrag_retrieve.py --version 3.0 --platform Windows
  python3 graphrag_retrieve.py --version 3.0 --out outputs/subgraph_3.0_windows.json
  python3 graphrag_retrieve.py --version 2.0 --print-prompt
"""

import os
import sys
import json
import argparse
from dataclasses import dataclass

from neo4j import GraphDatabase

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attack_tactics import TACTIC_ORDER, UNKNOWN_TACTIC_ORDER, canonical_tactic
from cisa_ingest import SOURCE_NAME as CISA_SOURCE, ACTOR_NAME as CISA_ACTOR
from neo4j_env import NEO4J_URI, NEO4J_USER, neo4j_password

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
# LockBit is tracked in ATT&CK as SOFTWARE, not as a group. G0125 is HAFNIUM and
# has nothing to do with LockBit; it must never appear here.
SOFTWARE_ID = {
    "2.0": "S1199",
    "3.0": "S1202",
}

UNKNOWN_TACTIC = "unknown"

# Description text is included to ground the model, but a full ATT&CK description
# is ~500 chars and there are ~60 techniques; trimmed so prompt context stays sane.
DESCRIPTION_CHARS = 200

# One row per technique. Grouping is by the non-aggregated RETURN columns, and
# attack_id is unique per node, so a technique attributed by BOTH sources still
# yields exactly one row — no de-duplication pass is needed downstream.
RETRIEVE_CYPHER = """
MATCH (t)
WHERE (t:Technique OR t:SubTechnique)
  AND any(p IN $platforms WHERE p IN coalesce(t.platforms, []))
  AND ( EXISTS { (:Malware     {attack_id: $software_id})-[:USES]->(t) }
     OR EXISTS { (:ThreatActor {name:      $actor})      -[:USES]->(t) } )
OPTIONAL MATCH (tool:Tool)-[:IMPLEMENTS]->(t)
RETURN t.attack_id                    AS attack_id,
       t.name                         AS name,
       coalesce(t.tactics, [])        AS tactics,
       coalesce(t.platforms, [])      AS platforms,
       coalesce(t.preconditions, [])  AS preconditions,
       coalesce(t.effects, [])        AS effects,
       coalesce(t.sources, [])        AS sources,
       coalesce(t.description, '')    AS description,
       [n IN collect(DISTINCT tool.name) WHERE n IS NOT NULL] AS tools
ORDER BY attack_id
"""


@dataclass(frozen=True)
class EmulationRequest:
    """
    What to build a plan for.

    Deliberately a structured record rather than a natural-language parser: the
    10-15 thesis scenarios are constructed with known parameters, so parsing an
    English sentence would be machinery with no caller.

    `objective` does not filter retrieval — it is carried through to the Phase C
    prompt and to Part 3's goal-completion metric.
    """
    version: str
    platforms: tuple = ("Windows",)
    objective: str = ""


def software_id(version: str) -> str:
    """ATT&CK software ID for a LockBit version."""
    try:
        return SOFTWARE_ID[version]
    except KeyError:
        raise ValueError(
            f"Unknown LockBit version {version!r}; known versions: {sorted(SOFTWARE_ID)}"
        ) from None


def primary_tactic(tactics: list) -> str:
    """
    The earliest kill-chain tactic among a technique's tactics — the phase the
    technique is placed in.

    Mirrors attack_tactics.get_tactic_order, which answers "what position?";
    this answers "which tactic holds that position?". A technique usable in an
    early role (Valid Accounts as initial access) is planned at that early role.

    Names are folded through canonical_tactic first, so the two spellings of the
    position-6 stage collapse into a single phase rather than presenting the same
    ATT&CK stage to the model twice.
    """
    known = [n for n in (canonical_tactic(t) for t in tactics) if n in TACTIC_ORDER]
    if not known:
        return UNKNOWN_TACTIC
    return min(known, key=lambda t: TACTIC_ORDER[t])


# ─────────────────────────────────────────────
# RETRIEVAL (the only part that touches Neo4j)
# ─────────────────────────────────────────────
def retrieve_subgraph(session, request: EmulationRequest) -> list:
    """Raw technique records for a request. No shaping — see order_by_phase."""
    result = session.run(RETRIEVE_CYPHER, {
        "software_id": software_id(request.version),
        "actor":       CISA_ACTOR,
        "platforms":   list(request.platforms),
    })
    return [dict(record) for record in result]


# ─────────────────────────────────────────────
# SHAPING (pure — no database, unit-tested offline)
# ─────────────────────────────────────────────
def order_by_phase(techniques: list) -> list:
    """
    Group techniques into ATT&CK kill-chain phases, earliest phase first.

    Within a phase, techniques are sorted by attack_id so the same graph always
    serialises to the same context — a generated plan that changes because the
    database returned rows in a different order would not be reproducible.
    """
    grouped = {}
    for technique in techniques:
        grouped.setdefault(primary_tactic(technique.get("tactics") or []), []).append(technique)

    phases = []
    for tactic in sorted(grouped, key=lambda t: TACTIC_ORDER.get(t, UNKNOWN_TACTIC_ORDER)):
        phases.append({
            "tactic":       tactic,
            "tactic_order": TACTIC_ORDER.get(tactic, UNKNOWN_TACTIC_ORDER),
            "techniques":   sorted(grouped[tactic], key=lambda t: t["attack_id"]),
        })
    return phases


def serialize(request: EmulationRequest, phases: list) -> dict:
    """The retrieved subgraph as a JSON-ready dict (also the Phase C prompt input)."""
    return {
        "adversary":       f"LockBit {request.version}",
        "software_id":     software_id(request.version),
        "platforms":       list(request.platforms),
        "objective":       request.objective,
        "phase_count":     len(phases),
        "technique_count": sum(len(p["techniques"]) for p in phases),
        "phases":          phases,
    }


def to_prompt_text(subgraph: dict) -> str:
    """The subgraph as a readable context block to paste into an LLM prompt."""
    lines = [
        f"Adversary: {subgraph['adversary']} ({subgraph['software_id']})",
        f"Target platforms: {', '.join(subgraph['platforms'])}",
    ]
    if subgraph["objective"]:
        lines.append(f"Objective: {subgraph['objective']}")
    lines.append(f"Known techniques: {subgraph['technique_count']} "
                 f"across {subgraph['phase_count']} phases")
    lines.append("")

    for phase in subgraph["phases"]:
        lines.append(f"## {phase['tactic']}")
        for t in phase["techniques"]:
            lines.append(f"- {t['attack_id']} {t['name']}")
            lines.append(f"  preconditions: {', '.join(t['preconditions']) or 'none'}"
                         f" | effects: {', '.join(t['effects']) or 'none'}")
            if t["tools"]:
                lines.append(f"  tools: {', '.join(sorted(t['tools']))}")
            lines.append(f"  sources: {', '.join(t['sources']) or 'unattributed'}")
            if t["description"]:
                lines.append(f"  {t['description'][:DESCRIPTION_CHARS].strip()}")
        lines.append("")
    return "\n".join(lines).strip()


def retrieve(request: EmulationRequest) -> dict:
    """Connect locally, retrieve, and shape — the one call Phase C will make."""
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, neo4j_password()))
    try:
        with driver.session() as session:
            techniques = retrieve_subgraph(session, request)
    finally:
        driver.close()
    return serialize(request, order_by_phase(techniques))


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--version", required=True, choices=sorted(SOFTWARE_ID),
                        help="LockBit version to build the subgraph for")
    parser.add_argument("--platform", action="append", dest="platforms",
                        help="target platform, repeatable (default: Windows)")
    parser.add_argument("--objective", default="",
                        help="carried into the prompt; does not filter retrieval")
    parser.add_argument("--out", help="write the subgraph JSON here")
    parser.add_argument("--print-prompt", action="store_true",
                        help="print the prompt-context block instead of a summary")
    args = parser.parse_args()

    request = EmulationRequest(
        version=args.version,
        platforms=tuple(args.platforms or ["Windows"]),
        objective=args.objective,
    )

    print(f"[1/2] Retrieving LockBit {request.version} ({software_id(request.version)}) "
          f"subgraph for {', '.join(request.platforms)} from {NEO4J_URI} ...")
    subgraph = retrieve(request)
    print(f"      ✅ {subgraph['technique_count']} techniques "
          f"across {subgraph['phase_count']} phases")

    if args.print_prompt:
        print()
        print(to_prompt_text(subgraph))
    else:
        print("\n[2/2] Phases in kill-chain order:")
        for phase in subgraph["phases"]:
            ids = ", ".join(t["attack_id"] for t in phase["techniques"])
            print(f"      {phase['tactic_order']:>2}  {phase['tactic']:<22} "
                  f"{len(phase['techniques']):>2}  {ids}")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(subgraph, f, indent=2)
        print(f"\n✅ Saved to {args.out}")


if __name__ == "__main__":
    main()
