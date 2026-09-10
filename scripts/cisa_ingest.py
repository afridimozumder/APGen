#!/usr/bin/env python3
"""
Step 1.5.1b — CISA advisory ingestion (AA23-165A, "Understanding Ransomware
Threat Actors: LockBit").

WHY THIS EXISTS: the MITRE STIX bundle only maps techniques to LockBit the
*software* (S1199 / S1202), which leaves the kill chain with no
credential-access, collection or exfiltration stage. This advisory documents
what LockBit *affiliates* do end to end, so it fills those gaps and gives every
technique a second, independent source.

The advisory publishes no STIX or JSON, so the extract stage parses the
technique tables out of the published HTML.

TWO-STAGE APPROACH:
  Stage A (AI-LAB): Download + parse advisory -> save to cisa_lockbit.json
  Stage B (local):  Load cisa_lockbit.json -> Neo4j

Usage:
  python3 cisa_ingest.py --stage extract --output outputs/cisa_lockbit.json
  python3 cisa_ingest.py --stage load    --input  outputs/cisa_lockbit.json
"""

import os
import re
import sys
import json
import argparse
import requests
from neo4j import GraphDatabase

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attack_tactics import get_tactic_order, normalize_tactic

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
NEO4J_URI  = os.getenv("NEO4J_URI",  "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "LockBit2025!")

ADVISORY_ID  = "AA23-165A"
ADVISORY_URL = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a"
SOURCE_NAME  = f"CISA {ADVISORY_ID}"

# The advisory describes the affiliates who deploy LockBit, not one payload
# version, so its techniques hang off an actor node rather than S1199/S1202.
ACTOR_NAME = "LockBit affiliates"

TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
# Captions read "Table 5: ... ATT&CK Techniques for Enterprise – Initial Access"
CAPTION_RE = re.compile(r"Table\s+\d+:[^<]*?[‐-―-]\s*([A-Za-z][A-Za-z &]*?)\s*$")

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def strip_tags(html: str) -> str:
    """Plain text of an HTML fragment, with entities and whitespace tidied."""
    text = re.sub(r"<[^>]+>", " ", html)
    for entity, char in (("&amp;", "&"), ("&nbsp;", " "), ("&quot;", '"'),
                         ("&#39;", "'"), ("&lt;", "<"), ("&gt;", ">")):
        text = text.replace(entity, char)
    return re.sub(r"\s+", " ", text).strip()


def parse_rows(table_html: str) -> list:
    """Rows of a table as lists of plain-text cells."""
    return [
        [strip_tags(cell) for cell in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)]
        for row in re.findall(r"<tr>(.*?)</tr>", table_html, re.S)
    ]


def find_tactic(html: str, table_start: int) -> str:
    """Tactic named in the caption immediately preceding a table, else ''."""
    preceding = strip_tags(html[max(0, table_start - 800):table_start])
    match = CAPTION_RE.search(preceding)
    return match.group(1).strip() if match else ""


def parse_techniques(html: str) -> list:
    """
    Every technique in the advisory's per-tactic ATT&CK tables.

    A table qualifies only if its header row is "Technique Title | ID | Use",
    which skips the incident-timeline and statistics tables on the same page.
    """
    techniques = {}
    for match in re.finditer(r"<table>.*?</table>", html, re.S):
        rows = parse_rows(match.group(0))
        if not rows or [c.lower() for c in rows[0][:3]] != ["technique title", "id", "use"]:
            continue
        tactic = find_tactic(html, match.start())
        for row in rows[1:]:
            if len(row) < 3 or not TECHNIQUE_ID_RE.match(row[1]):
                continue
            name, attack_id, use = row[0], row[1], row[2]
            # One ID can appear under several tactics; keep every tactic it maps to.
            entry = techniques.setdefault(
                attack_id,
                {"attack_id": attack_id, "name": name, "tactics": [], "procedures": []},
            )
            normalized = normalize_tactic(tactic)
            if normalized and normalized not in entry["tactics"]:
                entry["tactics"].append(normalized)
            if use and use not in entry["procedures"]:
                entry["procedures"].append(use)
    return list(techniques.values())


def parse_tools(html: str) -> list:
    """
    The freeware/open-source tools table: what LockBit affiliates actually run.

    These turn a technique list into something executable, e.g. "Rclone ->
    exfiltrate to cloud storage", so they are ingested alongside the techniques.
    """
    tools = []
    for match in re.finditer(r"<table>.*?</table>", html, re.S):
        rows = parse_rows(match.group(0))
        if not rows or [c.lower() for c in rows[0][:3]] != ["tool", "intended use",
                                                            "repurposed use by lockbit affiliates"]:
            continue
        for row in rows[1:]:
            if len(row) < 4:
                continue
            # The ID cell holds an ATT&CK ID then its title; techniques only.
            attack_id = row[3].split()[0] if row[3].split() else ""
            if not TECHNIQUE_ID_RE.match(attack_id):
                continue
            tools.append({
                "name": row[0],
                "intended_use": row[1],
                "repurposed_use": row[2],
                "technique_id": attack_id,
            })
    return tools


# ─────────────────────────────────────────────
# STAGE A — Download + parse → Save JSON
# ─────────────────────────────────────────────
def stage_extract(output_path):
    print(f"[1/3] Downloading CISA advisory {ADVISORY_ID} ...")
    response = requests.get(ADVISORY_URL, timeout=60)
    response.raise_for_status()
    response.encoding = "utf-8"
    html = response.text
    print(f"      ✅ Downloaded {len(html)} characters")

    print("[2/3] Parsing ATT&CK tables ...")
    techniques = parse_techniques(html)
    tools = parse_tools(html)
    if not techniques:
        raise ValueError("❌ No technique tables found — the advisory layout changed.")

    tactics = sorted({t for tech in techniques for t in tech["tactics"]})
    print(f"      ✅ Techniques : {len(techniques)}")
    print(f"      ✅ Tools      : {len(tools)}")
    print(f"      ✅ Tactics    : {', '.join(tactics)}")

    result = {
        "advisory_id":  ADVISORY_ID,
        "advisory_url": ADVISORY_URL,
        "actor_name":   ACTOR_NAME,
        "techniques":   techniques,
        "tools":        tools,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"[3/3] ✅ Saved to {output_path}")
    print("      → copy this file to your local computer then run --stage load")


# ─────────────────────────────────────────────
# STAGE B — Load JSON → Neo4j (run locally)
# ─────────────────────────────────────────────
def stage_load(input_path):
    print(f"[1/4] Reading {input_path} ...")
    with open(input_path, encoding="utf-8") as f:
        data = json.load(f)

    techniques = data["techniques"]
    tools      = data["tools"]
    print(f"      Techniques : {len(techniques)}")
    print(f"      Tools      : {len(tools)}")

    print(f"\n[2/4] Connecting to Neo4j at {NEO4J_URI} ...")
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    provenance = {"source": SOURCE_NAME, "url": data["advisory_url"]}

    with driver.session() as session:
        print("[3/4] Loading nodes ...")

        session.run("""
            MERGE (a:ThreatActor {name: $name})
            SET a.description = $description,
                a.source      = $source,
                a.source_url  = $url,
                a.confidence  = 1.0
        """, {
            "name":        data["actor_name"],
            "description": "Affiliates who deploy LockBit ransomware under its "
                           "ransomware-as-a-service model.",
            **provenance,
        })
        print(f"      ✅ ThreatActor node: {data['actor_name']}")

        # Techniques MERGE on attack_id, so an ID MITRE already loaded resolves
        # to that same node and gains a second entry in its sources list.
        for t in techniques:
            label = "SubTechnique" if "." in t["attack_id"] else "Technique"
            session.run(f"""
                MERGE (t:{label} {{attack_id: $attack_id}})
                ON CREATE SET t.name        = $name,
                              t.description = $description,
                              t.tactics     = $tactics,
                              t.source      = $source,
                              t.source_url  = $url,
                              t.confidence  = 1.0
                SET t.tactic_order = CASE WHEN t.tactic_order IS NULL
                                          OR $tactic_order < t.tactic_order
                                     THEN $tactic_order ELSE t.tactic_order END,
                    t.sources = CASE WHEN $source IN coalesce(t.sources, [])
                                     THEN t.sources
                                     ELSE coalesce(t.sources, []) + $source END
                WITH t
                MATCH (a:ThreatActor {{name: $actor}})
                MERGE (a)-[r:USES {{source: $source}}]->(t)
                SET r.description = $procedure,
                    r.source_url  = $url,
                    r.confidence  = 1.0
            """, {
                "attack_id":    t["attack_id"],
                "name":         t["name"],
                "description":  " ".join(t["procedures"])[:500],
                "tactics":      t["tactics"],
                "tactic_order": get_tactic_order(t["tactics"]),
                "procedure":    " ".join(t["procedures"])[:300],
                "actor":        data["actor_name"],
                **provenance,
            })
        print(f"      ✅ {len(techniques)} Technique/SubTechnique nodes linked to actor")

        for tool in tools:
            session.run("""
                MERGE (tool:Tool {name: $name})
                SET tool.intended_use   = $intended_use,
                    tool.repurposed_use = $repurposed_use,
                    tool.source         = $source,
                    tool.source_url     = $url,
                    tool.confidence     = 1.0
                WITH tool
                MATCH (t) WHERE (t:Technique OR t:SubTechnique)
                          AND t.attack_id = $technique_id
                MERGE (tool)-[r:IMPLEMENTS]->(t)
                SET r.source     = $source,
                    r.source_url = $url,
                    r.confidence = 1.0
            """, {**tool, **provenance})
        print(f"      ✅ {len(tools)} Tool nodes linked to techniques")

    print("\n[4/4] Verifying graph ...")
    with driver.session() as session:
        print("\n      📊 Node counts in Neo4j:")
        for row in session.run(
            "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC"
        ):
            print(f"         {row['label']:<20} : {row['count']}")
        corroborated = session.run("""
            MATCH (t) WHERE size(coalesce(t.sources, [])) > 1 RETURN count(t) AS c
        """).single()["c"]
        print(f"\n      🔗 Techniques confirmed by more than one source: {corroborated}")

    driver.close()
    print(f"\n✅ Step 1.5.1b complete — CISA {ADVISORY_ID} loaded into Neo4j!")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage",  choices=["extract", "load"], required=True)
    parser.add_argument("--input",  default="outputs/cisa_lockbit.json")
    parser.add_argument("--output", default="outputs/cisa_lockbit.json")
    args = parser.parse_args()

    if args.stage == "extract":
        stage_extract(args.output)
    elif args.stage == "load":
        stage_load(args.input)
