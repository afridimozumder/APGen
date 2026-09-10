#!/usr/bin/env python3
"""
Step 1.5.1a — ATT&CK STIX Ingestion for LockBit 2.0 (S1199) and LockBit 3.0 (S1202)

NOTE: In MITRE ATT&CK, LockBit is tracked as SOFTWARE (malware), not a threat group.
  - LockBit 2.0 = S1199
  - LockBit 3.0 = S1202

TWO-STAGE APPROACH:
  Stage A (AI-LAB): Download + filter → save to lockbit_stix.json
  Stage B (local):  Load lockbit_stix.json → Neo4j

Usage:
  python3 stix_ingest.py --stage extract --output /path/to/lockbit_stix.json
  python3 stix_ingest.py --stage load   --input  lockbit_stix.json
"""

import os
import sys
import json
import argparse
import requests
from neo4j import GraphDatabase

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attack_tactics import (  # noqa: F401  (re-exported for tests)
    TACTIC_ORDER,
    UNKNOWN_TACTIC_ORDER,
    get_tactic_order,
    normalize_tactic,
)

# Windows consoles default to cp1252, which cannot encode the status glyphs
# used in this script's output. Streams replaced by a test runner or a pipe
# may not expose reconfigure(), so only call it where it exists.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
NEO4J_URI  = os.getenv("NEO4J_URI",  "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "LockBit2025!")

# LockBit is SOFTWARE in ATT&CK, not a group
LOCKBIT_IDS = {
    "S1199": "LockBit 2.0",
    "S1202": "LockBit 3.0"
}

BUNDLE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# ─────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────
def get_attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""

def get_tactics(obj):
    phases = obj.get("kill_chain_phases", [])
    return [p["phase_name"] for p in phases if p.get("kill_chain_name") == "mitre-attack"]


def get_platforms(obj) -> list:
    """OS/platforms a technique applies to, e.g. ['Windows', 'ESXi']."""
    return obj.get("x_mitre_platforms", [])

def select_enrichment_techniques(all_techniques, wanted_ids, already_have):
    """
    ATT&CK objects for techniques another source attributed to LockBit.

    CISA advisories name techniques but publish no platform data, so those
    nodes cannot be filtered by target environment. MITRE documents every
    technique regardless of who it links it to, so its definitions supply the
    missing platforms. Revoked and deprecated objects are skipped: an ATT&CK ID
    can appear on several objects and only the live one should win.
    """
    selected = {}
    for stix_id, obj in all_techniques.items():
        attack_id = get_attack_id(obj)
        if attack_id not in wanted_ids or attack_id in already_have:
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        selected[stix_id] = obj
    return selected


def resolve_revoked_ids(all_techniques, relationships, wanted_ids):
    """
    Map an ATT&CK ID that has since been revoked onto the ID that replaced it.

    Advisories are written against the ATT&CK version current at publication and
    are never reissued, so CISA AA23-165A (June 2023, ATT&CK v13) still names
    T1562.001 for a technique MITRE has since renumbered to T1685. Without this
    map both IDs enter the graph as separate nodes and one real technique
    appears twice in a generated plan.
    """
    by_attack_id = {}
    for obj in all_techniques.values():
        by_attack_id.setdefault(get_attack_id(obj), []).append(obj)

    revoked_by = {r["source_ref"]: r["target_ref"] for r in relationships
                  if r.get("relationship_type") == "revoked-by"}

    aliases = {}
    for attack_id in wanted_ids:
        candidates = by_attack_id.get(attack_id, [])
        if any(not o.get("revoked") and not o.get("x_mitre_deprecated") for o in candidates):
            continue  # a live object still owns this ID
        for obj in candidates:
            replacement = all_techniques.get(revoked_by.get(obj["id"], ""))
            if replacement and get_attack_id(replacement):
                aliases[attack_id] = get_attack_id(replacement)
                break
    return aliases


def read_referenced_attack_ids(path):
    """ATT&CK IDs named by a companion extract, e.g. the CISA advisory JSON."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return {t["attack_id"] for t in data.get("techniques", [])}


def find_software_by_attack_ids(objects, attack_ids):
    """Find malware/tool objects matching a set of ATT&CK IDs (e.g. S1199, S1202)."""
    result = {}
    for o in objects:
        if o["type"] in ("malware", "tool"):
            aid = get_attack_id(o)
            if aid in attack_ids:
                result[o["id"]] = o
    return result

# ─────────────────────────────────────────────
# STAGE A — Download + Filter → Save JSON
# ─────────────────────────────────────────────
def stage_extract(output_path, enrich_path=None):
    print("[1/3] Downloading ATT&CK STIX bundle from github.com/mitre/cti ...")
    print("      (~60MB, takes 30-60 seconds)")
    r = requests.get(BUNDLE_URL, timeout=120)
    r.raise_for_status()
    objects = r.json()["objects"]
    print(f"      ✅ Downloaded {len(objects)} STIX objects")

    # Separate by type
    all_techniques = {o["id"]: o for o in objects if o["type"] == "attack-pattern"}
    all_software   = {o["id"]: o for o in objects if o["type"] in ("malware", "tool")}
    all_groups     = {o["id"]: o for o in objects if o["type"] == "intrusion-set"}
    all_campaigns  = {o["id"]: o for o in objects if o["type"] == "campaign"}
    relationships  = [o for o in objects if o["type"] == "relationship"]

    print(f"[2/3] Searching for LockBit software objects ...")

    # Find LockBit 2.0 and 3.0 by their ATT&CK software IDs
    lockbit_software = find_software_by_attack_ids(objects, set(LOCKBIT_IDS.keys()))

    if not lockbit_software:
        raise ValueError("❌ No LockBit software objects found in bundle!")

    for stix_id, obj in lockbit_software.items():
        aid = get_attack_id(obj)
        print(f"      ✅ Found: {obj['name']} | ATT&CK ID: {aid} | STIX: {stix_id}")

    lockbit_stix_ids = set(lockbit_software.keys())

    # Collect all relationships where LockBit software is source OR target
    lb_relations = [
        rel for rel in relationships
        if rel["source_ref"] in lockbit_stix_ids or rel["target_ref"] in lockbit_stix_ids
    ]
    print(f"      ✅ Relationships involving LockBit: {len(lb_relations)}")

    # Collect all connected node IDs (techniques, groups, campaigns linked to LockBit)
    connected_ids = set()
    for rel in lb_relations:
        connected_ids.add(rel["source_ref"])
        connected_ids.add(rel["target_ref"])
    # Remove the LockBit nodes themselves (already stored separately)
    connected_ids -= lockbit_stix_ids

    # Resolve connected nodes by type
    lb_techniques = {tid: all_techniques[tid] for tid in connected_ids if tid in all_techniques}
    lb_groups     = {tid: all_groups[tid]     for tid in connected_ids if tid in all_groups}
    lb_campaigns  = {tid: all_campaigns[tid]  for tid in connected_ids if tid in all_campaigns}

    print(f"      ✅ Techniques linked : {len(lb_techniques)}")
    print(f"      ✅ Groups linked     : {len(lb_groups)}")
    print(f"      ✅ Campaigns linked  : {len(lb_campaigns)}")

    # Techniques another source ties to LockBit, pulled in for their platform
    # data only. Kept separate from "techniques" so the load stage never treats
    # them as a MITRE attribution to LockBit.
    enrichment, id_aliases = {}, {}
    if enrich_path:
        referenced = read_referenced_attack_ids(enrich_path)
        already_have = {get_attack_id(t) for t in lb_techniques.values()}
        id_aliases = resolve_revoked_ids(all_techniques, relationships, referenced)
        # Chase each revoked ID to its replacement before selecting enrichment.
        referenced = {id_aliases.get(a, a) for a in referenced}
        enrichment = select_enrichment_techniques(all_techniques, referenced, already_have)
        print(f"      ✅ Enrichment from {os.path.basename(enrich_path)}: "
              f"{len(enrichment)} of {len(referenced)} referenced techniques")
        for old_id, new_id in sorted(id_aliases.items()):
            print(f"      ↪️  Revoked ID {old_id} → {new_id}")

    # Save
    result = {
        "lockbit_software": list(lockbit_software.values()),
        "techniques":       list(lb_techniques.values()),
        "enrichment_techniques": list(enrichment.values()),
        "id_aliases":       id_aliases,
        "groups":           list(lb_groups.values()),
        "campaigns":        list(lb_campaigns.values()),
        "relationships":    lb_relations
    }
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[3/3] ✅ Saved to {output_path}")
    print(f"      → scp this file to your local computer then run --stage load")


# ─────────────────────────────────────────────
# STAGE B — Load JSON → Neo4j (run locally)
# ─────────────────────────────────────────────
def stage_load(input_path):
    print(f"[1/4] Reading {input_path} ...")
    with open(input_path) as f:
        data = json.load(f)

    lockbit_software = data["lockbit_software"]
    techniques       = data["techniques"]
    enrichment       = data.get("enrichment_techniques", [])
    groups           = data["groups"]
    campaigns        = data["campaigns"]
    relations        = data["relationships"]

    print(f"      LockBit variants : {[s['name'] for s in lockbit_software]}")
    print(f"      Techniques       : {len(techniques)}")
    print(f"      Enrichment only  : {len(enrichment)}")
    print(f"      Groups linked    : {len(groups)}")
    print(f"      Campaigns        : {len(campaigns)}")
    print(f"      Relationships    : {len(relations)}")

    print(f"\n[2/4] Connecting to Neo4j at {NEO4J_URI} ...")
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    with driver.session() as session:

        print(f"[3/4] Loading nodes ...")

        # LockBit software nodes (Malware label)
        for s in lockbit_software:
            session.run("""
                MERGE (m:Malware {stix_id: $stix_id})
                SET m.name        = $name,
                    m.attack_id   = $attack_id,
                    m.description = $description,
                    m.type        = $type,
                    m.aliases     = $aliases,
                    m.source      = 'MITRE ATT&CK STIX',
                    m.source_url  = 'https://github.com/mitre/cti',
                    m.confidence  = 1.0
            """, {
                "stix_id":     s["id"],
                "name":        s.get("name", ""),
                "attack_id":   get_attack_id(s),
                "description": s.get("description", "")[:500],
                "type":        s.get("type", "malware"),
                "aliases":     s.get("aliases", [s.get("name", "")])
            })
            print(f"      ✅ Malware node: {s['name']} ({get_attack_id(s)})")

        # Technique / SubTechnique nodes
        for t in techniques:
            attack_id = get_attack_id(t)
            tactics = get_tactics(t)
            label = "SubTechnique" if "." in attack_id else "Technique"
            # Labels cannot be Cypher parameters; value is always "Technique" or "SubTechnique"
            session.run(f"""
                MERGE (t:{label} {{attack_id: $attack_id}})
                SET t.stix_id      = $stix_id,
                    t.name         = $name,
                    t.description  = $description,
                    t.tactics      = $tactics,
                    t.tactic_order = $tactic_order,
                    t.platforms    = $platforms,
                    t.platforms_source = 'MITRE ATT&CK STIX',
                    t.source       = 'MITRE ATT&CK STIX',
                    t.source_url   = 'https://github.com/mitre/cti',
                    t.confidence   = 1.0,
                    t.sources      = CASE WHEN 'MITRE ATT&CK STIX' IN coalesce(t.sources, [])
                                          THEN t.sources
                                          ELSE coalesce(t.sources, []) + 'MITRE ATT&CK STIX' END
            """, {
                "stix_id":      t["id"],
                "attack_id":    attack_id,
                "name":         t.get("name", ""),
                "description":  t.get("description", "")[:500],
                "tactics":      tactics,
                "tactic_order": get_tactic_order(tactics),
                "platforms":    get_platforms(t)
            })
        print(f"      ✅ {len(techniques)} Technique/SubTechnique nodes")

        # Platform data for techniques MITRE documents but does not itself tie to
        # LockBit. These deliberately do NOT append to t.sources and get no USES
        # edge: t.sources records who attributes a technique to LockBit, and
        # MITRE does not. Only the technique's definition comes from here.
        for t in enrichment:
            attack_id = get_attack_id(t)
            label = "SubTechnique" if "." in attack_id else "Technique"
            session.run(f"""
                MERGE (t:{label} {{attack_id: $attack_id}})
                ON CREATE SET t.name        = $name,
                              t.description = $description,
                              t.source      = 'MITRE ATT&CK STIX',
                              t.source_url  = 'https://github.com/mitre/cti',
                              t.confidence  = 1.0
                SET t.stix_id          = $stix_id,
                    t.platforms        = $platforms,
                    t.platforms_source = 'MITRE ATT&CK STIX'
            """, {
                "stix_id":     t["id"],
                "attack_id":   attack_id,
                "name":        t.get("name", ""),
                "description": t.get("description", "")[:500],
                "platforms":   get_platforms(t)
            })
        if enrichment:
            print(f"      ✅ {len(enrichment)} techniques enriched with platform data")

        # ThreatActor nodes (groups linked to LockBit)
        for g in groups:
            session.run("""
                MERGE (a:ThreatActor {stix_id: $stix_id})
                SET a.name        = $name,
                    a.attack_id   = $attack_id,
                    a.description = $description,
                    a.aliases     = $aliases,
                    a.source      = 'MITRE ATT&CK STIX',
                    a.source_url  = 'https://github.com/mitre/cti',
                    a.confidence  = 1.0
            """, {
                "stix_id":     g["id"],
                "name":        g.get("name", ""),
                "attack_id":   get_attack_id(g),
                "description": g.get("description", "")[:500],
                "aliases":     g.get("aliases", [])
            })
        print(f"      ✅ {len(groups)} ThreatActor nodes (groups using LockBit)")

        # Campaign nodes
        for c in campaigns:
            session.run("""
                MERGE (camp:Campaign {stix_id: $stix_id})
                SET camp.name        = $name,
                    camp.description = $description,
                    camp.attack_id   = $attack_id,
                    camp.source      = 'MITRE ATT&CK STIX',
                    camp.source_url  = 'https://github.com/mitre/cti',
                    camp.confidence  = 1.0
            """, {
                "stix_id":     c["id"],
                "name":        c.get("name", ""),
                "attack_id":   get_attack_id(c),
                "description": c.get("description", "")[:500]
            })
        print(f"      ✅ {len(campaigns)} Campaign nodes")

        # Relationships
        rel_count = 0
        for r in relations:
            result = session.run("""
                MATCH (a {stix_id: $src})
                MATCH (b {stix_id: $tgt})
                MERGE (a)-[rel:USES {stix_id: $rel_id}]->(b)
                SET rel.rel_type    = $rel_type,
                    rel.description = $description,
                    rel.source      = 'MITRE ATT&CK STIX',
                    rel.source_url  = 'https://github.com/mitre/cti',
                    rel.confidence  = 1.0
                RETURN rel
            """, {
                "src":         r["source_ref"],
                "tgt":         r["target_ref"],
                "rel_id":      r["id"],
                "rel_type":    r.get("relationship_type", "uses").upper().replace("-", "_"),
                "description": r.get("description", "")[:300]
            })
            row = result.single()
            if row:
                rel_count += 1
            else:
                print(f"      ⚠️  Skipped rel {r['id']}: node not found "
                      f"(src={r['source_ref']}, tgt={r['target_ref']})")
        print(f"      ✅ {rel_count} relationships created")

    # Verify — reuse same driver, open a fresh session
    print("\n[4/4] Verifying graph ...")
    with driver.session() as session:
        counts = session.run("""
            MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC
        """)
        print("\n      📊 Node counts in Neo4j:")
        for row in counts:
            print(f"         {row['label']:<20} : {row['count']}")
        rels = session.run("MATCH ()-[r]->() RETURN count(r) AS total")
        print(f"         {'Relationships':<20} : {rels.single()['total']}")

    driver.close()
    print("\n✅ Step 1.5.1a complete — LockBit 2.0 & 3.0 STIX data loaded into Neo4j!")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage",  choices=["extract", "load"], required=True)
    parser.add_argument("--input",  default="lockbit_stix.json")
    parser.add_argument("--output", default="lockbit_stix.json")
    parser.add_argument("--enrich", default=None,
                        help="Companion extract JSON (e.g. outputs/cisa_lockbit.json). "
                             "Techniques it names are pulled in for platform data only.")
    args = parser.parse_args()

    if args.stage == "extract":
        stage_extract(args.output, args.enrich)
    elif args.stage == "load":
        stage_load(args.input)
