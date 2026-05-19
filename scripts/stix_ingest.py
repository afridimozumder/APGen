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
import json
import argparse
import requests
from neo4j import GraphDatabase

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
def stage_extract(output_path):
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

    # Collect all connected node IDs
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

    # Save
    result = {
        "lockbit_software": list(lockbit_software.values()),
        "techniques":       list(lb_techniques.values()),
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
    groups           = data["groups"]
    campaigns        = data["campaigns"]
    relations        = data["relationships"]

    print(f"      LockBit variants : {[s['name'] for s in lockbit_software]}")
    print(f"      Techniques       : {len(techniques)}")
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
                    m.source_url  = 'https://github.com/mitre/cti'
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
            label = "SubTechnique" if "." in attack_id else "Technique"
            # Labels cannot be Cypher parameters; value is always "Technique" or "SubTechnique"
            session.run(f"""
                MERGE (t:{label} {{attack_id: $attack_id}})
                SET t.stix_id     = $stix_id,
                    t.name        = $name,
                    t.description = $description,
                    t.tactics     = $tactics,
                    t.source      = 'MITRE ATT&CK STIX',
                    t.source_url  = 'https://github.com/mitre/cti'
            """, {
                "stix_id":     t["id"],
                "attack_id":   attack_id,
                "name":        t.get("name", ""),
                "description": t.get("description", "")[:500],
                "tactics":     get_tactics(t)
            })
        print(f"      ✅ {len(techniques)} Technique/SubTechnique nodes")

        # ThreatActor nodes (groups linked to LockBit)
        for g in groups:
            session.run("""
                MERGE (a:ThreatActor {stix_id: $stix_id})
                SET a.name        = $name,
                    a.attack_id   = $attack_id,
                    a.description = $description,
                    a.aliases     = $aliases,
                    a.source      = 'MITRE ATT&CK STIX',
                    a.source_url  = 'https://github.com/mitre/cti'
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
                    camp.source_url  = 'https://github.com/mitre/cti'
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
    args = parser.parse_args()

    if args.stage == "extract":
        stage_extract(args.output)
    elif args.stage == "load":
        stage_load(args.input)
