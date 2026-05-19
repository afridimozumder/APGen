# APGen — Adversary Plan Generation with Knowledge Graphs and LLMs

A research codebase that builds a LockBit-focused Cyber Threat Intelligence Knowledge
Graph (CTI-KG) in Neo4j and uses it as structured ground truth for a GraphRAG + LLM
pipeline that automatically generates Adversary Emulation Plans (AEPs).

The motivation: large language models alone tend to hallucinate attack steps and
produce chains that are not grounded in any verified threat intelligence. Grounding
generation in a curated knowledge graph constrains the model to known techniques,
sub-techniques, and procedures attributable to a specific adversary — in this case,
LockBit ransomware.

Master's thesis project at Aalborg University (AAU), Denmark.

---

## Status

Phase A — Knowledge Graph construction. The first ingestion stage (MITRE ATT&CK STIX
for LockBit 2.0 / `S1199` and LockBit 3.0 / `S1202`) is complete; further sources will
be added incrementally.

---

## Repository layout

```
APGen/
├── scripts/
│   └── stix_ingest.py          two-stage MITRE ATT&CK STIX → Neo4j ingester
├── requirements.txt            runtime dependencies
├── requirements-dev.txt        test/dev dependencies
├── .env.example                template for local secrets (Neo4j, OpenAI)
└── .gitignore
```

---

## Quick start

### 1. Clone and install

```powershell
git clone https://github.com/afridimozumder/APGen.git
cd APGen
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 2. Configure environment

```powershell
Copy-Item .env.example .env
```

Edit `.env` and set `NEO4J_PASS` to the password for your local Neo4j instance, and
`OPENAI_API_KEY` if you intend to run LLM-backed pipeline stages.

### 3. Run Neo4j locally (Docker)

```bash
docker run --name apgen-neo4j -p 7474:7474 -p 7687:7687 -d \
  -v $HOME/neo4j/data:/data \
  -e NEO4J_AUTH=neo4j/<your-password> \
  -e NEO4J_PLUGINS='["apoc"]' \
  neo4j:community
```

Neo4j Browser: <http://localhost:7474> · Bolt: `bolt://localhost:7687`.

### 4. Run the STIX ingestion (Step 1.5.1a)

The ingestion script follows a two-stage pattern: a heavy `extract` stage that can run
on a compute cluster without Neo4j access, and a light `load` stage that runs locally
against Neo4j.

```powershell
# Stage 1 — fetch ATT&CK STIX bundle and extract LockBit subgraph to JSON
python scripts/stix_ingest.py --stage extract

# Stage 2 — load the JSON into Neo4j (idempotent; uses MERGE)
python scripts/stix_ingest.py --stage load
```

Output: a populated graph containing `Malware` nodes for LockBit variants, the
`Technique` / `SubTechnique` nodes they use, related `ThreatActor` nodes, and
provenance-tagged `USES` relationships.

---

## Roadmap (high level)

- **Part 1 — Knowledge Graph.** Ingest MITRE ATT&CK STIX, ATT&CK Evaluations
  emulation plans, vendor CTI reports, and an academic TTP reference into a unified
  graph with consistent provenance.
- **Part 2 — Plan generation.** GraphRAG retrieval over the KG to build prompt
  context, LLM-based plan generation, and graph-based validation against the KG to
  reject hallucinated steps.
- **Part 3 — Evaluation.** Quantitative comparison of KG-grounded plans against a
  naked-LLM baseline using technique coverage, precondition satisfaction, hallucination
  rate, tactic ordering, and similarity to ground-truth references.

---

## Conventions

- Every node and relationship written to Neo4j carries `source`, `source_url`, and
  `confidence` properties for full provenance traceability.
- Cypher writes use `MERGE` rather than `CREATE`, making every ingestion script safe
  to re-run.
- Credentials are read from environment variables (`NEO4J_URI`, `NEO4J_USER`,
  `NEO4J_PASS`, `OPENAI_API_KEY`); never hard-coded.

---

## License

MIT — see [`LICENSE`](LICENSE).
