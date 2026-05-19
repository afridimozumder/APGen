# LockBit CTI Knowledge Graph — Project Context for AI Assistant

## Who I Am
I am a student at Aalborg University (AAU), Denmark. My username on the HPC is `ua40oj@student.aau.dk`.

---

## Project Goal

Build a **LockBit-focused Cyber Threat Intelligence Knowledge Graph (CTI-KG)** in Neo4j,
populated from multiple CTI sources. The KG will later power a **GraphRAG + LLM pipeline**
that generates Adversary Emulation Plans (AEPs) for cybersecurity red-team exercises.

This is part of a larger 5-phase research pipeline:
1. Data + ontology design
2. **KG construction ← current phase**
3. Adversary subgraphs + GraphRAG retrieval
4. LLM plan generation (GPT-4o mini) + graph-based validation
5. Execution via CALDERA/Atomic Red Team + telemetry feedback loop

---

## KG Construction Steps (My Defined Scope)

| Step   | Source                                          | Method                                      | Status     |
|--------|-------------------------------------------------|---------------------------------------------|------------|
| 1.5.1a | MITRE ATT&CK STIX (github.com/mitre/cti)        | Python stix2 — LockBit 2.0 (S1199) & 3.0 (S1202) → Neo4j | ✅ DONE |
| 1.5.1b | ATT&CK Evaluations 2024 LockBit emulation plan  | Parse phases/steps → EmulationStep nodes linked to Technique nodes | ⏳ NEXT |
| 1.5.3  | Vendor reports — MITRE, DFIR Sophos, Kaspersky, Picus | LLM prompt (GPT-4o mini) → JSON triples → upsert with provenance | ⏳ PENDING |
| 1.5.4  | IEEE 2025 "Inside LockBit" paper                | Manual CSV extraction → LOAD CSV Cypher, version-tagged nodes | ⏳ PENDING |

**NOTE: Step 1.5.2 (Government advisories — CISA, FBI IC3, ACSC) has been removed from the project.**

---

## Infrastructure

### Local Computer (Windows — PowerShell)
- **Neo4j** runs via Docker: `localhost:7474` (browser), `localhost:7687` (Bolt)
- Credentials: username `neo4j`, password `LockBit2025!`
- Neo4j Browser: `http://localhost:7474`
- Docker run command used:
```bash
docker run --name lockbit-kg -p 7474:7474 -p 7687:7687 -d \
  --volume=$HOME/neo4j/data:/data \
  --volume=$HOME/neo4j/logs:/logs \
  --volume=$HOME/neo4j/import:/var/lib/neo4j/import \
  -e NEO4J_AUTH=neo4j/LockBit2025! \
  -e NEO4J_PLUGINS='["apoc"]' \
  neo4j:community
```

### AI-LAB (AAU HPC — for heavy tasks)
- URL: https://hpc.aau.dk/ai-lab/
- Login: `ssh ua40oj@student.aau.dk@ailab-fe01.srv.aau.dk`
- Job scheduler: **Slurm** (`sbatch`, `squeue --me`)
- Containers: **Singularity** — Python container at `/ceph/container/python/python_3.10.sif`
- Project folder: `/ceph/project/KGLLM/lockbit-KG/`
- Virtual env (packages): `/ceph/project/KGLLM/my_venv/`
- Slurm template: `/ceph/project/KGLLM/run_job.sh`

### Project Folder Structure on AI-LAB
```
/ceph/project/KGLLM/
├── run_job.sh                  ← Slurm template (one level above project)
├── my_venv/                    ← Python packages (shared venv)
└── lockbit-KG/
    ├── scripts/                ← all Python scripts
    ├── data/                   ← raw PDFs, CSVs, STIX files
    ├── outputs/                ← processed JSON results
    └── logs/                   ← Slurm job logs (%j.out / %j.err)
```

### Slurm Job Template (`/ceph/project/KGLLM/run_job.sh`)
```bash
#!/bin/bash
#SBATCH --job-name=lockbit-kg
#SBATCH --output=/ceph/project/KGLLM/lockbit-KG/logs/%j.out
#SBATCH --error=/ceph/project/KGLLM/lockbit-KG/logs/%j.err
#SBATCH --mem=16G
#SBATCH --cpus-per-task=4
#SBATCH --time=02:00:00

export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASS="LockBit2025!"
export OPENAI_API_KEY="your-openai-key-here"

srun singularity exec \
    -B /ceph/project/KGLLM:/ceph/project/KGLLM \
    /ceph/container/python/python_3.10.sif \
    /bin/bash -c "source /ceph/project/KGLLM/my_venv/bin/activate && \
    python3 /ceph/project/KGLLM/lockbit-KG/scripts/SCRIPT_NAME.py"
```

---

## Two-Stage Script Pattern (IMPORTANT)

AI-LAB **cannot connect to local Neo4j**. All scripts follow this pattern:

- **`--stage extract`** → runs on AI-LAB via Slurm: downloads/processes data, saves to JSON in `/outputs/`
- **`--stage load`** → runs locally: reads JSON file, loads into Neo4j

File transfer between AI-LAB and local:
```bash
# Download from AI-LAB to local
scp ua40oj@student.aau.dk@ailab-fe01.srv.aau.dk:/ceph/project/KGLLM/lockbit-KG/outputs/FILE.json .

# Upload script to AI-LAB
scp script.py ua40oj@student.aau.dk@ailab-fe01.srv.aau.dk:/ceph/project/KGLLM/lockbit-KG/scripts/
```

---

## Installed Python Packages
Installed in `/ceph/project/KGLLM/my_venv/` on AI-LAB and locally:
- `neo4j` — Neo4j Python driver
- `stix2` — STIX bundle parsing
- `requests` — HTTP downloads
- `pdfplumber` — PDF table extraction
- `openai` — GPT-4o mini API
- `spacy` — NLP

---

## Neo4j Schema (Constraints Already Created)

```cypher
CREATE CONSTRAINT IF NOT EXISTS FOR (n:ThreatActor)    REQUIRE n.stix_id   IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Technique)      REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:SubTechnique)   REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Software)       REQUIRE n.stix_id   IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Campaign)       REQUIRE n.stix_id   IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:EmulationStep)  REQUIRE n.step_id   IS UNIQUE;
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Procedure)      REQUIRE n.proc_id   IS UNIQUE;
```

### Node Types in Use
| Label | Description | Example |
|---|---|---|
| `Malware` | LockBit software variants | LockBit 2.0 (S1199), LockBit 3.0 (S1202) |
| `Technique` | ATT&CK techniques | T1486 Data Encrypted for Impact |
| `SubTechnique` | ATT&CK sub-techniques | T1059.001 PowerShell |
| `ThreatActor` | Groups that used LockBit | LockBit affiliate groups |
| `Campaign` | Specific intrusion campaigns | — |
| `EmulationStep` | Steps from ATT&CK Evaluations plan | Phase 1 Step 2 |
| `Procedure` | Specific observed behaviors from CTI | From vendor reports |

### Key Relationships
- `(Malware)-[:USES]->(Technique)`
- `(ThreatActor)-[:USES]->(Malware)`
- `(EmulationStep)-[:IMPLEMENTS]->(Technique)`
- `(Procedure)-[:IMPLEMENTS]->(Technique)`
- All relationships include provenance: `source`, `source_url`, `confidence`

---

## What Is Currently in Neo4j (After Step 1.5.1a)

- **Malware nodes**: LockBit 2.0 (S1199), LockBit 3.0 (S1202)
- **Technique/SubTechnique nodes**: ~50-60 nodes linked to LockBit
- **ThreatActor nodes**: Groups that used LockBit (from STIX relationships)
- **Relationships**: ~60 USES relationships with provenance metadata
- **Source**: All tagged with `source = 'MITRE ATT&CK STIX'`, `source_url = 'https://github.com/mitre/cti'`

---

## Completed Script — stix_ingest.py (Step 1.5.1a)

Key points about the working script:
- Downloads full ATT&CK enterprise bundle from `github.com/mitre/cti`
- Finds LockBit by searching for `type=malware` with `external_id` in `{S1199, S1202}`
- **Do NOT use G0125** — that is HAFNIUM, a different group entirely
- Collects all linked techniques, groups, campaigns via relationships (both directions)
- Stage extract saves `lockbit_stix.json`; stage load upserts into Neo4j using `MERGE`

---

## What Needs to Be Built Next

### Step 1.5.1b — ATT&CK Evaluations 2024 LockBit Emulation Plan
- **Source**: https://attackevals.mitre-engenuity.org/ (LockBit 2024 evaluation)
- **GitHub**: https://github.com/center-for-threat-informed-defense/attack-evals
- **Goal**: Parse each emulation phase and step → create `EmulationStep` nodes
- **Neo4j relationship**: `(EmulationStep)-[:IMPLEMENTS]->(Technique)`
- **Properties needed on EmulationStep**: `step_id`, `name`, `phase`, `description`, `technique_ref`, `source_url`, `date`
- **Same two-stage pattern**: extract on AI-LAB → load locally

### Step 1.5.3 — Vendor Report NLP Extraction
- **Sources**: MITRE, DFIR Sophos, Kaspersky, Picus LockBit reports (PDFs)
- **Method**: LLM prompt (GPT-4o mini) → extract JSON triples → upsert as `Procedure` nodes
- **Neo4j**: `(Procedure)-[:IMPLEMENTS]->(Technique)` with provenance metadata
- **Properties**: `source_url`, `date`, `confidence_score`
- **Runs on AI-LAB** (heavy — multiple PDF API calls)

### Step 1.5.4 — IEEE 2025 "Inside LockBit" Paper
- **Source**: IEEE 2025 paper "Inside LockBit" — manually extracted TTP table as CSV
- **Method**: `LOAD CSV` Cypher bulk import
- **Key value**: Version-differentiated technique nodes tagged with `lockbit_version` property
- **Runs locally** (simple CSV load, seconds)

---

## Coding Conventions to Follow

1. Always use **environment variables** for Neo4j credentials:
   ```python
   NEO4J_URI  = os.getenv("NEO4J_URI",  "bolt://localhost:7687")
   NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
   NEO4J_PASS = os.getenv("NEO4J_PASS", "LockBit2025!")
   ```

2. Always use `MERGE` (not `CREATE`) in Cypher — safe to re-run without duplicates

3. Always add provenance to every node and relationship:
   ```python
   "source":     "source name string",
   "source_url": "https://...",
   "confidence": 1.0   # float 0.0-1.0
   ```

4. Follow the **two-stage pattern**: `--stage extract` for AI-LAB, `--stage load` for local

5. Scripts go in `/ceph/project/KGLLM/lockbit-KG/scripts/`
   Outputs (JSON) go in `/ceph/project/KGLLM/lockbit-KG/outputs/`

---

## Important Lessons Learned (Avoid These Mistakes)

1. **LockBit is NOT a group in ATT&CK** — it is software. Use `S1199` and `S1202`, never `G0125`
2. **Nested break loops in Python are dangerous** — use a dedicated function with `return` to find objects
3. **AI-LAB cannot reach localhost:7687** — always split into extract/load stages
4. **`pip` is not available directly on AI-LAB** — use `python3 -m pip` inside Singularity container
5. **Singularity bind mount**: use `-B /ceph/project/KGLLM:/ceph/project/KGLLM` to expose the full project path inside the container

