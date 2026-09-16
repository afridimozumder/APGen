# APGen: Adversary Plan Generation with Knowledge Graphs and LLM

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

**Part 1 — Knowledge Graph (Phase A): built.** Two sources are ingested: MITRE ATT&CK STIX
(LockBit 2.0 / `S1199` and LockBit 3.0 / `S1202`) and CISA advisory AA23-165A. Together
they cover the kill chain from initial access to impact, with 14 techniques independently
attested by both. Techniques are annotated with authored preconditions/effects
(`scripts/attack_state.py`), validated by replaying them over MITRE's ordered ER6 LockBit
plan, which is also loaded as the reference spine for Part 3. Further sources will be added
incrementally.

**Part 2 — Plan generation (Phases B and C): end-to-end and producing plans.** The full
pipeline runs: retrieve a version/platform subgraph (§5) → generate a structured plan via
OpenRouter (§6) → validate it against that subgraph on grounding, tactic labelling,
preconditions and kill-chain order → refine on failure → batch both arms into a matched
dataset (§7). A first full batch (`openai/gpt-4o-mini`, 4 scenarios × 3 replicates × 2 arms
= 24 plans) completed and is analysed:

- **Grounding works.** Mean invented techniques per plan: **4.5 baseline vs 0.08 grounded**;
  12/12 baseline plans contain at least one hallucinated technique, against 1/12 grounded.
- **Validity alone is not a quality score.** Grounded plans reach 83% valid vs 0% baseline,
  but the two arms fail in opposite directions: baseline plans are complete yet always
  invalid, while grounded plans are usually valid yet mostly hollow — only 3/12 reach both
  encryption and exfiltration. The validator checks for the *absence* of errors, so a short
  plan passes by having nothing to flag, and the refinement loop can raise validity by
  dropping the offending step.

Open before Part 3: add a completeness metric (ER6 technique coverage plus an
objective-reached flag) alongside validity, and re-run against a stronger model. The
existing dataset is kept as-is rather than regenerated.

---

## Repository layout

```
APGen/
├── scripts/
│   ├── attack_tactics.py       shared ATT&CK tactic vocabulary and kill-chain ordering
│   ├── attack_state.py         authored precondition/effect state model
│   ├── stix_ingest.py          two-stage MITRE ATT&CK STIX → Neo4j ingester
│   ├── cisa_ingest.py          two-stage CISA advisory AA23-165A → Neo4j ingester
│   ├── state_annotate.py       annotate preconditions/effects + load MITRE Evals spine
│   ├── graphrag_retrieve.py    GraphRAG retrieval — KG subgraph → prompt context
│   ├── graphrag_generate.py    plan generation (KG-grounded + naked baseline) + refinement loop
│   ├── graphrag_validate.py    graph validator — grounding, preconditions, kill-chain order
│   └── graphrag_batch.py       batch: matched baseline + grounded plans → manifest
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

`.env` is loaded automatically at startup and is gitignored. Real environment variables
take precedence over it, so an HPC job or CI run can override without editing the file.
There is no built-in default password: any `--stage load` exits with an explanatory
message when `NEO4J_PASS` is unset. The `--stage extract` stages need no credentials at
all, which is what lets them run on a compute cluster with no access to Neo4j.

### 3. Run Neo4j locally (Docker)

```bash
docker run --name apgen-neo4j -p 7474:7474 -p 7687:7687 -d \
  -v $HOME/neo4j/data:/data \
  -e NEO4J_AUTH=neo4j/<your-password> \
  -e NEO4J_PLUGINS='["apoc"]' \
  neo4j:community
```

Neo4j Browser: <http://localhost:7474> · Bolt: `bolt://localhost:7687`.

### 4. Run the ingestion (Steps 1.5.1a and 1.5.1b)

Both ingesters follow a two-stage pattern: a heavy `extract` stage that can run on a
compute cluster without Neo4j access, and a light `load` stage that runs locally against
Neo4j. **Order matters** — the two sources exchange information, so run them as below.

```powershell
# 1. Extract the CISA advisory first: the STIX extract needs the technique IDs it names
python scripts/cisa_ingest.py --stage extract --output outputs/cisa_lockbit.json

# 2. Extract the ATT&CK bundle, pulling platform data for the techniques CISA named
python scripts/stix_ingest.py --stage extract --output outputs/lockbit_stix.json     --enrich outputs/cisa_lockbit.json

# 3. Load MITRE (idempotent; uses MERGE throughout)
python scripts/stix_ingest.py --stage load --input outputs/lockbit_stix.json

# 4. Load CISA, translating ATT&CK IDs MITRE has since renumbered
python scripts/cisa_ingest.py --stage load --input outputs/cisa_lockbit.json     --aliases outputs/lockbit_stix.json
```

Then annotate the graph with preconditions/effects and load the reference plan:

```powershell
# 5. Parse MITRE ATT&CK Evaluations ER6 LockBit plan (the ordered reference)
python scripts/state_annotate.py --stage extract --output outputs/evals_lockbit.json

# 6. Annotate every technique with preconditions/effects and load the reference
#    spine. Refuses to run if the state rules cannot reproduce the MITRE plan.
python scripts/state_annotate.py --stage load --input outputs/evals_lockbit.json
```

Preconditions and effects are an authored model (`scripts/attack_state.py`): a small
set of attacker states and a per-tactic rule for what each tactic requires and
produces. No CTI source publishes these, so the model is validated by replaying it
over MITRE's published, ordered ER6 LockBit plan — every step's preconditions must be
met by the effects of prior steps. That plan is also loaded as 8 ordered
`EmulationStep` nodes, serving as the gold-standard reference for Part 3.

Why the cross-references:

- `--enrich` lets the STIX extract fetch `x_mitre_platforms` for techniques only CISA
  attributes to LockBit. Without it those techniques have no platform data and are
  silently dropped by any environment filter. They are pulled for their definition only:
  they gain no `USES` edge and are not added to `sources`, because MITRE does not
  attribute them to LockBit.
- `--aliases` maps ATT&CK IDs that were current when the advisory was published to the
  IDs MITRE uses today (e.g. `T1562.001` → `T1685`). Without it the same technique enters
  the graph twice under two IDs and appears twice in a generated plan.

Output: `Malware` nodes for the LockBit variants, a `ThreatActor` node for affiliates,
`Technique` / `SubTechnique` nodes ordered along the kill chain by `tactic_order` and
filterable by `platforms`, `Tool` nodes linked by `IMPLEMENTS`, and provenance-tagged
`USES` relationships. Every node and relationship carries `source`, `source_url` and
`confidence`; techniques additionally carry a `sources` list recording every source that
attributes them to LockBit.

### 5. Retrieve an emulation subgraph (Part 2, Phase B)

With the graph populated, `graphrag_retrieve.py` returns the LockBit-specific slice an LLM
is allowed to see: techniques grouped into ATT&CK kill-chain phases, each carrying its
preconditions, effects, tools and sources. It only *reads* Neo4j, so it runs locally and
needs no `extract`/`load` split.

```powershell
# Phase summary, plus the JSON the generator will consume
python scripts/graphrag_retrieve.py --version 3.0 --platform Windows --out outputs/subgraph_3.0_windows.json

# The same subgraph rendered as a prompt-context block
python scripts/graphrag_retrieve.py --version 3.0 --objective "encrypt files and exfiltrate data" --print-prompt
```

A technique is included when MITRE attributes it to the requested payload (`S1199` /
`S1202`) **or** when CISA AA23-165A attributes it to LockBit affiliates. The MITRE leg is
version-specific; the CISA leg is not, because the advisory describes affiliate tradecraft
rather than one payload build. Techniques ingested only for their platform data carry no
`USES` edge and are therefore excluded.

The `EmulationStep` reference chain is deliberately never retrieved: it is MITRE's own
published plan and serves as Part 3's ground truth, so putting it in the generation context
would be teaching to the test.

### 6. Generate an emulation plan (Part 2, Phase C)

`graphrag_generate.py` prompts an LLM with a retrieved subgraph and parses a structured plan
back. Generation goes through **OpenRouter** (an OpenAI-compatible gateway), so the model is a
single env var and switching to a bigger model later is a config change, not a code change. It
writes nothing to Neo4j, so it runs locally and needs no `extract`/`load` split; it needs
`OPENROUTER_API_KEY` (in `.env` or the environment). The model defaults to
`openai/gpt-4o-mini` and can be overridden with `OPENROUTER_MODEL` — pick one that supports
structured outputs (`json_schema`), which the plan schema relies on.

```powershell
# From a saved retrieval dump (no Neo4j needed):
python scripts/graphrag_generate.py --subgraph outputs/subgraph_3.0_windows.json `
    --objective "encrypt files and exfiltrate data" `
    --out outputs/plans/lockbit_3.0_windows_001.json

# Or retrieving live in one shot:
python scripts/graphrag_generate.py --version 3.0 --platform Windows `
    --objective "encrypt files and exfiltrate data"
```

The prompt constrains the model to use **only** the techniques in the retrieved context;
after generation the tool reports any `ungrounded_techniques` — plan steps whose technique
was not in that context.

Add `--refine` to validate each plan and re-prompt with feedback when it fails, up to
`--max-attempts` (default 3):

```powershell
python scripts/graphrag_generate.py --subgraph outputs/subgraph_3.0_windows.json `
    --objective "encrypt files and exfiltrate data" --refine `
    --out outputs/plans/lockbit_3.0_windows_001.json
```

The validator (`graphrag_validate.py`) checks four things against the retrieved subgraph:
**grounding** (no hallucinated techniques; environment fit follows, since the subgraph was
already platform-filtered), **tactic labelling** (a step's phase must be a tactic the KG
actually records for that technique — so a plan can't dodge a gate by mislabelling a step),
**precondition satisfaction** (each step's preconditions, derived from the authoritative
`attack_state` model — not from the plan's self-reported fields — must be established by
earlier steps), and **kill-chain ordering** (phases in non-decreasing ATT&CK order). A saved
refined plan records its validation report and how many attempts it took.

### 7. Batch-generate the evaluation dataset (Part 2, Phase C)

`graphrag_batch.py` produces the matched dataset Part 3 evaluates: for each scenario
(LockBit 2.0/3.0 × Windows AD/endpoint) and each replicate, a **baseline** plan (naked LLM,
no KG context — the control) and a **KG-grounded** plan (with the refinement loop), both
validated against the same subgraph. It needs Neo4j up and `OPENROUTER_API_KEY` set.

```powershell
# Smoke run first — one scenario, one pair:
python scripts/graphrag_batch.py --limit 1 --replicates 1

# Full run: 4 scenarios × 3 replicates × 2 arms = 24 plans:
python scripts/graphrag_batch.py
```

Each plan is written to `outputs/plans/`, with a `batch_manifest.json` recording every plan's
verdict and a grounded-vs-baseline summary — the first look at the RQ2 result. Re-running
skips plans that already exist (use `--overwrite` to regenerate), so an interrupted batch
resumes without re-spending. The grounded arm's single-shot (pre-refinement) verdict is
recorded too, so the effect of grounding can be separated from the effect of refinement.

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
  `NEO4J_PASS`, `OPENROUTER_API_KEY`); never hard-coded.

---

## License

MIT — see [`LICENSE`](LICENSE).
