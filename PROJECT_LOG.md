# Project Log

Short running record of what was done and why. Newest entry first.
Not a plan — see `Project_Plan.md` for that. This is just "what happened, and why I did it".

---

## 2026-09-10 — Added the CISA advisory as a second source

**What I did:** Wrote `scripts/cisa_ingest.py` to pull CISA advisory AA23-165A
("Understanding Ransomware Threat Actors: LockBit") into the graph. Added 39 techniques,
31 tools, and a `LockBit affiliates` actor node.

**Why:** The MITRE data only describes LockBit the *malware*, so the graph had no
credential-access, collection, or exfiltration steps at all. An emulation plan can't
skip stealing data — that's the whole point of LockBit's double-extortion. The advisory
covers what the *affiliates* do end to end, so it fills those three gaps.

**Also from this:**
- Techniques now record a `sources` list, so 12 of them are confirmed by both MITRE and
  CISA. Before this, `confidence` was meaningless because everything came from one source.
- New `Tool` nodes (Mimikatz, Rclone, MegaSync, AnyDesk, and 27 more) linked to the
  techniques they carry out. This is what makes a plan actually runnable instead of just
  a list of technique IDs.
- Moved the tactic ordering table into `scripts/attack_tactics.py` so both ingest scripts
  share one copy instead of drifting apart.

**Result:** Kill chain is complete for the first time — initial access all the way through
to impact, with nothing missing in the middle.

---

## 2026-09-10 — Fixed console crash and missing confidence values

**What I did:** Forced UTF-8 output at the top of `stix_ingest.py`, and added
`confidence = 1.0` to every node.

**Why:** The script crashed on Windows because the console couldn't print the ✅ symbols,
so it only ran if I set an environment variable by hand. Separately, while reviewing the
code I noticed no node had a `confidence` value even though my own project rules say every
node and relationship must have one. Relationships had it; all 42 nodes didn't.

---

## 2026-09-10 — Captured platforms and kill-chain order

**What I did:** Changed `stix_ingest.py` to save two extra things on each technique:
which operating systems it applies to (`platforms`) and where it sits in the attack
sequence (`tactic_order`).

**Why:** I checked what the graph could actually support and found it couldn't order steps
or filter by target environment — both needed for Part 2. Turned out the data was already
sitting in the downloaded file; the loading code was just throwing it away. So this was a
re-ingest, not new research.

**Note:** the tactic names in current MITRE data are `stealth` and `defense-impairment`
rather than the older `defense-evasion`. The ordering table treats them as the same stage
so both spellings sort correctly.

---

## 2026-09-10 — Checked whether the graph was good enough for Part 2

**What I did:** Queried the live graph and compared it against what the Part 2 plan
generator needs.

**Why:** Before building anything on top of the graph, I wanted to know if it was actually
strong enough. Findings: it had 2 malware nodes, 40 techniques and 60 relationships, all
from one source — enough to list techniques, but missing environment info, step ordering,
and three whole stages of the kill chain. This check is what set up everything below.

---

## 2026-05-19 — Built the LockBit knowledge graph (Part 1 start)

**What I did:**
- Set up Neo4j in Docker locally (`bolt://localhost:7687`, browser at `localhost:7474`).
- Wrote `scripts/stix_ingest.py` — downloads the MITRE ATT&CK STIX bundle, keeps only the
  LockBit parts, and loads them into Neo4j.
- Loaded LockBit 2.0 (S1199) and LockBit 3.0 (S1202) with the 40 techniques MITRE links
  to them.
- Added a public README, a `.env` template, and a `.gitignore` that keeps secrets, raw
  data, and private notes out of the repo.

**Why:** This is the foundation for the whole thesis. Everything in Part 2 (generating
emulation plans) and Part 3 (evaluating them) reads from this graph.

**Two rules I set here and have to keep following:**
1. Every ingest script is split into `--stage extract` (runs on the HPC, saves a JSON file)
   and `--stage load` (runs on my laptop, writes to Neo4j). The HPC cannot reach my local
   database, so they can never be one step.
2. Always `MERGE`, never `CREATE`, so re-running a script is safe.

**Worth remembering:** in MITRE ATT&CK, LockBit is tracked as *software*, not as a group.
`G0125` is HAFNIUM and has nothing to do with LockBit.
