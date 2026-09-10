# Project Log

Short running record of what was done and why. Newest entry first.
Not a plan — see `Project_Plan.md` for that. This is just "what happened, and why I did it".

---

## 2026-09-10 — Added preconditions and effects (the validation groundwork)

**What I did:** Gave every technique a set of *preconditions* (what an attacker
must already have to run it) and *effects* (what running it gives them), and loaded
MITRE's own published LockBit plan as an ordered reference chain.

**Why:** This is the piece Part 2's plan validator and Part 3's "precondition
satisfaction rate" metric are built on. Without it, we can list techniques but can't
check whether a generated plan's steps are in a *possible* order — e.g. it can't
catch a plan that exfiltrates data before opening a command-and-control channel, or
encrypts before gaining admin.

**The hard part / the honest bit:** no CTI source publishes preconditions or effects.
They have to be authored, and that authored logic is exactly what later judges whether
the LLM's plans are valid. So the method matters:

- I wrote a small, transparent **state model** (`scripts/attack_state.py`): a handful
  of attacker states (foothold, credentials, elevated, c2, data staged/exfiltrated,
  impact) and a plain rule for each ATT&CK tactic saying what it needs and what it
  produces. It's deterministic rules I can defend line by line, not something an LLM
  made up.
- To check the rules aren't nonsense, I replay them over the **MITRE ATT&CK
  Evaluations ER6 LockBit plan** — a real, published, ordered attack plan. If our
  rules can reproduce MITRE's own plan with every step's preconditions satisfied by
  the earlier steps, the rules hold up. They do: the check passes with zero failures.
  If someone later changes the rules and breaks them, the load stage refuses to run.

**Also from this:**
- That MITRE plan is now in the graph as 8 ordered `EmulationStep` nodes (linked
  `NEXT` → `NEXT`), each tied to the techniques it performs. This doubles as the
  gold-standard reference plan Part 3 needs to compare generated plans against.
- The plan names 45 techniques; 26 are already in our graph and got linked. The other
  19 were left out on purpose — adding them is a separate scope decision, not part of
  this step.

**Result:** All 65 techniques carry preconditions/effects; the ordered MITRE reference
plan is loaded; provenance is still complete on every node and relationship. Part 2 can
now be built on top of this.

**Scope note:** Before this I had added the CISA advisory, which `CLAUDE.md` had listed
as removed scope. I discussed it and we decided to keep it (it's the only source for the
exfiltration/credential stages) and I updated the rule in `CLAUDE.md` to match. How the
CISA data is used specifically for *validation* in Part 3 is still open — parked for
later so we don't accidentally validate an LLM against LLM-derived data.

---

## 2026-09-10 — Filled in missing platform data, and merged two duplicated techniques

**What I did:** Two fixes to the ingest scripts, found by looking at the graph in the
browser after the CISA load.

### Fix 1 — techniques with no operating system attached

**The problem:** filtering a plan by `'Windows' IN t.platforms` silently deleted every
credential-access, collection and exfiltration step. Not because those steps are
non-Windows, but because we had *no platform information for them at all*, and an empty
list matches nothing.

**Why it happened:** platform data comes from MITRE's `x_mitre_platforms` field. CISA's
advisory doesn't publish platforms, so the 27 techniques that came only from CISA had none.
The stages I had just added were exactly the ones being dropped.

**The fix:** `stix_ingest.py --stage extract` now takes an optional `--enrich` argument
pointing at the CISA extract. Any technique CISA names is also pulled from the MITRE
catalogue, purely for its platform data.

**Important detail:** those techniques do *not* get added to the `sources` list and get no
`USES` relationship. `sources` records *who says LockBit uses this technique*, and MITRE
doesn't say that — it only defines what the technique is. Mixing the two would have
inflated my corroboration count with a number that means nothing.

### Fix 2 — the same technique stored twice under two different IDs

**The problem:** `T1562.001` and `T1685` were sitting in the graph as two separate nodes.
They are the same technique. All 8 tools were attached to one of them and none to the
other.

**Why it happened:** CISA's advisory is from June 2023 and was written against ATT&CK v13.
MITRE has since renumbered that technique (and one other). Advisories are never reissued,
so the old numbers are frozen in the text forever. A generated plan would have listed the
same step twice.

**The fix:** the extract stage now follows MITRE's own `revoked-by` records to map old IDs
to current ones, and the CISA loader applies that map *before* writing anything, so the
outdated ID never becomes a node in the first place. The original number is kept on the
node as `superseded_ids` so I can still trace back to what the advisory printed.

**Result:**
- 0 techniques without platform data (was 27). A Windows filter now keeps every stage.
- Corroborated techniques went from 12 to 14 — the two duplicates were hiding real
  agreement between the sources.
- Had to delete the 2 stale nodes by hand once; everything else was rebuilt from the saved
  JSON files.

**Lesson worth keeping:** when two sources are written years apart, their technique IDs
will drift. Any future source needs the same alias treatment.

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
