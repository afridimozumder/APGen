#!/usr/bin/env python3
"""
Part 2, Phase C — batch generation of the matched plan dataset for Part 3.

For each scenario (LockBit version × environment) and each replicate, generate a
matched pair:
  * grounded — KG-grounded + refinement loop (graphrag_generate.refine_plan)
  * baseline — naked LLM, no KG context (graphrag_generate.generate_baseline_plan)

Both are validated against the SAME retrieved subgraph, so the hallucination /
precondition / ordering comparison is apples-to-apples. A manifest records every
plan plus a grounded-vs-baseline summary — the first look at the RQ2 result. The
grounded arm's single-shot (pre-refinement) verdict is captured for free from the
refinement history, so Part 3 can separate the effect of grounding from the effect
of refinement.

Runs locally: retrieves subgraphs from Neo4j (once per version) and calls the
model via OpenRouter. Needs Neo4j up and OPENROUTER_API_KEY set.

Usage:
  python3 graphrag_batch.py --limit 1 --replicates 1     # smoke run (1 pair)
  python3 graphrag_batch.py                               # full 4×3 = 24 plans
"""

import os
import sys
import json
import argparse
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from graphrag_retrieve import EmulationRequest, retrieve
from graphrag_generate import (
    refine_plan, generate_baseline_plan, build_document, save_plan, resolve_model, _client,
)
from graphrag_validate import validate_plan

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")


@dataclass(frozen=True)
class Scenario:
    version: str
    environment: str
    objective: str


# The 2×2 matrix. AD-vs-endpoint is NOT a retrieval filter (both are Windows) — the
# distinction lives in the environment label and the objective wording, per the
# earlier design decision.
SCENARIOS = [
    Scenario("2.0", "Windows AD",
             "encrypt files and exfiltrate data across a Windows Active Directory domain"),
    Scenario("2.0", "Windows endpoint",
             "encrypt files and exfiltrate data on a standalone Windows endpoint without a domain"),
    Scenario("3.0", "Windows AD",
             "encrypt files and exfiltrate data across a Windows Active Directory domain"),
    Scenario("3.0", "Windows endpoint",
             "encrypt files and exfiltrate data on a standalone Windows endpoint without a domain"),
]


# ─────────────────────────────────────────────
# Naming and manifest shaping (pure)
# ─────────────────────────────────────────────
def _env_slug(environment: str) -> str:
    return environment.lower().replace(" ", "-")


def plan_path(out_dir: str, scenario: Scenario, arm: str, replicate: int) -> str:
    return os.path.join(
        out_dir,
        f"lockbit{scenario.version}_{_env_slug(scenario.environment)}_{arm}_r{replicate:02d}.json")


def _report_counts(report) -> dict:
    return {
        "valid":                       report.valid,
        "technique_count":             report.technique_count,
        "ungrounded_count":            len(report.ungrounded_techniques),
        "mislabelled_count":           len(report.mislabelled_steps),
        "precondition_failures_count": len(report.precondition_failures),
        "ordering_violations_count":   len(report.ordering_violations),
    }


def _entry(scenario, arm, replicate, path, model, counts, attempts=None, singleshot=None):
    entry = {
        "arm":         arm,
        "version":     scenario.version,
        "environment": scenario.environment,
        "objective":   scenario.objective,
        "replicate":   replicate,
        "file":        os.path.basename(path),
        "model":       model,
        **counts,
    }
    if attempts is not None:
        entry["attempts"] = attempts
    if singleshot is not None:
        entry["singleshot_valid"] = singleshot.valid
        entry["singleshot_ungrounded_count"] = len(singleshot.ungrounded_techniques)
    return entry


def _entry_from_existing(scenario, arm, replicate, path, model) -> dict:
    """Rebuild a manifest entry from an already-saved plan (skip-if-exists path)."""
    with open(path, encoding="utf-8") as f:
        meta = json.load(f)["metadata"]
    v = meta.get("validation", {})
    counts = {
        "valid":                       v.get("valid"),
        "technique_count":             v.get("technique_count"),
        "ungrounded_count":            len(v.get("ungrounded_techniques", [])),
        "mislabelled_count":           len(v.get("mislabelled_steps", [])),
        "precondition_failures_count": len(v.get("precondition_failures", [])),
        "ordering_violations_count":   len(v.get("ordering_violations", [])),
    }
    entry = _entry(scenario, arm, replicate, path, meta.get("model", model), counts,
                   attempts=meta.get("attempts"))
    entry["reused"] = True
    return entry


# ─────────────────────────────────────────────
# Generation of one plan (grounded / baseline)
# ─────────────────────────────────────────────
def _subgraph_for(scenario: Scenario, cache: dict) -> dict:
    """Subgraph for a scenario: retrieved once per version, objective set per scenario."""
    if scenario.version not in cache:
        cache[scenario.version] = retrieve(
            EmulationRequest(version=scenario.version, platforms=("Windows",), objective=""))
    subgraph = dict(cache[scenario.version])          # shallow copy; phases list is shared, not mutated
    subgraph["objective"] = scenario.objective
    return subgraph


def _grounded(scenario, subgraph, replicate, out_dir, client, model, max_attempts, overwrite):
    path = plan_path(out_dir, scenario, "grounded", replicate)
    if os.path.exists(path) and not overwrite:
        return _entry_from_existing(scenario, "grounded", replicate, path, model)
    plan, report, history = refine_plan(subgraph, client=client, model=model,
                                        max_attempts=max_attempts)
    doc = build_document(plan, subgraph, history[-1]["usage"], model,
                         report=report, attempts=len(history))
    save_plan(doc, path)
    return _entry(scenario, "grounded", replicate, path, model, _report_counts(report),
                  attempts=len(history), singleshot=history[0]["report"])


def _baseline(scenario, subgraph, replicate, out_dir, client, model, overwrite):
    path = plan_path(out_dir, scenario, "baseline", replicate)
    if os.path.exists(path) and not overwrite:
        return _entry_from_existing(scenario, "baseline", replicate, path, model)
    result = generate_baseline_plan(scenario.version, scenario.environment, scenario.objective,
                                    client=client, model=model)
    report = validate_plan(result.plan, subgraph)     # scored against the SAME KG subgraph
    doc = build_document(result.plan, subgraph, result.usage, model, report=report, attempts=1)
    save_plan(doc, path)
    return _entry(scenario, "baseline", replicate, path, model, _report_counts(report), attempts=1)


# ─────────────────────────────────────────────
# Orchestration + summary
# ─────────────────────────────────────────────
def _rate(rows, key):
    rows = [e for e in rows if e.get(key) is not None]
    return round(sum(1 for e in rows if e[key]) / len(rows), 3) if rows else None


def _mean(rows, key):
    vals = [e[key] for e in rows if e.get(key) is not None]
    return round(sum(vals) / len(vals), 2) if vals else None


def summarise(entries: list) -> dict:
    grounded = [e for e in entries if e["arm"] == "grounded"]
    baseline = [e for e in entries if e["arm"] == "baseline"]
    singleshot = [e for e in grounded if "singleshot_valid" in e]
    return {
        "baseline": {"n": len(baseline), "valid_rate": _rate(baseline, "valid"),
                     "mean_ungrounded": _mean(baseline, "ungrounded_count")},
        "grounded_singleshot": {"n": len(singleshot),
                                "valid_rate": _rate(singleshot, "singleshot_valid")},
        "grounded": {"n": len(grounded), "valid_rate": _rate(grounded, "valid"),
                     "mean_ungrounded": _mean(grounded, "ungrounded_count")},
    }


def run_batch(scenarios, replicates=3, out_dir="outputs/plans", client=None, model=None,
              max_attempts=3, overwrite=False):
    """Generate the matched dataset and write a manifest. Returns (manifest, path)."""
    client = client or _client()
    model = model or resolve_model()
    cache, entries = {}, []
    for scenario in scenarios:
        subgraph = _subgraph_for(scenario, cache)
        for replicate in range(1, replicates + 1):
            entries.append(_grounded(scenario, subgraph, replicate, out_dir, client,
                                     model, max_attempts, overwrite))
            entries.append(_baseline(scenario, subgraph, replicate, out_dir, client,
                                     model, overwrite))
    manifest = {"model": model, "replicates": replicates,
                "summary": summarise(entries), "plans": entries}
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "batch_manifest.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest, path


def _print_summary(summary: dict) -> None:
    print("\n[summary] valid_rate higher is better; mean_ungrounded lower is better:")
    for arm in ("baseline", "grounded_singleshot", "grounded"):
        s = summary.get(arm, {})
        print(f"  {arm:20} n={str(s.get('n', '?')):<3} "
              f"valid_rate={s.get('valid_rate')}  mean_ungrounded={s.get('mean_ungrounded')}")


def main():
    parser = argparse.ArgumentParser(
        description="Batch-generate matched baseline + KG-grounded LockBit plans")
    parser.add_argument("--replicates", type=int, default=3, help="pairs per scenario (default 3)")
    parser.add_argument("--out-dir", default="outputs/plans", dest="out_dir")
    parser.add_argument("--max-attempts", type=int, default=3, dest="max_attempts",
                        help="max refinement attempts for the grounded arm (default 3)")
    parser.add_argument("--model", default=None, help="override OPENROUTER_MODEL")
    parser.add_argument("--limit", type=int, default=None, help="use only the first N scenarios")
    parser.add_argument("--overwrite", action="store_true", help="regenerate existing plans")
    args = parser.parse_args()
    if args.replicates < 1:
        parser.error("--replicates must be at least 1")
    if args.max_attempts < 1:
        parser.error("--max-attempts must be at least 1")

    scenarios = SCENARIOS[:args.limit] if args.limit else SCENARIOS
    model = args.model or resolve_model()
    total = len(scenarios) * args.replicates * 2
    print(f"[batch] {len(scenarios)} scenarios × {args.replicates} replicates × 2 arms "
          f"= {total} plans, model {model}")

    try:
        manifest, path = run_batch(scenarios, replicates=args.replicates, out_dir=args.out_dir,
                                   model=model, max_attempts=args.max_attempts,
                                   overwrite=args.overwrite)
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        from graphrag_generate import _explain
        raise SystemExit(_explain(exc))

    _print_summary(manifest["summary"])
    print(f"\n✅ {len(manifest['plans'])} plans + manifest at {path}")


if __name__ == "__main__":
    main()
