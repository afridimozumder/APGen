#!/usr/bin/env python3
"""
Part 2, Phase C (slice 1) — KG-grounded emulation plan generator.

Turns the LockBit subgraph produced by graphrag_retrieve into one Adversary
Emulation Plan by prompting Claude and parsing structured JSON back. This is the
first half of RQ2 ("can the KG be used to generate a plan") for a single scenario.

WHAT THIS IS NOT: the graph-based validator, the refinement loop, the naked-LLM
baseline, and batch generation are separate later slices. `ungrounded_techniques`
here is a lightweight *signal* — it reports plan steps whose technique_id was not
in the context the model was given — not the validator, which additionally checks
precondition order, tactic ordering and environment fit.

WHY NO --stage extract / --stage load: that rule exists because the HPC cannot
reach the local Neo4j when *writing*. Generation reads the subgraph (locally, or
from a saved dump) and calls the Claude API; it writes nothing to Neo4j, and it
runs locally, so the two-stage split does not apply.

GROUNDING: the whole point is that the model may use ONLY the techniques handed
to it. That constraint is stated in the prompt (build_prompt) and measured after
the fact (ungrounded_techniques). Structured outputs guarantee the shape of the
plan; the prompt + the grounding check guard its content.

Usage:
  # From a saved retrieval dump (no Neo4j needed):
  python3 graphrag_generate.py --subgraph outputs/subgraph_3.0_windows.json \
      --objective "encrypt files and exfiltrate data" \
      --out outputs/plans/lockbit_3.0_windows_001.json

  # Retrieving live from Neo4j in one shot:
  python3 graphrag_generate.py --version 3.0 --platform Windows \
      --objective "encrypt files and exfiltrate data"

Requires ANTHROPIC_API_KEY in the environment (or .env); the SDK reads it.
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from graphrag_retrieve import (
    EmulationRequest, retrieve, to_prompt_text, SOFTWARE_ID,
)

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
# Default per the claude-api skill; override with ANTHROPIC_MODEL for a cheaper
# model (e.g. claude-sonnet-5) without touching code.
MODEL = "claude-opus-5"
# Adaptive thinking is enabled in generate_plan, and thinking tokens count against
# this cap — a 60-technique plan plus its reasoning does not reliably fit in 8k.
# 16k matches the SDK's non-streaming guidance; _ensure_plan reports a truncated
# response instead of letting it surface as a confusing NoneType error later.
MAX_TOKENS = 16000


def resolve_model() -> str:
    return os.getenv("ANTHROPIC_MODEL", MODEL)


# ─────────────────────────────────────────────
# PLAN SCHEMA (Pydantic → strict JSON schema for structured outputs)
# ─────────────────────────────────────────────
# extra="forbid" renders additionalProperties:false, and every field is required
# (no defaults), which is what structured outputs needs to guarantee validity.
# The shape mirrors the retrieval output so the model reorganises and narrates
# rather than invents.
class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")
    step_id: int
    technique_id: str
    technique_name: str
    description: str
    preconditions: list[str]
    effects: list[str]
    tools: list[str]


class Phase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tactic: str
    steps: list[Step]


class EmulationPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    adversary: str
    software_id: str
    environment: str
    objective: str
    phases: list[Phase]


# ─────────────────────────────────────────────
# PROMPT (pure)
# ─────────────────────────────────────────────
SYSTEM_PROMPT = (
    "You are an adversary emulation planner producing plans for an authorized "
    "lab/sandbox exercise. You MUST use ONLY the ATT&CK techniques provided in the "
    "context. Do not invent, substitute, or add techniques that are not listed — "
    "every step's technique_id must appear verbatim in the context. Preserve each "
    "technique's preconditions and effects as given. Order the phases along the "
    "ATT&CK kill chain, from initial access through to impact. Write a concise, "
    "operational description for each step, grounded in the procedures in the context."
)


def build_prompt(subgraph: dict, feedback: str = None) -> tuple:
    """
    (system, user) messages for a subgraph. Pure — no API, no I/O.

    When `feedback` is given (a refinement retry), it is appended so the model
    sees exactly what was wrong with its previous attempt.
    """
    user = (
        f"Adversary: {subgraph['adversary']} ({subgraph['software_id']})\n"
        f"Target environment: {', '.join(subgraph['platforms'])}\n"
        f"Objective: {subgraph['objective'] or 'emulate a representative LockBit intrusion'}\n"
        "\n"
        "CONTEXT (retrieved from the knowledge graph — the ONLY techniques you may use):\n"
        f"{to_prompt_text(subgraph)}\n"
        "\n"
        "Produce the emulation plan as structured JSON. Every step's technique_id must be "
        "one of the technique IDs above, and phases must follow the ATT&CK kill-chain order."
    )
    if feedback:
        user += f"\n\n{feedback}"
    return SYSTEM_PROMPT, user


# ─────────────────────────────────────────────
# GROUNDING SIGNAL (pure — NOT the validator)
# ─────────────────────────────────────────────
def subgraph_technique_ids(subgraph: dict) -> set:
    return {t["attack_id"] for p in subgraph["phases"] for t in p["techniques"]}


def plan_technique_ids(plan: EmulationPlan) -> set:
    return {s.technique_id for p in plan.phases for s in p.steps}


def ungrounded_techniques(plan: EmulationPlan, subgraph: dict) -> list:
    """
    Plan technique_ids that were NOT in the context handed to the model.

    A grounding signal only: a non-empty result means the model used a technique
    it was not given, which is exactly the hallucination the KG grounding is meant
    to prevent. This does not check precondition order, tactic ordering, or
    environment fit — that is the separate validator slice.
    """
    return sorted(plan_technique_ids(plan) - subgraph_technique_ids(subgraph))


# ─────────────────────────────────────────────
# GENERATION (the only part that calls the API)
# ─────────────────────────────────────────────
def generate_plan(subgraph: dict, client=None, model=None, feedback=None):
    """
    Generate a plan from a subgraph. Returns the raw API response, which carries
    `.parsed_output` (a validated EmulationPlan) and `.usage`.

    `client` is injectable so tests can pass a stub without hitting the API or
    needing a key. When omitted, a real Anthropic client is constructed (which
    requires ANTHROPIC_API_KEY). `feedback` is threaded into the prompt on a
    refinement retry.
    """
    if client is None:
        import anthropic
        client = anthropic.Anthropic()
    system, user = build_prompt(subgraph, feedback=feedback)
    response = client.messages.parse(
        model=model or resolve_model(),
        max_tokens=MAX_TOKENS,
        thinking={"type": "adaptive"},
        system=system,
        messages=[{"role": "user", "content": user}],
        output_format=EmulationPlan,
    )
    _ensure_plan(response)
    return response


def _ensure_plan(response) -> None:
    """
    Fail loudly if the turn did not yield a parseable plan.

    Without this, a refusal or a max_tokens truncation leaves parsed_output as
    None, surfacing later only as an opaque 'NoneType has no attribute phases'.
    Refusal is a realistic mode here — this is ransomware-emulation content — so
    the message names the category the API reported.
    """
    reason = getattr(response, "stop_reason", None)
    if reason == "refusal":
        details = getattr(response, "stop_details", None)
        category = getattr(details, "category", None)
        explanation = (getattr(details, "explanation", "") or "").strip()
        raise RuntimeError(
            f"The model refused to generate the plan (category: {category}). "
            f"{explanation}".strip())
    if reason == "max_tokens":
        raise RuntimeError(
            "The response hit max_tokens before a complete plan was returned; "
            "raise MAX_TOKENS in graphrag_generate.py.")
    if getattr(response, "parsed_output", None) is None:
        raise RuntimeError(f"No plan was parsed from the response (stop_reason: {reason}).")


def refine_plan(subgraph: dict, client=None, model=None, max_attempts=3):
    """
    Generate → validate → re-prompt with feedback, up to `max_attempts` times.

    Returns (plan, report, history). Stops as soon as a plan validates; on
    exhaustion returns the last attempt with its (still-invalid) report, so the
    caller always gets a plan plus an honest verdict. `history` is one dict per
    attempt: {"attempt", "report", "usage"}.

    The validator is imported lazily here: graphrag_validate imports this module
    for the plan schema, so a top-level import would be circular.
    """
    import graphrag_validate as gv

    if client is None:
        import anthropic
        client = anthropic.Anthropic()
    model = model or resolve_model()

    feedback = None
    history = []
    plan = report = None
    for attempt in range(1, max_attempts + 1):
        response = generate_plan(subgraph, client=client, model=model, feedback=feedback)
        plan = response.parsed_output
        report = gv.validate_plan(plan, subgraph)
        history.append({"attempt": attempt, "report": report, "usage": response.usage})
        if report.valid:
            break
        feedback = gv.format_feedback(report)
    return plan, report, history


# ─────────────────────────────────────────────
# PERSISTENCE
# ─────────────────────────────────────────────
def build_document(plan: EmulationPlan, subgraph: dict, usage, model: str,
                   report=None, attempts=None) -> dict:
    """
    Plan plus a provenance/metadata block, ready to write as JSON.

    When produced by the refinement loop, pass `report` (a ValidationReport) and
    `attempts` so the saved document records the full verdict and how many tries
    it took, not just the raw grounding signal.
    """
    metadata = {
        "model":        model,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "request": {
            "adversary":   subgraph["adversary"],
            "software_id": subgraph["software_id"],
            "environment": subgraph["platforms"],
            "objective":   subgraph["objective"],
        },
        "usage": {
            "input_tokens":  getattr(usage, "input_tokens", None),
            "output_tokens": getattr(usage, "output_tokens", None),
        } if usage is not None else None,
        "ungrounded_techniques": (report.ungrounded_techniques if report is not None
                                  else ungrounded_techniques(plan, subgraph)),
    }
    if report is not None:
        metadata["validation"] = report.to_dict()
    if attempts is not None:
        metadata["attempts"] = attempts
    return {"metadata": metadata, "plan": plan.model_dump()}


def save_plan(document: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(document, f, indent=2)


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
def load_subgraph(args) -> dict:
    """A subgraph from a saved dump (--subgraph) or from a live retrieval."""
    if args.subgraph:
        with open(args.subgraph, encoding="utf-8") as f:
            subgraph = json.load(f)
        if args.objective:
            subgraph["objective"] = args.objective  # let the CLI override the saved objective
        return subgraph
    request = EmulationRequest(
        version=args.version,
        platforms=tuple(args.platforms or ["Windows"]),
        objective=args.objective or "",
    )
    return retrieve(request)


def main():
    parser = argparse.ArgumentParser(description="Generate a KG-grounded LockBit emulation plan")
    parser.add_argument("--subgraph", help="saved retrieval dump; skips the live Neo4j query")
    parser.add_argument("--version", choices=sorted(SOFTWARE_ID),
                        help="LockBit version (when retrieving live)")
    parser.add_argument("--platform", action="append", dest="platforms",
                        help="target platform, repeatable (default: Windows)")
    parser.add_argument("--objective", default="", help="attacker objective for the plan")
    parser.add_argument("--out", help="write the plan document JSON here")
    parser.add_argument("--refine", action="store_true",
                        help="validate and re-prompt on failure instead of one-shot")
    parser.add_argument("--max-attempts", type=int, default=3, dest="max_attempts",
                        help="max refinement attempts (with --refine; default 3)")
    args = parser.parse_args()

    if not args.subgraph and not args.version:
        parser.error("provide --subgraph <file>, or --version to retrieve live")
    if args.max_attempts < 1:
        parser.error("--max-attempts must be at least 1")

    model = resolve_model()
    subgraph = load_subgraph(args)
    mode = "refining" if args.refine else "generating"
    print(f"[1/2] {mode.capitalize()} a plan for {subgraph['adversary']} on "
          f"{', '.join(subgraph['platforms'])} with {model} "
          f"({subgraph['technique_count']} techniques in context) ...")

    try:
        if args.refine:
            plan, report, history = refine_plan(subgraph, model=model,
                                                max_attempts=args.max_attempts)
            usage = history[-1]["usage"]
        else:
            response = generate_plan(subgraph, model=model)
            plan, report, history, usage = response.parsed_output, None, None, response.usage
    except Exception as exc:  # noqa: BLE001 — CLI boundary: turn any API failure into a clear message
        raise SystemExit(_explain(exc))

    if history is not None:
        for entry in history:
            r = entry["report"]
            verdict = "valid" if r.valid else _summarise_failures(r)
            print(f"      attempt {entry['attempt']}: {verdict}")

    step_count = sum(len(p.steps) for p in plan.phases)
    print(f"      {'✅' if _is_valid(report, plan, subgraph) else '⚠️ '} "
          f"{len(plan.phases)} phases, {step_count} steps")

    print("\n[2/2] Phases:")
    for phase in plan.phases:
        ids = ", ".join(s.technique_id for s in phase.steps)
        print(f"      {phase.tactic:<22} {len(phase.steps):>2}  {ids}")

    if args.out:
        attempts = len(history) if history is not None else None
        document = build_document(plan, subgraph, usage, model,
                                  report=report, attempts=attempts)
        save_plan(document, args.out)
        print(f"\n✅ Saved to {args.out}")


def _summarise_failures(report) -> str:
    """One-line failure summary for a validation report (CLI display)."""
    parts = []
    if report.ungrounded_techniques:
        parts.append(f"{len(report.ungrounded_techniques)} ungrounded")
    if report.precondition_failures:
        parts.append(f"{len(report.precondition_failures)} precondition")
    if report.ordering_violations:
        parts.append(f"{len(report.ordering_violations)} ordering")
    return "INVALID — " + ", ".join(parts)


def _is_valid(report, plan, subgraph) -> bool:
    """Valid per the report if we refined, else fall back to the grounding signal."""
    if report is not None:
        return report.valid
    return not ungrounded_techniques(plan, subgraph)


def _explain(exc: Exception) -> str:
    """Turn the likely API failures into an actionable message for the CLI user."""
    name = type(exc).__name__
    if name == "AuthenticationError" or "api_key" in str(exc).lower():
        return ("Anthropic API authentication failed. Set ANTHROPIC_API_KEY in .env "
                "or the environment (see .env.example).")
    if name == "RateLimitError":
        return "Rate limited by the Anthropic API. Wait and retry."
    if name == "APIConnectionError":
        return "Could not reach the Anthropic API. Check your network connection."
    return f"Plan generation failed ({name}): {exc}"


if __name__ == "__main__":
    main()
