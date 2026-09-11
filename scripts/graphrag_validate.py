#!/usr/bin/env python3
"""
Part 2, Phase C (slice 2) — graph-based plan validator.

Checks a generated emulation plan against the subgraph it was produced from. This
is the real validator that `graphrag_generate.ungrounded_techniques` was a
stand-in for, and it is what the refinement loop uses to decide whether to
re-prompt. It is also the basis for Part 3's per-plan metrics.

PURE BY DESIGN: no API, no Neo4j. The plan is validated against the subgraph it
was generated from — which retrieval already platform-filtered — so every check
is a function of data already in hand, and the whole module is offline-testable.

GROUND TRUTH, NOT SELF-REPORT: every input to the precondition check is verified
against the knowledge graph. The plan's own `preconditions`/`effects` fields are
ignored outright — the LLM wrote them. Crucially, so is the plan's *tactic label*
until it has been checked: the label decides which preconditions apply, so an
unverified label would let a plan choose its own gate. A review found exactly
that hole — filing an exfiltration technique under "initial-access" made an
invalid plan validate — which is why check 2 below exists.

The four checks:
  1. Grounding / hallucination — every technique_id must be in the context the
     model was given. Environment fit is subsumed here: the subgraph was already
     filtered to the target platform, so a grounded technique is environment-
     compatible by construction.
  2. Tactic labelling — a step's phase tactic must be one the technique actually
     has per the KG. Catches both a wrong role and an invented tactic name.
  3. Precondition satisfaction — walking the plan in order, each step's tactic
     preconditions must be established by the effects of earlier steps
     (attack_state.unmet_preconditions).
  4. Tactic ordering — phases must run in non-decreasing ATT&CK kill-chain order.
"""

import os
import sys
from dataclasses import dataclass, field, asdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attack_state import unmet_preconditions
from attack_tactics import get_tactic_order, canonical_tactic
from graphrag_generate import (
    EmulationPlan, ungrounded_techniques, plan_technique_ids,
)


@dataclass
class ValidationReport:
    """
    Outcome of validating one plan. `valid` is true iff all four checks pass.

    The failure lists drive the refinement loop's feedback; the counts let Part 3
    derive rates (hallucination rate, precondition-satisfaction rate) without
    re-walking the plan.
    """
    valid: bool
    ungrounded_techniques: list = field(default_factory=list)
    mislabelled_steps: list = field(default_factory=list)        # [(label, claimed, real)]
    precondition_failures: list = field(default_factory=list)    # [(label, [missing])]
    ordering_violations: list = field(default_factory=list)      # [(from_tactic, to_tactic)]
    technique_count: int = 0
    grounded_count: int = 0
    steps_checked: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def technique_tactics(subgraph: dict) -> dict:
    """
    {attack_id: [canonical tactics]} for everything in the retrieved context.

    Canonicalised because the subgraph's PHASE headings are already folded
    (`defense-impairment` → `defense-evasion`) while each technique's raw
    `tactics` field is not. Comparing the two un-folded would flag every
    technique in that phase as mislabelled.
    """
    return {t["attack_id"]: [canonical_tactic(x) for x in (t.get("tactics") or [])]
            for phase in subgraph["phases"] for t in phase["techniques"]}


def _mislabelled_steps(plan: EmulationPlan, subgraph: dict) -> list:
    """
    Grounded steps filed under a tactic the technique does not actually have.

    The model chooses `phase.tactic`, and that label decides which preconditions
    apply — so leaving it unverified lets a plan pick its own gate. An invented
    tactic name is caught by the same comparison, since it matches nothing.

    Ungrounded techniques are skipped: they are already reported by check 1, and
    the KG holds no tactics to judge them against.
    """
    known = technique_tactics(subgraph)
    mislabelled = []
    for phase in plan.phases:
        claimed = canonical_tactic(phase.tactic)
        for step in phase.steps:
            real = known.get(step.technique_id)
            if real is None:
                continue
            if claimed not in real:
                mislabelled.append(
                    (f"step {step.step_id} ({step.technique_id})", phase.tactic, real))
    return mislabelled


def _ordered_step_tactics(plan: EmulationPlan) -> list:
    """
    (label, tactic) pairs in plan order, one per step.

    A step's tactic is its PHASE's tactic — but only meaningful once check 2 has
    confirmed that label is a role the technique genuinely has. This is the input
    attack_state.unmet_preconditions expects, matching how
    state_annotate.check_spine validates the MITRE spine.
    """
    return [(f"step {step.step_id} ({step.technique_id})", phase.tactic)
            for phase in plan.phases for step in phase.steps]


def _ordering_violations(plan: EmulationPlan) -> list:
    """Adjacent phase transitions that go backwards along the kill chain."""
    violations = []
    prev_order, prev_tactic = None, None
    for phase in plan.phases:
        order = get_tactic_order([phase.tactic])
        if prev_order is not None and order < prev_order:
            violations.append((prev_tactic, phase.tactic))
        prev_order, prev_tactic = order, phase.tactic
    return violations


def validate_plan(plan: EmulationPlan, subgraph: dict) -> ValidationReport:
    """Validate a plan against the subgraph it was generated from."""
    ungrounded = ungrounded_techniques(plan, subgraph)
    mislabelled = _mislabelled_steps(plan, subgraph)
    precondition_failures = unmet_preconditions(_ordered_step_tactics(plan))
    ordering_violations = _ordering_violations(plan)

    technique_count = len(plan_technique_ids(plan))
    steps_checked = sum(len(p.steps) for p in plan.phases)

    return ValidationReport(
        valid=not (ungrounded or mislabelled or precondition_failures or ordering_violations),
        ungrounded_techniques=ungrounded,
        mislabelled_steps=mislabelled,
        precondition_failures=precondition_failures,
        ordering_violations=ordering_violations,
        technique_count=technique_count,
        grounded_count=technique_count - len(ungrounded),
        steps_checked=steps_checked,
    )


def format_feedback(report: ValidationReport) -> str:
    """
    Turn a failing report into a concrete re-prompt instruction.

    Returns "" for a valid report — the refinement loop only calls this on
    failure, but an empty string is safer than a header promising problems that
    are not then listed.
    """
    if report.valid:
        return ""

    problems = []
    if report.ungrounded_techniques:
        problems.append(
            "These technique IDs are NOT in the provided context and must be removed or "
            "replaced with techniques from the list: "
            + ", ".join(report.ungrounded_techniques) + ".")
    for label, claimed, real in report.mislabelled_steps:
        problems.append(
            f"{label} is placed in a '{claimed}' phase, but that technique's tactics are "
            f"{', '.join(real) or 'unknown'}. Move it to a phase matching one of those.")
    for label, missing in report.precondition_failures:
        problems.append(
            f"{label} cannot run yet: its preconditions ({', '.join(missing)}) are not "
            "established by any earlier step. Add or reorder an earlier step that provides them.")
    for frm, to in report.ordering_violations:
        problems.append(
            f"Phase '{to}' appears after '{frm}', which is out of ATT&CK kill-chain order. "
            "Order phases from initial access through to impact.")
    return ("PREVIOUS ATTEMPT HAD THESE PROBLEMS — fix all of them and use ONLY the "
            "techniques in the context:\n- " + "\n- ".join(problems))


if __name__ == "__main__":
    # Self-check: a well-ordered chain validates; the two faults a review found —
    # exfiltration before C2, and dodging that gate by mislabelling the phase —
    # must both be rejected.
    from graphrag_generate import Phase, Step

    def _step(tid):
        return Step(step_id=1, technique_id=tid, technique_name="x",
                    description="d", preconditions=[], effects=[], tools=[])

    def _plan(*phases):
        return EmulationPlan(adversary="LockBit 3.0", software_id="S1202",
                             environment="Windows", objective="o",
                             phases=[Phase(tactic=t, steps=[_step(i)]) for t, i in phases])

    subgraph = {"phases": [{"techniques": [
        {"attack_id": "T1078", "tactics": ["initial-access"]},
        {"attack_id": "T1071.001", "tactics": ["command-and-control"]},
        {"attack_id": "T1041", "tactics": ["exfiltration"]},
    ]}]}

    # Grounded, correctly labelled, kill-chain ordered, and C2 precedes exfiltration.
    good = _plan(("initial-access", "T1078"), ("command-and-control", "T1071.001"),
                 ("exfiltration", "T1041"))
    assert validate_plan(good, subgraph).valid, validate_plan(good, subgraph)

    # T1041 in its true role, but wired before any C2 → precondition failure.
    bad = _plan(("initial-access", "T1078"), ("exfiltration", "T1041"))
    bad_report = validate_plan(bad, subgraph)
    assert not bad_report.valid and bad_report.precondition_failures, "must catch exfil-before-c2"
    assert "c2" in format_feedback(bad_report)

    # The bypass: the same step filed under a tactic it does not have. Before the
    # fix this validated clean, because the label chose the (empty) preconditions.
    dodge = _plan(("initial-access", "T1078"), ("initial-access", "T1041"))
    dodge_report = validate_plan(dodge, subgraph)
    assert not dodge_report.valid, "mislabelled phase must not validate"
    assert dodge_report.mislabelled_steps, "mislabelled phase must be reported"

    # An invented tactic name is caught by the same comparison.
    invented = _plan(("totally-made-up", "T1041"),)
    assert validate_plan(invented, subgraph).mislabelled_steps, "invented tactic must be caught"

    assert format_feedback(ValidationReport(valid=True)) == "", "valid report needs no feedback"
    print("graphrag_validate self-check passed")
