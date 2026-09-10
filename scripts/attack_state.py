#!/usr/bin/env python3
"""
Authored precondition/effect model for LockBit techniques.

No CTI source publishes machine-readable preconditions or effects, so this
model is the project's own contribution. It is deliberately a small set of
transparent rules rather than anything an LLM generated, so that Part 2's
plan validator and Part 3's precondition-satisfaction metric rest on ground
truth we can defend line by line.

The model works on a vocabulary of attacker STATES — capabilities or accesses
an adversary accumulates as an intrusion progresses. Each ATT&CK tactic is
mapped to the states it requires (preconditions) and the states it produces
(effects). A plan is precondition-valid when, walking its steps in order,
every step's preconditions are already in the accumulated state set.

The mapping is validated against the MITRE ATT&CK Evaluations ER6 LockBit plan
(see scripts/state_annotate.py): replaying these rules over that published,
ordered plan must leave every step's preconditions satisfied. If it does not,
the rules are wrong, not the plan.
"""

from attack_tactics import TACTIC_ORDER, normalize_tactic

# ─────────────────────────────────────────────────────────────
# State vocabulary
# ─────────────────────────────────────────────────────────────
# Every state below is produced as the effect of some tactic; nothing is
# required that can never be produced. Kept intentionally small: a state earns
# its place only if it gates a later tactic or marks a plan objective.
FOOTHOLD         = "foothold"          # code execution on at least one host
ELEVATED         = "elevated"          # admin / SYSTEM / root on a host
CREDENTIALS      = "credentials"       # valid credentials harvested
DISCOVERY        = "discovery"         # host/network/domain knowledge gathered
DEFENSES_IMPAIRED = "defenses_impaired"  # AV/EDR/logging disabled or evaded
C2               = "c2"                # command-and-control channel established
DATA_STAGED      = "data_staged"       # target data collected/archived
DATA_EXFILTRATED = "data_exfiltrated"  # data removed from the environment
IMPACT_ACHIEVED  = "impact_achieved"   # encryption/destruction/disruption done

STATES = frozenset({
    FOOTHOLD, ELEVATED, CREDENTIALS, DISCOVERY, DEFENSES_IMPAIRED,
    C2, DATA_STAGED, DATA_EXFILTRATED, IMPACT_ACHIEVED,
})

# ─────────────────────────────────────────────────────────────
# Tactic → (preconditions, effects)
# ─────────────────────────────────────────────────────────────
# Preconditions are the states a technique in this tactic needs before it can
# run; effects are the states it establishes. Only three tactics gate on more
# than a foothold — lateral movement needs credentials, exfiltration needs a
# C2 channel, impact needs elevation — and those three gates are what make the
# precondition-satisfaction metric meaningful rather than trivially always-true.
TACTIC_STATE = {
    "initial-access":       ([],                        [FOOTHOLD]),
    "execution":            ([FOOTHOLD],                []),
    "persistence":          ([FOOTHOLD],                []),
    "privilege-escalation": ([FOOTHOLD],                [ELEVATED]),
    "defense-evasion":      ([FOOTHOLD],                [DEFENSES_IMPAIRED]),
    "defense-impairment":   ([FOOTHOLD],                [DEFENSES_IMPAIRED]),
    "stealth":              ([FOOTHOLD],                [DEFENSES_IMPAIRED]),
    "credential-access":    ([FOOTHOLD],                [CREDENTIALS]),
    "discovery":            ([FOOTHOLD],                [DISCOVERY]),
    "lateral-movement":     ([FOOTHOLD, CREDENTIALS],   [FOOTHOLD]),   # foothold on further hosts
    "collection":           ([FOOTHOLD],                [DATA_STAGED]),
    "command-and-control":  ([FOOTHOLD],                [C2]),
    "exfiltration":         ([FOOTHOLD, C2],            [DATA_EXFILTRATED]),
    "impact":               ([FOOTHOLD, ELEVATED],      [IMPACT_ACHIEVED]),
}


def _primary_tactic(tactics):
    """
    The earliest-kill-chain tactic among a technique's tactics.

    Mirrors attack_tactics.get_tactic_order: a technique that can act in an
    early role (e.g. Valid Accounts as initial access) is judged by that role,
    so its preconditions are the least restrictive it can legitimately need.
    """
    known = [normalize_tactic(t) for t in tactics if normalize_tactic(t) in TACTIC_STATE]
    if not known:
        return None
    return min(known, key=lambda t: TACTIC_ORDER.get(t, 99))


def technique_state(tactics):
    """
    (preconditions, effects) for a technique, given its list of tactics.

    Preconditions come from the technique's earliest tactic role (least
    restrictive). Effects are the union across all its roles, since a
    multi-tactic technique can achieve any of them. A state a technique
    produces is never also listed as something it requires.

    Returns two sorted lists. Unknown tactics yield ([], []).
    """
    primary = _primary_tactic(tactics)
    if primary is None:
        return [], []

    preconditions = set(TACTIC_STATE[primary][0])
    effects = set()
    for t in tactics:
        norm = normalize_tactic(t)
        if norm in TACTIC_STATE:
            effects.update(TACTIC_STATE[norm][1])

    preconditions -= effects  # cannot require what you yourself establish
    return sorted(preconditions), sorted(effects)


def unmet_preconditions(ordered_steps):
    """
    Walk (step_label, tactic) pairs in order and report precondition failures.

    Returns a list of (step_label, missing_states); empty means every step's
    preconditions were satisfied by the accumulated effects of prior steps.
    This is the core of both the spine self-check and Part 2's validator.
    """
    state = set()
    failures = []
    for label, tactic in ordered_steps:
        norm = normalize_tactic(tactic)
        pre, eff = TACTIC_STATE.get(norm, ([], []))
        missing = set(pre) - state
        if missing:
            failures.append((label, sorted(missing)))
        state.update(eff)
    return failures


if __name__ == "__main__":
    # Self-check: the rules must be internally consistent, and every state that
    # is ever required must be producible by some tactic.
    producible = {s for _, eff in TACTIC_STATE.values() for s in eff}
    required = {s for pre, _ in TACTIC_STATE.values() for s in pre}
    assert required <= producible, f"unproducible preconditions: {required - producible}"
    assert producible <= STATES, f"effects outside vocabulary: {producible - STATES}"

    # Valid Accounts (initial-access + persistence + privilege-escalation) must
    # be usable as initial access, i.e. need nothing but produce foothold+elevated.
    pre, eff = technique_state(["initial-access", "persistence", "privilege-escalation"])
    assert pre == [], pre
    assert eff == sorted([ELEVATED, FOOTHOLD]), eff

    # A well-ordered kill chain has no unmet preconditions...
    good = [("s1", "initial-access"), ("s2", "credential-access"),
            ("s3", "lateral-movement"), ("s4", "privilege-escalation"),
            ("s5", "command-and-control"), ("s6", "exfiltration"), ("s7", "impact")]
    assert unmet_preconditions(good) == [], unmet_preconditions(good)

    # ...but exfiltrating before establishing C2 is caught.
    bad = [("s1", "initial-access"), ("s2", "exfiltration")]
    assert unmet_preconditions(bad) == [("s2", [C2])], unmet_preconditions(bad)

    print("attack_state self-check passed")
