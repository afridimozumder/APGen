#!/usr/bin/env python3
"""
Shared ATT&CK tactic vocabulary for every ingestion script.

Sources name tactics differently: the MITRE STIX bundle uses kebab-case phase
names ("initial-access"), while CISA advisories use title case ("Initial
Access"). Both are normalised here so techniques from different sources sort
into the same emulation-plan phase.
"""

# Canonical ATT&CK kill-chain position per tactic, used to order emulation plan
# phases. Tactics that share an index are alternate names for the same stage:
# recent ATT&CK splits the old "defense-evasion" into "defense-impairment"
# (disabling defenses) and "stealth" (hiding activity).
TACTIC_ORDER = {
    "reconnaissance":       0,
    "resource-development": 1,
    "initial-access":       2,
    "execution":            3,
    "persistence":          4,
    "privilege-escalation": 5,
    "defense-evasion":      6,   # legacy name
    "defense-impairment":   6,
    "stealth":              7,
    "credential-access":    8,
    "discovery":            9,
    "lateral-movement":    10,
    "collection":          11,
    "command-and-control": 12,
    "exfiltration":        13,
    "impact":              14,
}
UNKNOWN_TACTIC_ORDER = 99  # sorts unrecognised tactics to the end of a plan

# Alternate ATT&CK names for one and the same kill-chain stage. Sources written
# years apart label that stage two ways: CISA's 2023 advisory predates the split
# and says "defense evasion", while current MITRE data splits the old tactic into
# "defense-impairment" (disabling defenses) and "stealth" (hiding activity). Left
# unfolded, one stage shows up as two phases in a generated plan.
#
# Folding is limited to the two names sharing kill-chain position 6. "stealth"
# sits at 7 and is a genuinely separate stage, so it is deliberately left alone.
#
# NOTE the direction: this folds onto the older umbrella term, the opposite of the
# revoked-technique-ID map in stix_ingest.py, which follows MITRE old -> current.
# There is no equivalent authority to follow here. MITRE split one tactic into
# two, so "defense-evasion" does not map onto "defense-impairment" alone — some of
# its techniques are really stealth. The umbrella term is the only label honest
# about covering both.
TACTIC_CANONICAL = {
    "defense-impairment": "defense-evasion",
}


def normalize_tactic(tactic: str) -> str:
    """
    Fold a human-readable tactic name onto the canonical kebab-case key.

    >>> normalize_tactic("Command and Control")
    'command-and-control'
    """
    return "-".join(tactic.lower().split())


def canonical_tactic(tactic: str) -> str:
    """
    Normalise a tactic name, then fold alternate spellings of one stage together.

    Use this wherever tactics become plan *phases*; normalize_tactic alone is
    enough when the name is only being looked up.

    >>> canonical_tactic("Defense Impairment")
    'defense-evasion'
    >>> canonical_tactic("stealth")
    'stealth'
    """
    normalized = normalize_tactic(tactic)
    return TACTIC_CANONICAL.get(normalized, normalized)


def get_tactic_order(tactics: list) -> int:
    """
    Earliest kill-chain position among a technique's tactics, for plan ordering.
    Unknown tactics sort last (UNKNOWN_TACTIC_ORDER) rather than raising.
    """
    return min((TACTIC_ORDER.get(normalize_tactic(t), UNKNOWN_TACTIC_ORDER)
                for t in tactics), default=UNKNOWN_TACTIC_ORDER)
