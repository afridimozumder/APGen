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


def normalize_tactic(tactic: str) -> str:
    """
    Fold a human-readable tactic name onto the canonical kebab-case key.

    >>> normalize_tactic("Command and Control")
    'command-and-control'
    """
    return "-".join(tactic.lower().split())


def get_tactic_order(tactics: list) -> int:
    """
    Earliest kill-chain position among a technique's tactics, for plan ordering.
    Unknown tactics sort last (UNKNOWN_TACTIC_ORDER) rather than raising.
    """
    return min((TACTIC_ORDER.get(normalize_tactic(t), UNKNOWN_TACTIC_ORDER)
                for t in tactics), default=UNKNOWN_TACTIC_ORDER)
