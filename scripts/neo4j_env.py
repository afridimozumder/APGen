#!/usr/bin/env python3
"""
Neo4j connection settings, read from the environment.

The password is deliberately given no default. A fallback baked into source is
published along with the repository — which is exactly how the old
`os.getenv("NEO4J_PASS", "LockBit2025!")` put a credential on GitHub — and
CLAUDE.md's rule is that credentials come from the environment, never from code.

`.env` is loaded on import so the file this repo already ships an example for
actually does something; until now nothing read it. Real environment variables
take precedence over `.env`, so an HPC job or a CI run can override it without
editing any file.

Validation is deferred to neo4j_password() rather than performed at import
time on purpose: `--stage extract` runs on the AI-LAB, which has no Neo4j and
no NEO4J_* variables set, and must not fail merely because it imported this
module.
"""

import os

from dotenv import load_dotenv

load_dotenv()  # no-op when .env is absent; never overrides a real env var

# Non-secret defaults, matching the local Docker instance documented in README.
NEO4J_URI  = os.getenv("NEO4J_URI",  "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")


def neo4j_password() -> str:
    """
    The Neo4j password, or a clear exit explaining how to supply it.

    Raises SystemExit rather than returning None so that a missing credential
    fails immediately with an actionable message, instead of surfacing as an
    authentication error from the driver several lines later.
    """
    password = os.getenv("NEO4J_PASS")
    if not password:
        raise SystemExit(
            "NEO4J_PASS is not set, and this script has no built-in default.\n"
            "\n"
            "  Put it in .env (gitignored; see .env.example):\n"
            "      NEO4J_PASS=your-password\n"
            "\n"
            "  Or set it for this session only:\n"
            "      PowerShell:  $env:NEO4J_PASS = 'your-password'\n"
            "      bash:        export NEO4J_PASS='your-password'\n"
        )
    return password
