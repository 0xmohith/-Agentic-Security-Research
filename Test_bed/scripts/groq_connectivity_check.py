#!/usr/bin/env python3
"""Explicit, benign connectivity check for the configured Groq model."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.groq_provider import GroqAttackerProvider, GroqProviderError


def main() -> int:
    try:
        provider = GroqAttackerProvider()
        response = provider.complete(
            "Reply with the single word READY.",
            system_prompt="You are a benign API connectivity check.",
        )
    except GroqProviderError as exc:
        print(f"Groq connectivity check failed: {exc}", file=sys.stderr)
        return 1

    if not response.text.strip():
        print("Groq connectivity check returned no text.", file=sys.stderr)
        return 1

    print("Groq connectivity check passed.")
    print(json.dumps(response.metadata, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
