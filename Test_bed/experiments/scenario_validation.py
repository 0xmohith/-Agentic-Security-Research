"""JSON Schema validation for scenario files."""

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "schemas"
    / "static_scenario.schema.json"
)


def validate_scenario(scenario: Any, source: str = "<scenario>") -> dict:
    """Validate a parsed scenario against the repository's scenario schema."""
    with SCHEMA_PATH.open("r", encoding="utf-8") as schema_file:
        schema = json.load(schema_file)

    validator = Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    errors = list(validator.iter_errors(scenario))
    if errors:
        leaves = []

        def collect_leaves(error):
            if error.context:
                for child in error.context:
                    collect_leaves(child)
            else:
                leaves.append(error)

        for error in errors:
            collect_leaves(error)
        error = max(
            leaves,
            key=lambda item: (
                len(item.absolute_path),
                tuple(str(part) for part in item.absolute_path),
            ),
        )
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise ValueError(f"{source}: invalid scenario at {location}: {error.message}")

    return scenario
