"""Build and validate the version-controlled adaptive configuration manifest."""

import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from experiments.adaptive_coverage import (
    EXPECTED_CONFIGURATION_COUNT,
    EXPECTED_EXCLUDED_PAIR,
    EXPECTED_STRATEGIES,
    format_coverage_report,
    validate_adaptive_coverage,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST_PATH = (
    ROOT / "configs" / "adaptive" / "adaptive_configuration_manifest.json"
)
MANIFEST_VERSION = "1.0"
MANIFEST_DESCRIPTION = (
    "Adaptive goal-carrier-strategy configuration coverage manifest. "
    "Contains configuration identities only; no payloads, trials, seeds, or executions."
)
EXPECTED_COMPATIBLE_PAIR_COUNT = 11
CONFIGURATION_FIELDS = (
    "configuration_id",
    "goal_id",
    "carrier_id",
    "strategy_id",
)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read adaptive definition {path}: {exc}") from exc


def _definition_files(root: Path, group: str) -> list[dict[str, Any]]:
    definitions = []
    for path in sorted((root / "attacks" / "definitions" / group).glob("*.json")):
        definition = _read_json(path)
        if not isinstance(definition, dict):
            raise ValueError(f"Definition must contain an object: {path}")
        definitions.append(definition)
    return definitions


def _configuration_id(goal_id: str, carrier_id: str, strategy_id: str) -> str:
    return f"{goal_id}-{carrier_id}-{strategy_id}"


def validate_adaptive_manifest(
    manifest: Mapping[str, Any],
    *,
    root: str | Path = ROOT,
) -> dict[str, Any]:
    """Validate manifest metadata, IDs, and coverage against canonical definitions."""
    errors: list[str] = []
    if not isinstance(manifest, Mapping):
        raise TypeError("Adaptive manifest must be a mapping")

    configurations = manifest.get("configurations")
    if not isinstance(configurations, list):
        configurations = []
        errors.append("configurations must be a list")

    normalized_entries: list[dict[str, Any]] = []
    configuration_ids: list[str] = []
    for index, configuration in enumerate(configurations):
        if not isinstance(configuration, Mapping):
            errors.append(f"configuration {index} must be an object")
            continue
        missing_fields = [
            field for field in CONFIGURATION_FIELDS if field not in configuration
        ]
        if missing_fields:
            errors.append(
                f"configuration {index} is missing: {', '.join(missing_fields)}"
            )
        if set(configuration) != set(CONFIGURATION_FIELDS):
            extras = sorted(set(configuration) - set(CONFIGURATION_FIELDS))
            if extras:
                errors.append(
                    f"configuration {index} has unsupported fields: "
                    f"{', '.join(extras)}"
                )
        goal_id = configuration.get("goal_id")
        carrier_id = configuration.get("carrier_id")
        strategy_id = configuration.get("strategy_id")
        configuration_id = configuration.get("configuration_id")
        if all(
            isinstance(value, str) and value
            for value in (goal_id, carrier_id, strategy_id)
        ):
            expected_id = _configuration_id(goal_id, carrier_id, strategy_id)
            if configuration_id != expected_id:
                errors.append(
                    f"configuration {index} ID must be {expected_id!r}"
                )
            normalized_entries.append({
                "goal_id": goal_id,
                "carrier_id": carrier_id,
                "strategy_id": strategy_id,
            })
        else:
            errors.append(
                f"configuration {index} must have non-empty goal, carrier, "
                "and strategy IDs"
            )
        if isinstance(configuration_id, str) and configuration_id:
            configuration_ids.append(configuration_id)

    id_counts = Counter(configuration_ids)
    for configuration_id, count in sorted(id_counts.items()):
        if count > 1:
            errors.append(
                f"duplicate configuration_id {configuration_id!r} appears {count} times"
            )

    metadata_values = {
        "manifest_version": MANIFEST_VERSION,
        "description": MANIFEST_DESCRIPTION,
        "configuration_count": EXPECTED_CONFIGURATION_COUNT,
        "compatible_pair_count": EXPECTED_COMPATIBLE_PAIR_COUNT,
        "strategies_per_pair": len(EXPECTED_STRATEGIES),
        "excluded_pairs": [{
            "goal_id": EXPECTED_EXCLUDED_PAIR[0],
            "carrier_id": EXPECTED_EXCLUDED_PAIR[1],
        }],
    }
    for key, expected_value in metadata_values.items():
        if manifest.get(key) != expected_value:
            errors.append(f"{key} must equal {expected_value!r}")

    coverage = validate_adaptive_coverage(normalized_entries, root=root)
    if not coverage["valid"]:
        errors.append("configuration coverage does not match canonical definitions")
    if len(configuration_ids) != len(configurations):
        errors.append("every configuration must have a non-empty configuration_id")

    return {
        "valid": not errors,
        "configuration_count": len(configurations),
        "unique_configuration_id_count": len(id_counts),
        "compatible_pair_count": coverage["compatible_pair_count"],
        "coverage": coverage,
        "errors": errors,
    }


def format_manifest_report(report: Mapping[str, Any]) -> str:
    """Return a readable deterministic manifest validation report."""
    lines = [
        "Adaptive configuration manifest",
        f"Status: {'PASS' if report['valid'] else 'FAIL'}",
        (
            f"Configurations: {report['configuration_count']} "
            f"({report['unique_configuration_id_count']} unique IDs)"
        ),
        f"Compatible goal-carrier pairs: {report['compatible_pair_count']}",
    ]
    lines.append(format_coverage_report(report["coverage"]))
    lines.append(f"Manifest errors: {len(report['errors'])}")
    lines.extend(f"  {error}" for error in report["errors"])
    return "\n".join(lines)


def build_adaptive_manifest(*, root: str | Path = ROOT) -> dict[str, Any]:
    """Derive and validate all configuration identities from canonical definitions."""
    root_path = Path(root)
    goals = _definition_files(root_path, "goals")
    carriers = _definition_files(root_path, "carriers")
    registry = _read_json(
        root_path / "attacks" / "definitions" / "strategy_eligibility.json"
    )
    canonical = (
        registry.get("canonical_strategy_definitions")
        if isinstance(registry, dict)
        else None
    )
    if not isinstance(canonical, dict):
        raise ValueError(
            "Strategy registry must define canonical_strategy_definitions"
        )

    goal_ids = sorted(
        goal["goal_id"]
        for goal in goals
        if isinstance(goal.get("goal_id"), str)
    )
    strategy_ids = sorted(
        strategy_id
        for strategy_id, relative_path in canonical.items()
        if isinstance(strategy_id, str) and isinstance(relative_path, str)
    )
    configurations = []
    for carrier in sorted(
        carriers,
        key=lambda item: (
            item.get("carrier_id")
            if isinstance(item.get("carrier_id"), str)
            else ""
        ),
    ):
        carrier_id = carrier.get("carrier_id")
        compatible_goals = carrier.get("compatible_goals")
        if not isinstance(carrier_id, str) or not isinstance(compatible_goals, list):
            continue
        for goal_id in goal_ids:
            if goal_id not in compatible_goals:
                continue
            for strategy_id in strategy_ids:
                configurations.append({
                    "configuration_id": _configuration_id(
                        goal_id,
                        carrier_id,
                        strategy_id,
                    ),
                    "goal_id": goal_id,
                    "carrier_id": carrier_id,
                    "strategy_id": strategy_id,
                })

    candidate_triples = [
        {
            "goal_id": item["goal_id"],
            "carrier_id": item["carrier_id"],
            "strategy_id": item["strategy_id"],
        }
        for item in configurations
    ]
    coverage = validate_adaptive_coverage(candidate_triples, root=root_path)
    if (
        not coverage["valid"]
        or coverage["actual_configuration_count"] != EXPECTED_CONFIGURATION_COUNT
        or coverage["unique_configuration_count"] != EXPECTED_CONFIGURATION_COUNT
        or coverage["compatible_pair_count"] != EXPECTED_COMPATIBLE_PAIR_COUNT
        or coverage["excluded_pairs"] != [{
            "goal_id": EXPECTED_EXCLUDED_PAIR[0],
            "carrier_id": EXPECTED_EXCLUDED_PAIR[1],
        }]
        or any(
            strategies != list(EXPECTED_STRATEGIES)
            for strategies in coverage["strategies_per_pair"].values()
        )
    ):
        raise ValueError(
            "Refusing to build an invalid adaptive manifest:\n"
            + format_coverage_report(coverage)
        )

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "description": MANIFEST_DESCRIPTION,
        "configuration_count": EXPECTED_CONFIGURATION_COUNT,
        "compatible_pair_count": EXPECTED_COMPATIBLE_PAIR_COUNT,
        "strategies_per_pair": len(EXPECTED_STRATEGIES),
        "excluded_pairs": [{
            "goal_id": EXPECTED_EXCLUDED_PAIR[0],
            "carrier_id": EXPECTED_EXCLUDED_PAIR[1],
        }],
        "configurations": configurations,
    }
    validation = validate_adaptive_manifest(manifest, root=root_path)
    if not validation["valid"]:
        raise ValueError(
            "Refusing to build an invalid adaptive manifest:\n"
            + format_manifest_report(validation)
        )
    return manifest


def write_adaptive_manifest(
    path: str | Path = DEFAULT_MANIFEST_PATH,
    *,
    root: str | Path = ROOT,
) -> dict[str, Any]:
    """Validate the full manifest before creating or replacing its JSON file."""
    manifest = build_adaptive_manifest(root=root)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return manifest


if __name__ == "__main__":
    written = write_adaptive_manifest()
    print(
        f"Wrote {written['configuration_count']} adaptive configurations "
        f"to {DEFAULT_MANIFEST_PATH}"
    )
