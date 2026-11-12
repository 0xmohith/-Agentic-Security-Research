"""Read-only coverage validation for the adaptive configuration space."""

import json
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFINITIONS_ROOT = ROOT / "attacks" / "definitions"
GOAL_CARRIER_STRATEGY_FIELDS = ("goal_id", "carrier_id", "strategy_id")
EXPECTED_GOALS = ("G1", "G2", "G3")
EXPECTED_CARRIERS = ("C1", "C2", "C3", "C4")
EXPECTED_STRATEGIES = ("T1", "T2", "T3", "T4", "T5", "T6", "T7")
EXPECTED_EXCLUDED_PAIR = ("G3", "C3")
EXPECTED_CONFIGURATION_COUNT = 77


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read coverage definition {path}: {exc}") from exc


def _definition_index(
    directory: Path,
    id_field: str,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    definitions: dict[str, dict[str, Any]] = {}
    errors = []
    for path in sorted(directory.glob("*.json")):
        definition = _read_json(path)
        if not isinstance(definition, dict):
            errors.append(f"{path.name}: definition must be an object")
            continue
        definition_id = definition.get(id_field)
        if not isinstance(definition_id, str) or not definition_id:
            errors.append(f"{path.name}: missing {id_field}")
            continue
        if definition_id in definitions:
            errors.append(f"{path.name}: duplicate {id_field} {definition_id}")
            continue
        definitions[definition_id] = definition
    return definitions, errors


def _load_matrix(source: Iterable[Mapping[str, Any]] | str | Path) -> list[Any]:
    if isinstance(source, (str, Path)):
        matrix = _read_json(Path(source))
        if isinstance(matrix, dict):
            matrix = matrix.get("configurations")
    else:
        matrix = list(source)
    if not isinstance(matrix, list):
        raise ValueError("Configuration matrix must be a list or an object with configurations")
    return matrix


def _combo_sort_key(combo: tuple[str, str, str]) -> tuple[int, int, int, str]:
    goal_id, carrier_id, strategy_id = combo
    return (
        int(goal_id[1:]) if goal_id[1:].isdigit() else 0,
        int(carrier_id[1:]) if carrier_id[1:].isdigit() else 0,
        int(strategy_id[1:]) if strategy_id[1:].isdigit() else 0,
        "|".join(combo),
    )


def _pair_sort_key(pair: tuple[str, str]) -> tuple[int, int, str]:
    goal_id, carrier_id = pair
    return (
        int(goal_id[1:]) if goal_id[1:].isdigit() else 0,
        int(carrier_id[1:]) if carrier_id[1:].isdigit() else 0,
        "|".join(pair),
    )


def _compatible_goals(carrier: Mapping[str, Any]) -> list[Any]:
    value = carrier.get("compatible_goals")
    return value if isinstance(value, list) else []


def validate_adaptive_coverage(
    source: Iterable[Mapping[str, Any]] | str | Path,
    *,
    root: str | Path = ROOT,
) -> dict[str, Any]:
    """Compare supplied configuration triples to canonical repository definitions."""
    root_path = Path(root)
    definitions_root = root_path / "attacks" / "definitions"
    goals, goal_errors = _definition_index(
        definitions_root / "goals",
        "goal_id",
    )
    carriers, carrier_errors = _definition_index(
        definitions_root / "carriers",
        "carrier_id",
    )
    definition_errors = goal_errors + carrier_errors
    for label, discovered, expected in (
        ("goal", set(goals), set(EXPECTED_GOALS)),
        ("carrier", set(carriers), set(EXPECTED_CARRIERS)),
    ):
        for definition_id in sorted(expected - discovered):
            definition_errors.append(f"Missing expected {label} definition: {definition_id}")
        for definition_id in sorted(discovered - expected):
            definition_errors.append(f"Unexpected {label} definition: {definition_id}")

    registry = _read_json(definitions_root / "strategy_eligibility.json")
    canonical = (
        registry.get("canonical_strategy_definitions")
        if isinstance(registry, dict)
        else None
    )
    if not isinstance(canonical, dict):
        raise ValueError("Strategy registry must define canonical_strategy_definitions")

    strategies: dict[str, dict[str, Any]] = {}
    for strategy_id, relative_path in sorted(canonical.items()):
        if not isinstance(strategy_id, str) or not isinstance(relative_path, str):
            definition_errors.append("Strategy registry entries must map string IDs to paths")
            continue
        strategy_path = definitions_root / relative_path
        if not strategy_path.is_file():
            definition_errors.append(
                f"{strategy_id}: canonical strategy definition is missing"
            )
            continue
        definition = _read_json(strategy_path)
        if not isinstance(definition, dict) or definition.get("strategy_id") != strategy_id:
            definition_errors.append(
                f"{strategy_id}: canonical strategy definition ID does not match"
            )
            continue
        strategies[strategy_id] = definition
    for strategy_id in sorted(set(EXPECTED_STRATEGIES) - set(strategies)):
        definition_errors.append(
            f"Missing expected strategy definition: {strategy_id}"
        )
    for strategy_id in sorted(set(strategies) - set(EXPECTED_STRATEGIES)):
        definition_errors.append(
            f"Unexpected strategy definition: {strategy_id}"
        )

    undefined_references: list[dict[str, Any]] = []
    compatibility_mismatches: list[dict[str, Any]] = []
    defined_goal_ids = set(goals)
    defined_carrier_ids = set(carriers)
    defined_strategy_ids = set(strategies)

    for carrier_id, carrier in sorted(carriers.items()):
        compatible_goals = carrier.get("compatible_goals")
        if not isinstance(compatible_goals, list):
            compatibility_mismatches.append({
                "carrier_id": carrier_id,
                "issue": "compatible_goals must be a list",
            })
            continue
        if len(compatible_goals) != len(set(
            item for item in compatible_goals if isinstance(item, str)
        )):
            compatibility_mismatches.append({
                "carrier_id": carrier_id,
                "issue": "compatible_goals contains duplicate entries",
            })
        for goal_id in compatible_goals:
            if not isinstance(goal_id, str) or goal_id not in defined_goal_ids:
                undefined_references.append({
                    "source": f"carrier:{carrier_id}",
                    "field": "compatible_goals",
                    "reference": goal_id,
                })

    matrix = _load_matrix(source)
    combinations: list[tuple[str, str, str]] = []
    invalid_entries: list[dict[str, Any]] = []
    for index, entry in enumerate(matrix):
        if not isinstance(entry, Mapping):
            invalid_entries.append({
                "index": index,
                "issue": "entry must be an object",
            })
            continue
        values = {field: entry.get(field) for field in GOAL_CARRIER_STRATEGY_FIELDS}
        if any(not isinstance(value, str) or not value for value in values.values()):
            invalid_entries.append({
                "index": index,
                "issue": "goal_id, carrier_id, and strategy_id must be non-empty strings",
            })
            continue

        goal_id = values["goal_id"]
        carrier_id = values["carrier_id"]
        strategy_id = values["strategy_id"]
        if goal_id not in defined_goal_ids:
            undefined_references.append({
                "index": index,
                "field": "goal_id",
                "reference": goal_id,
            })
        if carrier_id not in defined_carrier_ids:
            undefined_references.append({
                "index": index,
                "field": "carrier_id",
                "reference": carrier_id,
            })
        if strategy_id not in defined_strategy_ids:
            undefined_references.append({
                "index": index,
                "field": "strategy_id",
                "reference": strategy_id,
            })

        if (
            goal_id in defined_goal_ids
            and carrier_id in defined_carrier_ids
            and goal_id not in _compatible_goals(carriers[carrier_id])
        ):
            compatibility_mismatches.append({
                "index": index,
                "goal_id": goal_id,
                "carrier_id": carrier_id,
                "issue": "matrix contains an incompatible goal-carrier pair",
            })
        combinations.append((goal_id, carrier_id, strategy_id))

    compatible_pairs = {
        (goal_id, carrier_id)
        for carrier_id, carrier in carriers.items()
        for goal_id in _compatible_goals(carrier)
        if isinstance(goal_id, str) and goal_id in defined_goal_ids
    }
    all_defined_pairs = {
        (goal_id, carrier_id)
        for goal_id in goals
        for carrier_id in carriers
    }
    actual_excluded_pairs = all_defined_pairs - compatible_pairs
    expected_excluded_pairs = {EXPECTED_EXCLUDED_PAIR}
    for pair in sorted(
        actual_excluded_pairs.symmetric_difference(expected_excluded_pairs),
        key=_pair_sort_key,
    ):
        compatibility_mismatches.append({
            "goal_id": pair[0],
            "carrier_id": pair[1],
            "issue": (
                "unexpected excluded pair"
                if pair in actual_excluded_pairs
                else "expected excluded pair is marked compatible"
            ),
        })

    expected_combinations = {
        (goal_id, carrier_id, strategy_id)
        for goal_id, carrier_id in compatible_pairs
        for strategy_id in strategies
    }
    combination_counts = Counter(combinations)
    duplicate_combinations = sorted(
        (
            {"goal_id": goal, "carrier_id": carrier, "strategy_id": strategy, "count": count}
            for (goal, carrier, strategy), count in combination_counts.items()
            if count > 1
        ),
        key=lambda item: _combo_sort_key(
            (item["goal_id"], item["carrier_id"], item["strategy_id"])
        ),
    )
    actual_combinations = set(combination_counts)
    missing_combinations = sorted(expected_combinations - actual_combinations, key=_combo_sort_key)
    unexpected_combinations = sorted(actual_combinations - expected_combinations, key=_combo_sort_key)

    expected_pairs_sorted = sorted(compatible_pairs, key=_pair_sort_key)
    observed_strategy_coverage = {
        f"{goal_id}/{carrier_id}": sorted(
            strategy_id
            for strategy_id in EXPECTED_STRATEGIES
            if (goal_id, carrier_id, strategy_id) in actual_combinations
        )
        for goal_id, carrier_id in expected_pairs_sorted
    }
    missing_strategy_coverage = [
        {
            "goal_id": goal_id,
            "carrier_id": carrier_id,
            "missing_strategies": [
                strategy_id
                for strategy_id in EXPECTED_STRATEGIES
                if (goal_id, carrier_id, strategy_id) not in actual_combinations
            ],
        }
        for goal_id, carrier_id in expected_pairs_sorted
        if any(
            (goal_id, carrier_id, strategy_id) not in actual_combinations
            for strategy_id in EXPECTED_STRATEGIES
        )
    ]

    configuration_count_expected = len(compatible_pairs) * len(strategies)
    valid = (
        not definition_errors
        and len(compatible_pairs) == 11
        and configuration_count_expected == EXPECTED_CONFIGURATION_COUNT
        and not invalid_entries
        and not undefined_references
        and not compatibility_mismatches
        and not duplicate_combinations
        and not missing_combinations
        and not unexpected_combinations
    )
    return {
        "valid": valid,
        "expected_configuration_count": EXPECTED_CONFIGURATION_COUNT,
        "actual_configuration_count": len(matrix),
        "unique_configuration_count": len(actual_combinations),
        "compatible_pair_count": len(compatible_pairs),
        "compatible_pairs": [
            {"goal_id": goal_id, "carrier_id": carrier_id}
            for goal_id, carrier_id in expected_pairs_sorted
        ],
        "excluded_pairs": [
            {"goal_id": goal_id, "carrier_id": carrier_id}
            for goal_id, carrier_id in sorted(actual_excluded_pairs, key=_pair_sort_key)
        ],
        "strategy_ids": sorted(defined_strategy_ids),
        "strategies_per_pair": observed_strategy_coverage,
        "missing_strategy_coverage": missing_strategy_coverage,
        "missing_combinations": [
            dict(zip(GOAL_CARRIER_STRATEGY_FIELDS, combo))
            for combo in missing_combinations
        ],
        "duplicate_combinations": duplicate_combinations,
        "unexpected_combinations": [
            dict(zip(GOAL_CARRIER_STRATEGY_FIELDS, combo))
            for combo in unexpected_combinations
        ],
        "undefined_references": undefined_references,
        "compatibility_mismatches": compatibility_mismatches,
        "invalid_entries": invalid_entries,
        "definition_errors": definition_errors,
    }


def format_coverage_report(report: Mapping[str, Any]) -> str:
    """Render a deterministic plain-text summary of a coverage result."""
    lines = [
        "Adaptive configuration coverage",
        f"Status: {'PASS' if report['valid'] else 'FAIL'}",
        (
            "Configurations: "
            f"{report['unique_configuration_count']}/"
            f"{report['expected_configuration_count']} unique "
            f"({report['actual_configuration_count']} entries)"
        ),
        f"Compatible goal-carrier pairs: {report['compatible_pair_count']}",
        f"Strategies: {', '.join(report['strategy_ids'])}",
        "Compatible pairs:",
    ]
    lines.extend(
        f"  {pair['goal_id']}/{pair['carrier_id']}"
        for pair in report["compatible_pairs"]
    )
    lines.append("Excluded pairs:")
    lines.extend(
        f"  {pair['goal_id']}/{pair['carrier_id']}"
        for pair in report["excluded_pairs"]
    )
    issue_sections = (
        ("Missing combinations", "missing_combinations"),
        ("Duplicate combinations", "duplicate_combinations"),
        ("Unexpected combinations", "unexpected_combinations"),
        ("Undefined references", "undefined_references"),
        ("Compatibility mismatches", "compatibility_mismatches"),
        ("Invalid entries", "invalid_entries"),
        ("Definition errors", "definition_errors"),
    )
    for title, key in issue_sections:
        values = report[key]
        lines.append(f"{title}: {len(values)}")
        lines.extend(f"  {value}" for value in values)
    return "\n".join(lines)
