import json

import pytest

from experiments.adaptive_coverage import (
    EXPECTED_CARRIERS,
    EXPECTED_GOALS,
    EXPECTED_STRATEGIES,
    format_coverage_report,
    validate_adaptive_coverage,
)


def _complete_matrix():
    return [
        {
            "goal_id": goal_id,
            "carrier_id": carrier_id,
            "strategy_id": strategy_id,
        }
        for goal_id in EXPECTED_GOALS
        for carrier_id in EXPECTED_CARRIERS
        if (goal_id, carrier_id) != ("G3", "C3")
        for strategy_id in EXPECTED_STRATEGIES
    ]


def test_complete_matrix_has_77_combinations_and_11_compatible_pairs():
    report = validate_adaptive_coverage(_complete_matrix())

    assert report["valid"] is True
    assert report["expected_configuration_count"] == 77
    assert report["actual_configuration_count"] == 77
    assert report["unique_configuration_count"] == 77
    assert report["compatible_pair_count"] == 11
    assert len(report["compatible_pairs"]) == 11
    assert len(report["strategies_per_pair"]) == 11
    assert all(
        strategies == list(EXPECTED_STRATEGIES)
        for strategies in report["strategies_per_pair"].values()
    )
    assert report["excluded_pairs"] == [
        {"goal_id": "G3", "carrier_id": "C3"}
    ]


def test_missing_configuration_is_reported():
    matrix = _complete_matrix()
    matrix.remove({
        "goal_id": "G2",
        "carrier_id": "C4",
        "strategy_id": "T6",
    })

    report = validate_adaptive_coverage(matrix)

    assert report["valid"] is False
    assert report["missing_combinations"] == [{
        "goal_id": "G2",
        "carrier_id": "C4",
        "strategy_id": "T6",
    }]
    assert {
        "goal_id": "G2",
        "carrier_id": "C4",
        "missing_strategies": ["T6"],
    } in report["missing_strategy_coverage"]


def test_duplicate_configuration_is_reported():
    matrix = _complete_matrix()
    matrix.append(matrix[0].copy())

    report = validate_adaptive_coverage(matrix)

    assert report["valid"] is False
    assert report["actual_configuration_count"] == 78
    assert report["unique_configuration_count"] == 77
    assert report["duplicate_combinations"][0]["count"] == 2


@pytest.mark.parametrize(
    ("field", "value", "expected_reference"),
    [
        ("goal_id", "G9", "goal_id"),
        ("strategy_id", "T8", "strategy_id"),
        ("carrier_id", "C9", "carrier_id"),
    ],
)
def test_undefined_matrix_references_are_reported(field, value, expected_reference):
    matrix = _complete_matrix()
    matrix[0][field] = value

    report = validate_adaptive_coverage(matrix)

    assert report["valid"] is False
    assert any(
        issue.get("field") == expected_reference
        and issue.get("reference") == value
        for issue in report["undefined_references"]
    )


def test_incompatible_configuration_is_reported_as_mismatch():
    matrix = _complete_matrix()
    matrix.append({
        "goal_id": "G3",
        "carrier_id": "C3",
        "strategy_id": "T1",
    })

    report = validate_adaptive_coverage(matrix)

    assert report["valid"] is False
    assert any(
        issue.get("issue") == "matrix contains an incompatible goal-carrier pair"
        for issue in report["compatibility_mismatches"]
    )
    assert {
        "goal_id": "G3",
        "carrier_id": "C3",
        "strategy_id": "T1",
    } in report["unexpected_combinations"]


def test_validation_report_is_reproducible():
    first = format_coverage_report(validate_adaptive_coverage(_complete_matrix()))
    second = format_coverage_report(validate_adaptive_coverage(_complete_matrix()))

    assert first == second
    assert first.startswith("Adaptive configuration coverage\nStatus: PASS")
    assert "Configurations: 77/77 unique (77 entries)" in first


def test_matrix_can_be_loaded_from_json_file(tmp_path):
    matrix_path = tmp_path / "coverage.json"
    matrix_path.write_text(
        json.dumps({"configurations": _complete_matrix()}),
        encoding="utf-8",
    )

    report = validate_adaptive_coverage(matrix_path)

    assert report["valid"] is True
    assert report["unique_configuration_count"] == 77
