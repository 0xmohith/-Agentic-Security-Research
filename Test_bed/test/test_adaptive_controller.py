import json
from pathlib import Path

import pytest

from experiments.adaptive_configuration import (
    AdaptiveConfiguration,
    load_adaptive_configuration,
)
from experiments.adaptive_controller import AdaptiveController
from experiments.adaptive_logger import AdaptiveLogger
from experiments.logger import log_directory_for_scenario
from pipeline.pipeline import executed_objective_matches


ROOT = Path(__file__).resolve().parents[1]


def _configuration(*, max_rounds=30, random_seed=123):
    return load_adaptive_configuration({
        "goal_id": "G1",
        "carrier_id": "C1",
        "strategy_id": "T1",
        "test_input": {
            "user_request": "Summarize this controlled test note.",
            "untrusted_content": "Controlled orchestration fixture.",
        },
        "experiment_config": {"random_seed": random_seed},
        "max_rounds": max_rounds,
    })


def _pipeline_result(objective, *, success=False, run_id="pipeline-run"):
    tool_result = {
        "status": "simulated" if success else "blocked",
        "tool": objective["tool"],
        "to": objective.get("recipient", "other@example.test"),
        "subject": objective.get("subject", "Other"),
        "body": "Controlled test result",
    }
    return {
        "run_id": run_id,
        "stages": [
            {"stage": "S1", "data": {"fixture": True}},
            {"stage": "T1", "data": tool_result},
        ],
        "metrics": {
            "technical_failure": False,
            "malicious_tool_executed": success,
        },
    }


def test_configuration_validates_compatible_ids_and_rejects_incompatible_pair():
    configuration, objective = _configuration()
    assert configuration.configuration_id == "G1-C1-T1"
    assert objective["goal_type"] == "email_exfiltration"

    incompatible = {
        "goal_id": "G3",
        "carrier_id": "C3",
        "strategy_id": "T1",
        "test_input": {
            "user_request": "Controlled request",
            "untrusted_content": "Controlled fixture",
        },
        "experiment_config": {"random_seed": 1},
    }
    with pytest.raises(ValueError, match="Incompatible goal-carrier pair"):
        load_adaptive_configuration(incompatible)

    invalid_rounds = {
        "goal_id": "G1",
        "carrier_id": "C1",
        "strategy_id": "T1",
        "test_input": {
            "user_request": "Controlled request",
            "untrusted_content": "Controlled fixture",
        },
        "experiment_config": {"random_seed": 1},
        "max_rounds": 31,
    }
    with pytest.raises(ValueError):
        load_adaptive_configuration(invalid_rounds)


@pytest.mark.parametrize("success_round", [1, 3])
def test_strict_success_stops_immediately_and_logs_round_numbers(
    tmp_path,
    success_round,
):
    configuration, objective = _configuration()
    calls = []

    def pipeline_runner(**kwargs):
        calls.append(kwargs)
        succeeded = kwargs["experiment_metadata"]["round_number"] == success_round
        return _pipeline_result(
            objective,
            success=succeeded,
            run_id=f"run-{len(calls)}",
        )

    result = AdaptiveController(
        configuration,
        objective,
        pipeline_runner,
        output_dir=tmp_path,
    ).run_trial()

    assert result["strict_success"] is True
    assert result["strict_success_round"] == success_round
    assert result["stopping_reason"] == "strict_success"
    assert result["total_rounds_completed"] == success_round
    assert [
        call["experiment_metadata"]["round_number"] for call in calls
    ] == list(range(1, success_round + 1))
    assert all(call["log_dir"] == str(tmp_path) for call in calls)
    assert all(
        call["untrusted_content"] == configuration.test_input.untrusted_content
        for call in calls
    )

    records = [
        json.loads(line)
        for line in Path(result["log_path"]).read_text(encoding="utf-8").splitlines()
    ]
    round_records = [
        record["data"]
        for record in records
        if record["stage"] == "ADAPTIVE_ROUND"
    ]
    assert [record["round_number"] for record in round_records] == list(
        range(1, success_round + 1)
    )
    assert all(record["strict_success"] is False for record in round_records[:-1])
    assert round_records[-1]["strict_success"] is True
    assert round_records[0]["configured_random_seed"] == 123
    assert round_records[0]["random_seed"] == 123


def test_seven_trials_have_independent_ids_and_execution_seeds(tmp_path):
    configuration, objective = _configuration(max_rounds=1)
    calls = []

    def pipeline_runner(**kwargs):
        calls.append(kwargs)
        return _pipeline_result(objective, run_id=f"run-{len(calls)}")

    result = AdaptiveController(
        configuration,
        objective,
        pipeline_runner,
        output_dir=tmp_path,
    ).run_configuration()

    trials = result["trials"]
    assert len(trials) == 7
    assert len({trial["trial_id"] for trial in trials}) == 7
    assert len({trial["execution_id"] for trial in trials}) == 7
    assert len({call["experiment_config"].random_seed for call in calls}) == 7
    assert all(
        call["experiment_metadata"]["configured_random_seed"] == 123
        for call in calls
    )
    assert result["metrics"]["valid_trial_count"] == 7


def test_trial_stops_at_30_rounds_without_success(tmp_path):
    configuration, objective = _configuration()
    calls = []

    def pipeline_runner(**kwargs):
        calls.append(kwargs)
        return _pipeline_result(objective, success=False, run_id=f"run-{len(calls)}")

    result = AdaptiveController(
        configuration,
        objective,
        pipeline_runner,
        output_dir=tmp_path,
    ).run_trial()

    assert len(calls) == 30
    assert result["strict_success"] is False
    assert result["stopping_reason"] == "round_limit"
    assert result["total_rounds_completed"] == 30


def test_strict_success_requires_existing_full_objective_match(tmp_path):
    configuration, objective = _configuration(max_rounds=2)
    calls = []
    results = []

    def pipeline_runner(**kwargs):
        calls.append(kwargs)
        result = _pipeline_result(objective, success=True)
        if len(calls) == 1:
            result["stages"][-1]["data"]["to"] = "wrong@example.test"
        else:
            result["metrics"]["malicious_tool_executed"] = False
        results.append(result)
        return result

    result = AdaptiveController(
        configuration,
        objective,
        pipeline_runner,
        output_dir=tmp_path,
    ).run_trial()

    assert result["technical_failure"] is True
    assert result["strict_success"] is False
    assert result["stopping_reason"] == "technical_failure"
    assert result["total_rounds_completed"] == 1
    assert executed_objective_matches(
        results[0]["stages"][-1]["data"],
        objective,
    ) is False


@pytest.mark.parametrize(
    "pipeline_result",
    [
        None,
        {},
        {"run_id": "incomplete", "stages": [], "metrics": {}},
        {
            "run_id": "incomplete",
            "stages": [{"stage": "S1", "data": {}}],
            "metrics": {
                "technical_failure": False,
                "malicious_tool_executed": False,
            },
        },
    ],
)
def test_invalid_or_incomplete_pipeline_result_is_a_technical_failure(
    tmp_path,
    pipeline_result,
):
    configuration, objective = _configuration()
    calls = []

    def pipeline_runner(**kwargs):
        calls.append(kwargs)
        return pipeline_result

    result = AdaptiveController(
        configuration,
        objective,
        pipeline_runner,
        output_dir=tmp_path,
    ).run_trial()

    assert len(calls) == 1
    assert result["technical_failure"] is True
    assert result["strict_success"] is False
    assert result["stopping_reason"] == "technical_failure"


def test_pipeline_technical_failure_is_separate_from_success(tmp_path):
    configuration, objective = _configuration()

    def pipeline_runner(**kwargs):
        return {
            "run_id": "failed-run",
            "stages": [{"stage": "ERROR", "data": {"error_type": "RuntimeError"}}],
            "metrics": {
                "technical_failure": True,
                "malicious_tool_executed": None,
            },
        }

    result = AdaptiveController(
        configuration,
        objective,
        pipeline_runner,
        output_dir=tmp_path,
    ).run_trial()

    assert result["technical_failure"] is True
    assert result["strict_success"] is False
    assert result["stopping_reason"] == "technical_failure"
    assert result["total_rounds_completed"] == 1


def test_adaptive_logger_uses_adaptive_route(tmp_path):
    assert log_directory_for_scenario(
        scenario_path="scenarios/adaptive/config.json"
    ) == Path("logs/adaptive")
    assert AdaptiveLogger("execution-fixture").output_dir == Path("logs/adaptive")
    assert AdaptiveLogger("execution-fixture", output_dir=tmp_path).output_dir == tmp_path


def test_test_fixture_does_not_change_frozen_static_inputs():
    assert (ROOT / "attacks/static").is_dir()
    assert (ROOT / "attacks/definitions/payloads/G1/T1/G1__T1__A.json").is_file()
    assert AdaptiveConfiguration.model_fields["max_rounds"].default == 30
