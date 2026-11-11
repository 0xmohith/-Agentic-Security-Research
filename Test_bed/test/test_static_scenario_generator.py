import json
import shutil
from pathlib import Path

import pytest

from scripts.generate_static_scenarios import (
    DEFAULT_OUTPUT_DIR,
    DEFAULT_SEED,
    GenerationPlan,
    ScenarioGenerationError,
    _write_scenarios,
    _write_generation_plan,
    build_generation_plan,
    main,
)
import scripts.generate_static_scenarios as generator


ROOT = Path(__file__).resolve().parents[1]


def test_default_output_directory_is_attacks_static():
    assert DEFAULT_OUTPUT_DIR == ROOT / "attacks/static"


def _copy_definitions(tmp_path):
    destination = tmp_path / "attacks/definitions"
    shutil.copytree(ROOT / "attacks/definitions", destination)
    return destination


def test_plan_covers_all_strategies_and_ab_variants():
    plan = build_generation_plan()

    assert not plan.errors
    assert len(plan.compatible_pairs) == 11
    assert plan.discovered_payload_count == 42
    assert plan.expected_scenario_count == 154
    assert len(plan.scenarios) == 154
    assert {item["components"]["strategy_id"] for item in plan.scenarios} == {
        f"T{index}" for index in range(1, 8)
    }
    assert {item["variant"] for item in plan.scenarios} == {"A", "B"}
    assert all(item["components"]["injection_position"] == "middle" for item in plan.scenarios)


def test_carrier_goal_compatibility_skips_incompatible_combinations():
    plan = build_generation_plan()

    assert ("G3", "C3") not in plan.compatible_pairs
    assert {
        item["reason"]
        for item in plan.skipped
        if item["goal_id"] == "G3" and item["carrier_id"] == "C3"
    } == {"C3 does not declare G3 in compatible_goals"}
    assert not any(
        item["components"]["goal_id"] == "G3"
        and item["components"]["carrier_id"] == "C3"
        for item in plan.scenarios
    )


@pytest.mark.parametrize("missing_variant", ["A", "B"])
def test_missing_variant_blocks_generation(tmp_path, missing_variant):
    definitions = _copy_definitions(tmp_path)
    missing_payload = definitions / f"payloads/G1/T1/G1__T1__{missing_variant}.json"
    missing_payload.unlink()

    plan = build_generation_plan(tmp_path)

    assert any(
        f"G1/T1: missing payload variant(s): {missing_variant}" in error
        for error in plan.errors
    )
    assert not any(item["goal_id"] == "G1" for item in plan.skipped)
    assert not any(
        scenario["components"]["goal_id"] == "G1"
        and scenario["components"]["strategy_id"] == "T1"
        for scenario in plan.scenarios
    )


@pytest.mark.parametrize(
    ("metadata_key", "metadata_value", "error_text"),
    [
        ("equivalence_review", "pending", "equivalence_review=approved"),
        ("frozen", False, "frozen=true"),
    ],
)
def test_unapproved_or_unfrozen_payload_blocks_generation(
    tmp_path, metadata_key, metadata_value, error_text
):
    definitions = _copy_definitions(tmp_path)
    payload_path = definitions / "payloads/G1/T1/G1__T1__A.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    payload["metadata"][metadata_key] = metadata_value
    payload_path.write_text(json.dumps(payload), encoding="utf-8")

    plan = build_generation_plan(tmp_path)

    assert any(
        "G1/T1: payload metadata must be" in error and error_text in error
        for error in plan.errors
    )
    assert not any(item["goal_id"] == "G1" for item in plan.skipped)
    assert not any(
        scenario["components"]["goal_id"] == "G1"
        and scenario["components"]["strategy_id"] == "T1"
        for scenario in plan.scenarios
    )


@pytest.mark.parametrize("mutation", ["directory", "filename"])
def test_payload_path_must_match_internal_ids(tmp_path, mutation):
    definitions = _copy_definitions(tmp_path)
    payload_path = definitions / "payloads/G1/T1/G1__T1__A.json"
    if mutation == "directory":
        bad_path = definitions / "payloads/G1/T2/G1__T1__A.json"
    else:
        bad_path = definitions / "payloads/G1/T1/G1__T1__RENAMED.json"
    payload_path.rename(bad_path)

    with pytest.raises(ScenarioGenerationError, match="Misplaced or incorrectly named payload"):
        build_generation_plan(tmp_path)


def test_scenarios_use_fixed_middle_injection_and_validate_schema():
    plan = build_generation_plan()

    for scenario in plan.scenarios:
        carrier_id = scenario["components"]["carrier_id"]
        carrier_path = next(
            (ROOT / "attacks/definitions/carriers").glob(f"{carrier_id}_*.json")
        )
        carrier = json.loads(carrier_path.read_text(encoding="utf-8"))
        body_template = carrier["body_template"]
        before, after = body_template.split("{INJECTION_SLOT}")
        assert before in scenario["untrusted_content"]
        assert after in scenario["untrusted_content"]
        assert scenario["scenario_id"].endswith("-middle")
        assert scenario["experiment_config"]["executor_mode"] == "dry_run"
        assert scenario["attack_type"] == "static_disguised"
        assert scenario["defense"] == "none"
        assert scenario["trial_id"] == "trial-1"


def test_t6_reconstructs_ordered_fragments_with_assembly_joiner():
    plan = build_generation_plan()
    payload_path = (
        ROOT / "attacks/definitions/payloads/G3/T6/G3__T6__A.json"
    )
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    scenario = next(
        item for item in plan.scenarios
        if item["scenario_id"] == "G3-C1-T6-A-middle"
    )
    ordered = sorted(payload["fragments"], key=lambda fragment: fragment["position"])
    expected = payload["assembly"]["joiner"].join(
        fragment["content"] for fragment in ordered
    )

    assert payload["fragmentation"]["separator"] == payload["assembly"]["joiner"]
    assert expected in scenario["untrusted_content"]
    assert payload["payload_text"] not in scenario["untrusted_content"]


def test_t6_separator_joiner_mismatch_stops_planning(tmp_path):
    definitions = _copy_definitions(tmp_path)
    payload_path = definitions / "payloads/G3/T6/G3__T6__A.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    payload["assembly"]["joiner"] = " different joiner "
    payload_path.write_text(json.dumps(payload), encoding="utf-8")

    plan = build_generation_plan(tmp_path)

    assert any("ambiguous T6 assembly" in error for error in plan.errors)
    assert len(plan.scenarios) < plan.expected_scenario_count


def test_check_only_validates_without_writing(tmp_path):
    output_dir = tmp_path / "check-only-output"

    assert main(["--check-only", "--output-dir", str(output_dir)]) == 0
    assert not output_dir.exists()


def test_only_g3_c3_is_excluded_for_compatibility():
    plan = build_generation_plan()

    assert len(plan.skipped) == 1
    assert plan.skipped[0] == {
        "goal_id": "G3",
        "carrier_id": "C3",
        "reason": "C3 does not declare G3 in compatible_goals",
    }


def test_explicit_seed_is_applied_to_every_scenario():
    plan = build_generation_plan(seed=42)

    assert {scenario["experiment_config"]["random_seed"] for scenario in plan.scenarios} == {42}
    assert build_generation_plan().scenarios[0]["experiment_config"]["random_seed"] == DEFAULT_SEED


def test_same_seed_reproduces_configs_and_different_seed_changes_them():
    first = build_generation_plan(seed=42)
    repeated = build_generation_plan(seed=42)
    different = build_generation_plan(seed=43)

    assert first.scenarios == repeated.scenarios
    assert [
        scenario["experiment_config"] for scenario in first.scenarios
    ] == [
        scenario["experiment_config"] for scenario in repeated.scenarios
    ]
    assert [
        scenario["experiment_config"] for scenario in first.scenarios
    ] != [
        scenario["experiment_config"] for scenario in different.scenarios
    ]


@pytest.mark.parametrize("incomplete", ["errors", "count"])
def test_incomplete_plan_returns_nonzero_without_creating_output(
    tmp_path, monkeypatch, incomplete
):
    plan = build_generation_plan()
    if incomplete == "errors":
        plan.errors.append("test blocking error")
    else:
        plan.scenarios.pop()
    monkeypatch.setattr(generator, "build_generation_plan", lambda seed: plan)
    output_dir = tmp_path / "must-not-exist"

    assert main(["--output-dir", str(output_dir)]) != 0
    assert not output_dir.exists()


def test_writer_requires_exact_expected_scenario_count(tmp_path):
    plan = build_generation_plan()
    plan.scenarios.pop()
    output_dir = tmp_path / "incomplete"

    with pytest.raises(ScenarioGenerationError, match="expected 154 scenarios, found 153"):
        _write_generation_plan(plan, output_dir)

    assert not output_dir.exists()


def test_missing_payload_plan_does_not_create_any_output_files(tmp_path, monkeypatch):
    definitions = _copy_definitions(tmp_path)
    (definitions / "payloads/G1/T1/G1__T1__B.json").unlink()
    plan = build_generation_plan(tmp_path)
    monkeypatch.setattr(generator, "build_generation_plan", lambda seed: plan)
    output_dir = tmp_path / "blocked-output"

    assert main(["--output-dir", str(output_dir)]) != 0
    assert not output_dir.exists()


def test_writer_refuses_to_overwrite_existing_scenario(tmp_path):
    scenario = {"scenario_id": "G1-C1-T1-A-middle"}
    destination = tmp_path / f"{scenario['scenario_id']}.json"
    destination.write_text("existing", encoding="utf-8")

    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        _write_scenarios([scenario], tmp_path)

    assert destination.read_text(encoding="utf-8") == "existing"
