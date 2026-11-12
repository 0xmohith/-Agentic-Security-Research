import copy
import json

import pytest

from experiments.adaptive_coverage import EXPECTED_STRATEGIES
from experiments.adaptive_manifest import (
    DEFAULT_MANIFEST_PATH,
    build_adaptive_manifest,
    format_manifest_report,
    validate_adaptive_manifest,
    write_adaptive_manifest,
)


def test_generated_manifest_has_complete_77_configuration_space():
    manifest = build_adaptive_manifest()
    configurations = manifest["configurations"]

    assert manifest["configuration_count"] == 77
    assert len(configurations) == 77
    assert len({item["configuration_id"] for item in configurations}) == 77
    pairs = {
        (item["goal_id"], item["carrier_id"])
        for item in configurations
    }
    assert len(pairs) == 11
    assert ("G3", "C3") not in pairs
    assert manifest["excluded_pairs"] == [{"goal_id": "G3", "carrier_id": "C3"}]
    assert all(
        {
            item["strategy_id"]
            for item in configurations
            if (item["goal_id"], item["carrier_id"]) == pair
        } == set(EXPECTED_STRATEGIES)
        for pair in pairs
    )


def test_manifest_generation_is_deterministic():
    first = build_adaptive_manifest()
    second = build_adaptive_manifest()

    assert first == second
    assert json.dumps(first, indent=2, ensure_ascii=False) == json.dumps(
        second,
        indent=2,
        ensure_ascii=False,
    )


def test_version_controlled_manifest_is_valid():
    manifest = json.loads(DEFAULT_MANIFEST_PATH.read_text(encoding="utf-8"))
    report = validate_adaptive_manifest(manifest)

    assert report["valid"] is True
    assert len(manifest["configurations"]) == 77


@pytest.mark.parametrize("mutation", ["missing", "duplicate"])
def test_manifest_validation_detects_missing_or_duplicate_entries(mutation):
    manifest = build_adaptive_manifest()
    invalid = copy.deepcopy(manifest)
    if mutation == "missing":
        invalid["configurations"].pop()
        invalid["configuration_count"] = 76
    else:
        invalid["configurations"].append(
            copy.deepcopy(invalid["configurations"][0])
        )
        invalid["configuration_count"] = 78

    report = validate_adaptive_manifest(invalid)

    assert report["valid"] is False
    assert report["coverage"]["valid"] is False
    if mutation == "missing":
        assert report["coverage"]["missing_combinations"]
    else:
        assert report["coverage"]["duplicate_combinations"]
        assert any("duplicate configuration_id" in error for error in report["errors"])


def test_writer_persists_valid_manifest_and_returns_same_content(tmp_path):
    destination = tmp_path / "configs/adaptive/adaptive_configuration_manifest.json"

    returned = write_adaptive_manifest(destination)
    persisted = json.loads(destination.read_text(encoding="utf-8"))

    assert persisted == returned
    assert validate_adaptive_manifest(persisted)["valid"] is True
    report = format_manifest_report(validate_adaptive_manifest(persisted))
    assert report.startswith("Adaptive configuration manifest\nStatus: PASS")


def test_writer_does_not_create_output_when_build_validation_fails(
    tmp_path,
    monkeypatch,
):
    destination = tmp_path / "adaptive_configuration_manifest.json"

    def fail_build(*, root):
        raise ValueError("invalid coverage")

    monkeypatch.setattr(
        "experiments.adaptive_manifest.build_adaptive_manifest",
        fail_build,
    )
    with pytest.raises(ValueError, match="invalid coverage"):
        write_adaptive_manifest(destination)

    assert not destination.exists()
