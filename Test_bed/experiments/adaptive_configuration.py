"""Validated configuration for fixed-input adaptive orchestration tests."""

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from experiments.configuration import ExperimentConfig


ROOT = Path(__file__).resolve().parents[1]
DEFINITIONS_ROOT = ROOT / "attacks" / "definitions"
GOAL_IDS = ("G1", "G2", "G3")
CARRIER_IDS = ("C1", "C2", "C3", "C4")
STRATEGY_IDS = ("T1", "T2", "T3", "T4", "T5", "T6", "T7")
MAX_ADAPTIVE_ROUNDS = 30


class AdaptiveTestInput(BaseModel):
    """Fixed test text; this model does not generate or revise payloads."""

    model_config = ConfigDict(extra="forbid", strict=True)

    user_request: str = Field(min_length=1)
    untrusted_content: str = Field(min_length=1)


class AdaptiveConfiguration(BaseModel):
    """One compatible goal-carrier-strategy test configuration."""

    model_config = ConfigDict(extra="forbid", strict=True)

    goal_id: Literal["G1", "G2", "G3"]
    carrier_id: Literal["C1", "C2", "C3", "C4"]
    strategy_id: Literal["T1", "T2", "T3", "T4", "T5", "T6", "T7"]
    test_input: AdaptiveTestInput
    experiment_config: ExperimentConfig
    max_rounds: int = Field(
        default=MAX_ADAPTIVE_ROUNDS,
        ge=1,
        le=MAX_ADAPTIVE_ROUNDS,
    )

    @model_validator(mode="after")
    def require_disabled_defense(self):
        if self.experiment_config.defense_enabled:
            raise ValueError("Adaptive orchestration requires defense_enabled=false")
        return self

    @property
    def configuration_id(self) -> str:
        return f"{self.goal_id}-{self.carrier_id}-{self.strategy_id}"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot load adaptive definition {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"Adaptive definition must contain an object: {path}")
    return value


def _load_configuration_data(
    source: dict[str, Any] | str | Path,
) -> dict[str, Any]:
    if isinstance(source, dict):
        return source
    if isinstance(source, (str, Path)):
        return _read_json(Path(source))
    raise TypeError("Adaptive configuration must be a mapping or JSON path")


def _goal_objective(goal: dict[str, Any]) -> dict[str, Any]:
    return {
        "goal_type": goal["goal_type"],
        "tool": goal["tool"],
        **goal["fixed"],
        "matching": goal["matching"],
    }


def load_adaptive_configuration(
    source: dict[str, Any] | str | Path,
    *,
    root: Path = ROOT,
) -> tuple[AdaptiveConfiguration, dict[str, Any]]:
    """Load one configuration and its existing goal-defined objective."""
    data = _load_configuration_data(source)
    config = AdaptiveConfiguration.model_validate(data)
    definitions_root = Path(root) / "attacks" / "definitions"

    goal_path = next(
        (definitions_root / "goals").glob(f"{config.goal_id}_*.json"),
        None,
    )
    if goal_path is None:
        raise ValueError(f"No goal definition exists for {config.goal_id}")
    goal = _read_json(goal_path)
    if goal.get("goal_id") != config.goal_id:
        raise ValueError(f"Goal definition does not match {config.goal_id}")

    carrier_path = next(
        (definitions_root / "carriers").glob(f"{config.carrier_id}_*.json"),
        None,
    )
    if carrier_path is None:
        raise ValueError(f"No carrier definition exists for {config.carrier_id}")
    carrier = _read_json(carrier_path)
    if config.goal_id not in carrier.get("compatible_goals", []):
        raise ValueError(
            f"Incompatible goal-carrier pair: {config.goal_id}-{config.carrier_id}"
        )

    registry = _read_json(definitions_root / "strategy_eligibility.json")
    canonical = registry.get("canonical_strategy_definitions")
    if not isinstance(canonical, dict):
        raise ValueError("Strategy registry has no canonical definitions")
    relative_strategy_path = canonical.get(config.strategy_id)
    if not isinstance(relative_strategy_path, str) or not relative_strategy_path:
        raise ValueError(f"No canonical definition exists for {config.strategy_id}")
    strategy = _read_json(definitions_root / relative_strategy_path)
    if strategy.get("strategy_id") != config.strategy_id:
        raise ValueError(
            f"Canonical strategy definition does not match {config.strategy_id}"
        )
    if (
        config.strategy_id == "T7"
        and strategy.get("experimental_eligibility") != "eligible"
    ):
        raise ValueError("T7 is not marked eligible for adaptive testing")

    return config, _goal_objective(goal)
