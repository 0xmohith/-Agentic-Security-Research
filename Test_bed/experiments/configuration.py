"""Validated runtime configuration for a single dry-run experiment."""

import secrets
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from config import AGENT_1_MODEL, AGENT_2_MODEL, AGENT_3_MODEL


class AgentModelConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    agent1: str = Field(default=AGENT_1_MODEL, min_length=1)
    agent2: str = Field(default=AGENT_2_MODEL, min_length=1)
    agent3: str = Field(default=AGENT_3_MODEL, min_length=1)


class ExperimentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    agent_model_configuration: AgentModelConfiguration = Field(
        default_factory=AgentModelConfiguration
    )
    agent3_mode: Literal["strict", "neutral"] = "strict"
    defense_enabled: bool = False
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    random_seed: int = Field(
        default_factory=lambda: secrets.randbelow(2**31),
        ge=0,
        le=2**31 - 1,
    )
    top_p: float | None = Field(default=None, gt=0.0, le=1.0)
    top_k: int | None = Field(default=None, gt=0)
    num_predict: int | None = Field(default=None, gt=0)
    repeat_penalty: float | None = Field(default=None, gt=0.0)
    executor_mode: Literal["dry_run"] = "dry_run"
    scenario_version: str | None = None

    def generation_options(self) -> dict:
        """Return the supported Ollama generation options for all agents."""
        options = {
            "temperature": self.temperature,
            "seed": self.random_seed,
        }
        for field in ("top_p", "top_k", "num_predict", "repeat_penalty"):
            value = getattr(self, field)
            if value is not None:
                options[field] = value
        return options


def legacy_experiment_config(defense: str = "none") -> dict:
    """Provide safe defaults without misrepresenting legacy defense labels."""
    if defense not in (None, "", "none"):
        raise NotImplementedError(
            f"Legacy defense {defense!r} has no implemented activation path."
        )

    return {
        "defense_enabled": False,
        "executor_mode": "dry_run",
    }
