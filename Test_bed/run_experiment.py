import json
import sys

from pipeline.pipeline import run_pipeline
from experiments.logger import log_directory_for_scenario
from experiments.configuration import ExperimentConfig, legacy_experiment_config
from experiments.scenario_validation import validate_scenario


def load_scenario(path):
    with open(path, "r", encoding="utf-8") as f:
        scenario = json.load(f)

    validate_scenario(scenario, str(path))

    attack_type = scenario.get("attack_type", "none")

    # Attack scenarios and positive controls require an
    # experimenter-defined objective appropriate to their tool.
    if attack_type not in {"none", "benign_control"}:
        objective = scenario.get("objective")

        if not isinstance(objective, dict):
            raise ValueError(
                f"{path}: attack/control scenario requires an objective object"
            )

        tool = objective.get("tool")

        if tool == "send_email":
            required_fields = ("recipient",)
        elif tool == "add_calendar_event":
            required_fields = ("title", "time")
        else:
            raise ValueError(
                f"{path}: unsupported or missing objective.tool: {tool!r}"
            )

        missing = [
            field for field in required_fields
            if not objective.get(field)
        ]

        if missing:
            raise ValueError(
                f"{path}: objective for {tool} is missing: "
                + ", ".join(missing)
            )

    return scenario


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage:")
        print("  python run_experiment.py <scenario.json>")
        sys.exit(1)

    scenario_path = sys.argv[1]

    scenario = load_scenario(scenario_path)
    experiment_config = ExperimentConfig.model_validate(
        scenario.get(
            "experiment_config",
            legacy_experiment_config(scenario.get("defense", "none")),
        )
    )
    components = scenario.get("components", {})

    log_dir = log_directory_for_scenario(
        scenario_path=scenario_path,
        attack_type=scenario.get("attack_type", "none"),
    )

    result = run_pipeline(
        user_request=scenario["user_request"],
        untrusted_content=scenario["untrusted_content"],
        scenario_id=scenario["scenario_id"],
        attack_type=scenario.get("attack_type", "none"),
        defense=scenario.get("defense", "none"),
        attack_goal=scenario.get("objective"),
        attack_indicator=scenario.get("attack_indicator"),
        log_dir=log_dir,
        experiment_config=experiment_config,
        experiment_metadata={
            "template_id": scenario.get("template_id", "legacy"),
            "payload_id": scenario.get(
                "payload_id",
                components.get("payload_id"),
            ),
            "variant": scenario.get("variant"),
            "trial_id": scenario.get("trial_id", "legacy"),
            "injection_position": components.get("injection_position"),
        },
    )

    print("\n========== EXPERIMENT COMPLETE ==========")
    print("Scenario:", scenario["scenario_id"])
    print("Run ID:", result["run_id"])
    print("Log file:", result.get("log_path"))
    print("Metrics:")
    print(json.dumps(result["metrics"], indent=2))