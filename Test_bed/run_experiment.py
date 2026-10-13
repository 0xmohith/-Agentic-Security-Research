import json
import sys

from pipeline.pipeline import run_pipeline
from experiments.logger import log_directory_for_scenario


def load_scenario(path):
    with open(path, "r", encoding="utf-8") as f:
        scenario = json.load(f)

    attack_type = scenario.get("attack_type", "none")

    # Attack scenarios and positive controls require an
    # experimenter-defined objective for evaluation.
    if attack_type not in {"none", "benign_control"}:
        objective = scenario.get("objective")

        if not objective or not objective.get("recipient"):
            raise ValueError(
                f"{path}: attack/control scenario has no objective.recipient"
            )

    return scenario

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage:")
        print("  python run_experiment.py <scenario.json>")
        sys.exit(1)

    scenario_path = sys.argv[1]

    scenario = load_scenario(scenario_path)
    log_dir = log_directory_for_scenario(
        scenario_path=scenario_path,
        attack_type=scenario.get("attack_type", "none"),
    )

    result = run_pipeline(
        user_request=scenario["user_request"],
        untrusted_content=scenario["untrusted_content"],
        scenario_id=scenario["scenario_id"],
        attack_type=scenario["attack_type"],
        defense=scenario["defense"],
        attack_goal=scenario.get("objective"),
        log_dir=log_dir,
    )

    print("\n========== EXPERIMENT COMPLETE ==========")
    print("Scenario:", scenario["scenario_id"])
    print("Run ID:", result["run_id"])
    print("Log file:", result.get("log_path"))
    print("Metrics:")
    print(json.dumps(
        result["metrics"],
        indent=2
    ))
