"""JSONL logging for mock-only adaptive orchestration runs."""

from pathlib import Path

from experiments.logger import ExperimentLogger, log_directory_for_scenario


class AdaptiveLogger(ExperimentLogger):
    """Use the existing JSONL format while routing records to logs/adaptive."""

    def __init__(self, execution_id: str, output_dir: str | Path | None = None):
        adaptive_dir = (
            Path(output_dir)
            if output_dir is not None
            else log_directory_for_scenario(scenario_path="adaptive")
        )
        super().__init__(execution_id, output_dir=adaptive_dir)

    def log_round(self, data: dict) -> None:
        self.log(stage="ADAPTIVE_ROUND", data=data)

    def log_trial(self, data: dict) -> None:
        self.log(stage="ADAPTIVE_TRIAL", data=data)
