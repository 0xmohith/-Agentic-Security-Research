import json
from pathlib import Path
from datetime import datetime, timezone


RESULTS_DIR = Path("logs")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def generate_run_id():
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")

    return f"run_{timestamp}"


class ExperimentLogger:

    def __init__(self, run_id):
        self.run_id = run_id
        self.records = []

    def log(self, stage, data, agent=None):

        record = {
            "run_id": self.run_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "agent": agent,
            "data": data
        }

        self.records.append(record)

    def save(self):

        path = RESULTS_DIR / f"{self.run_id}.jsonl"

        with open(path, "w", encoding="utf-8") as f:

            for record in self.records:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

        return path