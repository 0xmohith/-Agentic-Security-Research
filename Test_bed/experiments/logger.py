import json
from pathlib import Path
from datetime import datetime, timezone


DEFAULT_LOG_DIR = Path("logs/historical")

def _to_jsonable(value):
    """Recursively convert values into JSON-serializable data."""
    if hasattr(value, "model_dump"):
        return _to_jsonable(value.model_dump(mode="json"))

    if hasattr(value, "dict") and callable(value.dict):
        return _to_jsonable(value.dict())

    if isinstance(value, dict):
        return {
            str(key): _to_jsonable(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [_to_jsonable(item) for item in value]

    return value

def log_directory_for_scenario(scenario_path=None, attack_type="none"):
    """Map a scenario source/type to its corresponding logs subdirectory."""
    source_parts = {part.lower() for part in Path(scenario_path or "").parts}

    # Source directories are authoritative because they distinguish controls
    # from static/adaptive attack runs, even when their labels are similar.
    source_routes = {
        "adaptive": "adaptive",
        "static": "static",
        "controls": "controls",
        "benign": "benign",
        "validation": "validation",
    }
    for source_name, log_name in source_routes.items():
        if source_name in source_parts:
            return Path("logs") / log_name

    normalized_type = (attack_type or "none").lower()
    type_routes = (
        ("adaptive", "adaptive"),
        ("static", "static"),
        ("control", "controls"),
        ("benign", "benign"),
        ("canary", "validation"),
    )
    for marker, log_name in type_routes:
        if marker in normalized_type:
            return Path("logs") / log_name

    return DEFAULT_LOG_DIR


def generate_run_id():
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")

    return f"run_{timestamp}"


class ExperimentLogger:

    def __init__(self, run_id, output_dir=DEFAULT_LOG_DIR):
        self.run_id = run_id
        self.records = []
        self.output_dir = Path(output_dir)
        self.saved_path = None

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

        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / f"{self.run_id}.jsonl"

        with open(path, "w", encoding="utf-8") as f:

            for record in self.records:
               f.write(
                json.dumps(
                     _to_jsonable(record),
                     ensure_ascii=False,
                     allow_nan=False,
                    ) + "\n"
                )

        self.saved_path = path
        return path
