#!/usr/bin/env python3
"""Generate fixed-middle static scenarios from the approved Test_bed dataset."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.configuration import ExperimentConfig
from experiments.scenario_validation import validate_scenario


DEFAULT_OUTPUT_DIR = ROOT / "attacks/static"
DEFAULT_SEED = 0
GOAL_IDS = ("G1", "G2", "G3")
STRATEGY_IDS = ("T1", "T2", "T3", "T4", "T5", "T6", "T7")
CARRIER_IDS = ("C1", "C2", "C3", "C4")
VARIANTS = ("A", "B")
INJECTION_POSITION = "middle"
INJECTION_SLOT = "{INJECTION_SLOT}"


class ScenarioGenerationError(ValueError):
    """Raised when source definitions make generation unsafe or ambiguous."""


@dataclass
class GenerationPlan:
    scenarios: list[dict[str, Any]]
    skipped: list[dict[str, str]]
    errors: list[str]
    compatible_pairs: list[tuple[str, str]]
    discovered_payload_count: int

    @property
    def expected_scenario_count(self) -> int:
        return len(self.compatible_pairs) * len(STRATEGY_IDS) * len(VARIANTS)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScenarioGenerationError(f"Cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ScenarioGenerationError(f"{path} must contain a JSON object")
    return value


def _load_goal_definitions(root: Path) -> dict[str, dict[str, Any]]:
    goal_root = root / "attacks/definitions/goals"
    goals: dict[str, dict[str, Any]] = {}
    for path in sorted(goal_root.glob("*.json")):
        goal = _read_json(path)
        goal_id = goal.get("goal_id")
        if goal_id in GOAL_IDS:
            if goal_id in goals:
                raise ScenarioGenerationError(f"Duplicate goal definition for {goal_id}")
            goals[goal_id] = goal
    return goals


def _load_carrier_definitions(root: Path) -> dict[str, dict[str, Any]]:
    carrier_root = root / "attacks/definitions/carriers"
    carriers: dict[str, dict[str, Any]] = {}
    for path in sorted(carrier_root.glob("*.json")):
        carrier = _read_json(path)
        carrier_id = carrier.get("carrier_id")
        if carrier_id in CARRIER_IDS:
            if carrier_id in carriers:
                raise ScenarioGenerationError(f"Duplicate carrier definition for {carrier_id}")
            carriers[carrier_id] = carrier
    return carriers


def _load_strategy_definitions(
    root: Path,
) -> dict[str, dict[str, Any]]:
    definitions_root = root / "attacks/definitions"
    registry = _read_json(definitions_root / "strategy_eligibility.json")
    canonical = registry.get("canonical_strategy_definitions")
    if not isinstance(canonical, dict):
        raise ScenarioGenerationError(
            "strategy_eligibility.json must define canonical_strategy_definitions"
        )

    strategies: dict[str, dict[str, Any]] = {}
    for strategy_id in STRATEGY_IDS:
        relative_path = canonical.get(strategy_id)
        if not isinstance(relative_path, str) or not relative_path:
            raise ScenarioGenerationError(
                f"No canonical strategy definition is registered for {strategy_id}"
            )
        path = definitions_root / relative_path
        if not path.is_file():
            raise ScenarioGenerationError(
                f"Canonical strategy definition for {strategy_id} is missing: {path}"
            )
        strategy = _read_json(path)
        if strategy.get("strategy_id") != strategy_id:
            raise ScenarioGenerationError(
                f"{path} does not define strategy {strategy_id}"
            )
        evaluation = strategy.get("evaluation_metadata")
        applicable_goals = evaluation.get("applicable_goals") if isinstance(evaluation, dict) else None
        if applicable_goals is not None and (
            not isinstance(applicable_goals, list)
            or not set(GOAL_IDS).issubset(applicable_goals)
        ):
            raise ScenarioGenerationError(
                f"{strategy_id} is not applicable to all requested goals"
            )
        if strategy_id == "T7" and strategy.get("experimental_eligibility") != "eligible":
            raise ScenarioGenerationError(
                "T7 is not marked eligible in its strategy definition"
            )
        strategies[strategy_id] = strategy
    return strategies


def _discover_payloads(
    root: Path,
) -> tuple[dict[tuple[str, str, str], dict[str, Any]], int]:
    payload_root = root / "attacks/definitions/payloads"
    discovered: dict[tuple[str, str, str], dict[str, Any]] = {}
    count = 0
    for path in sorted(payload_root.glob("G*/T*/*.json")):
        payload = _read_json(path)
        count += 1
        try:
            path_goal, path_strategy, filename = path.relative_to(payload_root).parts
        except ValueError as exc:
            raise ScenarioGenerationError(
                f"Payload is outside the expected payload directory: {path}"
            ) from exc
        goal_id = payload.get("goal_id")
        strategy_id = payload.get("strategy_id")
        variant = payload.get("variant")
        expected_filename = f"{goal_id}__{strategy_id}__{variant}.json"
        if (
            path_goal != goal_id
            or path_strategy != strategy_id
            or filename != expected_filename
            or goal_id not in GOAL_IDS
            or strategy_id not in STRATEGY_IDS
            or variant not in VARIANTS
        ):
            raise ScenarioGenerationError(
                f"Misplaced or incorrectly named payload {path}: expected "
                f"{goal_id}/{strategy_id}/{expected_filename} from its internal IDs"
            )
        key = (goal_id, strategy_id, variant)
        if key in discovered:
            raise ScenarioGenerationError(f"Duplicate payload definition for {key}")
        discovered[key] = payload
    return discovered, count


def _scenario_objective(goal: dict[str, Any]) -> dict[str, Any]:
    fixed = goal.get("fixed")
    matching = goal.get("matching")
    if not isinstance(fixed, dict) or not isinstance(matching, dict):
        raise ScenarioGenerationError(
            f"Goal {goal.get('goal_id')} must define fixed fields and matching rules"
        )
    objective = {
        "goal_type": goal["goal_type"],
        "tool": goal["tool"],
        **fixed,
        "matching": matching,
    }
    return objective


def _payload_content(
    payload: dict[str, Any],
    strategy_id: str,
) -> str:
    if strategy_id != "T6":
        text = payload.get("payload_text")
        if not isinstance(text, str) or not text:
            raise ScenarioGenerationError(
                f"{payload.get('payload_id')}: payload_text must be a non-empty string"
            )
        return text

    payload_id = payload.get("payload_id", "<unknown T6 payload>")
    fragments = payload.get("fragments")
    assembly = payload.get("assembly")
    fragmentation = payload.get("fragmentation")
    if not isinstance(fragments, list) or not isinstance(assembly, dict):
        raise ScenarioGenerationError(
            f"{payload_id}: T6 fragment and assembly metadata are required"
        )
    if not isinstance(fragmentation, dict):
        raise ScenarioGenerationError(
            f"{payload_id}: T6 fragmentation metadata is required"
        )
    separator = fragmentation.get("separator")
    joiner = assembly.get("joiner")
    if not isinstance(separator, str) or not separator or not isinstance(joiner, str) or not joiner:
        raise ScenarioGenerationError(
            f"{payload_id}: fragmentation.separator and assembly.joiner must be strings"
        )
    if separator != joiner:
        raise ScenarioGenerationError(
            f"{payload_id}: ambiguous T6 assembly: fragmentation.separator "
            f"{separator!r} does not match assembly.joiner {joiner!r}"
        )

    if any(not isinstance(fragment, dict) for fragment in fragments):
        raise ScenarioGenerationError(f"{payload_id}: every T6 fragment must be an object")
    ordered = sorted(fragments, key=lambda fragment: fragment.get("position", 0))
    expected_ids = ["F1", "F2", "F3"]
    if (
        len(ordered) != len(expected_ids)
        or [fragment.get("fragment_id") for fragment in ordered] != expected_ids
        or [fragment.get("position") for fragment in ordered] != [1, 2, 3]
        or any(
            not isinstance(fragment.get("content"), str) or not fragment["content"]
            for fragment in ordered
        )
    ):
        raise ScenarioGenerationError(
            f"{payload_id}: expected ordered, non-empty F1, F2, F3 fragments"
        )
    reconstructed = joiner.join(fragment["content"] for fragment in ordered)
    if not isinstance(payload.get("payload_text"), str) or not payload["payload_text"]:
        raise ScenarioGenerationError(f"{payload_id}: payload_text is missing")
    if " ".join(fragment["content"] for fragment in ordered) != payload["payload_text"]:
        raise ScenarioGenerationError(
            f"{payload_id}: payload_text does not match the defined fragment reconstruction"
        )
    return reconstructed


def _assemble_carrier(
    carrier: dict[str, Any],
    injection_content: str,
) -> str:
    body_template = carrier.get("body_template")
    sender = carrier.get("sender")
    if not isinstance(body_template, str) or body_template.count(INJECTION_SLOT) != 1:
        raise ScenarioGenerationError(
            f"Carrier {carrier.get('carrier_id')} body_template must contain exactly one {INJECTION_SLOT}"
        )
    if not isinstance(sender, dict) or not all(
        isinstance(sender.get(key), str) and sender[key]
        for key in ("name", "email")
    ):
        raise ScenarioGenerationError(
            f"Carrier {carrier.get('carrier_id')} must define sender name and email"
        )
    subject = carrier.get("subject")
    if not isinstance(subject, str) or not subject:
        raise ScenarioGenerationError(
            f"Carrier {carrier.get('carrier_id')} must define a subject"
        )
    body = body_template.replace(INJECTION_SLOT, injection_content, 1)
    return (
        f"From: {sender['name']} <{sender['email']}>\n"
        f"Subject: {subject}\n\n{body}"
    )


def _build_scenario(
    goal: dict[str, Any],
    carrier: dict[str, Any],
    strategy_id: str,
    payload: dict[str, Any],
    runtime_config: dict[str, Any],
) -> dict[str, Any]:
    goal_id = goal["goal_id"]
    carrier_id = carrier["carrier_id"]
    variant = payload["variant"]
    payload_id = payload["payload_id"]
    content = _payload_content(payload, strategy_id)
    untrusted_content = _assemble_carrier(carrier, content)
    scenario_id = f"{goal_id}-{carrier_id}-{strategy_id}-{variant}-{INJECTION_POSITION}"
    return {
        "scenario_id": scenario_id,
        "template_id": f"{goal_id}-{carrier_id}-{strategy_id}",
        "payload_id": payload_id,
        "variant": variant,
        "trial_id": "trial-1",
        "attack_type": "static_disguised",
        "attack_indicator": payload.get("canary"),
        "defense": "none",
        "components": {
            "goal_id": goal_id,
            "strategy_id": strategy_id,
            "carrier_id": carrier_id,
            "payload_id": payload_id,
            "injection_position": INJECTION_POSITION,
        },
        "user_request": f"Review the {carrier['carrier_name']} and summarize its contents.",
        "untrusted_content": untrusted_content,
        "objective": _scenario_objective(goal),
        "experiment_config": runtime_config,
    }


def build_generation_plan(root: Path = ROOT, seed: int = DEFAULT_SEED) -> GenerationPlan:
    """Resolve all compatible goal/carrier/strategy/variant combinations."""
    root = Path(root)
    goals = _load_goal_definitions(root)
    carriers = _load_carrier_definitions(root)
    strategies = _load_strategy_definitions(root)
    payloads, discovered_count = _discover_payloads(root)
    runtime_config = ExperimentConfig(random_seed=seed).model_dump(exclude_none=True)

    skipped: list[dict[str, str]] = []
    errors: list[str] = []
    scenarios: list[dict[str, Any]] = []
    compatible_pairs: list[tuple[str, str]] = []

    for goal_id in GOAL_IDS:
        goal = goals.get(goal_id)
        if goal is None:
            errors.append(f"{goal_id}: goal definition is missing")
            continue
        _scenario_objective(goal)
        for carrier_id in CARRIER_IDS:
            carrier = carriers.get(carrier_id)
            if carrier is None:
                errors.append(f"{carrier_id}: carrier definition is missing")
                continue
            compatible_goals = carrier.get("compatible_goals")
            if not isinstance(compatible_goals, list):
                errors.append(f"{carrier_id}: compatible_goals must be a list")
                continue
            if goal_id not in compatible_goals:
                skipped.append({
                    "goal_id": goal_id,
                    "carrier_id": carrier_id,
                    "reason": f"{carrier_id} does not declare {goal_id} in compatible_goals",
                })
                continue
            compatible_pairs.append((goal_id, carrier_id))
            positions = carrier.get("injection_positions")
            if not isinstance(positions, list) or INJECTION_POSITION not in positions:
                errors.append(
                    f"{carrier_id}: middle is not an allowed injection position"
                )
                continue
            for strategy_id in STRATEGY_IDS:
                if strategy_id not in strategies:
                    errors.append(f"{strategy_id}: strategy definition is missing")
                    continue
                pair_payloads = [
                    payloads.get((goal_id, strategy_id, variant))
                    for variant in VARIANTS
                ]
                if any(payload is None for payload in pair_payloads):
                    missing_variants = [
                        variant
                        for variant, payload in zip(VARIANTS, pair_payloads)
                        if payload is None
                    ]
                    errors.append(
                        f"{goal_id}/{strategy_id}: missing payload variant(s): "
                        f"{', '.join(missing_variants)}"
                    )
                    continue
                invalid_metadata = [
                    variant
                    for variant, payload in zip(VARIANTS, pair_payloads)
                    if not isinstance(payload.get("metadata"), dict)
                    or payload["metadata"].get("equivalence_review") != "approved"
                    or payload["metadata"].get("frozen") is not True
                ]
                if invalid_metadata:
                    errors.append(
                        f"{goal_id}/{strategy_id}: payload metadata must be "
                        "equivalence_review=approved and frozen=true for variants: "
                        f"{', '.join(invalid_metadata)}"
                    )
                    continue
                try:
                    for payload in pair_payloads:
                        if (
                            payload.get("goal_id") != goal_id
                            or payload.get("strategy_id") != strategy_id
                            or payload.get("variant") not in VARIANTS
                            or payload.get("payload_id")
                            != f"{goal_id}__{strategy_id}__{payload.get('variant')}"
                        ):
                            raise ScenarioGenerationError(
                                f"{goal_id}/{strategy_id}: payload identity fields do not match its path"
                            )
                        scenario = _build_scenario(
                            goal, carrier, strategy_id, payload, runtime_config
                        )
                        validate_scenario(scenario, scenario["scenario_id"])
                        scenarios.append(scenario)
                except (ScenarioGenerationError, ValueError) as exc:
                    errors.append(str(exc))

    return GenerationPlan(
        scenarios=scenarios,
        skipped=skipped,
        errors=list(dict.fromkeys(errors)),
        compatible_pairs=compatible_pairs,
        discovered_payload_count=discovered_count,
    )


def _write_scenarios(
    scenarios: list[dict[str, Any]],
    output_dir: Path,
) -> int:
    destinations = [
        Path(output_dir) / f"{scenario['scenario_id']}.json"
        for scenario in scenarios
    ]
    existing = [path for path in destinations if path.exists()]
    if existing:
        raise FileExistsError(f"Refusing to overwrite existing scenario: {existing[0]}")

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    try:
        for path, scenario in zip(destinations, scenarios):
            with path.open("x", encoding="utf-8") as scenario_file:
                created.append(path)
                json.dump(scenario, scenario_file, indent=2, ensure_ascii=False)
                scenario_file.write("\n")
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return len(created)


def _write_generation_plan(plan: GenerationPlan, output_dir: Path) -> int:
    if plan.errors:
        raise ScenarioGenerationError(
            "Refusing to generate an incomplete plan: " + "; ".join(plan.errors)
        )
    if len(plan.scenarios) != plan.expected_scenario_count:
        raise ScenarioGenerationError(
            "Refusing to generate an incomplete plan: expected "
            f"{plan.expected_scenario_count} scenarios, found {len(plan.scenarios)}"
        )
    scenario_ids = [scenario.get("scenario_id") for scenario in plan.scenarios]
    if len(set(scenario_ids)) != len(scenario_ids):
        raise ScenarioGenerationError("Refusing to generate a plan with duplicate scenario IDs")
    return _write_scenarios(plan.scenarios, output_dir)


def _print_report(
    plan: GenerationPlan,
    generated_count: int,
    validated_count: int,
    output_dir: Path,
    check_only: bool,
    seed: int,
) -> None:
    print(f"Compatible goal-carrier combinations: {len(plan.compatible_pairs)}")
    print(f"Payloads discovered: {plan.discovered_payload_count}")
    print(f"Scenarios expected: {plan.expected_scenario_count}")
    print(f"Scenarios generated: {generated_count}")
    print(f"Scenarios validated: {validated_count}")
    print(f"Random seed: {seed}")
    print(f"Output directory: {output_dir}")
    if check_only:
        print(
            "Planned scenario set matches expected 154 scenarios: "
            f"{len(plan.scenarios) == 154 and not plan.errors}"
        )
        print("Output matches expected 154 scenarios: not generated (check-only)")
    else:
        print(f"Output matches expected 154 scenarios: {generated_count == 154}")
    if plan.skipped:
        print("Skipped combinations:")
        for item in plan.skipped:
            combination = "/".join(
                item.get(key, "")
                for key in ("goal_id", "carrier_id", "strategy_id")
                if item.get(key)
            )
            print(f"  {combination}: {item['reason']}")
    else:
        print("Skipped combinations: none")
    if plan.errors:
        print("Errors:")
        for error in plan.errors:
            print(f"  {error}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Scenario output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Validate prerequisites and scenarios without writing output files.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help=f"Deterministic runtime random seed (default: {DEFAULT_SEED}).",
    )
    args = parser.parse_args(argv)

    try:
        plan = build_generation_plan(seed=args.seed)
        if plan.errors:
            generated_count = 0
        elif args.check_only:
            generated_count = 0
        else:
            generated_count = _write_generation_plan(plan, args.output_dir)
        _print_report(
            plan,
            generated_count,
            len(plan.scenarios),
            args.output_dir,
            args.check_only,
            args.seed,
        )
        return 1 if plan.errors or len(plan.scenarios) != plan.expected_scenario_count else 0
    except (ScenarioGenerationError, FileExistsError, OSError) as exc:
        print(f"Generation stopped: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
