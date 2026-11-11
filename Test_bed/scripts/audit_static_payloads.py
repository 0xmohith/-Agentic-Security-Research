#!/usr/bin/env python3
"""Read-only structural and consistency audit for static payload fixtures."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PAYLOAD_ROOT = ROOT / "attacks/definitions/payloads"
GOAL_ROOT = ROOT / "attacks/definitions/goals"
STRATEGY_ROOT = ROOT / "attacks/definitions/strategies"
REVIEW_PATH = ROOT / "attacks/definitions/reviews/static_payload_equivalence_review_v1.json"
ELIGIBILITY_PATH = ROOT / "attacks/definitions/strategy_eligibility.json"
CARRIER_ROOT = ROOT / "attacks/definitions/carriers"
GOALS = ("G1", "G2", "G3")
STRATEGIES = ("T1", "T2", "T3", "T4", "T5", "T6", "T7")
VARIANTS = ("A", "B")
EXPECTED_COUNT = len(GOALS) * len(STRATEGIES) * len(VARIANTS)
CORRECTIONS = {
    "G2__T2__A": ("inits body", "in its body"),
    "G3__T2__A": ("eventtitled", "event titled"),
    "G3__T3__B": ("ProjectAlpha Review", "Project Alpha Review"),
    "G3__T5__B": ("at2026-11-10T10:00", "at 2026-11-10T10:00"),
}
T7_RELAY_MARKER_PATTERN = re.compile(
    r"\b(?:relay(?:[-_ ]?(?:tracking|aware|marker))?"
    r"|stage[-_ ]?[1-5]|S[1-5]|B[12])\b",
    re.IGNORECASE,
)


def read_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, str(exc)


def goal_path(goal_id: str) -> Path | None:
    matches = sorted(GOAL_ROOT.glob(f"{goal_id}_*.json"))
    return matches[0] if len(matches) == 1 else None


def add(items: list[dict[str, str]], severity: str, code: str, file: str, message: str) -> None:
    items.append({"severity": severity, "code": code, "file": file, "message": message})


def audit() -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    pair_findings: list[dict[str, Any]] = []
    consistency: list[dict[str, str]] = []
    expected: dict[str, dict[str, Any]] = {}
    found: list[str] = []
    missing: list[str] = []
    payload_texts: dict[str, list[str]] = defaultdict(list)
    canaries: dict[str, list[str]] = defaultdict(list)

    goals: dict[str, dict[str, Any]] = {}
    for gid in GOALS:
        path = goal_path(gid)
        if path is None:
            add(errors, "FAIL", "goal_definition", str(GOAL_ROOT), f"Expected exactly one {gid} goal definition; found {len(list(GOAL_ROOT.glob(gid + '_*.json')))}.")
            continue
        data, error = read_json(path)
        if error or not isinstance(data, dict):
            add(errors, "FAIL", "goal_definition_json", str(path.relative_to(ROOT)), f"Cannot read goal definition: {error or 'top-level JSON value is not an object'}.")
            continue
        if data.get("goal_id") != gid:
            add(errors, "FAIL", "goal_definition_id", str(path.relative_to(ROOT)), f"goal_id is {data.get('goal_id')!r}, expected {gid}.")
        needed = ("fixed", "evaluator_fields", "canary_field", "matching", "tool")
        absent = [key for key in needed if key not in data]
        if absent:
            add(errors, "FAIL", "goal_definition_information", str(path.relative_to(ROOT)), "Missing required objective definition field(s): " + ", ".join(absent) + ".")
        goals[gid] = data

    strategy_paths = {
        path.stem.split("_")[0]: path
        for path in STRATEGY_ROOT.glob("T[1-7]_*.json")
    }
    eligibility, eligibility_error = read_json(ELIGIBILITY_PATH)
    if eligibility_error or not isinstance(eligibility, dict):
        add(errors, "FAIL", "strategy_eligibility_json", str(ELIGIBILITY_PATH.relative_to(ROOT)), f"Cannot read strategy eligibility: {eligibility_error or 'top-level JSON value is not an object'}.")
        eligibility = {}
    canonical = eligibility.get("canonical_strategy_definitions", {})
    if not isinstance(canonical, dict):
        add(errors, "FAIL", "strategy_eligibility", str(ELIGIBILITY_PATH.relative_to(ROOT)), "canonical_strategy_definitions must be an object.")
        canonical = {}

    strategies: dict[str, dict[str, Any]] = {}
    for sid in STRATEGIES:
        path = strategy_paths.get(sid)
        if path is None:
            add(errors, "FAIL", "strategy_definition", str(STRATEGY_ROOT), f"No definition file found for {sid}.")
            continue
        if canonical.get(sid) != f"strategies/{path.name}":
            add(errors, "FAIL", "canonical_strategy_mapping", str(ELIGIBILITY_PATH.relative_to(ROOT)), f"{sid} must map to strategies/{path.name}.")
        data, error = read_json(path)
        if error or not isinstance(data, dict):
            add(errors, "FAIL", "strategy_definition_json", str(path.relative_to(ROOT)), f"Cannot read strategy definition: {error or 'top-level JSON value is not an object'}.")
            continue
        if data.get("strategy_id") != sid:
            add(errors, "FAIL", "strategy_definition_id", str(path.relative_to(ROOT)), f"strategy_id is {data.get('strategy_id')!r}, expected {sid}.")
        evaluation = data.get("evaluation_metadata")
        if not isinstance(evaluation, dict) or evaluation.get("applicable_goals") != list(GOALS):
            add(errors, "FAIL", "strategy_applicable_goals", str(path.relative_to(ROOT)), f"applicable_goals must be {list(GOALS)}.")
        strategies[sid] = data
    if len(canonical) != len(STRATEGIES) or set(canonical) != set(STRATEGIES):
        add(errors, "FAIL", "canonical_strategy_inventory", str(ELIGIBILITY_PATH.relative_to(ROOT)), "Canonical mappings must cover exactly T1-T7.")
    if strategies.get("T7", {}).get("experimental_eligibility") != "eligible":
        add(errors, "FAIL", "t7_eligibility", "attacks/definitions/strategies/T7_relay_aware_injection.json", "T7 must be eligible for the approved dataset.")
    fixture_entries = eligibility.get("fixture_eligibility", [])
    if not isinstance(fixture_entries, list) or any(
        isinstance(item, dict) and item.get("strategy_id") == "T7"
        for item in fixture_entries
    ):
        add(errors, "FAIL", "t7_fixture_eligibility", str(ELIGIBILITY_PATH.relative_to(ROOT)), "T7 must not be restricted to fixture-only eligibility.")

    carrier_ids: set[str] = set()
    compatible_goals: set[str] = set()
    for path in sorted(CARRIER_ROOT.glob("*.json")):
        data, error = read_json(path)
        if error or not isinstance(data, dict):
            add(errors, "FAIL", "carrier_definition_json", str(path.relative_to(ROOT)), f"Cannot read carrier definition: {error or 'top-level JSON value is not an object'}.")
            continue
        carrier_id = data.get("carrier_id")
        goals_for_carrier = data.get("compatible_goals")
        if not isinstance(carrier_id, str) or not carrier_id:
            add(errors, "FAIL", "carrier_definition_id", str(path.relative_to(ROOT)), "carrier_id must be a non-empty string.")
        elif carrier_id in carrier_ids:
            add(errors, "FAIL", "duplicate_carrier_id", str(path.relative_to(ROOT)), f"Duplicate carrier_id {carrier_id!r}.")
        else:
            carrier_ids.add(carrier_id)
        if not isinstance(goals_for_carrier, list):
            add(errors, "FAIL", "carrier_goal_compatibility", str(path.relative_to(ROOT)), "compatible_goals must be a list.")
            continue
        invalid_goals = set(goals_for_carrier) - set(GOALS)
        if invalid_goals:
            add(errors, "FAIL", "carrier_goal_compatibility", str(path.relative_to(ROOT)), f"Unknown compatible goal IDs: {sorted(invalid_goals)}.")
        compatible_goals.update(goal for goal in goals_for_carrier if goal in GOALS)
    if not carrier_ids:
        add(errors, "FAIL", "carrier_inventory", str(CARRIER_ROOT.relative_to(ROOT)), "No carrier definitions found.")
    for gid in GOALS:
        if gid not in compatible_goals:
            add(errors, "FAIL", "carrier_goal_coverage", str(CARRIER_ROOT.relative_to(ROOT)), f"No carrier is compatible with {gid}.")

    for gid in GOALS:
        for sid in STRATEGIES:
            for variant in VARIANTS:
                rel = f"attacks/definitions/payloads/{gid}/{sid}/{gid}__{sid}__{variant}.json"
                path = ROOT / rel
                expected[rel] = {"goal": gid, "strategy": sid, "variant": variant}
                if not path.is_file():
                    missing.append(rel)
                    add(errors, "FAIL", "missing_expected_payload", rel, "Expected experimental payload file is missing.")
                    continue
                found.append(rel)
                data, error = read_json(path)
                if error:
                    add(errors, "FAIL", "json_parse", rel, error)
                    continue
                if not isinstance(data, dict):
                    add(errors, "FAIL", "json_type", rel, "Top-level JSON value must be an object.")
                    continue
                for key, value in (("payload_id", f"{gid}__{sid}__{variant}"), ("goal_id", gid), ("strategy_id", sid), ("variant", variant)):
                    if data.get(key) != value:
                        add(errors, "FAIL", "identity_mismatch", rel, f"{key} is {data.get(key)!r}; expected {value!r}.")
                text = data.get("payload_text")
                if not isinstance(text, str) or not text:
                    add(errors, "FAIL", "payload_text", rel, "payload_text must be a non-empty string.")
                    text = ""
                elif text != text.strip():
                    add(errors, "FAIL", "payload_text_whitespace", rel, "payload_text has leading or trailing whitespace.")
                canary = data.get("canary")
                if not isinstance(canary, str) or not canary:
                    add(errors, "FAIL", "canary", rel, "canary must be a non-empty string.")
                elif canary not in text:
                    add(errors, "FAIL", "canary_missing_from_text", rel, "canary does not occur in payload_text.")
                else:
                    canaries[canary].append(rel)
                if text:
                    payload_texts[text].append(rel)
                    if data.get("word_count") != len(text.split()):
                        add(errors, "FAIL", "word_count", rel, f"word_count is {data.get('word_count')!r}; expected {len(text.split())}.")
                    if re.search(r"\s{2,}", text):
                        add(warnings, "WARNING", "repeated_whitespace", rel, "Repeated whitespace found; review whether intentional.")
                    if any(ord(ch) < 32 and ch not in "\t\n\r" for ch in text):
                        add(errors, "FAIL", "control_character", rel, "Unexpected control character in payload_text.")
                    elif any(ch in "\t\n\r" for ch in text):
                        add(warnings, "WARNING", "line_control_character", rel, "Tab or newline in payload_text requires manual review.")
                    prose_for_spacing = re.sub(r"\bhttps?://\S+|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", " ", text)
                    if re.search(r"[.!?][A-Za-z][a-z]{2,}", prose_for_spacing):
                        add(warnings, "WARNING", "possible_missing_space", rel, "Possible missing space after sentence punctuation; inspect manually.")
                    if re.search(r"\w@[\w.-]+\.(?:com|org|net|edu|gov)\w", text, re.I):
                        add(warnings, "WARNING", "email_concatenation", rel, "Possible text concatenated directly to an email address; inspect manually.")
                    if text.count('"') % 2:
                        add(warnings, "WARNING", "quotation_marks", rel, "Unbalanced straight quotation mark; inspect manually.")
                    if re.search(r"(?:^|\s)[,;:](?:\s|$)|(?:[!?.,]){2,}", text):
                        add(warnings, "WARNING", "punctuation", rel, "Suspicious punctuation pattern; inspect manually.")
                    if re.search(r"(?:^|\s)(?:[.!?]\s*){2,}(?:$|[A-Z])", text):
                        add(warnings, "WARNING", "empty_sentence", rel, "Possible empty sentence; inspect manually.")
                for key in ("dataset_version",):
                    if key not in data or data[key] in (None, ""):
                        add(errors, "FAIL", "missing_version", rel, f"{key} must exist and be non-empty.")
                meta = data.get("metadata")
                requirements = {
                    "is_adaptive": False,
                    "generation_method": "manual",
                    "equivalence_review": "approved",
                    "frozen": True,
                }
                if not isinstance(meta, dict):
                    add(errors, "FAIL", "metadata", rel, "metadata must be an object.")
                else:
                    for key, expected_value in requirements.items():
                        if meta.get(key) != expected_value:
                            add(errors, "FAIL", "metadata_value", rel, f"metadata.{key} is {meta.get(key)!r}; expected {expected_value!r}.")
                if gid in goals:
                    goal = goals[gid]
                    fixed = goal.get("fixed")
                    if isinstance(fixed, dict):
                        for field, value in fixed.items():
                            if not isinstance(value, str) or value not in text:
                                add(errors, "FAIL", "objective_fixed_value", rel, f"Goal-defined fixed value {field} is not present in payload_text.")
                    else:
                        add(errors, "FAIL", "objective_definition", rel, "Goal fixed values are unavailable; objective consistency cannot be checked.")
                if sid == "T7":
                    if data.get("dataset_version") != "v1":
                        add(errors, "FAIL", "t7_dataset_version", rel, "dataset_version must be 'v1'.")
                    if data.get("mechanism") != "relay_aware":
                        add(errors, "FAIL", "t7_mechanism", rel, "mechanism must be 'relay_aware'.")
                    if data.get("relay_aware") is not True:
                        add(errors, "FAIL", "t7_relay_aware", rel, "relay_aware must be true.")
                    if not isinstance(text, str) or not text:
                        add(errors, "FAIL", "t7_payload_text", rel, "T7 payload_text must be a non-empty string.")
                    if not isinstance(canary, str) or not canary or canary not in text:
                        add(errors, "FAIL", "t7_canary", rel, "T7 payload_text must contain its declared canary.")
                    if T7_RELAY_MARKER_PATTERN.search(text):
                        add(warnings, "WARNING", "t7_relay_marker", rel, "T7 payload_text contains a relay or stage marker; review its consistency with the strategy definition.")

    for duplicate, locations in payload_texts.items():
        if len(locations) > 1:
            add(errors, "FAIL", "duplicate_payload_text", ", ".join(locations), "Identical payload_text occurs in multiple expected payloads.")
    for canary, locations in canaries.items():
        if len(locations) > 1:
            add(errors, "FAIL", "duplicate_canary", ", ".join(locations), f"Canary {canary!r} is not globally unique.")

    # Detect extra payload JSON files in the expected T1-T7 inventory.
    unexpected = []
    for path in sorted(PAYLOAD_ROOT.glob("G*/T[1-7]/*.json")):
        rel = str(path.relative_to(ROOT))
        if rel not in expected:
            unexpected.append(rel)
            add(errors, "FAIL", "unexpected_payload", rel, "Unexpected JSON file in the T1-T7 payload directories.")

    # Pairwise validation uses the payload data already parsed from disk.
    for gid in GOALS:
        for sid in STRATEGIES:
            pair_rel = [f"attacks/definitions/payloads/{gid}/{sid}/{gid}__{sid}__{v}.json" for v in VARIANTS]
            pair_data = []
            for rel in pair_rel:
                data, error = read_json(ROOT / rel) if (ROOT / rel).is_file() else (None, "missing")
                pair_data.append(data if isinstance(data, dict) and error is None else None)
            finding: dict[str, Any] = {"pair": f"{gid}/{sid}", "files": pair_rel, "status": "PASS", "findings": []}
            if None in pair_data:
                finding["status"] = "FAIL"
                finding["findings"].append("Both variants must exist and parse.")
            else:
                a, b = pair_data
                if a.get("goal_id") != b.get("goal_id") or a.get("strategy_id") != b.get("strategy_id"):
                    finding["status"] = "FAIL"; finding["findings"].append("Variants do not share goal and strategy IDs.")
                if a.get("payload_id") == b.get("payload_id"):
                    finding["status"] = "FAIL"; finding["findings"].append("Variants must have distinct payload IDs.")
                if not a.get("canary") or not b.get("canary") or a.get("canary") == b.get("canary"):
                    finding["status"] = "FAIL"; finding["findings"].append("Variants must have distinct non-empty canaries.")
                ca, cb = len(str(a.get("payload_text", "")).split()), len(str(b.get("payload_text", "")).split())
                if max(ca, cb) and abs(ca - cb) / max(ca, cb) > 0.20:
                    finding["status"] = "FAIL"; finding["findings"].append(f"Word counts differ by more than 20% ({ca} vs {cb}).")
                for key in ("version", "dataset_version"):
                    if a.get(key) != b.get(key):
                        finding["status"] = "FAIL"; finding["findings"].append(f"{key} differs between variants.")
                if a.get("metadata") != b.get("metadata"):
                    finding["status"] = "FAIL"; finding["findings"].append("Metadata differs between variants.")
                if any(not isinstance(x.get("metadata"), dict) or x["metadata"].get("frozen") is not True or x["metadata"].get("equivalence_review") != "approved" for x in (a, b)):
                    finding["status"] = "FAIL"; finding["findings"].append("Both variants must be approved and frozen.")
                goal = goals.get(gid, {})
                contract = {k: goal.get(k) for k in ("tool", "evaluator_fields", "matching", "canary_field", "canary_match")}
                if not all(contract.values()):
                    finding["status"] = "FAIL"; finding["findings"].append("Goal tool/evaluator/canary configuration is incomplete.")
                else:
                    finding["findings"].append("Goal-defined tool/evaluator contract is shared; payload files contain no explicit tool/evaluator fields, so prose-level equivalence needs manual review.")
                    add(warnings, "WARNING", "implicit_tool_evaluator_equivalence", " / ".join(pair_rel), "Payload format has no explicit tool/evaluator fields; confirm both texts invoke the goal-defined tool and expected fields.")
                for item in (a, b):
                    text = item.get("payload_text", "")
                    fixed = goal.get("fixed", {})
                    if not isinstance(fixed, dict) or any(not isinstance(v, str) or v not in text for v in fixed.values()):
                        finding["status"] = "FAIL"; finding["findings"].append("A variant omits one or more goal-defined fixed objective values.")
            pair_findings.append(finding)

    review, review_error = read_json(REVIEW_PATH)
    if review_error or not isinstance(review, dict):
        add(errors, "FAIL", "equivalence_review_json", str(REVIEW_PATH.relative_to(ROOT)), f"Cannot read equivalence review: {review_error or 'top-level JSON value is not an object'}.")
        review = {}
    review_scope = review.get("review_scope", {})
    if (
        not isinstance(review_scope, dict)
        or review_scope.get("strategies") != list(STRATEGIES)
        or review_scope.get("goals") != list(GOALS)
        or review_scope.get("pairs_per_goal") != len(STRATEGIES)
        or review_scope.get("total_pairs") != len(GOALS) * len(STRATEGIES)
        or review_scope.get("variants") != list(VARIANTS)
    ):
        add(errors, "FAIL", "equivalence_review_scope", str(REVIEW_PATH.relative_to(ROOT)), "Review scope must cover G1-G3, T1-T7, 21 A/B pairs.")
    pair_reviews = review.get("pair_reviews", [])
    expected_pairs = {(goal, strategy) for goal in GOALS for strategy in STRATEGIES}
    reviewed_pairs: set[tuple[str, str]] = set()
    if not isinstance(pair_reviews, list):
        add(errors, "FAIL", "equivalence_pair_reviews", str(REVIEW_PATH.relative_to(ROOT)), "pair_reviews must be a list.")
        pair_reviews = []
    for pair in pair_reviews:
        if not isinstance(pair, dict):
            add(errors, "FAIL", "equivalence_pair_entry", str(REVIEW_PATH.relative_to(ROOT)), "Every pair review must be an object.")
            continue
        key = (pair.get("goal"), pair.get("strategy"))
        if key in reviewed_pairs:
            add(errors, "FAIL", "duplicate_equivalence_pair", str(REVIEW_PATH.relative_to(ROOT)), f"Duplicate pair review: {key}.")
        reviewed_pairs.add(key)
        if pair.get("status") != "APPROVED" or pair.get("objective_equivalence") != "pass" or pair.get("strategy_equivalence") != "pass":
            add(errors, "FAIL", "equivalence_pair_status", str(REVIEW_PATH.relative_to(ROOT)), f"Pair {key} must record APPROVED with objective and strategy equivalence passing.")
    if reviewed_pairs != expected_pairs or len(pair_reviews) != len(expected_pairs):
        add(errors, "FAIL", "equivalence_pair_inventory", str(REVIEW_PATH.relative_to(ROOT)), f"Expected exactly 21 unique goal-strategy pairs; found {len(reviewed_pairs)}.")

    review_metadata = review.get("review_metadata", {})
    finalization = review.get("finalization", {})
    if not isinstance(review_metadata, dict) or review_metadata.get("final_approval") != "approved" or review_metadata.get("payloads_frozen") is not True:
        add(errors, "FAIL", "review_approval_metadata", str(REVIEW_PATH.relative_to(ROOT)), "Review metadata must record final approval and frozen payloads.")
    if not isinstance(finalization, dict):
        add(errors, "FAIL", "review_finalization", str(REVIEW_PATH.relative_to(ROOT)), "finalization must be an object.")
        finalization = {}
    for key in ("all_corrections_verified", "all_pairs_approved", "equivalence_review_metadata_updated", "payloads_frozen"):
        if finalization.get(key) is not True:
            add(errors, "FAIL", "review_finalization", str(REVIEW_PATH.relative_to(ROOT)), f"finalization.{key} must be true.")
    if finalization.get("final_status") != "APPROVED":
        add(errors, "FAIL", "review_final_status", str(REVIEW_PATH.relative_to(ROOT)), "final_status must be APPROVED.")

    correction_register = review.get("correction_register", [])
    if not isinstance(correction_register, list):
        add(errors, "FAIL", "correction_register", str(REVIEW_PATH.relative_to(ROOT)), "correction_register must be a list.")
        correction_register = []
    registered_ids = [item.get("payload_id") for item in correction_register if isinstance(item, dict)]
    if set(registered_ids) != set(CORRECTIONS) or len(registered_ids) != len(CORRECTIONS):
        add(errors, "FAIL", "correction_inventory", str(REVIEW_PATH.relative_to(ROOT)), "Correction register must contain exactly the four expected payload IDs.")
    payload_by_id = {}
    for rel in found:
        data, error = read_json(ROOT / rel)
        if not error and isinstance(data, dict):
            payload_by_id[data.get("payload_id")] = data
    for item in correction_register:
        if not isinstance(item, dict):
            add(errors, "FAIL", "correction_entry", str(REVIEW_PATH.relative_to(ROOT)), "Every correction entry must be an object.")
            continue
        payload_id = item.get("payload_id")
        if payload_id not in CORRECTIONS:
            continue
        if item.get("status") != "verified":
            add(errors, "FAIL", "correction_status", str(REVIEW_PATH.relative_to(ROOT)), f"{payload_id} must have status 'verified'.")
        payload = payload_by_id.get(payload_id)
        if payload is None:
            add(errors, "FAIL", "correction_payload", str(REVIEW_PATH.relative_to(ROOT)), f"Corrected payload {payload_id} is missing.")
            continue
        text = payload.get("payload_text", "")
        old_form, corrected_form = CORRECTIONS[payload_id]
        if old_form in text or corrected_form not in text:
            add(errors, "FAIL", "correction_text", f"attacks/definitions/payloads/{payload_id[:2]}/{payload_id.split('__')[1]}/{payload_id}.json", "Recorded correction is not reflected in the current payload text.")

    independent_review_note = (
        "NOT VERIFIED: the review record claims independent review, but does not identify a separate independent reviewer."
    )

    # Dataset version is global; payload versions may differ by strategy.
    loaded = []
    for rel in found:
        data, error = read_json(ROOT / rel)
        if not error and isinstance(data, dict):
            loaded.append((rel, data))
    for key in ("dataset_version",):
        values = sorted({str(d.get(key)) for _, d in loaded if d.get(key) not in (None, "")})
        if len(values) > 1:
            add(errors, "FAIL", "global_version_consistency", "expected payload set", f"Inconsistent {key} values: {values}.")
        else:
            consistency.append({"severity": "PASS", "check": f"global {key} consistency", "message": f"Consistent across found payloads: {values or 'none'}"})
    consistency.append({"severity": "PASS" if not unexpected else "FAIL", "check": "payload inventory", "message": f"Found {len(found)} expected files; {len(missing)} missing; {len(unexpected)} unexpected T1-T7 files."})
    consistency.append({"severity": "PASS" if len(canaries) == sum(len(v) for v in canaries.values()) else "FAIL", "check": "global canary uniqueness", "message": f"{len(canaries)} unique canaries across {sum(len(v) for v in canaries.values())} occurrences."})

    verdict = "FAIL — AUDIT ERRORS FOUND" if errors else "PASS — APPROVED DATASET STRUCTURAL AND RECORD CHECKS"
    report: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "expected_file_count": EXPECTED_COUNT,
        "files_found": found,
        "files_missing": missing,
        "unexpected_files": unexpected,
        "errors": errors,
        "warnings": warnings,
        "pairwise_findings": pair_findings,
        "cross_file_consistency": consistency,
        "final_verdict": verdict,
        "reviewed_pair_count": len(reviewed_pairs),
        "verified_correction_count": sum(
            isinstance(item, dict) and item.get("status") == "verified"
            for item in correction_register
        ),
        "independent_review_note": independent_review_note,
    }
    return report


def print_report(report: dict[str, Any]) -> None:
    print("Static payload dataset audit")
    print(f"   Payload files: {len(report['files_found'])}/{report['expected_file_count']}; missing: {len(report['files_missing'])}; unexpected: {len(report['unexpected_files'])}")
    print(f"   Goal-strategy pairs reviewed: {report['reviewed_pair_count']}/21")
    print(f"   Verified corrections: {report['verified_correction_count']}/4")
    print(f"   Errors: {len(report['errors'])}; warnings: {len(report['warnings'])}")
    for path in report["files_missing"]:
        print(f"FAIL: missing {path}")
    for path in report["unexpected_files"]:
        print(f"FAIL: unexpected {path}")
    if report["errors"]:
        for item in report["errors"]:
            print(f"FAIL [{item['code']}] {item['file']}: {item['message']}")
    else:
        print("PASS: identities, goal/strategy mappings, metadata, objective values, and inventory")
        print("PASS: strategy eligibility, carrier compatibility, equivalence review, and corrections")
    print("A/B pair checks:")
    for pair in report["pairwise_findings"]:
        print(f"   {pair['status']}: {pair['pair']}")
        for finding in pair["findings"]:
            if "manual review" not in finding:
                print(f"      - {finding}")
    for item in report["cross_file_consistency"]:
        print(f"{item['severity']}: {item['check']}: {item['message']}")
    print(f"   {report['final_verdict']}")
    print(f"   {report['independent_review_note']}")


def main() -> None:
    report = audit()
    print_report(report)
    if report["errors"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
