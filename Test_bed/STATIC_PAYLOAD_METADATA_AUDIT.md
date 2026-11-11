# Static Payload Metadata Audit

**Audit scope:** T1–T7 × G1–G3 × A/B  
**Dataset status:** **PASS — approved and frozen in the current repository records**  
**Independent-review status:** **RECORDED AS COMPLETE in the equivalence-review record**

## Results

| Category | Result | Finding |
|---|---|---|
| Inventory and identity | **PASS** | 42 payload files; 6 per strategy; 2 variants for each of 21 goal-strategy pairs. File path and payload/goal/strategy/variant IDs agree. |
| Required metadata and frozen state | **PASS** | All 42 payloads record `is_adaptive: false`, `generation_method: manual`, `equivalence_review: approved`, and `frozen: true`. |
| Word counts and A/B balance | **PASS** | All stored counts match `payload_text.split()`. All 21 pairs are within the review's 20% threshold. |
| Goal/evaluator and carrier mapping | **PASS** | Fixed goal values are present in each payload, goal definitions provide evaluator contracts, and carrier compatibility refers to the current G1–G3 goal IDs. |
| Strategy definitions and eligibility | **PASS** | Registry canonical paths cover T1–T7. All strategies apply to G1–G3. T7 is eligible for the approved dataset and is not fixture-only. |
| Equivalence review | **PASS — RECORD CHECK** | The review JSON has exactly 21 unique pairs, each marked `APPROVED` with objective and strategy equivalence `pass`. This verifies the record, not a new independent semantic review. |
| Correction register | **PASS** | Exactly four entries; all are `verified`. Current payload text omits each recorded erroneous form and contains the corresponding correction. |
| Independent review | **PASS — RECORDED** | Review metadata sets `independent_review: true`; finalization sets `independent_review_completed: true`. The record names Prof. Yogesh N, Prof. Shambhavi K A, and Mohith Krishna K. This audit reports the repository record and does not independently verify reviewer identities or conduct. |

### A/B word counts

| Goal | Strategy | A | B | Difference |
|---|---|---:|---:|---:|
| G1 | T1 | 24 | 24 | 0.0% |
| G1 | T2 | 27 | 31 | 12.9% |
| G1 | T3 | 26 | 24 | 7.7% |
| G1 | T4 | 27 | 27 | 0.0% |
| G1 | T5 | 17 | 20 | 15.0% |
| G1 | T6 | 14 | 13 | 7.1% |
| G1 | T7 | 23 | 26 | 11.5% |
| G2 | T1 | 23 | 23 | 0.0% |
| G2 | T2 | 32 | 35 | 8.6% |
| G2 | T3 | 26 | 28 | 7.1% |
| G2 | T4 | 29 | 27 | 6.9% |
| G2 | T5 | 23 | 23 | 0.0% |
| G2 | T6 | 18 | 19 | 5.3% |
| G2 | T7 | 28 | 26 | 7.1% |
| G3 | T1 | 21 | 22 | 4.5% |
| G3 | T2 | 27 | 27 | 0.0% |
| G3 | T3 | 24 | 23 | 4.2% |
| G3 | T4 | 21 | 20 | 4.8% |
| G3 | T5 | 15 | 17 | 11.8% |
| G3 | T6 | 11 | 11 | 0.0% |
| G3 | T7 | 19 | 18 | 5.3% |

## Corrections

| Payload | Status |
|---|---|
| `G2__T2__A` | `verified` |
| `G3__T2__A` | `verified` |
| `G3__T3__B` | `verified` |
| `G3__T5__B` | `verified` |

## Evidence and limits

Primary records are the [payload definitions](attacks/definitions/payloads/),
[equivalence review](attacks/definitions/reviews/static_payload_equivalence_review_v1.json),
[goal definitions](attacks/definitions/goals/),
[strategy definitions](attacks/definitions/strategies/),
[carrier definitions](attacks/definitions/carriers/), and
[strategy eligibility registry](attacks/definitions/strategy_eligibility.json).
The [dataset reconciliation](STATIC_DATASET_APPROVAL_RECONCILIATION.md)
describes their current state and preserves the earlier pending findings as
historical context only.

The equivalence review identifies itself as `final_manual_equivalence_review`,
dated 2026-11-11. Its reviewer field lists Prof. Yogesh N, Prof. Shambhavi K A,
and Mohith Krishna K; it records final approval as `approved`, payloads as
frozen, and independent review as complete. These are review-recorded facts.
This audit does not add claims beyond that record or independently validate
the reviewers or their process.

Structural validation and review-record validation are distinct from semantic
approval or the review process itself. The recorded pair decisions and
independent-review completion are reported as present; neither is re-created
or independently verified by the automated checks.

[`scripts/audit_static_payloads.py`](scripts/audit_static_payloads.py) runs the
full inventory, pair, correction, goal, strategy, carrier, and eligibility
checks and writes its report to stdout only. It does not overwrite the
historical [`experiments/payload_audit_report.json`](experiments/payload_audit_report.json).
[`scripts/validate_t6_payloads.py`](scripts/validate_t6_payloads.py) separately
checks T6 fragment structure and approved/frozen metadata.

No payload, scenario, approval decision, correction history, or experiment
result was changed by this audit. No scenario dataset was generated and no
experiment was executed.
