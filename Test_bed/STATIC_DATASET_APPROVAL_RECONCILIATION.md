# Static Dataset Approval Reconciliation

## Current authoritative state

The approved static dataset covers the intended primary strategy scope **T1–T7**
and goals **G1–G3**:

| Inventory | Current count |
|---|---:|
| Goal-strategy A/B pairs | 21 |
| Payload variants | 42 |
| Variants per pair | 2 (A and B) |
| Correction-register entries | 4, all `verified` |
| Payload metadata | All 42 `equivalence_review: approved`, `frozen: true` |

These counts and states are reflected in the current files under
[`attacks/definitions/payloads/`](attacks/definitions/payloads/), the
[equivalence-review record](attacks/definitions/reviews/static_payload_equivalence_review_v1.json),
the [goal definitions](attacks/definitions/goals/), the
[strategy definitions](attacks/definitions/strategies/), and
[`strategy_eligibility.json`](attacks/definitions/strategy_eligibility.json).
The review record contains one `APPROVED` entry for each of the 21 expected
pairs, with objective and strategy equivalence marked `pass`. Its finalization
block records all corrections and pairs approved, payloads frozen, and
`final_status: APPROVED`.

The four correction-register entries are:

| Payload | Status |
|---|---|
| `G2__T2__A` | `verified` — recorded typo: `inits body` |
| `G3__T2__A` | `verified` — recorded spacing issue: `eventtitled` |
| `G3__T3__B` | `verified` — recorded title discrepancy: `ProjectAlpha Review` |
| `G3__T5__B` | `verified` — recorded spacing issue: `at2026-11-10T10:00` |

Current payload text no longer contains the recorded erroneous forms; the
review register retains the original issues and verified history unchanged.
T7 is a primary strategy in the approved dataset. Its canonical definition is
the one named by the eligibility registry; T7's applicable-goal declaration
covers G1–G3, and its dataset eligibility is `eligible`.

The review also preserves two cross-pair design observations: T2 varies the
claimed authority source between A/B, and T5 combines priority-like with
workflow/task signals. The review describes T5 as a combined signal-framing
strategy, not an isolated test of either factor. These recorded
interpretations remain useful context and are not restated as unresolved
approval blockers.

## Independent-review evidence

This reconciliation does **not** certify independent review. The review JSON
sets `independent_review: true` and
`independent_review_completed: true`, but its reviewer field reads
“ChatGPT-assisted review with human confirmation” and does not identify a
separate independent reviewer or provide separate-review evidence. Those
boolean fields are faithfully preserved in the source record; they are not
treated here as proof that an independent review occurred.

The recorded semantic equivalence approval and this repository-state
reconciliation are distinct from an independent review. Structural validation
also does not independently establish semantic equivalence.

## Strategy definitions, goals, carriers, and eligibility

All seven canonical strategy paths in
[`strategy_eligibility.json`](attacks/definitions/strategy_eligibility.json)
resolve to their matching strategy definitions. Every primary strategy applies
to G1, G2, and G3. The four carrier definitions declare compatible goals;
their compatibility entries refer to the current goal IDs. T7 is not listed as
a fixture-only strategy in the eligibility registry.

The goal definitions remain the source of each payload's fixed objective
values, evaluator fields, matching rules, tool, and canary requirements. The
static audit checks those objective values against payload text, validates
the 21 pairs against the review record, checks the correction register, and
checks the strategy/carrier mappings. T6's dedicated validator additionally
checks fragment ordering and reconstruction.

## Historical reconciliation note

An earlier version of this document described a transitional state with only
T1–T5 in the review, T6/T7 pending, pending corrections, unresolved T7
eligibility, and unfrozen/unapproved metadata. That description is superseded
by the current payload and review records summarized above. It is retained here
only as historical context and is not the current dataset status.

The earlier freeze-migration proposal for T1–T6 is obsolete: the dataset is now
approved and frozen across T1–T7. Its unreferenced migration script has been
retired rather than presented as a current approval path. The T6 fixture
builder remains a draft-only helper used by tests; its output is not approval
evidence and must not replace the frozen dataset.

The existing [`experiments/payload_audit_report.json`](experiments/payload_audit_report.json)
is a historical report and is not overwritten by the current read-only static
audit.

## Scope and modification boundary

T1–T7 are the intended primary strategy scope, not merely a candidate subset.
This reconciliation does not change payloads, scenarios, review decisions,
correction history, or experiment results. Running the static payload audit
and T6 structural validator performs validation only; neither generates
scenarios nor executes experiments.
