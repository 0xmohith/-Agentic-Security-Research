import pytest

from experiments.adaptive_metrics import compute_adaptive_asr


def _trial(trial_id, *, success_round=None, rounds=30, technical_failure=False):
    return {
        "trial_id": trial_id,
        "technical_failure": technical_failure,
        "strict_success": success_round is not None,
        "strict_success_round": success_round,
        "total_rounds_completed": rounds,
    }


def test_asr_checkpoints_count_success_by_round_and_exclude_failures():
    trials = [
        _trial("trial-1", success_round=1),
        _trial("trial-2", success_round=6),
        _trial("trial-3", success_round=9),
        _trial("trial-4", success_round=30),
        _trial("trial-5"),
        _trial("trial-6", technical_failure=True),
    ]

    metrics = compute_adaptive_asr(trials)

    assert metrics == {
        "valid_trial_count": 5,
        "technical_failure_count": 1,
        "success_count@1": 1,
        "ASR@1": 0.2,
        "success_count@5": 1,
        "ASR@5": 0.2,
        "success_count@10": 3,
        "ASR@10": 0.6,
        "success_count@30": 4,
        "ASR@30": 0.8,
    }


def test_asr_is_null_when_there_are_no_valid_trials():
    metrics = compute_adaptive_asr([_trial("trial-failed", technical_failure=True)])

    assert metrics["valid_trial_count"] == 0
    assert metrics["technical_failure_count"] == 1
    assert metrics["ASR@1"] is None
    assert metrics["ASR@30"] is None


@pytest.mark.parametrize(
    "trials",
    [
        [_trial("duplicate"), _trial("duplicate")],
        [{"trial_id": "missing-status"}],
        [_trial("invalid-round", success_round=31, rounds=30)],
        [_trial("false-success-round", rounds=2) | {"strict_success_round": 1}],
    ],
)
def test_invalid_trial_summaries_are_rejected(trials):
    with pytest.raises(ValueError):
        compute_adaptive_asr(trials)
