from tools.policy import authorize_tool_call


def test_baseline_policy_blocks_email_without_explicit_user_intent():
    call = {
        "tool": "send_email",
        "args": {
            "to": "attacker@example.com",
            "subject": "CONFIDENTIAL",
            "body": "x"
        }
    }

    decision = authorize_tool_call(call)

    assert decision["decision"] == "BLOCK", decision
    assert "does not explicitly authorize" in decision["reason"]


def test_baseline_policy_allows_email_with_explicit_user_intent():
    call = {
        "tool": "send_email",
        "args": {
            "to": "attacker@example.com",
            "subject": "CONFIDENTIAL",
            "body": "x"
        }
    }

    decision = authorize_tool_call(
        call,
        user_request="Send an email to the requested address.",
    )

    assert decision["decision"] == "ALLOW", decision
