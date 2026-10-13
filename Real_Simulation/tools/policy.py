from tools.mock_tools import AVAILABLE_TOOLS
from tools.gmail_tool import ALLOWED_RECIPIENTS


AUTHORIZED_TOOLS = {
    "send_email"
}


def authorize_tool_call(tool_call):
    """
    Validate the proposed tool call before execution.

    This policy checks tool authorization and arguments.
    Gmail performs its own recipient validation and
    requires explicit human approval before sending.
    """

    if not isinstance(tool_call, dict):
        return {
            "decision": "BLOCK",
            "reason": "Tool call must be a dictionary."
        }

    tool = tool_call.get("tool")
    args = tool_call.get("args", {})

    if tool is None:
        return {
            "decision": "NO_TOOL",
            "reason": "Agent 3 proposed no tool call."
        }

    if tool not in AUTHORIZED_TOOLS:
        return {
            "decision": "BLOCK",
            "reason": f"Tool '{tool}' is not authorized."
        }

    if not isinstance(args, dict):
        return {
            "decision": "BLOCK",
            "reason": "Tool arguments must be a dictionary."
        }

    if tool == "send_email":

        recipient = args.get("to")
        subject = args.get("subject")
        body = args.get("body")

        if not isinstance(recipient, str) or not recipient.strip():
            return {
                "decision": "BLOCK",
                "reason": "send_email requires a valid recipient."
            }

        recipient = recipient.strip().lower()

        if recipient not in ALLOWED_RECIPIENTS:
            return {
                "decision": "BLOCK",
                "reason": "Recipient is not allowlisted."
            }

        if not isinstance(subject, str) or not subject.strip():
            return {
                "decision": "BLOCK",
                "reason": "Email subject cannot be empty."
            }

        if not isinstance(body, str) or not body.strip():
            return {
                "decision": "BLOCK",
                "reason": "Email body cannot be empty."
            }

    return {
        "decision": "ALLOW",
        "reason": "Tool and arguments passed policy checks."
    }


def execute_tool(tool_call):
    """
    Execute a tool only after the caller receives ALLOW.
    """

    tool = tool_call.get("tool")
    args = tool_call.get("args", {})

    if tool not in AVAILABLE_TOOLS:
        raise ValueError(f"Unknown tool: {tool}")

    return AVAILABLE_TOOLS[tool](**args)