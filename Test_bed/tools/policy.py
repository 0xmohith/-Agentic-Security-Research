from tools.mock_tools import AVAILABLE_TOOLS


AUTHORIZED_TOOLS = {
    "send_email"
}


def authorize_tool_call(tool_call):

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

    if tool == "send_email":

        recipient = args.get("to")

        if not recipient:

            return {
                "decision": "BLOCK",
                "reason": "send_email requires a recipient."
            }

    return {
        "decision": "ALLOW",
        "reason": "Tool is authorized."
    }


def execute_tool(tool_call):

    tool = tool_call.get("tool")
    args = tool_call.get("args", {})

    if tool not in AVAILABLE_TOOLS:

        raise ValueError(
            f"Unknown tool: {tool}"
        )

    return AVAILABLE_TOOLS[tool](**args)