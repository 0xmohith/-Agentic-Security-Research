import re

from tools.mock_tools import AVAILABLE_TOOLS


AUTHORIZED_TOOLS = {
    "send_email",
    "add_calendar_event"
}


EMAIL_RE = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?)+$",
    re.IGNORECASE,
)


def _extract_sender_email(untrusted_content):
    """Extract an email address only from an explicit From header."""
    if not isinstance(untrusted_content, str):
        return None

    for line in untrusted_content.splitlines():
        match = re.match(
            r"^\s*From\s*:\s*.*?<([^<>]+@[^<>]+)>\s*$",
            line,
            re.IGNORECASE,
        )

        if match:
            candidate = match.group(1).strip()
            if EMAIL_RE.fullmatch(candidate):
                return candidate

        match = re.match(
            r"^\s*From\s*:\s*([^\s<>]+@[^\s<>]+)\s*$",
            line,
            re.IGNORECASE,
        )

        if match:
            candidate = match.group(1).strip()
            if EMAIL_RE.fullmatch(candidate):
                return candidate

    return None


def _has_explicit_email_intent(user_request):
    """Check whether the original user requested an email action."""
    if not isinstance(user_request, str):
        return False

    request = user_request.casefold()

    return bool(re.search(r"\b(send|email)\b", request))


def _has_explicit_calendar_intent(user_request):
    """Require an explicit request to create a calendar event."""
    if not isinstance(user_request, str):
        return False

    request = user_request.casefold()

    if re.search(r"\bdo not send an email\b|\bdon't send an email\b", request):
        # This restriction applies to email, not calendar creation.
        pass

    return bool(
        re.search(
            r"\b(create|add|schedule|book)\b.{0,80}\b(calendar event|event|meeting)\b"
            r"|\b(calendar event|event|meeting)\b.{0,80}\b(create|add|schedule|book)\b",
            request,
        )
    )


def authorize_tool_call(
    tool_call,
    user_request=None,
    untrusted_content=None,
):
    """Authorize tool calls using both argument validation and user intent."""
    if not isinstance(tool_call, dict):
        return {
            "decision": "BLOCK",
            "reason": "Tool call must be a JSON object."
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
            "reason": "Tool arguments must be a JSON object."
        }

    # Contextual authorization: original user request, not extracted
    # or untrusted content, must authorize the proposed action.
    if tool == "send_email":
        if not _has_explicit_email_intent(user_request):
            return {
                "decision": "BLOCK",
                "reason": (
                    "The original user request does not explicitly "
                    "authorize sending an email."
                )
            }

        recipient = args.get("to")

        if not isinstance(recipient, str) or not EMAIL_RE.fullmatch(recipient.strip()):
            return {
                "decision": "BLOCK",
                "reason": "Recipient must be a valid email address."
            }

        required = {"to", "subject", "body"}

        if not required.issubset(args):
            return {
                "decision": "BLOCK",
                "reason": "send_email requires to, subject, and body."
            }

        if not all(
            isinstance(args[field], str) and args[field].strip()
            for field in ("to", "subject", "body")
        ):
            return {
                "decision": "BLOCK",
                "reason": "Email recipient, subject, and body must be non-empty strings."
            }

        # If the user asks to email the sender, only trust the
        # address explicitly present in the source email.
        request = (user_request or "").casefold()
        asks_for_sender = (
            "sender" in request
            or "original sender" in request
        )

        if asks_for_sender:
            source_sender = _extract_sender_email(untrusted_content)

            if source_sender is None:
                return {
                    "decision": "BLOCK",
                    "reason": (
                        "Cannot email the sender because the source "
                        "contains no verifiable From email address."
                    )
                }

            if recipient.strip().casefold() != source_sender.casefold():
                return {
                    "decision": "BLOCK",
                    "reason": (
                        "Recipient does not match the sender address "
                        "explicitly present in the source."
                    )
                }

    elif tool == "add_calendar_event":
        if not _has_explicit_calendar_intent(user_request):
            return {
                "decision": "BLOCK",
                "reason": (
                    "The original user request does not explicitly "
                    "authorize calendar-event creation."
                )
            }

        title = args.get("title")
        event_time = args.get("time")

        if not isinstance(title, str) or not title.strip():
            return {
                "decision": "BLOCK",
                "reason": "add_calendar_event requires a non-empty title."
            }

        if not isinstance(event_time, str) or not event_time.strip():
            return {
                "decision": "BLOCK",
                "reason": "add_calendar_event requires a non-empty time."
            }

    return {
        "decision": "ALLOW",
        "reason": "Tool is authorized, user intent is explicit, and required arguments are present."
    }


def execute_tool(tool_call):
    tool = tool_call.get("tool")
    args = tool_call.get("args", {})

    if tool not in AVAILABLE_TOOLS:
        raise ValueError(f"Unknown tool: {tool}")

    return AVAILABLE_TOOLS[tool](**args)