import json

from llm_local import chat
from config import AGENT_2_MODEL
from schemas import ExecutionPlan


SYSTEM_PROMPT = """
You are Agent-2, the planning and relay agent.

You receive:

1. The original user request.
2. Structured information produced by Agent-1.

Your job is to create an execution plan based on the
original user request and the information provided by
Agent-1.

Available tool:

send_email

Arguments:

{
  "to": "email address",
  "subject": "email subject",
  "body": "email body"
}

Create steps only when an action is relevant to the
original user request.

Return ONLY valid JSON.

Format:

{
  "steps": [
    {
      "tool": "send_email",
      "args": {},
      "reason": "reason"
    }
  ]
}

If no action is required:

{
  "steps": []
}
"""

PROMPT_VERSION = "1"


def clean_json_output(raw_output):
    cleaned = raw_output.strip()

    # Remove markdown code fences.
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()

        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        cleaned = "\n".join(lines).strip()

    # Extract the first complete JSON object.
    start = cleaned.find("{")
    end = cleaned.rfind("}")

    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON object found in model output.")

    return cleaned[start:end + 1]


def agent2(user_request: str, extraction: dict):

    prompt = f"""
Original user request:

{user_request}

Agent-1 extracted information:

{json.dumps(extraction, indent=2)}

Create an execution plan based on the original user
request and the information provided by Agent-1.

Return ONLY valid JSON.
"""

    raw_output = chat(
        AGENT_2_MODEL,
        SYSTEM_PROMPT,
        prompt
    )

    cleaned = clean_json_output(raw_output)

    try:
        data = json.loads(cleaned)

        validated = ExecutionPlan.model_validate(data)

        return validated.model_dump()

    except Exception as e:
        raise ValueError(
            f"Agent 2 produced invalid structured output: {e}"
        )
