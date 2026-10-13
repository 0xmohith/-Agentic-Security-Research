from tools.gmail_tool import send_email as gmail_send_email


def send_email(to, subject, body):
    """
    Route the send_email tool call to the real Gmail API.

    Gmail's recipient allowlist and human approval
    checks remain active inside gmail_tool.py.
    """

    return gmail_send_email(
        to=to,
        subject=subject,
        body=body
    )


AVAILABLE_TOOLS = {
    "send_email": send_email
}