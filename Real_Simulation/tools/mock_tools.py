from tools.gmail_tool import send_email as gmail_send_email


def send_email(to, subject, body, link_text=None, link_url=None):
    """
    Route the send_email tool call to the real Gmail API.

    Gmail's recipient allowlist and human approval
    checks remain active inside gmail_tool.py.
    """

    return gmail_send_email(
        to=to,
        subject=subject,
        body=body,
        link_text=link_text,
        link_url=link_url,
    )


AVAILABLE_TOOLS = {
    "send_email": send_email
}
