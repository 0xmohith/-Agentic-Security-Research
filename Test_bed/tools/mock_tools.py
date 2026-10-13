def send_email(to, subject, body):

    return {
        "status": "simulated",
        "tool": "send_email",
        "to": to,
        "subject": subject,
        "body": body
    }


AVAILABLE_TOOLS = {
    "send_email": send_email
}