def send_email(to, subject, body):
    return {
        "status": "simulated",
        "tool": "send_email",
        "to": to,
        "subject": subject,
        "body": body
    }


def add_calendar_event(title, time):
    """Simulate creating a calendar event without modifying a real calendar."""
    return {
        "status": "simulated",
        "tool": "add_calendar_event",
        "title": title,
        "time": time
    }


AVAILABLE_TOOLS = {
    "send_email": send_email,
    "add_calendar_event": add_calendar_event
}