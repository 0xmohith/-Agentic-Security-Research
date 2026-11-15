import base64
import html
import os
from urllib.parse import urlsplit

from email.message import EmailMessage
from pathlib import Path

from dotenv import load_dotenv
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

load_dotenv(PROJECT_ROOT / ".env")

SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.readonly",
]

CREDENTIALS_FILE = (
    PROJECT_ROOT
    / os.getenv(
        "GMAIL_CREDENTIALS_FILE",
        "secrets/credentials.json"
    )
)

TOKEN_FILE = (
    PROJECT_ROOT
    / os.getenv(
        "GMAIL_TOKEN_FILE",
        "secrets/token.json"
    )
)

ALLOWED_RECIPIENTS = {
    address.strip().lower()
    for address in os.getenv(
        "GMAIL_ALLOWED_RECIPIENTS",
        "mohithkrishnak322@gmail.com,test@gmail.com",
    ).split(",")
    if address.strip()
}

REQUIRE_APPROVAL = (
    os.getenv("GMAIL_REQUIRE_APPROVAL", "true").lower()
    == "true"
)


# --------------------------------------------------
# OAUTH AUTHENTICATION
# --------------------------------------------------

def get_gmail_service():
    """
    Authenticate with Google OAuth and return a Gmail API client.

    The first successful authentication creates token.json.
    """

    if not CREDENTIALS_FILE.exists():
        raise FileNotFoundError(
            f"OAuth credentials not found: {CREDENTIALS_FILE}"
        )

    credentials = None

    if TOKEN_FILE.exists():
        credentials = Credentials.from_authorized_user_file(
            str(TOKEN_FILE),
            SCOPES
        )

    if credentials and credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())

    if not credentials or not credentials.valid:
        flow = InstalledAppFlow.from_client_secrets_file(
            str(CREDENTIALS_FILE),
            SCOPES
        )

        credentials = flow.run_local_server(
            port=0,
            open_browser=True
        )

    TOKEN_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    TOKEN_FILE.write_text(
        credentials.to_json(),
        encoding="utf-8"
    )

    return build(
        "gmail",
        "v1",
        credentials=credentials
    )


# --------------------------------------------------
# EMAIL VALIDATION
# --------------------------------------------------

def validate_email(recipient, subject, body):
    """
    Validate an email before requesting authorization.
    """

    recipient = recipient.strip().lower()

    if recipient not in ALLOWED_RECIPIENTS:
        raise PermissionError(
            f"Recipient is not allowlisted: {recipient}"
        )

    if not subject.strip():
        raise ValueError("Email subject cannot be empty.")

    if not body.strip():
        raise ValueError("Email body cannot be empty.")

    return recipient


def validate_link(link_text, link_url):
    """Validate an optional HTTP(S) link before adding it to an email."""

    if link_text is None and link_url is None:
        return

    if not isinstance(link_text, str) or not link_text.strip():
        raise ValueError("Link text must be a non-empty string.")

    if not isinstance(link_url, str) or not link_url:
        raise ValueError("Link URL must be a non-empty string.")

    if any(character.isspace() or ord(character) < 32 for character in link_url):
        raise ValueError("Link URL cannot contain whitespace or control characters.")

    try:
        parsed_url = urlsplit(link_url)
        # Accessing .port also validates that any supplied port is numeric
        # and within the valid range.
        parsed_url.port
    except ValueError as error:
        raise ValueError("Link URL is invalid.") from error

    if (
        parsed_url.scheme.lower() not in {"http", "https"}
        or not parsed_url.hostname
        or parsed_url.username is not None
        or parsed_url.password is not None
    ):
        raise ValueError("Link URL must be an HTTP or HTTPS URL with a hostname.")


def build_email_message(recipient, subject, body, link_text=None, link_url=None):
    """Build a plain-text message, or a safe multipart message with a link."""

    validate_link(link_text, link_url)

    message = EmailMessage()
    message["To"] = recipient
    message["Subject"] = subject

    if link_text is None and link_url is None:
        # Preserve the existing representation for emails without a link.
        message.set_content(body)
        return message

    plain_body = f"{body}\n\n{link_text}: {link_url}"
    html_body = (
        f"{html.escape(body).replace(chr(10), '<br>')}<br><br>"
        f'<a href="{html.escape(link_url, quote=True)}">'
        f"{html.escape(link_text)}</a>"
    )
    message.set_content(plain_body)
    message.add_alternative(html_body, subtype="html")
    return message


# --------------------------------------------------
# SEND EMAIL
# --------------------------------------------------

def send_email(
    to=None,
    subject="",
    body="",
    recipient=None,
    link_text=None,
    link_url=None,
):
    """
    Send an email through Gmail after explicit human approval.

    Supports both:
      - Agent-3: to=...
      - Standalone test: recipient=...

    Only allowlisted recipients are permitted.
    """

    # Preserve compatibility with the standalone test script.
    if to is None:
        to = recipient

    if not isinstance(to, str) or not to.strip():
        raise ValueError("A valid recipient is required.")

    if not isinstance(subject, str) or not subject.strip():
        raise ValueError("Email subject cannot be empty.")

    if not isinstance(body, str) or not body.strip():
        raise ValueError("Email body cannot be empty.")

    recipient = validate_email(
        to,
        subject,
        body
    )

    print("\n========== EMAIL APPROVAL ==========")
    print("Recipient:", recipient)
    print("Subject:", subject)
    print("\nMessage:")
    print(body)
    print("====================================")

    if REQUIRE_APPROVAL:
        approval = input(
            "\nType SEND to authorize this email: "
        ).strip()

        if approval != "SEND":
            return {
                "success": False,
                "status": "rejected_by_user",
                "recipient": recipient
            }

    message = build_email_message(
        recipient,
        subject,
        body,
        link_text=link_text,
        link_url=link_url,
    )

    encoded_message = base64.urlsafe_b64encode(
        message.as_bytes()
    ).decode("utf-8")

    service = get_gmail_service()

    result = (
        service.users()
        .messages()
        .send(
            userId="me",
            body={"raw": encoded_message}
        )
        .execute()
    )

    return {
        "success": True,
        "status": "sent",
        "recipient": recipient,
        "message_id": result.get("id"),
        "thread_id": result.get("threadId")
    }
