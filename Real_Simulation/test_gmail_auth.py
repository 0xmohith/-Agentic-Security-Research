from tools.gmail_tool import get_gmail_service


def main():
    print("Starting Gmail OAuth test...")

    service = get_gmail_service()

    print("Gmail API client created successfully.")
    print("OAuth authentication succeeded.")


if __name__ == "__main__":
    main()