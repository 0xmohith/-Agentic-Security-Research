from tools.gmail_tool import send_email


def main():
    result = send_email(
        recipient="mohithkrishnak322@gmail.com",
        subject="Real Simulation Testbed - Gmail Integration Test",
        body=(
            "Hello,\n\n"
            "This is a test email sent through the Gmail API "
            "from the Real Simulation Testbed.\n\n"
            "This message was sent as part of an authorized "
            "integration test."
        )
    )

    print("\n========== RESULT ==========")
    print(result)


if __name__ == "__main__":
    main()