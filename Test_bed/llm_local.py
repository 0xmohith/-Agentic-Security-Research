from ollama import Client
from config import OLLAMA_HOST


client = Client(host=OLLAMA_HOST)


def chat(model, system, user):
    response = client.chat(
        model=model,
        messages=[
            {
                "role": "system",
                "content": system
            },
            {
                "role": "user",
                "content": user
            }
        ]
    )

    return response["message"]["content"]