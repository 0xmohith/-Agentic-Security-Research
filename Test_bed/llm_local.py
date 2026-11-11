from collections.abc import Mapping

from ollama import Client
from config import OLLAMA_HOST


client = Client(host=OLLAMA_HOST)


def chat(model, system, user, *, options: Mapping | None = None):
    parameters = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": system
            },
            {
                "role": "user",
                "content": user
            }
        ]
    }
    if options is not None:
        parameters["options"] = dict(options)

    response = client.chat(**parameters)

    return response["message"]["content"]