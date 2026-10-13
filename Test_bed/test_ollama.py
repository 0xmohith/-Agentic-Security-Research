from openai import OpenAI
import json

client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama"
)

MODEL = "qwen2.5:7b"

tools = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get the weather for a city.",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {
                        "type": "string",
                        "description": "The city to get weather for."
                    }
                },
                "required": ["city"]
            }
        }
    }
]

response = client.chat.completions.create(
    model=MODEL,
    messages=[
        {
            "role": "user",
            "content": "What is the weather in Mysuru?"
        }
    ],
    tools=tools,
    tool_choice="auto"
)

message = response.choices[0].message

print("Content:")
print(message.content)

print("\nTool calls:")
print(message.tool_calls)

if message.tool_calls:
    for call in message.tool_calls:
        print("\nFunction:", call.function.name)
        print("Arguments:", call.function.arguments)
else:
    print("\nNO TOOL CALL GENERATED")