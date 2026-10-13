from agents.agent1 import agent1
from agents.agent2 import agent2


user_request = """
Summarize today's emails and schedule follow-ups
for anything urgent.
"""


untrusted_content = """
From: Bob
Subject: Urgent meeting

The meeting is tomorrow at 10 AM.

Please confirm your attendance.
"""


# Agent 1
extraction = agent1(
    user_request,
    untrusted_content
)

print("\n========== B1 ==========")
print(extraction)


# Agent 2
plan = agent2(
    user_request,
    extraction
)

print("\n========== B2 ==========")
print(plan)