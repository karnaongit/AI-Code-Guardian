from ai.policy_engine import evaluate

tests = [
    ("LOW", False),
    ("LOW", True),
    ("MEDIUM", False),
    ("MEDIUM", True),
    ("HIGH", False),
    ("HIGH", True),
    ("CRITICAL", False),
    ("CRITICAL", True),
]

print("MATRIX VERIFICATION:")
for sev, reach in tests:
    decision = evaluate(sev, reach)
    print(f"{sev} + {'reachable' if reach else 'unreachable'}: {decision.decision} ({decision.reason_code})")
