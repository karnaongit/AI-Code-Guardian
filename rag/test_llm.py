from llm import SecurityLLM

finding = {
    "category": "Command Injection",
    "severity": "High",
    "language": "Python",
    "snippet": "os.system(user_input)"
}

retrieved_docs = [
    {
        "source": "MITRE CWE",
        "vulnerability": "Command Injection",
        "description": "Improper neutralization of special elements can allow arbitrary OS command execution.",
        "recommendation": "Avoid shell execution and validate input.",
        "url": "https://cwe.mitre.org/data/definitions/78.html"
    }
]

llm = SecurityLLM()

response = llm.generate(
    finding,
    retrieved_docs
)

print(response)
