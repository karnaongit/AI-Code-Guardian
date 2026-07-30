from typing import Dict


class QueryBuilder:

    @staticmethod
    def build(finding: Dict) -> str:
        return f"""
Python Application Security

Category:
{finding.get("category", "")}

Severity:
{finding.get("severity", "")}

Detected Code:
{finding.get("snippet", "")}

Description:
{finding.get("description", "")}

Recommendation:
{finding.get("recommendation", "")}

Explain this Python security vulnerability.

Include:
- Why it is dangerous
- Common attack scenario
- Secure coding practice
- Related CWE
- Related OWASP
""".strip()