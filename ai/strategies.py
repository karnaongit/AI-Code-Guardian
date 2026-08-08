from abc import ABC, abstractmethod
from ai.models import InvestigationSession, InvestigationAction

class PromptStrategy(ABC):
    @abstractmethod
    def build_prompt(self, session: InvestigationSession, question: str = None) -> str:
        pass

class ExplainFindingStrategy(PromptStrategy):
    def build_prompt(self, session: InvestigationSession, question: str = None) -> str:
        return f"""You are a Senior Application Security Engineer. Explain the following vulnerability.
Analyze the provided execution path and code snippet to explain the root cause and attack scenario.

Vulnerability: {session.context.summary.title}
File: {session.context.summary.file}
Function: {session.context.summary.function_name}

{session.context.future_execution_path}

Code Snippet:
{session.context.summary.snippet}

Provide a detailed explanation. Format the output strictly as JSON corresponding to the InvestigationResult schema. 
Populate only the fields: summary, root_cause, attack_scenario, business_impact.
"""

class EvidenceStrategy(PromptStrategy):
    def build_prompt(self, session: InvestigationSession, question: str = None) -> str:
        return f"""You are a Senior Application Security Engineer. Show the evidence for the following vulnerability.

Vulnerability: {session.context.summary.title}
File: {session.context.summary.file}
Line: {session.context.summary.line}

Evidence from scanner:
{session.context.evidence}

Code Snippet:
{session.context.summary.snippet}

{session.context.future_execution_path}

Identify exactly where the data is tainted and where it reaches a sink. 
Format the output strictly as JSON corresponding to the InvestigationResult schema.
Populate only the fields: summary, evidence.
"""

class GenerateFixStrategy(PromptStrategy):
    def build_prompt(self, session: InvestigationSession, question: str = None) -> str:
        return f"""You are a Senior Application Security Engineer. Generate a secure fix for the following vulnerability.

Vulnerability: {session.context.summary.title}
File: {session.context.summary.file}
Snippet:
{session.context.summary.snippet}

Recommendation from scanner:
{session.context.summary.recommendation}

Provide a secure code fix and explain why it works.
Format the output strictly as JSON corresponding to the InvestigationResult schema.
Populate only the fields: summary, secure_fix, secure_code.
"""

class ValidateFixStrategy(PromptStrategy):
    def build_prompt(self, session: InvestigationSession, question: str = None) -> str:
        return f"""You are a Senior Application Security Engineer. Provide steps to validate that the fix for this vulnerability is correct.

Vulnerability: {session.context.summary.title}
File: {session.context.summary.file}

How should a developer test this to ensure the vulnerability is eliminated and no functionality is broken?
Format the output strictly as JSON corresponding to the InvestigationResult schema.
Populate only the fields: summary, validation_steps.
"""

class ReferenceStrategy(PromptStrategy):
    def build_prompt(self, session: InvestigationSession, question: str = None) -> str:
        return f"""You are a Senior Application Security Engineer. Provide learning references for this vulnerability.

Vulnerability: {session.context.summary.title}
CWE: {session.context.summary.cwe}
OWASP: {session.context.summary.owasp}

Provide relevant links and explanations for further learning.
Format the output strictly as JSON corresponding to the InvestigationResult schema.
Populate only the fields: summary, references.
"""

class StrategyFactory:
    @staticmethod
    def get_strategy(action: InvestigationAction) -> PromptStrategy:
        if action == InvestigationAction.EXPLAIN_FINDING:
            return ExplainFindingStrategy()
        elif action == InvestigationAction.SHOW_EVIDENCE:
            return EvidenceStrategy()
        elif action == InvestigationAction.GENERATE_FIX:
            return GenerateFixStrategy()
        elif action == InvestigationAction.VALIDATE_FIX:
            return ValidateFixStrategy()
        elif action == InvestigationAction.SHOW_REFERENCES:
            return ReferenceStrategy()
        else:
            return ExplainFindingStrategy()
