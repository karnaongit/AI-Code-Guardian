from __future__ import annotations

from abc import ABC, abstractmethod

from scanner.language_learning.models import (
    GeneratedQuery,
    GrammarAnalysis,
)


class BaseLLM(ABC):

    @abstractmethod
    def generate(self, prompt: str) -> str:
        raise NotImplementedError


class QueryGenerator:

    def __init__(self, llm: BaseLLM):
        self.llm = llm

    def generate(
        self,
        analysis: GrammarAnalysis,
    ) -> GeneratedQuery:

        prompt = self._build_prompt(analysis)

        response = self.llm.generate(prompt)

        return GeneratedQuery(
            name="default",
            source=response.strip(),
        )

    def _build_prompt(
    self,
    analysis: GrammarAnalysis,
) -> str:

        node_types_with_fields = []
        for node_type in sorted(analysis.named_node_types):
            fields = analysis.field_map.get(node_type)
            if fields:
                field_list = ", ".join(sorted(fields.keys()))
                node_types_with_fields.append(f"{node_type} (fields: {field_list})")
            else:
                node_types_with_fields.append(node_type)
                
        node_types_str = "\n".join(node_types_with_fields)

        return f"""
    You are an expert Tree-sitter engineer.

    Your job is to generate a VALID Tree-sitter query (.scm)
    for the language below.

    --------------------------------------------------
    LANGUAGE
    --------------------------------------------------

    {analysis.grammar.language}

    --------------------------------------------------
    AVAILABLE TREE-SITTER NODE TYPES & FIELDS
    --------------------------------------------------

    {node_types_str}

    --------------------------------------------------
    IMPORTANT
    --------------------------------------------------

    You MUST ONLY use node types that appear above.

    Never invent node names.

    If a construct does not exist,
    simply omit it.

    --------------------------------------------------
    CAPTURE NAMES
    --------------------------------------------------

    You MUST use these primary captures:

    @function
    @class
    @method
    @import
    @call
    @variable
    @constant

    To enable context enrichment, you SHOULD also capture sub-fields
    by appending a dot (.) to the primary capture name.
    
    For example:
    @call.receiver (the object a method is called on)
    @call.argument (the arguments passed to the call)
    @function.name (the name of the function)
    @function.parameter (parameters of the function)
    @class.name (the name of the class)
    @class.super (the superclass)
    @import.source (the module being imported from)
    
    These sub-captures must be attached to the appropriate inner nodes.

    --------------------------------------------------
    REQUIREMENTS
    --------------------------------------------------

    Generate queries for:

    • functions
    • classes
    • methods
    • imports
    • function calls
    • variables
    • constants

    Generate ONE query block per construct.

    Example format

    (function_definition
        name: (identifier) @function.name
        parameters: (parameters (identifier) @function.parameter)) @function

    (class_definition
        name: (identifier) @class.name) @class

    (import_statement
        module: (identifier) @import.source) @import

    (call
        function: (member_expression
            object: (identifier) @call.receiver
            property: (property_identifier))
        arguments: (arguments (string) @call.argument)) @call

    --------------------------------------------------
    OUTPUT RULES
    --------------------------------------------------

    Return ONLY raw Tree-sitter query.

    No markdown.

    No explanation.

    No comments.

    No ``` blocks.

    Return valid .scm only.
    """.strip()