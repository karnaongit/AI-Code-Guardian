from __future__ import annotations

from tree_sitter import Language
from typer import prompt

from scanner.language_learning.cache_manager import CacheManager
from scanner.language_learning.grammar_analyzer import GrammarAnalyzer
from scanner.language_learning.grammar_loader import GrammarLoader
from scanner.language_learning.models import GeneratedQuery
from scanner.language_learning.query_generator import (
    BaseLLM,
    QueryGenerator,
)
from scanner.language_learning.validator import QueryValidator


class LanguageLearningManager:
    """
    Public API for automatic Tree-sitter language learning.
    """

    def __init__(
        self,
        llm: BaseLLM,
        cache: CacheManager | None = None,
    ):
        self.llm = llm

        self.loader = GrammarLoader()
        self.analyzer = GrammarAnalyzer()
        self.generator = QueryGenerator(llm)
        self.validator = QueryValidator()
        self.cache = cache or CacheManager()

    def learn(
    self,
    language_name: str,
    language: Language,
    sample_code: str,
    *,
    force: bool = False,
) -> dict:

        if not force and self.cache.exists(language_name):
            return self.cache.load_profile(language_name)

        grammar = self.loader.load(language_name)

        analysis = self.analyzer.analyze(grammar)
        print(type(analysis))
        print(analysis)

        MAX_ATTEMPTS = 3

        generated_query = None
        validation = None

        for attempt in range(MAX_ATTEMPTS):

            print(f"\nLearning attempt {attempt + 1}/{MAX_ATTEMPTS}")

            if attempt == 0:

                generated_query = self.generator.generate(
                    analysis
                )

            else:

                node_types_with_fields = []
                for node_type in sorted(analysis.named_node_types):
                    fields = analysis.field_map.get(node_type)
                    if fields:
                        field_list = ", ".join(sorted(fields.keys()))
                        node_types_with_fields.append(f"{node_type} (fields: {field_list})")
                    else:
                        node_types_with_fields.append(node_type)
                        
                node_types_str = "\n".join(node_types_with_fields)

                prompt = f"""
    The previous Tree-sitter query failed validation.

    Language:
    {analysis.grammar.language}

    Named node types and their available fields:

    {node_types_str}

    Previous query:

    {generated_query.source}

    Validation errors:

    {chr(10).join(validation.errors)}

    Generate a corrected Tree-sitter query.

    Requirements:

    - Return ONLY Tree-sitter query syntax.
    - No markdown.
    - No explanation.
    - Use ONLY node types listed above.
    - Never invent node names.

    Use ONLY these primary capture names:

    @function
    @class
    @method
    @import
    @call
    @variable
    @constant

    You SHOULD also generate sub-captures to provide context, by appending a dot (.)
    to the primary capture name.
    
    Examples:
    @call.receiver
    @call.argument
    @function.name
    @function.parameter
    @class.name
    @import.source
    
    Ensure all sub-captures are nested appropriately within their primary captures.
    """

                generated_query = GeneratedQuery(
                    name="default",
                    source=self.llm.generate(prompt).strip(),
                )

            generated_query = GeneratedQuery(
                name=generated_query.name,
                source=generated_query.source.strip(),
            )
            
            print("\nGenerated Query")
            print("-" * 60)
            print(generated_query.source)
            print("-" * 60)

            validation = self.validator.validate(
    language=language,
    analysis=analysis,
    query=generated_query,
    source_code=sample_code,
)

            if validation.valid:
                if validation.recovered_query:
                    print("✓ Query validation passed (using salvaged blocks).")
                    generated_query = GeneratedQuery(
                        name=generated_query.name,
                        source=validation.recovered_query,
                    )
                else:
                    print("✓ Query validation passed.")
                break

            print("✗ Validation failed.")
            print(validation.errors)

        if validation is None or not validation.valid:

            raise RuntimeError(
                f"""
    Unable to generate a valid Tree-sitter query.

    Language:
    {language_name}

    Attempts:
    {MAX_ATTEMPTS}

    Errors:

    {chr(10).join(validation.errors)}
    """
            )

        profile = {
            "language": language_name,
            "coverage": validation.coverage,
            "captures": validation.captures,
            "confidence": validation.confidence,
        }

        self.cache.save(
            language=language_name,
            query=generated_query.source,
            profile=profile,
        )

        return profile


    def ensure(
        self,
        language_name: str,
        language: Language,
        sample_code: str,
    ) -> str:
        """
        Returns a valid cached query.
        Generates one only if it does not already exist.
        """

        if not self.cache.exists(language_name):
            self.learn(
                language_name=language_name,
                language=language,
                sample_code=sample_code,
            )

        return self.cache.load_query(language_name)

    def regenerate(
    self,
    prompt: str,
) -> GeneratedQuery:

        return GeneratedQuery(
            name="default",
            source=self.llm.generate(prompt).strip(),
        )
        
        
    def is_cached(
        self,
        language_name: str,
    ) -> bool:
        return self.cache.exists(language_name)

    def load_profile(
        self,
        language_name: str,
    ) -> dict:
        return self.cache.load_profile(language_name)

    def load_query(
        self,
        language_name: str,
    ) -> str:
        return self.cache.load_query(language_name)

    def clear_cache(self) -> None:
        self.cache.clear()