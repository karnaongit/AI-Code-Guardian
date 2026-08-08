from pathlib import Path
from typing import Optional

from tree_sitter import Parser

from scanner.language_manager import LanguageManager
from scanner.query_manager import QueryManager
from scanner.query_runner import QueryRunner
from scanner.symbol_builder import SymbolBuilder

from scanner.language_learning.nemotron_llm import NemotronLLM
from tree_sitter import Query

from scanner.context_enricher import ContextEnricher
from scanner.language_learning.manager import LanguageLearningManager


class UniversalParser:

    def __init__(self, llm: Optional[NemotronLLM] = None):

        self.language_manager = LanguageManager()

        llm = llm or NemotronLLM()

        learning_manager = LanguageLearningManager(llm)

        self.query_manager = QueryManager(
            learning_manager=learning_manager,
            query_directory=Path(
                "scanner/queries"
            ),
        )

        self.query_runner = QueryRunner()

        self.symbol_builder = SymbolBuilder()
        
        self.context_enricher = ContextEnricher()

    def parse(
        self,
        source_code: str,
        filename: str,
    ):

        language_name, language = (
            self.language_manager.detect_language(
                filename
            )
        )

        parser = Parser(language)

        tree = parser.parse(
            source_code.encode("utf-8")
        )

        query_source = self.query_manager.get_query(
            language_name=language_name,
            language=language,
            sample_code=source_code,
        )

        

        query = Query(
            language,
            query_source,
        )

        captures = self.query_runner.run(
            query,
            tree,
        )

        parsed_file = self.symbol_builder.build(
            captures,
            language_name,
            filename
        )
        
        return self.context_enricher.enrich(parsed_file)