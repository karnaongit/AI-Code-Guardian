from __future__ import annotations

from pathlib import Path

from scanner.language_learning.manager import LanguageLearningManager


class QueryManager:
    def __init__(
        self,
        learning_manager: LanguageLearningManager,
        query_directory: str | Path,
    ):
        self.learning_manager = learning_manager
        self.query_directory = Path(query_directory)

    def get_query(
        self,
        language_name: str,
        language,
        sample_code: str,
    ) -> str:
        """
        Returns a valid Tree-sitter query.

        Workflow:

            Existing .scm
                    ↓
                 return

            Missing .scm
                    ↓
            LanguageLearningManager
                    ↓
            Gemini
                    ↓
            Validate
                    ↓
            Save query
                    ↓
                 return
        """

        query_path = self.query_directory / f"{language_name}.scm"

        if query_path.exists():
            return query_path.read_text(encoding="utf-8")
            
        dynamic_path = self.learning_manager.cache.query_path(language_name)
        if dynamic_path.exists():
            return dynamic_path.read_text(encoding="utf-8")

        return self.learning_manager.ensure(
            language_name=language_name,
            language=language,
            sample_code=sample_code,
        )

    def regenerate(
        self,
        language_name: str,
        language,
        sample_code: str,
    ) -> str:

        return self.learning_manager.regenerate(
            language_name=language_name,
            language=language,
            sample_code=sample_code,
        )