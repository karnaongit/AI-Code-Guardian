from pathlib import Path

from tree_sitter_language_pack import get_language


class LanguageManager:

    LANGUAGE_MAP = {
        ".py": "python",
        ".java": "java",
        ".js": "javascript",
        ".ts": "typescript",
        ".cpp": "cpp",
        ".c": "c",
        ".cs": "c_sharp",
        ".go": "go",
        ".rs": "rust",
        ".php": "php",
        ".kt": "kotlin",
    }

    @classmethod
    def detect_language(cls, filename: str):

        extension = Path(filename).suffix.lower()

        language_name = cls.LANGUAGE_MAP.get(extension)

        if language_name is None:
            raise ValueError(
                f"Unsupported language: {extension}"
            )

        language = get_language(language_name)

        return language_name, language

    @classmethod
    def supported_languages(cls):

        return tuple(sorted(cls.LANGUAGE_MAP.values()))

    @classmethod
    def is_supported(cls, filename: str):

        extension = Path(filename).suffix.lower()

        return extension in cls.LANGUAGE_MAP