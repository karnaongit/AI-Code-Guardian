from __future__ import annotations

import json
from pathlib import Path


class CacheManager:
    """
    Stores generated Tree-sitter queries and language profiles.

    Directory Layout

    scanner/
    └── language_learning/
        ├── queries/
        │   ├── python/
        │   │   └── default.scm
        │   ├── javascript/
        │   │   └── default.scm
        │   └── java/
        │       └── default.scm
        │
        └── profiles/
            ├── python/
            │   └── profile.json
            ├── javascript/
            │   └── profile.json
            └── java/
                └── profile.json
    """

    def __init__(self):

        self.query_root = Path(
            "scanner/language_learning/queries"
        )

        self.profile_root = Path(
            "scanner/language_learning/profiles"
        )

        self.query_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.profile_root.mkdir(
            parents=True,
            exist_ok=True,
        )

    # ------------------------------------------------------------------

    def language_query_dir(
        self,
        language: str,
    ) -> Path:

        return self.query_root / language.lower()

    def language_profile_dir(
        self,
        language: str,
    ) -> Path:

        return self.profile_root / language.lower()

    # ------------------------------------------------------------------

    def query_path(
        self,
        language: str,
    ) -> Path:

        return (
            self.language_query_dir(language)
            / "default.scm"
        )

    def profile_path(
        self,
        language: str,
    ) -> Path:

        return (
            self.language_profile_dir(language)
            / "profile.json"
        )

    # ------------------------------------------------------------------

    def exists(
        self,
        language: str,
    ) -> bool:

        return (
            self.query_path(language).exists()
            and self.profile_path(language).exists()
        )

    # ------------------------------------------------------------------

    def save(
        self,
        language: str,
        query: str,
        profile: dict,
    ) -> None:

        self.language_query_dir(language).mkdir(
            parents=True,
            exist_ok=True,
        )

        self.language_profile_dir(language).mkdir(
            parents=True,
            exist_ok=True,
        )

        self.query_path(language).write_text(
            query,
            encoding="utf-8",
        )

        with self.profile_path(language).open(
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                profile,
                file,
                indent=4,
            )

    # ------------------------------------------------------------------

    def load_query(
        self,
        language: str,
    ) -> str:

        return self.query_path(language).read_text(
            encoding="utf-8"
        )

    def load_profile(
        self,
        language: str,
    ) -> dict:

        with self.profile_path(language).open(
            "r",
            encoding="utf-8",
        ) as file:

            return json.load(file)

    # ------------------------------------------------------------------

    def delete(
        self,
        language: str,
    ) -> None:

        query_dir = self.language_query_dir(language)

        if query_dir.exists():

            for file in query_dir.iterdir():
                file.unlink()

            query_dir.rmdir()

        profile_dir = self.language_profile_dir(language)

        if profile_dir.exists():

            for file in profile_dir.iterdir():
                file.unlink()

            profile_dir.rmdir()

    # ------------------------------------------------------------------

    def clear(self) -> None:

        for root in (
            self.query_root,
            self.profile_root,
        ):

            if not root.exists():
                continue

            for directory in root.iterdir():

                if not directory.is_dir():
                    continue

                for file in directory.iterdir():
                    file.unlink()

                directory.rmdir()