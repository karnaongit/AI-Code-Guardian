from pathlib import Path

import pandas as pd


class KnowledgeLoader:

    REQUIRED_COLUMNS = [
        "source",
        "vulnerability",
        "description",
        "recommendation",
        "url",
    ]

    def __init__(self, csv_path: Path):
        self.csv_path = csv_path

    def load(self):

        if not self.csv_path.exists():
            raise FileNotFoundError(
                f"Knowledge base not found: {self.csv_path}"
            )

        df = pd.read_csv(self.csv_path)

        if df.empty:
            raise ValueError("Knowledge base is empty.")

        missing = [
            col
            for col in self.REQUIRED_COLUMNS
            if col not in df.columns
        ]

        if missing:
            raise ValueError(
                f"Missing columns: {missing}"
            )

        return df