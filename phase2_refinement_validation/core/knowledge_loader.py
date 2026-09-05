"""
Knowledge Loader

Loads rules, payloads, fingerprints, signatures and other
knowledge files used during validation.
"""

from pathlib import Path
from typing import Any, Dict

import yaml


class KnowledgeLoader:
    """
    Loads knowledge from the knowledge directory.
    """

    def __init__(self, knowledge_root: str = "phase2_refinement_validation/knowledge"):
        self.root = Path(knowledge_root)
        self.cache: Dict[str, Any] = {}

    # ---------------------------------------------------------
    # Public API
    # ---------------------------------------------------------

    def load(self, category: str, name: str) -> Dict[str, Any]:
        """
        Load a knowledge file.

        Example:
            load("rules", "sqli")
            load("payloads", "xss")
        """

        cache_key = f"{category}:{name}"

        if cache_key in self.cache:
            return self.cache[cache_key]

        file_path = self.root / category / f"{name}.yaml"

        if not file_path.exists():
            return {}

        with open(file_path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}

        self.cache[cache_key] = data

        return data

    def clear_cache(self) -> None:
        """Clear cached knowledge."""
        self.cache.clear()