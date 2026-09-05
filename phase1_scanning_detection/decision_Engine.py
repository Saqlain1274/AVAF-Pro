"""
AVAF PRO
Decision Engine

Purpose
-------
Transforms raw runtime browser events into
runtime attack-surface artifacts.

This module NEVER:

✘ Parses HTML
✘ Uses wordlists
✘ Guesses URLs
✘ Detects vulnerabilities

It ONLY performs behavioural inference.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


# ==========================================================
# RUNTIME ARTIFACT
# ==========================================================

@dataclass(slots=True)
class RuntimeArtifact:

    category: str
    source: str
    value: str

    confidence: float = 1.0

    metadata: Dict[str, Any] = field(default_factory=dict)


# ==========================================================
# DECISION ENGINE
# ==========================================================

class DecisionEngine:

    def __init__(self):
    
        self.artifacts: List[RuntimeArtifact] = []
        self._seen = set()
    
        self.handlers = {
            "navigation": self._analyze_navigation,
            "network": self._analyze_network,
            "dom": self._analyze_dom,
            "storage": self._analyze_storage,
            "worker": self._analyze_worker,
            "messaging": self._analyze_message,
            "form": self._analyze_form,
        }

    def _dispatch(self, event):

        event_type = event.get("type")
    
        if event_type == "navigation":
            self._navigation(event)
    
        elif event_type == "network":
            self._network(event)
    
        elif event_type == "dom":
            self._dom(event)
    
        elif event_type == "storage":
            self._storage(event)
    
        elif event_type == "worker":
            self._worker(event)
    
        elif event_type == "messaging":
            self._message(event)
    
        elif event_type == "form":
            self._form(event)

    # ------------------------------------------------------
    # MAIN ANALYSIS
    # ------------------------------------------------------

    def analyze(self, events: List[dict]) -> List[RuntimeArtifact]:
    
        self.artifacts.clear()
        self._seen.clear()
    
        for event in events:
    
            if not isinstance(event, dict):
                continue
    
            handler = self.handlers.get(
                event.get("type")
            )
    
            if handler:
                handler(event)
    
        base_artifacts = list(self.artifacts)
    
        self.artifacts.extend(
            self.correlate(base_artifacts)
        )
    
        return self.artifacts
    
    # ------------------------------------------------------
    # COMPATIBILITY API
    # ------------------------------------------------------

    def decide(self, events: List[dict]) -> List[RuntimeArtifact]:
        """
        Backward-compatible wrapper used by the crawler.
        """
        return self.analyze(events)

    # ------------------------------------------------------
    # ADD ARTIFACT
    # ------------------------------------------------------

    def _add(
        self,
        category,
        source,
        value,
        confidence=1.0,
        **metadata
    ):

        if not value:
            return

        key = (category, value)

        if key in self._seen:
            return

        self._seen.add(key)

        self.artifacts.append(

            RuntimeArtifact(

                category=category,
                source=source,
                value=value,
                confidence=confidence,
                metadata=metadata

            )

        )

    # ------------------------------------------------------
    # NAVIGATION
    # ------------------------------------------------------

    def _analyze_navigation(self, event: dict):

        data = event.get("data", {})

        self._add(

            category="page",

            source="navigation",

            value=data.get("url"),

            trigger=data.get("trigger"),

            title=data.get("title")

        )

    # ------------------------------------------------------
    # NETWORK
    # ------------------------------------------------------

    def _analyze_network(self, event: dict):

        data = event.get("data", {})

        self._add(

            category="endpoint",

            source=data.get("engine", "network"),

            value=data.get("url"),

            method=data.get("method"),

            status=data.get("status"),

            duration=data.get("duration")

        )

    # ------------------------------------------------------
    # DOM
    # ------------------------------------------------------

    def _analyze_dom(self, event: dict):

        data = event.get("data", {})

        tag = data.get("tag")

        if tag:
            tag = tag.upper()

        self._add(

            category="dom",

            source=data.get("event", "mutation"),

            value=tag,

            id=data.get("id"),

            classes=data.get("classes")

        )

    # ------------------------------------------------------
    # STORAGE
    # ------------------------------------------------------

    def _analyze_storage(self, event: dict):

        data = event.get("data", {})

        self._add(

            category="storage",

            source=data.get("engine"),

            value=data.get("operation"),

            key=data.get("key")

        )

      # ------------------------------------------------------
    # WORKERS
    # ------------------------------------------------------

    def _analyze_worker(self, event: dict):

        data = event.get("data", {})

        self._add(

            category="worker",

            source=data.get("engine"),

            value=data.get("script")

        )

    # ------------------------------------------------------
    # MESSAGING
    # ------------------------------------------------------

    def _analyze_message(self, event: dict):

        data = event.get("data", {})

        self._add(

            category="messaging",

            source=data.get("engine"),

            value=data.get("target") or data.get("name")

        )

    # ------------------------------------------------------
    # FORMS
    # ------------------------------------------------------

    def _analyze_form(self, event: dict):

        data = event.get("data", {})

        self._add(

            category="form",

            source="runtime",

            value=data.get("action"),

            method=data.get("method", "GET")

        )

    # ------------------------------------------------------
    # CORRELATION
    # ------------------------------------------------------

    def correlate(self, source_artifacts=None) -> List[RuntimeArtifact]:
    
        artifacts = (
            list(source_artifacts)
            if source_artifacts is not None
            else list(self.artifacts)
        )
    
        correlated = []
    
        groups = {}
    
        for artifact in artifacts:
    
            groups.setdefault(
                artifact.category,
                []
            ).append(artifact)