from __future__ import annotations

import hashlib
import heapq
import time

from dataclasses import dataclass, field
from typing import Any

from streamlit import Page

from phase1_scanning_detection.behavior.element_collector import ElementCollector
from phase1_scanning_detection.behavior.dom_analyzer import DOMAnalyzer
from phase1_scanning_detection.behavior.runtime_analyzer import RuntimeAnalyzer
from phase1_scanning_detection.behavior.priority_engine import PriorityEngine
from phase1_scanning_detection.behavior.task_builder import TaskBuilder

from playwright.async_api import (
    Page,
    ElementHandle,
)


# ==========================================================
# Behavior Task
# ==========================================================

@dataclass(order=True)
class BehaviorTask:
    """
    A single interaction candidate.

    This object is consumed later by the InteractionEngine.
    """

    priority: float

    action: str = field(compare=False)

    selector: str = field(compare=False)

    description: str = field(compare=False)

    element: ElementHandle | None = field(
        default=None,
        compare=False,
    )

    metadata: dict[str, Any] = field(
        default_factory=dict,
        compare=False,
    )

    explored: bool = field(
        default=False,
        compare=False,
    )


# ==========================================================
# Behavior Engine
# ==========================================================

class BehaviorEngine:
    """
    Runtime Behaviour Discovery Engine

    Responsibilities
    ----------------
    ✓ Discover interactive DOM elements

    ✓ Discover runtime artifacts

    ✓ Prioritize interactions

    ✓ Remove duplicates

    ✓ Produce BehaviourTasks

    Never
    -----
    ✘ Click anything

    ✘ Fill forms

    ✘ Navigate pages

    ✘ Execute JavaScript payloads

    InteractionEngine performs execution.
    """

    def __init__(self):

        # DOM fingerprints
        
        self.page = None

        self.dom_history: set[str] = set()

        #
        # Already queued tasks
        #

        self.task_history: set[tuple] = set()

        #
        # Priority queue
        #

        self.tasks: list[BehaviorTask] = []

        #
        # Runtime statistics
        #

        self.started = time.time()

        self.pages_seen = 0

        self.interactions = 0

        #
        # Runtime cache
        #

        self.runtime_artifacts: dict[str, Any] = {}

        #
        # Current page
        #

        self.page: Page | None = None
        
        self.runtime_artifacts = {}

        self.tasks = []

        self.task_history = set()

        self.dom_history = set()

        self.started = time.time()

        self.pages_seen = 0

        #
        # Modular components
        #

        self.dom_analyzer = DOMAnalyzer()

        self.runtime_analyzer = RuntimeAnalyzer()

        self.priority_engine = PriorityEngine()

        self.task_builder = TaskBuilder()
        
    # ==========================================================
    # Reset
    # ==========================================================
    
    def reset(self):
    
        self.tasks.clear()
    
        self.task_history.clear()
    
        self.runtime_artifacts.clear()
    
        self.elements.clear()
    
        self.page = None
    
    
    # ==========================================================
    # Attach Page
    # ==========================================================
    
    async def attach(
        self,
        page: Page,
    ):
    
        self.page = page
    
    
    # ==========================================================
    # DOM Fingerprint
    # ==========================================================
    
    async def fingerprint(self) -> str:
    
        if self.page is None:
    
            return ""
    
        if self.page.is_closed():
    
            return ""
    
        try:
    
            html = await self.page.content()
    
        except Exception:
    
            return ""
    
        return hashlib.sha256(
    
            html.encode("utf-8")
    
        ).hexdigest()
    
    
    # ==========================================================
    # DOM Changed
    # ==========================================================
    
    async def dom_changed(self) -> bool:
    
        fingerprint = await self.fingerprint()
    
        if not fingerprint:
    
            return False
    
        if fingerprint in self.dom_history:
    
            return False
    
        self.dom_history.add(
    
            fingerprint
    
        )
    
        return True
    
    
    # ==========================================================
    # Runtime Artifacts
    # ==========================================================
    
    def load_runtime(
    
        self,
    
        runtime_data: dict,
    
    ):
    
        self.runtime_artifacts = (
    
            runtime_data.get(
    
                "artifacts",
    
                {}
    
            )
    
            if runtime_data
    
            else {}
    
        )
         
    # ==========================================================
    # Clear Tasks
    # ==========================================================
    
    def clear_tasks(self):
    
        self.tasks.clear()
    
        self.task_history.clear()
    
    
    # ==========================================================
    # Add Task
    # ==========================================================
    
    def add_task(self, task: BehaviorTask):
    
        key = (
    
            task.action,
    
            task.selector,
    
            task.description,
    
        )
    
        if key in self.task_history:
    
            return
    
        self.task_history.add(key)
    
        heapq.heappush(
    
            self.tasks,
    
            task,
    
        )
    
    
    # ==========================================================
    # Build Task
    # ==========================================================
    
    def build_task(
    
        self,
    
        priority: float,
    
        action: str,
    
        selector: str,
    
        description: str,
    
        element: ElementHandle | None,
    
        **metadata,
    
    ):
    
        self.add_task(
    
            BehaviorTask(
    
                priority=priority,
    
                action=action,
    
                selector=selector,
    
                description=description,
    
                element=element,
    
                metadata=metadata,
    
            )
    
        )
    
    
    # ==========================================================
    # Get Tasks
    # ==========================================================
    
    def get_tasks(self) -> list[BehaviorTask]:
    
        return sorted(
    
            self.tasks,
    
            reverse=True,
    
        )
    
    
    # ==========================================================
    # Runtime Statistics
    # ==========================================================
    
    def statistics(self):
    
        return {
    
            "pages_seen": self.pages_seen,
    
            "queued_tasks": len(self.tasks),
    
            "unique_tasks": len(self.task_history),
    
            "runtime": round(
    
                time.time() - self.started,
    
                2,
    
            ),
    
        }
        
    # ==========================================================
    # Clear Tasks
    # ==========================================================
    
    def clear_tasks(self):
    
        self.tasks.clear()
    
        self.task_history.clear()


    # ==========================================================
    # Add Task
    # ==========================================================
    
    def add_task(self, task: BehaviorTask):
    
        key = (
    
            task.action,
    
            task.selector,
    
            task.description,
    
        )
    
        if key in self.task_history:
    
            return
    
        self.task_history.add(key)
    
        heapq.heappush(
    
            self.tasks,
    
            task,
    
        )
    
    
    # ==========================================================
    # Build Task
    # ==========================================================
    
    def build_task(
    
        self,
    
        priority: float,
    
        action: str,
    
        selector: str,
    
        description: str,
    
        element: ElementHandle | None,
    
        **metadata,
    
    ):
    
        self.add_task(
    
            BehaviorTask(
    
                priority=priority,
    
                action=action,
    
                selector=selector,
    
                description=description,
    
                element=element,
    
                metadata=metadata,
    
            )
    
        )
    
    
    # ==========================================================
    # Get Tasks
    # ==========================================================
    
    def get_tasks(self) -> list[BehaviorTask]:
    
        return sorted(
    
            self.tasks,
    
            reverse=True,
    
        )
    
    
    # ==========================================================
    # Runtime Statistics
    # ==========================================================
    
    def statistics(self):
    
        return {
    
            "pages_seen": self.pages_seen,
    
            "queued_tasks": len(self.tasks),
    
            "unique_tasks": len(self.task_history),
    
            "runtime": round(
    
                time.time() - self.started,
    
                2,
    
            ),
    
        }
            
    async def discover(self):
    
        #
        # Collect runtime DOM
        #
    
        collector = ElementCollector(
    
            self.page
    
        )
    
        elements = await collector.collect()
    
        #
        # Analyze DOM
        #
    
        dom_assets = await self.dom_analyzer.analyze(
    
            elements
    
        )
    
        #
        # Analyze Runtime
        #
    
        runtime_assets = self.runtime_analyzer.analyze(
    
            self.runtime_artifacts
    
        )
    
        #
        # Prioritize
        #
    
        prioritized = self.priority_engine.build(
    
            dom_assets,
    
            runtime_assets,
    
        )
    
        #
        # Build Tasks
        #
    
        self.tasks = self.task_builder.build(
    
            prioritized
    
        )
    
        return self.tasks