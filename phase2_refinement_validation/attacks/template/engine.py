"""
===============================================================================
Attack Plugin Template

Reference implementation for all attack plugins.
===============================================================================
"""

from phase2_refinement_validation.attacks.base_attack import BaseAttack
from phase2_refinement_validation.engine.attack_engine import AttackEngine


class AttackTemplate(BaseAttack, AttackEngine):

    id = "template"

    name = "Attack Template"

    capability = None

    def supports(
        self,
        vector,
    ) -> bool:
        return False

    def generate_payloads(
        self,
        vector,
    ):
        return []

    def execute(
        self,
        vector,
        context,
    ):

        return self.execute_pipeline(
            vector=vector,
            context=context,
            detector=None,
        )