"""
===============================================================================
AVAF Pro

Phase 2 Bootstrap

Creates and wires the complete Phase 2 runtime.

Responsibilities
----------------
- Register all active attack plugins.
- Register all validation plugins.
- Create AttackDispatcher.
- Create ValidationOrchestrator.
- Create AnalyzerEngine.
- Create IntegrationEngine.

This module is responsible only for composition.
It does not contain attack or validation logic.
===============================================================================
"""

from __future__ import annotations

from phase2_refinement_validation.analysis.analyzer_engine import AnalyzerEngine
from phase2_refinement_validation.dispatcher.attack_dispatcher import (
    AttackDispatcher,
)
from phase2_refinement_validation.engine.integration_engine import (
    IntegrationEngine,
)
from phase2_refinement_validation.engine.validation_orchestrator import (
    ValidationOrchestrator,
)
from phase2_refinement_validation.registry.attack_registry import (
    AttackRegistry,
)
from phase2_refinement_validation.registry.validator_registry import (
    ValidatorRegistry,
)

# ---------------------------------------------------------------------------
# Active attacks
# ---------------------------------------------------------------------------

from phase2_refinement_validation.attacks.command_injection.engine import (
    CommandInjectionAttack,
)
from phase2_refinement_validation.attacks.file_upload.engine import (
    FileUploadAttack,
)
from phase2_refinement_validation.attacks.idor.engine import (
    IDORAttack,
)
from phase2_refinement_validation.attacks.ldap_injection.engine import (
    LDAPInjectionAttack,
)
from phase2_refinement_validation.attacks.lfi.engine import (
    LFIAttack,
)
from phase2_refinement_validation.attacks.nosql_injection.engine import (
    NoSQLInjectionAttack,
)
from phase2_refinement_validation.attacks.open_redirect.engine import (
    OpenRedirectAttack,
)
from phase2_refinement_validation.attacks.rfi.engine import (
    RFIAttack,
)
from phase2_refinement_validation.attacks.sqli.engine import (
    SQLInjectionAttack,
)
from phase2_refinement_validation.attacks.ssrf.engine import (
    SSRFAttack,
)
from phase2_refinement_validation.attacks.template.engine import (
    AttackTemplate,
)
from phase2_refinement_validation.attacks.xss.engine import (
    XSSAttack,
)
from phase2_refinement_validation.attacks.xxe.engine import (
    XXEAttack,
)

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

from phase2_refinement_validation.validators.sqli_validator import (
    SQLiValidator,
)


def create_attack_registry() -> AttackRegistry:
    """
    Create and populate the active attack registry.
    """

    registry = AttackRegistry()

    registry.register_many(
        CommandInjectionAttack(),
        FileUploadAttack(),
        IDORAttack(),
        LDAPInjectionAttack(),
        LFIAttack(),
        NoSQLInjectionAttack(),
        OpenRedirectAttack(),
        RFIAttack(),
        SQLInjectionAttack(),
        SSRFAttack(),
        AttackTemplate(),
        XSSAttack(),
        XXEAttack(),
    )

    registry.lock()

    return registry


def create_validator_registry() -> ValidatorRegistry:
    """
    Create vulnerability-specific validators.

    The generic algorithm pipeline is owned by
    ValidationOrchestrator.

    Vulnerability-specific validators are optional
    refinements and must never manufacture a
    confirmed finding from incomplete evidence.
    """

    registry = ValidatorRegistry()

    # -------------------------------------------------------------
    # SQLi validator is retained as a vulnerability-specific
    # refinement component.
    #
    # It is NOT the final confirmation authority.
    # -------------------------------------------------------------

    registry.register(
        SQLiValidator(),
    )

    registry.lock()

    return registry


def create_phase2_engine(
    analyzer_registry,
):
    """
    Create the complete Phase 2 execution pipeline.

    Returns
    -------
    IntegrationEngine
        Fully wired Phase 2 coordinator.
    """

    # -----------------------------------------------------------------------
    # Registries
    # -----------------------------------------------------------------------

    attack_registry = create_attack_registry()

    validator_registry = create_validator_registry()

    # -----------------------------------------------------------------------
    # Dispatcher
    # -----------------------------------------------------------------------

    attack_dispatcher = AttackDispatcher(
        attack_registry,
    )

    # -----------------------------------------------------------------------
    # Validation
    # -----------------------------------------------------------------------

    validation_orchestrator = ValidationOrchestrator(
        validator_registry,
    )

    # -----------------------------------------------------------------------
    # Passive analysis
    # -----------------------------------------------------------------------

    analyzer_engine = AnalyzerEngine(
        analyzer_registry,
    )

    # -----------------------------------------------------------------------
    # Integration
    # -----------------------------------------------------------------------

    return IntegrationEngine(
        attack_registry=attack_registry,
        analyzer_engine=analyzer_engine,
        validation_orchestrator=validation_orchestrator,
        attack_dispatcher=attack_dispatcher,
    )
