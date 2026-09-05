"""
AVAF Pro - Phase 2 Validation Orchestrator

One AttackResult -> one isolated ValidationContext ->

Replay -> Analysis -> Evidence -> Verification -> Confidence
                                                        |
                                                        v
                                             deterministic gate
                                                        |
                                                 CONFIRMED/REJECTED

This file owns orchestration only. It does not construct Phase-1 vectors,
generate attack payloads, or perform vulnerability detection itself.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Iterable

from phase2_refinement_validation.algorithms.analysis_validator import AnalysisValidator
from phase2_refinement_validation.algorithms.replay_validator import ReplayValidator
from phase2_refinement_validation.algorithms.evidence_validator import EvidenceValidator
from phase2_refinement_validation.algorithms.verification_validator import VerificationValidator
from phase2_refinement_validation.algorithms.confidence_validator import ConfidenceValidator

from phase2_refinement_validation.models.attack_plan import AttackPlan
from phase2_refinement_validation.models.attack_result import AttackResult
from phase2_refinement_validation.models.validation_context import ValidationContext
from phase2_refinement_validation.models.validation_result import ValidationResult
from phase2_refinement_validation.registry.validator_registry import ValidatorRegistry

logger = logging.getLogger(__name__)


class ValidationOrchestrator:
    """Candidate-isolated Phase-2 validation coordinator."""

    CONFIDENCE_THRESHOLD = 70.0
    PIPELINE_VALIDATOR = "phase2_algorithm_pipeline"

    def __init__(self, registry: ValidatorRegistry) -> None:
        self.registry = registry

        # Replay must precede response analysis/evidence.
        self.algorithm_factories = (
            ReplayValidator,
            AnalysisValidator,
            EvidenceValidator,
            VerificationValidator,
            ConfidenceValidator,
        )

        self.algorithm_names = [
            factory().name for factory in self.algorithm_factories
        ]

        print(
            "[VALIDATION] Pipeline="
            + " -> ".join(self.algorithm_names),
            flush=True,
        )

    # ------------------------------------------------------------------
    # PUBLIC
    # ------------------------------------------------------------------
    
    def validate_parallel(
        self,
        attack_results: Iterable[AttackResult],
        context: ValidationContext,
        max_workers: int = 1,
        progress_cb=None,
    ) -> list[ValidationResult]:
    
        candidates = list(attack_results or [])
        total = len(candidates)

        if not total:
            self._progress(progress_cb, 100.0)
            print("[VALIDATION] No AttackResults supplied.", flush=True)
            return []

        workers = max(
            1,
            min(
                int(max_workers or 1),
                total,
            ),
        )

        print(
            f"[VALIDATION] Candidates={total} "
            f"Workers={workers} Algorithms={len(self.algorithm_factories)}",
            flush=True,
        )

        confirmed: list[ValidationResult] = []
        completed = 0

        with ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="avaf-validation",
        ) as executor:

            futures = {
                executor.submit(
                    self._validate_isolated,
                    attack_result,
                    context,
                    index,
                    total,
                ): index
                for index, attack_result in enumerate(candidates, start=1)
            }

            for future in as_completed(futures):
                index = futures[future]

                try:
                    result = future.result()

                    if (
                        result is not None
                        and bool(getattr(result, "success", False))
                        and getattr(result, "status", "") == "confirmed"
                    ):
                        confirmed.append(result)
                        print(
                            f"[VALIDATION] Candidate={index}/{total} "
                            f"-> CONFIRMED confidence="
                            f"{self._number(getattr(result, 'confidence', 0.0)):.1f}",
                            flush=True,
                        )
                    else:
                        print(
                            f"[VALIDATION] Candidate={index}/{total} -> REJECTED",
                            flush=True,
                        )

                except Exception as exc:
                    logger.exception("Validation candidate %s failed.", index)
                    print(
                        f"[VALIDATION] Candidate={index}/{total} "
                        f"-> ERROR {type(exc).__name__}: {exc}",
                        flush=True,
                    )

                finally:
                    completed += 1
                    value = completed / total * 100.0
                    self._progress(progress_cb, value)
                    print(
                        f"[PROGRESS] PHASE2 "
                        f"{50.0 + value * 0.49:.1f} "
                        f"validation ({completed}/{total})",
                        flush=True,
                    )

        # Stable order for GUI/reporting.
        confirmed.sort(
            key=lambda result: int(
                (getattr(result, "metadata", {}) or {}).get(
                    "candidate_index", 0
                ) or 0
            )
        )

        print(
            f"[VALIDATION] Complete Candidates={total} "
            f"Confirmed={len(confirmed)} Rejected={total-len(confirmed)}",
            flush=True,
        )
        return confirmed

    # ------------------------------------------------------------------
    # ISOLATION
    # ------------------------------------------------------------------

    def _validate_isolated(
        self,
        attack_result: AttackResult,
        parent_context: ValidationContext,
        index: int,
        total: int,
    ) -> ValidationResult:

        try:
            candidate_context = self._build_candidate_context(
                parent_context,
                attack_result,
            )
            return self._validate_one(
                attack_result,
                candidate_context,
                index,
                total,
            )

        except Exception as exc:
            logger.exception("Candidate %s crashed.", index)

            attack_name = str(
                getattr(attack_result, "attack", "unknown") or "unknown"
            )
            vector_id = self._vector_id(
                getattr(attack_result, "vector", None)
            )

            print(
                f"[VALIDATION] Candidate={index}/{total} "
                f"FATAL attack={attack_name} vector={vector_id} "
                f"error={type(exc).__name__}: {exc}",
                flush=True,
            )

            return ValidationResult(
                validator=self.PIPELINE_VALIDATOR,
                success=False,
                status="error",
                confidence=0.0,
                duration=0.0,
                summary=f"Candidate validation failed: {type(exc).__name__}: {exc}",
                evidence=[
                    self._text(getattr(attack_result, "evidence", ""))
                ],
                indicators=[],
                metadata={
                    "attack": attack_name,
                    "vector_id": vector_id,
                    "candidate_index": index,
                    "candidate_total": total,
                    "fatal_error": f"{type(exc).__name__}: {exc}",
                },
            )

    # ------------------------------------------------------------------
    # CONTEXT CREATION
    # ------------------------------------------------------------------

    @staticmethod
    def _build_candidate_context(
        parent: ValidationContext,
        attack_result: AttackResult,
    ) -> ValidationContext:

        if attack_result is None:
            raise ValueError("AttackResult is required.")

        vector = getattr(attack_result, "vector", None)
        if vector is None:
            raise ValueError(
                "AttackResult has no originating AttackVector."
            )

        vector_metadata = dict(getattr(vector, "metadata", {}) or {})

        vector_id = str(
            vector_metadata.get(
                "vector_id",
                getattr(vector, "id", ""),
            )
            or ""
        )

        attack_name = str(
            getattr(attack_result, "attack", "") or ""
        )

        plan = AttackPlan(
            vector_id=vector_id,
            vulnerability_type=str(
                vector_metadata.get(
                    "candidate_type",
                    vector_metadata.get(
                        "vulnerability_type",
                        attack_name,
                    ),
                )
                or attack_name
            ),
            confidence=ValidationOrchestrator._number(
                getattr(
                    attack_result,
                    "confidence",
                    vector_metadata.get("confidence", 0.0),
                )
            ),
            risk=str(
                vector_metadata.get(
                    "risk",
                    getattr(vector, "risk", ""),
                )
                or ""
            ),
            method=str(
                getattr(vector, "method", "GET") or "GET"
            ).upper(),
            url=str(getattr(vector, "url", "") or ""),
            parameter=str(getattr(vector, "parameter", "") or ""),
            location=str(
                getattr(
                    vector,
                    "parameter_type",
                    getattr(vector, "location", ""),
                )
                or ""
            ),
            content_type=str(
                vector_metadata.get(
                    "content_type",
                    getattr(vector, "content_type", ""),
                )
                or ""
            ),
            original_value=getattr(vector, "original_value", None),
            metadata=vector_metadata,
        )

        # IMPORTANT: fresh context. Do not copy candidate results/cache/exchanges.
        candidate = ValidationContext(
            attack_plan=plan,
            baseline=getattr(parent, "baseline", None),
        )

        candidate.metadata.update(
            dict(getattr(parent, "metadata", {}) or {})
        )
        candidate.metadata.update(
            {
                "phase": 2,
                "candidate_attack": attack_name,
                "candidate_vector_id": vector_id,
                "candidate_url": plan.url,
                "candidate_parameter": plan.parameter,
                "candidate_location": plan.location,
            }
        )

        candidate.cache["attack_result"] = attack_result

        attack_metadata = getattr(attack_result, "metadata", {}) or {}
        attack_response = attack_metadata.get("response")

        if attack_response is None:
            attack_response = getattr(attack_result, "response", None)

        if attack_response is not None:
            candidate.cache["attack_response"] = attack_response

        attack_evidence = ValidationOrchestrator._text(
            getattr(attack_result, "evidence", "")
        )
        attack_indicator = ValidationOrchestrator._text(
            getattr(attack_result, "indicator", "")
        )

        candidate.metadata.update(
            {
                "attack": attack_name,
                "payload": getattr(attack_result, "payload", "") or "",
                "attack_evidence": attack_evidence,
                "attack_indicator": attack_indicator,
                "attack_confidence": ValidationOrchestrator._number(
                    getattr(attack_result, "confidence", 0.0)
                ),
            }
        )

        print(
            f"[CONTEXT] Candidate={vector_id or '?'} "
            f"attack={attack_name} url={plan.url} "
            f"parameter={plan.parameter!r} location={plan.location!r} "
            f"attack_response={'YES' if attack_response is not None else 'NO'} "
            f"evidence={'YES' if attack_evidence else 'NO'} "
            f"indicator={'YES' if attack_indicator else 'NO'}",
            flush=True,
        )

        return candidate

    # ------------------------------------------------------------------
    # PARENT CONTEXT
    # ------------------------------------------------------------------

    @staticmethod
    def build_parent_context(attack_context) -> ValidationContext:
        if attack_context is None:
            raise ValueError("attack_context is required.")

        metadata = dict(getattr(attack_context, "metadata", {}) or {})

        metadata.setdefault(
            "url",
            getattr(attack_context, "url", ""),
        )
        metadata.setdefault(
            "scheme",
            getattr(attack_context, "scheme", ""),
        )
        metadata.setdefault(
            "timeout",
            getattr(attack_context, "timeout", 15),
        )
        metadata.setdefault(
            "verify_ssl",
            getattr(attack_context, "verify_ssl", False),
        )

        parent = ValidationContext(
            attack_plan=AttackPlan(
                vector_id="",
                vulnerability_type="",
                confidence=0.0,
                risk="",
                method="",
                url=str(getattr(attack_context, "url", "") or ""),
                parameter="",
                location="",
                content_type="",
                original_value=None,
                metadata=metadata,
            ),
            baseline=getattr(
                attack_context,
                "original_response",
                None,
            ),
        )

        parent.metadata.update(metadata)
        parent.cache["attack_context"] = attack_context
        return parent

    @staticmethod
    def _validator_matches_attack(
        validator,
        attack_name: str,
    ) -> bool:
        """
        Determine whether a registry validator applies to this attack.

        Prefer an explicit supported attack declaration when available.
        Fall back to a conservative name match.
        """

        attack_name = str(
            attack_name or ""
        ).strip().lower()

        if not attack_name:
            return False

        supported = getattr(
            validator,
            "supported_attacks",
            None,
        )

        if supported:
            try:
                return attack_name in {
                    str(item).strip().lower()
                    for item in supported
                }
            except Exception:
                pass

        validator_name = str(
            getattr(
                validator,
                "name",
                validator.__class__.__name__,
            )
            or ""
        ).lower()

        aliases = {
            "sqli": "sql",
            "sql_injection": "sql",
            "sql injection": "sql",
            "ldap_injection": "ldap",
            "xss": "xss",
            "ssrf": "ssrf",
            "idor": "idor",
        }

        attack_key = aliases.get(
            attack_name,
            attack_name,
        )

        return attack_key in validator_name

    # ------------------------------------------------------------------
    # ONE CANDIDATE
    # ------------------------------------------------------------------

    def _validate_one(
        self,
        attack_result: AttackResult,
        context: ValidationContext,
        index: int,
        total: int,
    ) -> ValidationResult:

        started = time.perf_counter()

        attack_name = str(
            getattr(
                attack_result,
                "attack",
                "unknown",
            )
            or "unknown"
        )

        vector_id = self._vector_id(
            getattr(
                attack_result,
                "vector",
                None,
            )
        )

        print(
            f"[VALIDATION] Candidate={index}/{total} "
            f"START attack={attack_name} vector={vector_id}",
            flush=True,
        )

        # ==============================================================
        # REGISTRY VALIDATORS
        #
        # Registry validators are supporting evidence only.
        # They never replace the mandatory generic validation chain.
        # ==============================================================

        registry_results = []
        registry_errors = []

        validators = self._registry_all()

        print(
            f"[REGISTRY] Candidate={index}/{total} "
            f"validators={len(validators)}",
            flush=True,
        )

        for validator in validators:

            if not self._validator_matches_attack(
                validator,
                attack_name,
            ):
                print(
                    f"[REGISTRY] Candidate={index}/{total} "
                    f"Validator="
                    f"{getattr(validator, 'name', validator.__class__.__name__)} "
                    f"SKIPPED "
                    f"reason=not_applicable_to_attack "
                    f"attack={attack_name}",
                    flush=True,
                )
                continue

            name = str(
                getattr(
                    validator,
                    "name",
                    validator.__class__.__name__,
                )
                or validator.__class__.__name__
            )

            try:

                result = self._run_registry_validator(
                    validator,
                    attack_result,
                    context,
                )

                if result is None:
                    result = ValidationResult(
                        validator=name,
                        success=False,
                        status="no_result",
                        confidence=0.0,
                        summary=f"{name} returned no result.",
                    )

                registry_results.append(result)

                print(
                    f"[REGISTRY] Candidate={index}/{total} "
                    f"Validator={name} "
                    f"success="
                    f"{bool(getattr(result, 'success', False))} "
                    f"confidence="
                    f"{self._number(getattr(result, 'confidence', 0.0)):.1f}",
                    flush=True,
                )

            except Exception as exc:

                error = (
                    f"{type(exc).__name__}: {exc}"
                )

                registry_errors.append(
                    {
                        "validator": name,
                        "error": error,
                    }
                )

                print(
                    f"[REGISTRY] Candidate={index}/{total} "
                    f"Validator={name} ERROR={error}",
                    flush=True,
                )

                logger.exception(
                    "Registry validator '%s' failed.",
                    name,
                )

        # ==============================================================
        # GENERIC VALIDATION CHAIN
        #
        # Every mandatory stage is attempted:
        #
        # Replay
        #   -> Analysis
        #   -> Evidence
        #   -> Verification
        #   -> Confidence
        #
        # No stage is silently skipped.
        # ==============================================================

        stage_results = []
        stage_errors = []

        for factory in self.algorithm_factories:

            algorithm = factory()

            name = str(
                getattr(
                    algorithm,
                    "name",
                    algorithm.__class__.__name__,
                )
                or algorithm.__class__.__name__
            )

            stage_started = time.perf_counter()

            print(
                f"[ALGORITHM] Candidate={index}/{total} "
                f"Stage={name} START",
                flush=True,
            )

            try:

                result = algorithm.run(context)

                if result is None:
                    result = ValidationResult(
                        validator=name,
                        success=False,
                        status="no_result",
                        confidence=0.0,
                        summary=f"{name} returned no result.",
                    )

                stage_results.append(result)

                # Store every stage result by its real validator name.
                context.results[name] = result

                # Keep replay/verification context synchronized.
                self._synchronize_context(
                    context,
                    attack_result,
                    name,
                )

                elapsed = (
                    time.perf_counter()
                    - stage_started
                )

                print(
                    f"[ALGORITHM] Candidate={index}/{total} "
                    f"Stage={name} "
                    f"success="
                    f"{bool(getattr(result, 'success', False))} "
                    f"confidence="
                    f"{self._number(getattr(result, 'confidence', 0.0)):.1f} "
                    f"time={elapsed:.3f}s",
                    flush=True,
                )

            except Exception as exc:

                elapsed = (
                    time.perf_counter()
                    - stage_started
                )

                error = (
                    f"{type(exc).__name__}: {exc}"
                )

                result = ValidationResult(
                    validator=name,
                    success=False,
                    status="error",
                    confidence=0.0,
                    summary=f"{name} failed: {error}",
                    metadata={
                        "error": str(exc),
                    },
                )

                stage_results.append(result)

                stage_errors.append(
                    {
                        "algorithm": name,
                        "error": error,
                    }
                )

                context.results[name] = result

                print(
                    f"[ALGORITHM] Candidate={index}/{total} "
                    f"Stage={name} ERROR={error} "
                    f"time={elapsed:.3f}s",
                    flush=True,
                )

                logger.exception(
                    "Algorithm '%s' failed for candidate %s.",
                    name,
                    index,
                )

        # ==============================================================
        # BUILD STAGE STATE
        # ==============================================================

        expected = list(
            self.algorithm_names
        )

        actual = [
            str(
                getattr(
                    result,
                    "validator",
                    "",
                )
                or ""
            )
            for result in stage_results
        ]

        missing_stages = [
            name
            for name in expected
            if name not in actual
        ]

        duplicate_stages = [
            name
            for name in set(actual)
            if actual.count(name) > 1
        ]

        all_present = bool(
            len(stage_results) == len(expected)
            and not missing_stages
            and not duplicate_stages
        )

        all_success = bool(
            all_present
            and all(
                bool(
                    getattr(
                        result,
                        "success",
                        False,
                    )
                )
                for result in stage_results
            )
        )

        # ==============================================================
        # IMPORTANT FIX:
        #
        # The following values MUST be derived before the confirmation
        # gate. They previously existed in the gate without being
        # initialized, causing broken validation logic / NameError.
        # ==============================================================

        attack_metadata = getattr(
            attack_result,
            "metadata",
            {},
        ) or {}

        # --------------------------------------------------------------
        # REAL HTTP EXECUTION
        # --------------------------------------------------------------

        real_http_execution = bool(
            attack_metadata.get(
                "real_http_execution",
                False,
            )
        )

        request_sent = bool(
            attack_metadata.get(
                "request_sent",
                False,
            )
        )

        response_received = bool(
            attack_metadata.get(
                "response_received",
                False,
            )
        )

        payload_executed = bool(
            attack_metadata.get(
                "payload_executed",
                False,
            )
        )

        # AttackEngine stores the actual response in metadata["response"].
        # ValidationContext may also contain it in cache.
        real_attack_response = (
            context.cache.get(
                "attack_response"
            )
        )

        if real_attack_response is None:
            real_attack_response = attack_metadata.get(
                "response"
            )

        if real_attack_response is None:
            real_attack_response = getattr(
                attack_result,
                "response",
                None,
            )

        # A response alone is not enough. It must have come from the
        # real HTTP execution path.
        real_attack_response_available = bool(
            real_http_execution
            and response_received
            and real_attack_response is not None
        )

        # --------------------------------------------------------------
        # ATTACK EVIDENCE / INDICATOR
        # --------------------------------------------------------------

        attack_evidence = getattr(
            attack_result,
            "evidence",
            None,
        )

        if attack_evidence is None:
            attack_evidence = attack_metadata.get(
                "evidence"
            )

        attack_indicator = getattr(
            attack_result,
            "indicator",
            None,
        )

        if attack_indicator is None:
            attack_indicator = attack_metadata.get(
                "indicator"
            )

        attack_evidence = (
            attack_evidence
            or ""
        )

        attack_indicator = (
            attack_indicator
            or ""
        )

        evidence_available = bool(
            real_attack_response_available
            and (
                attack_evidence
                or attack_indicator
            )
        )

        # ==============================================================
        # GET SPECIFIC VALIDATION STAGE RESULTS
        # ==============================================================

        verification_result = None
        confidence_result = None

        for result in stage_results:

            validator_name = str(
                getattr(
                    result,
                    "validator",
                    "",
                )
                or ""
            ).lower()

            if validator_name == "verification":
                verification_result = result

            elif validator_name == "confidence":
                confidence_result = result

        # Fallback to context.results in case a validator uses a
        # different result storage path.
        if verification_result is None:
            verification_result = context.results.get(
                "Verification"
            )

        if confidence_result is None:
            confidence_result = context.results.get(
                "Confidence"
            )

        verification_success = bool(
            verification_result is not None
            and getattr(
                verification_result,
                "success",
                False,
            )
        )

        confidence = self._number(
            getattr(
                confidence_result,
                "confidence",
                0.0,
            )
            if confidence_result is not None
            else 0.0
        )

        verified_indicator_count = (
            self._verified_indicator_count(
                context,
                verification_result,
            )
        )

        # ==============================================================
        # SECURITY EVIDENCE GATE
        # ==============================================================
        
        registry_success = any(
            bool(getattr(result, "success", False))
            for result in registry_results
        )
        
        attack_metadata = getattr(
            attack_result,
            "metadata",
            {},
        ) or {}
        
        real_http_execution = bool(
            attack_metadata.get(
                "real_http_execution",
                False,
            )
        )
        
        request_sent = bool(
            attack_metadata.get(
                "request_sent",
                False,
            )
        )
        
        response_received = bool(
            attack_metadata.get(
                "response_received",
                False,
            )
        )
        
        payload_executed = bool(
            attack_metadata.get(
                "payload_executed",
                False,
            )
        )
        
        # ==============================================================
        # FINAL SECURITY CONFIRMATION GATE
        # ==============================================================
        #
        # Verification is the vulnerability-security authority.
        #
        # Confirmation requires:
        #
        #   algorithms pass
        #   + real HTTP execution
        #   + request sent
        #   + response received
        #   + verification explicitly passed
        #   + verification explicitly marked verified
        #   + verified security indicator
        #   + vulnerability evidence available
        #
        # IMPORTANT:
        #
        # `payload_executed` is NOT a universal confirmation requirement.
        #
        # AttackExecutor can prove:
        #
        #   payload_transmitted
        #   real_http_execution
        #   request_sent
        #   response_received
        #
        # It cannot universally prove application-level interpretation.
        # Vulnerability-specific Verification establishes that.
        #
        # Confidence remains a measurement and diagnostic signal.
        # It is NOT a second independent veto after Verification passes.
        #
        # No fixed confirmed count is used.
        # ==============================================================
        
        verification_metadata = (
            getattr(
                verification_result,
                "metadata",
                {},
            )
            or {}
        )
        
        verification_verified = bool(
            verification_metadata.get(
                "verified",
                False,
            )
        )
        
        positive_security_evidence = bool(
            verified_indicator_count > 0
        )
        
        confirmed = bool(
            all_present
            and all_success
            and not stage_errors
            and real_http_execution
            and request_sent
            and response_received
            and verification_success
            and verification_verified
            and positive_security_evidence
            and evidence_available
        )
    
        failed_stages = [
            str(
                getattr(
                    result,
                    "validator",
                    "",
                )
                or ""
            )
            for result in stage_results
            if not bool(
                getattr(
                    result,
                    "success",
                    False,
                )
            )
        ]

        failed_stages.extend(
            f"missing:{name}"
            for name in missing_stages
        )

        failed_stages.extend(
            f"duplicate:{name}"
            for name in duplicate_stages
        )

        if not real_http_execution:
            failed_stages.append(
                "real_http_execution"
            )

        if not request_sent:
            failed_stages.append(
                "request_not_sent"
            )


        if not evidence_available:
            failed_stages.append(
                "evidence_unavailable"
            )

        if confidence < self.CONFIDENCE_THRESHOLD:
            failed_stages.append(
                "confidence_below_threshold"
            )

        # Remove duplicates while preserving order.
        failed_stages = list(
            dict.fromkeys(
                failed_stages
            )
        )

        # ==============================================================
        # DIAGNOSTICS
        # ==============================================================

        print(
            f"[CONFIRM-GATE] candidate={index}/{total} "
            f"attack={attack_name} "
            f"vector={vector_id} "
            f"all_present={all_present} "
            f"all_success={all_success} "
            f"stage_errors={len(stage_errors)} "
            f"real_http_execution={real_http_execution} "
            f"payload_executed={payload_executed} "
            f"verification_success={verification_success} "
            f"verified_indicators={verified_indicator_count} "
            f"registry_success={registry_success} "
            f"positive_security_evidence="
            f"{positive_security_evidence} "
            f"evidence_available={evidence_available} "
            f"confidence={confidence:.1f} "
            f"threshold={self.CONFIDENCE_THRESHOLD:.1f} "
            f"confirmed={confirmed}",
            flush=True,
        )

        print(
            f"[CONFIRM-GATE] candidate={index}/{total} "
            f"missing={missing_stages or 'none'} "
            f"duplicates={duplicate_stages or 'none'} "
            f"failed={failed_stages or 'none'}",
            flush=True,
        )

        print(
            f"[CONFIRM-GATE] candidate={index}/{total} "
            f"attack_evidence="
            f"{'YES' if attack_evidence else 'NO'} "
            f"attack_indicator="
            f"{'YES' if attack_indicator else 'NO'} "
            f"attack_response="
            f"{'YES' if real_attack_response is not None else 'NO'} "
            f"replay_response="
            f"{'YES' if context.cache.get('replay_response') is not None else 'NO'} "
            f"exchanges={len(context.exchanges)}",
            flush=True,
        )

        if verification_result is not None:
            print(
                f"[CONFIRM-GATE] verification_metadata="
                f"{getattr(verification_result, 'metadata', {}) or {}}",
                flush=True,
            )

        if confidence_result is not None:
            print(
                f"[CONFIRM-GATE] confidence_metadata="
                f"{getattr(confidence_result, 'metadata', {}) or {}}",
                flush=True,
            )

        # ==============================================================
        # FINAL METADATA
        # ==============================================================

        duration = (
            time.perf_counter()
            - started
        )

        attack_evidence_value = (
            attack_evidence
            or attack_indicator
        )

        metadata = {
            "attack": attack_name,
            "vector_id": vector_id,

            "url": str(
                getattr(
                    context.attack_plan,
                    "url",
                    "",
                )
                or ""
            ),

            "parameter": str(
                getattr(
                    context.attack_plan,
                    "parameter",
                    "",
                )
                or ""
            ),

            "location": str(
                getattr(
                    context.attack_plan,
                    "location",
                    "",
                )
                or ""
            ),

            "payload": (
                getattr(
                    attack_result,
                    "payload",
                    "",
                )
                or ""
            ),

            # ----------------------------------------------------------
            # REAL EXECUTION PROOF
            # ----------------------------------------------------------

            "real_http_execution": real_http_execution,
            "request_sent": request_sent,
            "response_received": response_received,
            "payload_executed": payload_executed,

            # ----------------------------------------------------------
            # ALGORITHM STATE
            # ----------------------------------------------------------

            "algorithm_stages": actual,
            "algorithm_expected": expected,

            "algorithm_success": {
                str(
                    getattr(
                        result,
                        "validator",
                        "",
                    )
                    or ""
                ): bool(
                    getattr(
                        result,
                        "success",
                        False,
                    )
                )
                for result in stage_results
            },

            "algorithm_confidence": {
                str(
                    getattr(
                        result,
                        "validator",
                        "",
                    )
                    or ""
                ): self._number(
                    getattr(
                        result,
                        "confidence",
                        0.0,
                    )
                )
                for result in stage_results
            },

            "algorithm_errors": stage_errors,

            # ----------------------------------------------------------
            # REGISTRY
            # ----------------------------------------------------------

            "registry_results": [
                {
                    "validator": str(
                        getattr(
                            result,
                            "validator",
                            "",
                        )
                        or ""
                    ),
                    "success": bool(
                        getattr(
                            result,
                            "success",
                            False,
                        )
                    ),
                    "confidence": self._number(
                        getattr(
                            result,
                            "confidence",
                            0.0,
                        )
                    ),
                    "summary": str(
                        getattr(
                            result,
                            "summary",
                            "",
                        )
                        or ""
                    ),
                }
                for result in registry_results
            ],

            "registry_errors": registry_errors,

            # ----------------------------------------------------------
            # SECURITY EVIDENCE
            # ----------------------------------------------------------

            "verification_success": verification_success,
            "verified_indicators": verified_indicator_count,
            "registry_success": registry_success,
            "positive_security_evidence": positive_security_evidence,
            "evidence_available": evidence_available,

            "attack_evidence_present": bool(
                attack_evidence
            ),

            "attack_indicator_present": bool(
                attack_indicator
            ),

            "attack_response_available": bool(
                real_attack_response_available
            ),

            "replay_response_available": (
                context.cache.get(
                    "replay_response"
                )
                is not None
            ),

            "exchange_count": len(
                context.exchanges
            ),

            # ----------------------------------------------------------
            # CONFIDENCE
            # ----------------------------------------------------------

            "final_confidence": round(
                confidence,
                2,
            ),

            # ----------------------------------------------------------
            # CONFIRMATION POLICY
            # ----------------------------------------------------------

            "confirmation_policy": {
                "all_present": all_present,
                "all_success": all_success,
                "no_stage_errors": not bool(
                    stage_errors
                ),
                "real_http_execution": (
                    real_http_execution
                ),
                "request_sent": request_sent,
                "response_received": (
                    response_received
                ),
                "payload_executed": (
                    payload_executed
                ),
                "verification_success": (
                    verification_success
                ),
                "evidence_available": (
                    evidence_available
                ),
                "positive_security_evidence": (
                    positive_security_evidence
                ),
                "confidence_threshold": None,
                "confidence_passed": (
                    verification_success
                ),
                "confidence_role": (
                    "evidence_quality_score"
                ),
            },

            "candidate_index": index,
            "candidate_total": total,
            "failed_stages": failed_stages,
            "duration": round(
                duration,
                6,
            ),
        }

        print(
            "[CONFIRM-SOURCE] "
            f"attack={attack_name!r} "
            f"real_http_execution="
            f"{real_http_execution} "
            f"payload_executed="
            f"{payload_executed} "
            f"attack_evidence="
            f"{attack_evidence!r} "
            f"attack_indicator="
            f"{attack_indicator!r} "
            f"registry_success="
            f"{registry_success} "
            f"verified_indicators="
            f"{verified_indicator_count} "
            f"verification_success="
            f"{verification_success} "
            f"final_confidence="
            f"{confidence:.1f}",
            flush=True,
        )

        # ==============================================================
        # FINAL RESULT
        # ==============================================================

        if confirmed:

            print(
                f"[VALIDATION] Candidate={index}/{total} "
                f"CONFIRMED attack={attack_name} "
                f"confidence={confidence:.1f}",
                flush=True,
            )

            return ValidationResult(
                validator=self.PIPELINE_VALIDATOR,
                success=True,
                status="confirmed",
                confidence=round(
                    confidence,
                    2,
                ),
                duration=duration,
                summary=(
                    f"{attack_name} passed the complete "
                    f"Phase-2 validation pipeline."
                ),
                evidence=[
                    attack_evidence_value
                ],
                indicators=list(
                    getattr(
                        context,
                        "indicators",
                        [],
                    )
                    or []
                ),
                metadata=metadata,
            )

        print(
            f"[VALIDATION] Candidate={index}/{total} "
            f"REJECTED attack={attack_name} "
            f"failed_stages="
            f"{failed_stages or 'none'} "
            f"confidence={confidence:.1f}",
            flush=True,
        )

        return ValidationResult(
            validator=self.PIPELINE_VALIDATOR,
            success=False,
            status="rejected",
            confidence=round(
                confidence,
                2,
            ),
            duration=duration,
            summary=(
                "Candidate did not satisfy the complete "
                "Phase-2 confirmation policy."
            ),
            evidence=[
                attack_evidence_value
            ],
            indicators=list(
                getattr(
                    context,
                    "indicators",
                    [],
                )
                or []
            ),
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # RESPONSE CONTRACT
    # ------------------------------------------------------------------

    @classmethod
    def _synchronize_context(
        cls,
        context: ValidationContext,
        attack_result: AttackResult,
        stage_name: str,
    ) -> None:
        """
        Normalize response locations between validators.

        ReplayValidator has used context.baseline/context.exchanges while
        VerificationValidator consumes cache['replay_response'].  The
        orchestrator is the integration boundary, so both representations
        are synchronized here.
        """

        attack_response = context.cache.get("attack_response")

        if attack_response is None:
            attack_response = (
                getattr(attack_result, "metadata", {}) or {}
            ).get("response")

        if attack_response is None:
            attack_response = getattr(
                attack_result,
                "response",
                None,
            )

        if attack_response is not None:
            context.cache["attack_response"] = attack_response

        replay_response = context.cache.get("replay_response")

        if replay_response is None:
            replay_response = getattr(context, "baseline", None)

        if replay_response is None:
            exchanges = getattr(context, "exchanges", None) or []
            if exchanges:
                replay_response = exchanges[-1]

        if replay_response is not None:
            context.cache["replay_response"] = replay_response

        if stage_name == "Verification":
            verification_meta = (
                context.metadata.get("verification", {}) or {}
            )
            verified = bool(
                verification_meta.get(
                    "verified",
                    context.metadata.get("verified", False),
                )
            )
            context.metadata["verified"] = verified
            context.metadata["verified_indicators"] = (
                1 if verified else 0
            )

    # ------------------------------------------------------------------
    # REGISTRY
    # ------------------------------------------------------------------

    def _registry_all(self) -> list[Any]:
        if self.registry is None:
            return []

        method = getattr(self.registry, "all", None)

        if not callable(method):
            print(
                "[REGISTRY] No all() method; "
                "generic validation will continue.",
                flush=True,
            )
            return []

        return list(method() or [])
    
    @staticmethod
    def _run_registry_validator(
        validator,
        attack_result,
        context,
    ):

        method = getattr(
            validator,
            "validate",
            None,
        )

        if not callable(method):

            method = getattr(
                validator,
                "run",
                None,
            )

        if not callable(method):
            raise TypeError(
                f"{validator.__class__.__name__} "
                "has no validate()/run() method."
            )

        # -------------------------------------------------------------
        # First use the canonical keyword contract.
        #
        # SQLiValidator currently requires:
        #
        #     validate(*, result=..., context=...)
        #
        # -------------------------------------------------------------

        try:

            return method(
                result=attack_result,
                context=context,
            )

        except TypeError as keyword_error:

            # ---------------------------------------------------------
            # Compatibility fallback for older validators.
            # Do NOT silently call method() with no arguments.
            # ---------------------------------------------------------

            try:
                return method(
                    attack_result,
                    context,
                )

            except TypeError:

                try:
                    return method(
                        context,
                        attack_result,
                    )

                except TypeError:
                    raise keyword_error
    # ------------------------------------------------------------------
    # CONFIDENCE
    # ------------------------------------------------------------------

    @classmethod
    def _final_confidence(cls, result) -> float:
        if result is None:
            return 0.0

        value = cls._number(
            getattr(result, "confidence", 0.0)
        )

        # Defensive normalization for accidental 0..1 output.
        if 0.0 < value <= 1.0:
            value *= 100.0

        return max(0.0, min(100.0, value))

    # ------------------------------------------------------------------
    # VERIFIED INDICATORS
    # ------------------------------------------------------------------

    @classmethod
    def _verified_indicator_count(
        cls,
        context: ValidationContext,
        verification_result,
    ) -> int:

        try:
            count = int(
                context.metadata.get(
                    "verified_indicators",
                    0,
                )
                or 0
            )
        except Exception:
            count = 0

        if count > 0:
            return count

        result_metadata = (
            getattr(
                verification_result,
                "metadata",
                {},
            )
            or {}
        )

        try:
            count = int(
                result_metadata.get(
                    "verified_indicators",
                    0,
                )
                or 0
            )
        except Exception:
            count = 0

        if count > 0:
            return count

        verified = 0

        for indicator in (
            getattr(context, "indicators", []) or []
        ):
            try:
                if bool(
                    getattr(
                        indicator,
                        "verified",
                        False,
                    )
                ):
                    verified += 1
            except Exception:
                pass

        return verified

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    @staticmethod
    def _vector_id(vector) -> str:
        if vector is None:
            return ""

        metadata = getattr(vector, "metadata", {}) or {}

        return str(
            metadata.get(
                "vector_id",
                getattr(vector, "id", ""),
            )
            or ""
        )

    @staticmethod
    def _text(value) -> str:
        if value is None:
            return ""

        if isinstance(value, str):
            return value.strip()

        for attribute in (
            "value",
            "evidence",
            "indicator",
            "marker",
            "pattern",
            "expected",
        ):
            candidate = getattr(value, attribute, None)
            if candidate not in (None, ""):
                return str(candidate).strip()

        return str(value).strip()

    @staticmethod
    def _number(value, default: float = 0.0) -> float:
        try:
            return float(value or 0.0)
        except (TypeError, ValueError):
            return float(default)

    @staticmethod
    def _progress(callback, value) -> None:
        if not callable(callback):
            return

        try:
            callback(
                max(
                    0.0,
                    min(
                        100.0,
                        float(value),
                    ),
                )
            )
        except Exception:
            logger.debug(
                "Validation progress callback failed.",
                exc_info=True,
            )