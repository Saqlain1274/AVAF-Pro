"""
===============================================================================
AVAF Pro - Attack Engine
===============================================================================

Shared execution pipeline for payload-based Phase-2 attacks.

Responsibilities
----------------
1. Generate attack payloads through the attack plugin.
2. Build a real PreparedRequest.
3. Send the PreparedRequest through AttackExecutor.
4. Record proof that real HTTP execution occurred.
5. Pass the REAL HTTP response to the vulnerability-specific detector.
6. Preserve request/response evidence inside AttackResult.metadata.
7. Return only detector-produced AttackResult objects.

Architecture
------------
Phase-1 AttackVector
        |
        v
Attack Plugin
        |
        v
generate_payloads()
        |
        v
AttackRequestBuilder
        |
        v
PreparedRequest
        |
        v
AttackExecutor
        |
        v
REAL HTTP REQUEST
        |
        v
REAL HTTP RESPONSE
        |
        v
Vulnerability Detector
        |
        v
AttackResult
        |
        v
ValidationOrchestrator

Important
---------
This class does NOT decide whether a vulnerability is confirmed.

A detector result is only a candidate finding.

Final confirmation belongs to:

    Replay
        ->
    Analysis
        ->
    Evidence
        ->
    Verification
        ->
    Confidence
        ->
    deterministic confirmation gate

No fake response, synthetic evidence, or artificial confirmation is created
here.
===============================================================================
"""

from __future__ import annotations

from abc import ABC
from abc import abstractmethod
from typing import Any


class AttackEngine(ABC):
    """
    Shared real-HTTP execution pipeline for attack plugins.

    Every payload follows:

        payload
          -> PreparedRequest
          -> AttackExecutor.execute()
          -> real HTTP response
          -> detector
          -> AttackResult
    """

    # =========================================================================
    # PUBLIC EXECUTION PIPELINE
    # =========================================================================

    def execute_pipeline(
        self,
        *,
        vector,
        context,
        detector,
    ) -> list:
        """
        Execute every payload generated for the supplied vector.

        A payload is considered HTTP-executed only when AttackExecutor returns
        an ExecutionResult containing a real response.

        Detector output alone is NEVER treated as proof of HTTP execution.
        """

        if vector is None:
            raise ValueError(
                "AttackEngine requires a non-null AttackVector."
            )

        if context is None:
            raise ValueError(
                "AttackEngine requires a non-null AttackContext."
            )

        if detector is None:
            raise ValueError(
                "AttackEngine requires a vulnerability detector."
            )

        # ---------------------------------------------------------------------
        # Per-vector execution state
        # ---------------------------------------------------------------------

        results: list = []

        payload_count = 0
        executed_count = 0
        detector_result_count = 0
        execution_failure_count = 0

        print(
            "[ATTACK-PIPELINE] "
            f"START attack_vector={self._vector_id(vector)!r} "
            f"parameter={getattr(vector, 'parameter', '')!r} "
            f"url={getattr(vector, 'url', '')!r}",
            flush=True,
        )

        # ---------------------------------------------------------------------
        # Generate payloads.
        #
        # This is attack-specific and remains inside the plugin.
        # ---------------------------------------------------------------------

        payloads = self.generate_payloads(vector)

        if payloads is None:
            payloads = []

        for payload_index, payload in enumerate(
            payloads,
            start=1,
        ):

            payload_count += 1

            print(
                "[ATTACK-PIPELINE] "
                f"payload={payload_index} "
                f"attack_vector={self._vector_id(vector)!r} "
                f"payload={payload!r}",
                flush=True,
            )

            # =================================================================
            # BUILD REAL REQUEST
            # =================================================================

            try:

                prepared_request = context.builder.build(
                    vector=vector,
                    payload=payload,
                )

            except Exception as exc:

                print(
                    "[ATTACK-BUILD-ERROR] "
                    f"vector={self._vector_id(vector)!r} "
                    f"payload_index={payload_index} "
                    f"error={type(exc).__name__}: {exc}",
                    flush=True,
                )

                execution_failure_count += 1
                continue

            if prepared_request is None:
                print(
                    "[ATTACK-BUILD-ERROR] "
                    f"vector={self._vector_id(vector)!r} "
                    f"payload_index={payload_index} "
                    "builder_returned=None",
                    flush=True,
                )

                execution_failure_count += 1
                continue

            print(
                "[ATTACK-REQUEST-BUILT] "
                f"vector={self._vector_id(vector)!r} "
                f"method={getattr(prepared_request, 'method', '')!r} "
                f"url={getattr(prepared_request, 'url', '')!r}",
                flush=True,
            )

            # =================================================================
            # REAL HTTP EXECUTION
            # =================================================================

            try:

                execution_result = context.executor.execute(
                    prepared_request
                )

            except Exception as exc:

                execution_failure_count += 1

                print(
                    "[ATTACK-HTTP-ERROR] "
                    f"vector={self._vector_id(vector)!r} "
                    f"payload_index={payload_index} "
                    f"error={type(exc).__name__}: {exc}",
                    flush=True,
                )

                # A failed HTTP request is NOT passed to the detector as if
                # it were a vulnerability response.
                continue

            # -----------------------------------------------------------------
            # HARD REAL-HTTP CHECK
            # -----------------------------------------------------------------

            response = getattr(
                execution_result,
                "response",
                None,
            )

            status_code = getattr(
                execution_result,
                "status_code",
                None,
            )

            request = getattr(
                execution_result,
                "request",
                None,
            )

            elapsed = getattr(
                execution_result,
                "elapsed",
                None,
            )

            real_http_execution = bool(
                response is not None
                and request is not None
                and status_code is not None
                and int(status_code) > 0
            )

            if not real_http_execution:

                print(
                    "[ATTACK-HTTP-INVALID] "
                    f"vector={self._vector_id(vector)!r} "
                    f"payload_index={payload_index} "
                    "executor returned no valid HTTP response/request proof",
                    flush=True,
                )

                execution_failure_count += 1
                continue

            executed_count += 1

            # =================================================================
            # EXECUTION PROOF
            # =================================================================

            request_url = getattr(
                request,
                "url",
                getattr(
                    prepared_request,
                    "url",
                    "",
                ),
            )

            response_url = getattr(
                response,
                "url",
                getattr(
                    execution_result,
                    "url",
                    "",
                ),
            )

            print(
                "[EXECUTION-PROOF] "
                f"real_http_execution=True "
                f"vector={self._vector_id(vector)!r} "
                f"payload_index={payload_index} "
                f"method={getattr(request, 'method', getattr(prepared_request, 'method', ''))!r} "
                f"request_url={request_url!r} "
                f"response_url={response_url!r} "
                f"status={status_code} "
                f"elapsed={elapsed!r}",
                flush=True,
            )

            print(
                "[REAL-HTTP] "
                f"attack_vector={self._vector_id(vector)!r} "
                f"payload_index={payload_index} "
                f"status={status_code} "
                f"url={response_url!r}",
                flush=True,
            )

            # =================================================================
            # DETECTOR
            # =================================================================

            try:

                attack_result = detector.detect(
                    vector=vector,
                    payload=payload,
                    response=response,
                )

            except Exception as exc:

                print(
                    "[DETECTOR-ERROR] "
                    f"vector={self._vector_id(vector)!r} "
                    f"payload_index={payload_index} "
                    f"error={type(exc).__name__}: {exc}",
                    flush=True,
                )

                continue

            if attack_result is None:

                print(
                    "[ATTACK-TRACE] "
                    f"vector={self._vector_id(vector)!r} "
                    f"payload_index={payload_index} "
                    "detector_result=NONE "
                    "real_http_execution=True",
                    flush=True,
                )

                continue

            detector_result_count += 1

            # =================================================================
            # ATTACH EXECUTION PROOF TO RESULT
            # =================================================================

            metadata = getattr(
                attack_result,
                "metadata",
                None,
            )

            if not isinstance(metadata, dict):
                metadata = {}

            execution_metadata = getattr(
                execution_result,
                "metadata",
                {},
            ) or {}
            
            metadata.update(
                {
                    # ---------------------------------------------------------
                    # Hard execution proof
                    # ---------------------------------------------------------
                    "real_http_execution": bool(
                        execution_metadata.get(
                            "real_http_execution",
                            request is not None and response is not None,
                        )
                    ),
            
                    "request_sent": bool(
                        execution_metadata.get(
                            "request_sent",
                            request is not None,
                        )
                    ),
            
                    "response_received": bool(
                        execution_metadata.get(
                            "response_received",
                            response is not None,
                        )
                    ),
            
                    # Transmission is provable from the HTTP execution result.
                    # Application interpretation is NOT claimed here.
                    "payload_transmitted": bool(
                        execution_metadata.get(
                            "payload_transmitted",
                            False,
                        )
                    ),
            
                    # Never manufacture application execution.
                    "payload_executed": bool(
                        execution_metadata.get(
                            "payload_executed",
                            False,
                        )
                    ),

                    # ---------------------------------------------------------
                    # Request/response references
                    # ---------------------------------------------------------
                    "request": request,
                    "response": response,

                    # ---------------------------------------------------------
                    # Execution details
                    # ---------------------------------------------------------
                    "request_url": request_url,
                    "response_url": response_url,
                    "method": getattr(
                        request,
                        "method",
                        getattr(
                            prepared_request,
                            "method",
                            "",
                        ),
                    ),
                    "status_code": status_code,
                    "response_time": elapsed,

                    # ---------------------------------------------------------
                    # Traceability
                    # ---------------------------------------------------------
                    "vector_id": self._vector_id(vector),
                    "parameter": getattr(
                        vector,
                        "parameter",
                        "",
                    ),
                    "parameter_type": getattr(
                        vector,
                        "parameter_type",
                        "",
                    ),
                    "payload_index": payload_index,

                    # ---------------------------------------------------------
                    # Request was generated by the actual Phase-2 builder.
                    # ---------------------------------------------------------
                    "request_built_by_attack_engine": True,
                }
            )

            attack_result.metadata = metadata

            # -----------------------------------------------------------------
            # Preserve HTTP fields on AttackResult.
            # -----------------------------------------------------------------

            try:
                attack_result.status_code = status_code
            except Exception:
                pass

            try:
                attack_result.response_time = elapsed
            except Exception:
                pass

            # -----------------------------------------------------------------
            # Preserve the actual response/request for validation.
            # -----------------------------------------------------------------

            self._store_execution_context(
                context=context,
                attack_result=attack_result,
                execution_result=execution_result,
            )

            # -----------------------------------------------------------------
            # Explicit detector trace.
            # -----------------------------------------------------------------

            print(
                "[ATTACK-TRACE] "
                f"vector={self._vector_id(vector)!r} "
                f"payload_index={payload_index} "
                f"payload={payload!r} "
                f"status={status_code} "
                f"real_http_execution="
                f"{getattr(attack_result, 'metadata', {}).get('real_http_execution', False)} "
                f"payload_transmitted="
                f"{getattr(attack_result, 'metadata', {}).get('payload_transmitted', False)} "
                f"payload_executed="
                f"{getattr(attack_result, 'metadata', {}).get('payload_executed', False)} "
                f"detector_result={type(attack_result).__name__} "
                f"detector_success={getattr(attack_result, 'success', None)!r} "
                f"detector_confidence={getattr(attack_result, 'confidence', None)!r} "
                f"evidence={getattr(attack_result, 'evidence', '')!r} "
                f"indicator={getattr(attack_result, 'indicator', '')!r}",
                flush=True,
            )

            results.append(
                attack_result
            )

        # =====================================================================
        # FINAL PIPELINE AUDIT
        # =====================================================================

        print(
            "[ATTACK-PIPELINE] "
            f"COMPLETE vector={self._vector_id(vector)!r} "
            f"payloads={payload_count} "
            f"http_executed={executed_count} "
            f"detector_results={detector_result_count} "
            f"http_failures={execution_failure_count} "
            f"attack_results={len(results)}",
            flush=True,
        )

        return results

    # =========================================================================
    # EXECUTION CONTEXT
    # =========================================================================

    @staticmethod
    def _store_execution_context(
        *,
        context,
        attack_result,
        execution_result,
    ) -> None:
        """
        Preserve the real attack exchange for the validation layer.

        ValidationContext is deliberately populated here rather than by the
        detector. This prevents a detector from manufacturing execution proof.
        """

        response = getattr(
            execution_result,
            "response",
            None,
        )

        request = getattr(
            execution_result,
            "request",
            None,
        )

        # ---------------------------------------------------------------------
        # cache
        # ---------------------------------------------------------------------

        cache = getattr(
            context,
            "cache",
            None,
        )

        if not isinstance(cache, dict):
            cache = {}
            context.cache = cache

        cache["attack_result"] = attack_result
        cache["attack_response"] = response
        cache["attack_request"] = request

        cache["real_http_execution"] = bool(
            response is not None
            and request is not None
            and getattr(
                execution_result,
                "status_code",
                None,
            ) is not None
            and int(
                getattr(
                    execution_result,
                    "status_code",
                    0,
                ) or 0
            ) > 0
        )
        
        cache["payload_executed"] = False
        cache["payload_transmitted"] = bool(
            cache["real_http_execution"]
        )

        # ---------------------------------------------------------------------
        # exchanges
        # ---------------------------------------------------------------------

        exchanges = getattr(
            context,
            "exchanges",
            None,
        )

        if exchanges is None:
            exchanges = []
            context.exchanges = exchanges

        # Do not create a fake exchange. Only append the actual execution
        # objects supplied by AttackExecutor.
        exchanges.append(
            {
                "request": request,
                "response": response,
                "attack_result": attack_result,
                "real_http_execution": True,
            }
        )

        # ---------------------------------------------------------------------
        # metadata
        # ---------------------------------------------------------------------

        metadata = getattr(
            context,
            "metadata",
            None,
        )

        if not isinstance(metadata, dict):
            metadata = {}
            context.metadata = metadata

        metadata["real_http_execution"] = True
        
        # IMPORTANT:
        # Sending a payload is NOT proof that the target executed it.
        # Execution/interpretation must be established by the
        # vulnerability-specific detector/validator.
        metadata["payload_transmitted"] = bool(
            getattr(
                attack_result,
                "payload",
                None,
            )
        )
        
        metadata["payload_executed"] = bool(
            getattr(
                attack_result,
                "metadata",
                {},
            )
            and getattr(
                attack_result,
                "metadata",
                {},
            ).get(
                "payload_executed",
                False,
            )
        )
        
        metadata["attack_request"] = request
        metadata["attack_response"] = response

    # =========================================================================
    # HELPERS
    # =========================================================================

    @staticmethod
    def _vector_id(vector: Any) -> str:
        """
        Produce a stable human-readable vector identifier.

        This is only for logging/traceability. It does not generate vectors.
        """

        if vector is None:
            return "unknown"

        metadata = getattr(
            vector,
            "metadata",
            {},
        )

        if isinstance(metadata, dict):

            value = metadata.get(
                "vector_id"
            )

            if value:
                return str(value)

        value = getattr(
            vector,
            "id",
            None,
        )

        if value:
            return str(value)

        parameter = getattr(
            vector,
            "parameter",
            None,
        )

        url = getattr(
            vector,
            "url",
            None,
        )

        if parameter or url:
            return (
                f"{url or ''}"
                f"#{parameter or ''}"
            )

        return "unknown"

    # =========================================================================
    # PAYLOAD GENERATION CONTRACT
    # =========================================================================

    @abstractmethod
    def generate_payloads(
        self,
        vector,
    ):
        """
        Return payloads applicable to this attack/vector combination.

        Payload generation remains attack-specific.

        No HTTP request is performed here.
        """
        raise NotImplementedError
