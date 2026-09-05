"""
===============================================================================
AVAF Pro - Shared Attack Execution Engine
===============================================================================

This class owns the common payload-attack execution pipeline.

Pipeline:

    Phase-1 AttackVector
        |
        v
    Payload Provider
        |
        v
    Prepared HTTP Request
        |
        v
    REAL AttackExecutor HTTP request
        |
        v
    Attack-specific Detector
        |
        v
    AttackResult
        |
        v
    Phase-2 Validation/Confirmation

IMPORTANT
---------
This class never confirms a vulnerability.

A detector result is only a candidate finding.

Final confirmation belongs to the validation orchestrator.

Execution proof
---------------
An AttackResult is marked with:

    real_http_execution=True
    payload_executed=True
    request_sent=True
    response_received=True/False

These flags are derived from the actual ExecutionResult produced by
AttackExecutor. They are NOT invented by the validation layer.
===============================================================================
"""

from __future__ import annotations

from abc import ABC
from abc import abstractmethod
from typing import Any


class AttackEngine(ABC):
    """
    Shared execution pipeline for payload-based attacks.
    """

    def execute_pipeline(
        self,
        *,
        vector,
        context,
        detector,
    ):
        """
        Execute every payload generated for the supplied vector.

        IMPORTANT:

        - Payload generation does not equal execution.
        - Detector success does not equal confirmation.
        - HTTP execution must come from AttackExecutor.
        - Every detector result receives execution evidence.
        """

        results = []

        payloads = self.generate_payloads(vector)

        if payloads is None:
            payloads = []

        payloads = list(payloads)

        print(
            "[ATTACK-PIPELINE] "
            f"vector={getattr(vector, 'parameter', '')!r} "
            f"attack={getattr(self, 'id', '')!r} "
            f"payload_count={len(payloads)}",
            flush=True,
        )

        for payload_index, payload in enumerate(
            payloads,
            start=1,
        ):

            print(
                "[ATTACK-PAYLOAD] "
                f"attack={getattr(self, 'id', '')!r} "
                f"payload={payload_index}/{len(payloads)} "
                f"value={payload!r}",
                flush=True,
            )

            # =================================================================
            # BUILD REAL REQUEST
            # =================================================================

            prepared_request = context.builder.build(
                vector=vector,
                payload=payload,
            )

            if prepared_request is None:
                print(
                    "[ATTACK-PIPELINE] "
                    f"request_build_failed "
                    f"attack={getattr(self, 'id', '')!r} "
                    f"payload={payload!r}",
                    flush=True,
                )
                continue

            print(
                "[ATTACK-REQUEST] "
                f"attack={getattr(self, 'id', '')!r} "
                f"method={getattr(prepared_request, 'method', '')!r} "
                f"url={getattr(prepared_request, 'url', '')!r}",
                flush=True,
            )

            # =================================================================
            # REAL HTTP EXECUTION
            # =================================================================

            execution_result = context.executor.execute(
                prepared_request
            )

            if execution_result is None:
                print(
                    "[ATTACK-EXECUTION] "
                    "executor returned None; "
                    "this payload cannot become a finding.",
                    flush=True,
                )
                continue

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

            request_sent = request is not None
            response_received = response is not None

            real_http_execution = bool(
                request_sent
                and response_received
            )

            # =================================================================
            # EXECUTION EVIDENCE
            # =================================================================
            #
            # AttackExecutor is the authoritative source for HTTP execution
            # metadata.
            #
            # payload_transmitted means the controlled payload was actually sent
            # through the HTTP request.
            #
            # payload_executed is intentionally NOT manufactured here.
            # Vulnerability-specific validators establish application-level
            # effects from the real response.
            # =================================================================
            
            execution_metadata = getattr(
                execution_result,
                "metadata",
                None,
            )
            
            if not isinstance(
                execution_metadata,
                dict,
            ):
                execution_metadata = {}
            
            payload_transmitted = bool(
                execution_metadata.get(
                    "payload_transmitted",
                    real_http_execution and bool(payload),
                )
            )
            
            payload_executed = bool(
                execution_metadata.get(
                    "payload_executed",
                    False,
                )
            )

            # =================================================================
            # EXECUTION PROOF
            # =================================================================

            execution_metadata = getattr(
                execution_result,
                "metadata",
                None,
            )

            if execution_metadata is None:
                execution_metadata = {}

                execution_result.metadata = (
                    execution_metadata
                )

            execution_metadata.update(
                {
                    "real_http_execution": (
                        real_http_execution
                    ),
                    "payload_transmitted": (
                        payload_transmitted
                    ),
                    "payload_executed": (
                        payload_executed
                    ),
                    "request_sent": request_sent,
                    "response_received": (
                        response_received
                    ),
                    "payload_index": payload_index,
                    "payload_count": len(payloads),
                    "attack_id": getattr(
                        self,
                        "id",
                        "",
                    ),       
                    "payload_index": payload_index,
                    "payload_count": len(payloads),
                    "attack_id": getattr(
                        self,
                        "id",
                        "",
                    ),
                }
            )

            print(
                "[EXECUTION-PROOF] "
                f"attack={getattr(self, 'id', '')!r} "
                f"payload={payload!r} "
                f"request_sent={request_sent} "
                f"response_received={response_received} "
                f"real_http_execution={real_http_execution} "
                f"payload_executed={payload_executed} "
                f"status={getattr(execution_result, 'status_code', None)} "
                f"time={getattr(execution_result, 'elapsed', None)!r}",
                flush=True,
            )

            # =================================================================
            # DO NOT LET A NON-EXECUTED REQUEST REACH DETECTION
            # =================================================================

            if not real_http_execution:
                print(
                    "[ATTACK-PIPELINE] "
                    "Execution proof FAILED. "
                    "Detector will NOT be treated as security evidence.",
                    flush=True,
                )

                continue

            # =================================================================
            # DETECTION
            # =================================================================

            attack_result = detector.detect(
                vector=vector,
                payload=payload,
                response=response,
            )
            
            if attack_result is not None:
                attack_result.metadata.update(
                    {
                        "real_http_execution": (
                            real_http_execution
                        ),
                        "payload_transmitted": (
                            payload_transmitted
                        ),
                        "payload_executed": (
                            payload_executed
                        ),
                        "request_sent": (
                            request_sent
                        ),
                        
                        "response_received": (
                            response_received
                        ),
                        "http_status": (
                            execution_result.status_code
                        ),
                        "elapsed": (
                            execution_result.elapsed
                        ),
                        "request": (
                            execution_result.request
                        ),
                        "response": (
                            execution_result.response
                        ),
                    }
                )

            print(
                "[ATTACK-TRACE] "
                f"attack={getattr(self, 'id', '')!r} "
                f"vector={getattr(vector, 'parameter', '')!r} "
                f"payload={payload!r} "
                f"status={getattr(execution_result, 'status_code', None)} "
                f"detector_result="
                f"{type(attack_result).__name__ if attack_result is not None else 'NONE'} "
                f"detector_success="
                f"{getattr(attack_result, 'success', None)} "
                f"detector_confidence="
                f"{getattr(attack_result, 'confidence', None)}",
                flush=True,
            )

            if attack_result is None:
                continue

            # =================================================================
            # ATTACH REAL EXECUTION EVIDENCE
            # =================================================================

            attack_result.status_code = (
                execution_result.status_code
            )

            attack_result.response_time = (
                execution_result.elapsed
            )

            if getattr(
                attack_result,
                "metadata",
                None,
            ) is None:
                attack_result.metadata = {}

            attack_result.metadata.update(
                {
                    "request": request,
                    "response": response,

                    "real_http_execution": (
                        real_http_execution
                    ),

                    "payload_executed": (
                        payload_executed
                    ),

                    "request_sent": request_sent,

                    "response_received": (
                        response_received
                    ),

                    "request_url": getattr(
                        execution_result,
                        "url",
                        "",
                    ),

                    "request_method": getattr(
                        execution_result,
                        "method",
                        "",
                    ),

                    "response_status": getattr(
                        execution_result,
                        "status_code",
                        None,
                    ),

                    "response_time": getattr(
                        execution_result,
                        "elapsed",
                        None,
                    ),

                    "execution_metadata": dict(
                        execution_metadata
                    ),
                }
            )

            # Preserve originating vector.
            if getattr(
                attack_result,
                "vector",
                None,
            ) is None:

                attack_result.vector = vector

            print(
                "[ATTACK-RESULT] "
                f"attack={getattr(attack_result, 'attack', '')!r} "
                f"payload={getattr(attack_result, 'payload', '')!r} "
                f"confidence={getattr(attack_result, 'confidence', 0.0)!r} "
                f"evidence={getattr(attack_result, 'evidence', '')!r} "
                f"indicator={getattr(attack_result, 'indicator', '')!r} "
                f"real_http_execution={real_http_execution} "
                f"payload_executed={payload_executed}",
                flush=True,
            )

            results.append(
                attack_result
            )

        print(
            "[ATTACK-PIPELINE] "
            f"attack={getattr(self, 'id', '')!r} "
            f"completed "
            f"results={len(results)}",
            flush=True,
        )

        return results

    @abstractmethod
    def generate_payloads(
        self,
        vector,
    ):
        """
        Return payloads applicable to the supplied vector.
        """
        raise NotImplementedError