"""
AVAF Pro - Replay Validator

Creates a real baseline request and a real attack-payload request.

The attack response is stored as:
    context.cache["replay_response"]

The baseline is stored as:
    context.baseline

This validator does not decide vulnerability status.
"""

from __future__ import annotations

from phase2_refinement_validation.algorithms.base_algorithm import (
    BaseAlgorithm,
)
from phase2_refinement_validation.attacks.attack_request_builder import (
    AttackRequestBuilder,
)
from phase2_refinement_validation.core.http_client import (
    HTTPClient,
)
from phase2_refinement_validation.models.http_exchange import (
    HTTPExchange,
    HTTPRequest,
    HTTPResponse,
)
from phase2_refinement_validation.models.validation_context import (
    ValidationContext,
)
from phase2_refinement_validation.models.validation_result import (
    ValidationResult,
)


class ReplayValidator(BaseAlgorithm):

    def __init__(self):
        super().__init__("Replay")

        self.builder = AttackRequestBuilder()
        self.client = HTTPClient()

    def run(
        self,
        context: ValidationContext,
    ) -> ValidationResult:

        try:

            attack_result = context.cache.get(
                "attack_result"
            )

            if attack_result is None:
                return self._result(
                    context,
                    False,
                    0.0,
                    "Replay failed: AttackResult unavailable.",
                )

            vector = getattr(
                attack_result,
                "vector",
                None,
            )

            if vector is None:
                return self._result(
                    context,
                    False,
                    0.0,
                    "Replay failed: originating AttackVector unavailable.",
                )

            original_value = getattr(
                vector,
                "original_value",
                context.attack_plan.original_value,
            )

            payload = getattr(
                attack_result,
                "payload",
                None,
            )

            # -------------------------------------------------------------
            # BASELINE
            # -------------------------------------------------------------

            baseline_prepared = self.builder.build(
                vector,
                original_value,
            )

            baseline_response = self.client.send(
                baseline_prepared
            )

            baseline_exchange = self._make_exchange(
                baseline_prepared,
                baseline_response,
            )

            context.baseline = (
                baseline_exchange
            )

            # -------------------------------------------------------------
            # ATTACK REPLAY
            # -------------------------------------------------------------

            if payload not in (
                None,
                "",
            ):

                attack_prepared = self.builder.build(
                    vector,
                    payload,
                )

                attack_response = self.client.send(
                    attack_prepared
                )

                attack_exchange = self._make_exchange(
                    attack_prepared,
                    attack_response,
                )

            else:

                # If an attack module did not expose a payload, preserve
                # its already captured response when available.
                existing_response = (
                    getattr(
                        attack_result,
                        "metadata",
                        {},
                    )
                    or {}
                ).get(
                    "response"
                )

                if existing_response is not None:

                    attack_exchange = (
                        self._make_exchange_from_existing(
                            vector,
                            existing_response,
                        )
                    )

                else:

                    attack_exchange = (
                        baseline_exchange
                    )

            context.add_response(
                baseline_exchange
            )

            context.add_response(
                attack_exchange
            )

            context.cache[
                "baseline_response"
            ] = baseline_exchange.response

            context.cache[
                "replay_response"
            ] = attack_exchange.response

            context.cache[
                "attack_exchange"
            ] = attack_exchange

            attack_status = int(
                getattr(
                    attack_exchange.response,
                    "status",
                    0,
                )
                or 0
            )

            success = bool(
                attack_status > 0
                and payload not in (None, "")
            )

            return self._result(
                context,
                success,
                100.0 if success else 0.0,
                (
                    "Attack payload replay completed."
                    if success
                    else
                    "Attack replay returned no valid HTTP response."
                ),
                metadata={
                    "baseline_status": getattr(
                        baseline_exchange.response,
                        "status",
                        0,
                    ),
                    "attack_status": attack_status,
                    "payload_replayed": bool(
                        payload not in (
                            None,
                            "",
                        )
                    ),
                },
            )

        except Exception as exc:

            return self._result(
                context,
                False,
                0.0,
                (
                    f"Replay failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
                metadata={
                    "error": str(exc),
                },
            )

    # =========================================================================
    # EXCHANGE
    # =========================================================================

    @staticmethod
    def _make_exchange(
        prepared,
        response,
    ) -> HTTPExchange:

        body = str(
            getattr(
                response,
                "body",
                "",
            )
            or ""
        )

        http_response = HTTPResponse(
            status=int(
                getattr(
                    response,
                    "status",
                    0,
                )
                or 0
            ),
            headers=dict(
                getattr(
                    response,
                    "headers",
                    {},
                )
                or {}
            ),
            cookies=dict(
                getattr(
                    response,
                    "cookies",
                    {},
                )
                or {}
            ),
            body=body,
            url=str(
                getattr(
                    response,
                    "url",
                    prepared.url,
                )
            ),
            elapsed=float(
                getattr(
                    response,
                    "elapsed",
                    0.0,
                )
                or 0.0
            ),
            content_length=len(
                body
            ),
        )

        request = HTTPRequest(
            method=str(
                prepared.method
            ),
            url=str(
                prepared.url
            ),
            headers=dict(
                prepared.headers
                or {}
            ),
            cookies=dict(
                prepared.cookies
                or {}
            ),
            params=(
                dict(prepared.params)
                if isinstance(
                    prepared.params,
                    dict,
                )
                else {}
            ),
            data=(
                dict(prepared.data)
                if isinstance(
                    prepared.data,
                    dict,
                )
                else {}
            ),
            json=(
                dict(prepared.json)
                if isinstance(
                    prepared.json,
                    dict,
                )
                else {}
            ),
        )

        return HTTPExchange(
            request=request,
            response=http_response,
            final_url=str(
                getattr(
                    response,
                    "url",
                    prepared.url,
                )
            ),
            successful=(
                http_response.status > 0
            ),
        )

    @staticmethod
    def _make_exchange_from_existing(
        vector,
        response,
    ) -> HTTPExchange:

        body = str(
            getattr(
                response,
                "body",
                getattr(
                    response,
                    "text",
                    "",
                ),
            )
            or ""
        )

        http_response = HTTPResponse(
            status=int(
                getattr(
                    response,
                    "status",
                    getattr(
                        response,
                        "status_code",
                        0,
                    ),
                )
                or 0
            ),
            headers=dict(
                getattr(
                    response,
                    "headers",
                    {},
                )
                or {}
            ),
            cookies=dict(
                getattr(
                    response,
                    "cookies",
                    {},
                )
                or {}
            ),
            body=body,
            url=str(
                getattr(
                    response,
                    "url",
                    getattr(
                        vector,
                        "url",
                        "",
                    ),
                )
            ),
            elapsed=float(
                getattr(
                    response,
                    "elapsed",
                    0.0,
                )
                or 0.0
            ),
            content_length=len(
                body
            ),
        )

        request = HTTPRequest(
            method=str(
                getattr(
                    vector,
                    "method",
                    "GET",
                )
            ),
            url=str(
                getattr(
                    vector,
                    "url",
                    "",
                )
            ),
            headers={},
            cookies={},
            params={},
            data={},
            json={},
        )

        return HTTPExchange(
            request=request,
            response=http_response,
            final_url=http_response.url,
            successful=(
                http_response.status > 0
            ),
        )

    # =========================================================================
    # RESULT
    # =========================================================================

    @staticmethod
    def _result(
        context,
        success,
        confidence,
        summary,
        metadata=None,
    ):

        result = ValidationResult(
            validator="Replay",
            success=bool(success),
            status=(
                "passed"
                if success
                else "rejected"
            ),
            confidence=float(
                confidence
            ),
            summary=summary,
            metadata=metadata or {},
        )

        context.add_result(
            result
        )

        return result
