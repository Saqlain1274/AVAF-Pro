"""
===============================================================================
AVAF Pro - Attack Executor

Real HTTP execution layer.

Responsibilities
----------------
- Send the exact PreparedRequest produced by AttackRequestBuilder.
- Preserve query parameters.
- Preserve form data.
- Preserve JSON bodies.
- Preserve headers.
- Preserve cookies.
- Preserve multipart files.
- Preserve raw bodies.
- Record real HTTP execution proof.
- Record payload transmission proof.
- Return the complete HTTP response to the detector.

This class does NOT:
- detect vulnerabilities
- calculate confidence
- confirm vulnerabilities
- decide which attack to run
- claim application-level payload execution

Important distinction
---------------------
The executor proves HTTP transmission.

It does NOT decide whether the target application interpreted the
payload in a security-relevant way. That decision belongs to the
vulnerability-specific detection/verification pipeline.
===============================================================================
"""

from __future__ import annotations

import time

import requests

from .execution_result import ExecutionResult


class AttackExecutor:

    def __init__(
        self,
        timeout: float = 8.0,
        verify_ssl: bool = False,
        connect_timeout: float = 3.0,
        read_timeout: float | None = None,
    ) -> None:

        self.timeout = float(timeout)

        self.connect_timeout = float(
            connect_timeout
        )

        self.read_timeout = float(
            read_timeout
            if read_timeout is not None
            else timeout
        )

        self.verify_ssl = bool(
            verify_ssl
        )

        self.session = requests.Session()

    # =========================================================================
    # REAL HTTP EXECUTION
    # =========================================================================

    def execute(
        self,
        prepared,
    ) -> ExecutionResult:

        if prepared is None:
            raise ValueError(
                "AttackExecutor received None PreparedRequest."
            )

        # =====================================================================
        # PREPARED REQUEST
        # =====================================================================

        method = str(
            getattr(
                prepared,
                "method",
                "GET",
            )
            or "GET"
        ).upper()

        url = str(
            getattr(
                prepared,
                "url",
                "",
            )
            or ""
        )

        if not url:
            raise ValueError(
                "PreparedRequest contains no URL."
            )

        headers = dict(
            getattr(
                prepared,
                "headers",
                None,
            )
            or {}
        )

        cookies = dict(
            getattr(
                prepared,
                "cookies",
                None,
            )
            or {}
        )

        params = getattr(
            prepared,
            "params",
            None,
        )

        data = getattr(
            prepared,
            "data",
            None,
        )

        json_body = getattr(
            prepared,
            "json",
            None,
        )

        files = getattr(
            prepared,
            "files",
            None,
        )

        raw_body = getattr(
            prepared,
            "body",
            None,
        )

        prepared_metadata = getattr(
            prepared,
            "metadata",
            None,
        )

        if not isinstance(
            prepared_metadata,
            dict,
        ):
            prepared_metadata = {}

        payload = str(
            prepared_metadata.get(
                "attack_payload",
                "",
            )
            or ""
        )

        # =====================================================================
        # REQUEST CONSTRUCTION AUDIT
        # =====================================================================

        print(
            "[ATTACK-REQUEST-AUDIT] "
            f"method={method!r} "
            f"url={url!r} "
            f"payload={payload!r} "
            f"params={bool(params)} "
            f"data={bool(data)} "
            f"json={bool(json_body)} "
            f"files={bool(files)} "
            f"raw_body={raw_body is not None} "
            f"headers={len(headers)} "
            f"cookies={len(cookies)}",
            flush=True,
        )

        # =====================================================================
        # REQUEST CONSTRUCTION
        #
        # Query parameters are independent from the request body.
        #
        # Body priority:
        #
        #   raw body
        #       ↓
        #   JSON
        #       ↓
        #   form data
        #       ↓
        #   empty body
        # =====================================================================

        request_kwargs = {
            "method": method,
            "url": url,
            "headers": headers,
            "cookies": cookies,
            "params": params or {},
            "timeout": (
                self.connect_timeout,
                self.read_timeout,
            ),
            "verify": self.verify_ssl,
            "allow_redirects": True,
        }

        if files:
            request_kwargs["files"] = files

        if raw_body is not None:

            request_kwargs["data"] = raw_body

        elif json_body is not None:

            request_kwargs["json"] = json_body

        elif data is not None:

            request_kwargs["data"] = data

        # =====================================================================
        # SHOW WHAT WILL ACTUALLY BE SENT
        # =====================================================================

        print(
            "[REAL-HTTP-REQUEST] "
            f"method={method!r} "
            f"url={url!r} "
            f"params={params or {}} "
            f"data={data if data is not None else None!r} "
            f"json={json_body if json_body is not None else None!r} "
            f"raw_body={'YES' if raw_body is not None else 'NO'} "
            f"cookies={cookies}",
            flush=True,
        )

        # =====================================================================
        # ACTUAL HTTP REQUEST
        # =====================================================================

        start = time.perf_counter()

        try:

            response = self.session.request(
                **request_kwargs
            )

        except requests.RequestException as exc:

            elapsed = (
                time.perf_counter()
                - start
            )

            print(
                "[REAL-HTTP] REQUEST FAILED "
                f"method={method!r} "
                f"url={url!r} "
                f"elapsed={elapsed:.3f}s "
                f"error={type(exc).__name__}: {exc}",
                flush=True,
            )

            raise

        elapsed = (
            time.perf_counter()
            - start
        )

        # =====================================================================
        # REAL HTTP EXECUTION PROOF
        # =====================================================================

        request_object = getattr(
            response,
            "request",
            None,
        )

        request_sent = bool(
            request_object is not None
        )

        response_received = bool(
            response is not None
        )

        real_http_execution = bool(
            request_sent
            and response_received
        )

        # =====================================================================
        # PAYLOAD TRANSMISSION PROOF
        # =====================================================================
        #
        # This proves that the attack payload was supplied to the prepared
        # request and that a real HTTP exchange occurred.
        #
        # It does NOT claim that the application interpreted the payload.
        # =====================================================================

        payload_transmitted = bool(
            real_http_execution
            and payload != ""
        )

        # =====================================================================
        # APPLICATION-LEVEL EXECUTION
        # =====================================================================
        #
        # Deliberately false here.
        #
        # AttackExecutor cannot establish vulnerability-specific application
        # execution by itself.
        #
        # Detection/verification must establish that from the response.
        # =====================================================================

        payload_executed = False

        # =====================================================================
        # EXECUTION METADATA
        # =====================================================================

        metadata = {
            "real_http_execution": bool(
                real_http_execution
            ),

            "request_sent": bool(
                request_sent
            ),

            "response_received": bool(
                response_received
            ),

            "payload_transmitted": bool(
                payload_transmitted
            ),

            "payload_executed": bool(
                payload_executed
            ),

            "method": method,

            "request_url": url,

            "response_url": str(
                getattr(
                    response,
                    "url",
                    "",
                )
                or ""
            ),

            "status_code": getattr(
                response,
                "status_code",
                None,
            ),

            "elapsed": elapsed,

            "query_parameters_sent": bool(
                params
            ),

            "form_data_sent": bool(
                data is not None
                and raw_body is None
                and json_body is None
            ),

            "json_body_sent": bool(
                json_body is not None
                and raw_body is None
            ),

            "raw_body_sent": bool(
                raw_body is not None
            ),

            "cookies_sent": bool(
                cookies
            ),

            "headers_sent": bool(
                headers
            ),
        }

        # Preserve original prepared-request metadata for downstream
        # debugging/auditing without allowing it to overwrite execution proof.
        metadata["prepared_metadata"] = dict(
            prepared_metadata
        )

        # =====================================================================
        # EXECUTION LOG
        # =====================================================================

        print(
            "[REAL-HTTP] "
            f"request_sent={request_sent} "
            f"response_received={response_received} "
            f"real_http_execution={real_http_execution} "
            f"status={response.status_code} "
            f"elapsed={elapsed:.3f}s "
            f"url={response.url!r}",
            flush=True,
        )

        print(
            "[EXECUTION-PROOF] "
            f"real_http_execution={real_http_execution} "
            f"request_sent={request_sent} "
            f"response_received={response_received} "
            f"payload_transmitted={payload_transmitted} "
            f"payload_executed={payload_executed} "
            f"method={method!r} "
            f"url={url!r} "
            f"status={response.status_code} "
            f"payload={payload!r}",
            flush=True,
        )

        # =====================================================================
        # RESULT
        # =====================================================================

        return ExecutionResult(
            url=str(
                response.url
            ),

            method=method,

            payload=payload,

            status_code=response.status_code,

            headers=dict(
                response.headers
            ),

            cookies=response.cookies.get_dict(),

            body=response.text,

            elapsed=elapsed,

            request=request_object,

            response=response,

            metadata=metadata,
        )