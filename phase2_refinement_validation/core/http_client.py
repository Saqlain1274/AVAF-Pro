"""
===============================================================================
AVAF Pro

HTTP Client

Responsibilities
----------------
- Execute prepared HTTP requests
- Preserve request/response information
- Measure response time
- Capture redirects
- Never decide whether a vulnerability exists

The HTTPClient is transport only.
===============================================================================
"""

from __future__ import annotations

import time

import requests

from ..models.http_exchange import (
    HTTPRequest,
    HTTPResponse,
)
from ..builders.prepared_request import PreparedRequest


class HTTPClient:

    def __init__(
        self,
        verify_ssl: bool = False,
        timeout: int = 15,
    ) -> None:

        self.session = requests.Session()

        self.verify_ssl = verify_ssl
        self.timeout = timeout

    # =========================================================================
    # SEND PREPARED REQUEST
    # =========================================================================

    def send(
        self,
        request: PreparedRequest,
    ) -> HTTPResponse:

        method = request.method.upper()

        headers = dict(
            request.headers or {}
        )

        cookies = dict(
            request.cookies or {}
        )

        params = dict(
            request.params or {}
        )

        data = dict(
            request.data or {}
        )

        json_data = (
            dict(request.json)
            if request.json
            else None
        )

        started = time.perf_counter()

        try:

            response = self.session.request(

                method=method,

                url=request.url,

                params=params,

                data=data,

                json=json_data,

                headers=headers,

                cookies=cookies,

                files=request.files or None,

                timeout=self.timeout,

                verify=self.verify_ssl,

                allow_redirects=True,

            )

            elapsed = (
                time.perf_counter()
                - started
            )

            return HTTPResponse(

                status=response.status_code,

                headers=dict(
                    response.headers
                ),

                body=response.text,

                url=response.url,

                elapsed=elapsed,

                cookies=response.cookies.get_dict(),

            )

        except requests.RequestException as exc:

            elapsed = (
                time.perf_counter()
                - started
            )

            return HTTPResponse(

                status=0,

                headers={},

                body=str(exc),

                url=request.url,

                elapsed=elapsed,

                cookies={},

            )