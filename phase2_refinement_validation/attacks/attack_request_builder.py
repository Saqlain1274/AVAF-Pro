"""
===============================================================================
AVAF Pro - Attack Request Builder
===============================================================================

Purpose
-------
Build a PreparedRequest from an existing Phase-1 AttackVector.

This component ONLY prepares the HTTP request.

It does NOT:
    - send HTTP requests
    - detect vulnerabilities
    - perform validation
    - decide whether an attack succeeded
    - confirm findings

Design rules
------------
1. The Phase-1 vector is the source of truth.
2. Only the selected parameter is mutated.
3. The original host/port/path are preserved.
4. No URLs are invented.
5. No wordlists are used.
6. The payload is recorded in PreparedRequest.metadata.
7. PreparedRequest itself remains an HTTP-request model.
8. AttackExecutor is responsible for REAL HTTP execution.
===============================================================================
"""

from __future__ import annotations

from copy import deepcopy
from urllib.parse import parse_qsl
from urllib.parse import urlencode
from urllib.parse import urlparse
from urllib.parse import urlunparse

from ..builders.prepared_request import PreparedRequest


class AttackRequestBuilder:
    """
    Build a PreparedRequest from an existing AttackVector.

    The builder mutates exactly one discovered parameter while preserving
    the remainder of the original request wherever possible.
    """

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def build(
        self,
        vector,
        payload,
    ) -> PreparedRequest:
        """
        Build a prepared attack request.

        The payload is NOT a field of PreparedRequest.

        Instead it is stored in PreparedRequest.metadata["attack_payload"]
        so that the executor and audit trail can still identify exactly
        which payload produced the request.
        """

        parameter_type = self._parameter_type(vector)
        parameter = self._parameter(vector)
        url = self._url(vector)

        if not url:
            raise ValueError(
                "AttackVector has no URL."
            )

        if not parameter:
            raise ValueError(
                "AttackVector has no parameter."
            )

        builders = {
            "query": self._build_query,
            "form": self._build_form,
            "json": self._build_json,
            "header": self._build_header,
            "cookie": self._build_cookie,
        }

        builder = builders.get(
            parameter_type
        )

        if builder is None:
            raise NotImplementedError(
                "Unsupported attack parameter type: "
                f"{parameter_type!r}"
            )

        prepared = builder(
            vector,
            payload,
        )

        self._attach_attack_metadata(
            prepared=prepared,
            vector=vector,
            payload=payload,
        )

        self._audit_request(
            vector=vector,
            payload=payload,
            prepared=prepared,
        )

        return prepared

    # =========================================================================
    # IDOR
    # =========================================================================

    def replace_identifier(
        self,
        vector,
        identifier,
    ) -> PreparedRequest:
        """
        Build a request with an IDOR identifier replaced.

        The identifier declares where the original identifier was found.
        Only that location is modified.
        """

        source = str(
            getattr(
                identifier,
                "source",
                "",
            )
            or ""
        ).strip().lower()

        replacement = getattr(
            identifier,
            "replacement_value",
            None,
        )

        if replacement is None:
            raise ValueError(
                "IDOR identifier has no replacement value."
            )

        if source == "query":
            prepared = self._build_query(
                vector,
                replacement,
            )

        elif source == "form":
            prepared = self._build_form(
                vector,
                replacement,
            )

        elif source == "json":
            prepared = self._build_json(
                vector,
                replacement,
            )

        elif source == "url":
            prepared = self._build_url_identifier(
                vector,
                getattr(
                    identifier,
                    "original_value",
                    None,
                ),
                replacement,
            )

        else:
            raise ValueError(
                "Unsupported IDOR identifier source: "
                f"{source!r}"
            )

        self._attach_attack_metadata(
            prepared=prepared,
            vector=vector,
            payload=replacement,
            extra={
                "idor": True,
                "idor_source": source,
                "idor_original_value": getattr(
                    identifier,
                    "original_value",
                    None,
                ),
                "idor_replacement_value": replacement,
            },
        )

        return prepared

    # =========================================================================
    # QUERY
    # =========================================================================

    def _build_query(
        self,
        vector,
        payload,
    ) -> PreparedRequest:

        parsed = urlparse(
            self._url(vector)
        )

        parameter = self._parameter(
            vector
        )

        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

        found = False
        new_pairs = []

        for name, value in pairs:

            if (
                name == parameter
                and not found
            ):
                new_pairs.append(
                    (
                        name,
                        str(payload),
                    )
                )

                found = True

            else:
                new_pairs.append(
                    (
                        name,
                        value,
                    )
                )

        if not found:
            raise ValueError(
                "Query parameter was not found in "
                f"the original URL: {parameter!r}"
            )

        new_query = urlencode(
            new_pairs,
            doseq=True,
        )

        new_url = urlunparse(
            parsed._replace(
                query=new_query
            )
        )

        return PreparedRequest(
            method=self._method(vector),
            url=new_url,
            headers=self._headers(vector),
            cookies=self._cookies(vector),
            params=deepcopy(
                getattr(
                    vector,
                    "params",
                    {},
                )
                or {}
            ),
            data=deepcopy(
                getattr(
                    vector,
                    "data",
                    {},
                )
                or {}
            ),
            json=deepcopy(
                getattr(
                    vector,
                    "json",
                    {},
                )
                or {}
            ),
            files=deepcopy(
                getattr(
                    vector,
                    "files",
                    {},
                )
                or {}
            ),
        )

    # =========================================================================
    # FORM
    # =========================================================================

    def _build_form(
        self,
        vector,
        payload,
    ) -> PreparedRequest:

        data = deepcopy(
            getattr(
                vector,
                "data",
                None,
            )
        )

        if not isinstance(
            data,
            dict,
        ):
            raise ValueError(
                "Form vector does not contain "
                "a dictionary body."
            )

        parameter = self._parameter(
            vector
        )

        if parameter not in data:
            raise ValueError(
                "Form parameter was not found in "
                f"the original request: {parameter!r}"
            )

        data[parameter] = payload

        return PreparedRequest(
            method=self._method(vector),
            url=self._url(vector),
            headers=self._headers(vector),
            cookies=self._cookies(vector),
            params=self._params(vector),
            data=data,
            json=self._json(vector),
            files=self._files(vector),
        )

    # =========================================================================
    # JSON
    # =========================================================================

    def _build_json(
        self,
        vector,
        payload,
    ) -> PreparedRequest:

        body = deepcopy(
            getattr(
                vector,
                "json",
                None,
            )
        )

        if not isinstance(
            body,
            dict,
        ):
            raise ValueError(
                "JSON vector does not contain "
                "a dictionary JSON body."
            )

        parameter = self._parameter(
            vector
        )

        if parameter not in body:
            raise ValueError(
                "JSON parameter was not found in "
                f"the original request: {parameter!r}"
            )

        body[parameter] = payload

        return PreparedRequest(
            method=self._method(vector),
            url=self._url(vector),
            headers=self._headers(vector),
            cookies=self._cookies(vector),
            params=self._params(vector),
            data=self._data(vector),
            json=body,
            files=self._files(vector),
        )

    # =========================================================================
    # HEADER
    # =========================================================================

    def _build_header(
        self,
        vector,
        payload,
    ) -> PreparedRequest:

        headers = self._headers(
            vector
        )

        parameter = self._parameter(
            vector
        )

        existing_name = None

        for name in headers:

            if (
                str(name).lower()
                == parameter.lower()
            ):
                existing_name = name
                break

        if existing_name is None:
            raise ValueError(
                "Header parameter was not found in "
                f"the original request: {parameter!r}"
            )

        headers[existing_name] = str(
            payload
        )

        return PreparedRequest(
            method=self._method(vector),
            url=self._url(vector),
            headers=headers,
            cookies=self._cookies(vector),
            params=self._params(vector),
            data=self._data(vector),
            json=self._json(vector),
            files=self._files(vector),
        )

    # =========================================================================
    # COOKIE
    # =========================================================================

    def _build_cookie(
        self,
        vector,
        payload,
    ) -> PreparedRequest:

        cookies = self._cookies(
            vector
        )

        parameter = self._parameter(
            vector
        )

        if parameter not in cookies:
            raise ValueError(
                "Cookie parameter was not found in "
                f"the original request: {parameter!r}"
            )

        cookies[parameter] = str(
            payload
        )

        return PreparedRequest(
            method=self._method(vector),
            url=self._url(vector),
            headers=self._headers(vector),
            cookies=cookies,
            params=self._params(vector),
            data=self._data(vector),
            json=self._json(vector),
            files=self._files(vector),
        )

    # =========================================================================
    # IDOR URL PATH
    # =========================================================================

    def _build_url_identifier(
        self,
        vector,
        original_value,
        replacement_value,
    ) -> PreparedRequest:

        url = self._url(vector)

        if original_value is None:
            raise ValueError(
                "IDOR identifier has no original value."
            )

        original_text = str(
            original_value
        )

        replacement_text = str(
            replacement_value
        )

        if not original_text:
            raise ValueError(
                "IDOR identifier original value is empty."
            )

        parsed = urlparse(
            url
        )

        segments = parsed.path.split(
            "/"
        )

        replaced = False

        for index, segment in enumerate(
            segments
        ):

            if segment == original_text:

                segments[index] = (
                    replacement_text
                )

                replaced = True
                break

        if not replaced:
            raise ValueError(
                "IDOR identifier was not found as "
                "an exact URL path segment."
            )

        new_path = "/".join(
            segments
        )

        new_url = urlunparse(
            parsed._replace(
                path=new_path
            )
        )

        print(
            "[TRACE][BUILDER][IDOR] "
            f"before={url!r} "
            f"after={new_url!r} "
            f"original={original_text!r} "
            f"replacement={replacement_text!r}",
            flush=True,
        )

        return PreparedRequest(
            method=self._method(vector),
            url=new_url,
            headers=self._headers(vector),
            cookies=self._cookies(vector),
            params=self._params(vector),
            data=self._data(vector),
            json=self._json(vector),
            files=self._files(vector),
        )

    # =========================================================================
    # METADATA
    # =========================================================================

    @staticmethod
    def _attach_attack_metadata(
        *,
        prepared: PreparedRequest,
        vector,
        payload,
        extra: dict | None = None,
    ) -> None:
        """
        Store attack-specific information without adding attack fields
        to PreparedRequest itself.

        PreparedRequest remains a pure HTTP request model.
        """

        metadata = getattr(
            prepared,
            "metadata",
            None,
        )

        if not isinstance(
            metadata,
            dict,
        ):
            metadata = {}

        metadata.update(
            {
                "attack_request": True,
                "attack_payload": str(
                    payload
                ),
                "vector_parameter": str(
                    getattr(
                        vector,
                        "parameter",
                        "",
                    )
                    or ""
                ),
                "vector_parameter_type": str(
                    getattr(
                        vector,
                        "parameter_type",
                        "",
                    )
                    or ""
                ),
                "source_vector_url": str(
                    getattr(
                        vector,
                        "url",
                        "",
                    )
                    or ""
                ),
            }
        )

        if extra:
            metadata.update(
                extra
            )

        prepared.metadata = metadata

    # =========================================================================
    # AUDIT
    # =========================================================================

    @staticmethod
    def _audit_request(
        *,
        vector,
        payload,
        prepared,
    ) -> None:
        """
        Prove that a request was constructed.

        This is NOT execution proof.

        AttackExecutor must produce execution proof after the request
        actually reaches the HTTP client.
        """

        print(
            "[ATTACK-REQUEST-AUDIT] "
            f"parameter_type="
            f"{getattr(vector, 'parameter_type', '')!r} "
            f"parameter="
            f"{getattr(vector, 'parameter', '')!r} "
            f"method="
            f"{getattr(prepared, 'method', '')!r} "
            f"url="
            f"{getattr(prepared, 'url', '')!r} "
            f"payload={payload!r}",
            flush=True,
        )

    # =========================================================================
    # SAFE VECTOR ACCESSORS
    # =========================================================================

    @staticmethod
    def _parameter_type(
        vector,
    ) -> str:

        return str(
            getattr(
                vector,
                "parameter_type",
                "",
            )
            or ""
        ).strip().lower()

    @staticmethod
    def _parameter(
        vector,
    ) -> str:

        return str(
            getattr(
                vector,
                "parameter",
                "",
            )
            or ""
        )

    @staticmethod
    def _url(
        vector,
    ) -> str:

        return str(
            getattr(
                vector,
                "url",
                "",
            )
            or ""
        )

    @staticmethod
    def _method(
        vector,
    ) -> str:

        return str(
            getattr(
                vector,
                "method",
                "GET",
            )
            or "GET"
        ).upper()

    @staticmethod
    def _headers(
        vector,
    ) -> dict:

        value = deepcopy(
            getattr(
                vector,
                "headers",
                {},
            )
            or {}
        )

        if not isinstance(
            value,
            dict,
        ):
            return {}

        return value

    @staticmethod
    def _cookies(
        vector,
    ) -> dict:

        value = deepcopy(
            getattr(
                vector,
                "cookies",
                {},
            )
            or {}
        )

        if not isinstance(
            value,
            dict,
        ):
            return {}

        return value

    @staticmethod
    def _params(
        vector,
    ) -> dict:

        value = deepcopy(
            getattr(
                vector,
                "params",
                {},
            )
            or {}
        )

        if not isinstance(
            value,
            dict,
        ):
            return {}

        return value

    @staticmethod
    def _data(
        vector,
    ) -> dict:

        value = deepcopy(
            getattr(
                vector,
                "data",
                {},
            )
            or {}
        )

        if not isinstance(
            value,
            dict,
        ):
            return {}

        return value

    @staticmethod
    def _json(
        vector,
    ) -> dict:

        value = deepcopy(
            getattr(
                vector,
                "json",
                {},
            )
            or {}
        )

        if not isinstance(
            value,
            dict,
        ):
            return {}

        return value

    @staticmethod
    def _files(
        vector,
    ) -> dict:

        value = deepcopy(
            getattr(
                vector,
                "files",
                {},
            )
            or {}
        )

        if not isinstance(
            value,
            dict,
        ):
            return {}

        return value