from __future__ import annotations

from dataclasses import dataclass

from ..models.http_exchange import (
    HTTPRequest,
    HTTPResponse,
)


@dataclass(slots=True)
class HTTPExchange:

    validator: str

    request: HTTPRequest

    response: HTTPResponse

    baseline: bool = False

    payload: str | None = None


class Recorder:

    def __init__(self) -> None:

        self._history: list[
            HTTPExchange
        ] = []

    def record(
        self,
        validator: str,
        request: HTTPRequest,
        response: HTTPResponse,
        *,
        baseline: bool = False,
        payload: str | None = None,
    ) -> None:

        self._history.append(

            HTTPExchange(

                validator=validator,

                request=request,

                response=response,

                baseline=baseline,

                payload=payload,

            )

        )

    def history(
        self,
    ) -> list[HTTPExchange]:

        return list(
            self._history
        )

    def clear(self) -> None:

        self._history.clear()

    def count(self) -> int:

        return len(
            self._history
        )

    def by_validator(
        self,
        validator: str,
    ) -> list[HTTPExchange]:

        return [
            exchange
            for exchange
            in self._history
            if exchange.validator
            == validator
        ]