from dataclasses import dataclass


@dataclass(slots=True)
class OpenRedirectEvidence:

    payload: str

    location: str