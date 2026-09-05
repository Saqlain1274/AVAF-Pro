"""
===============================================================================
File Upload Payload Provider
===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(slots=True)
class UploadPayload:

    filename: str

    content_type: str

    content: bytes


UPLOAD_PAYLOADS = (

    UploadPayload(
        filename="shell.php",
        content_type="application/x-php",
        content=b"<?php echo 'AVAF'; ?>",
    ),

    UploadPayload(
        filename="shell.phtml",
        content_type="application/x-php",
        content=b"<?php phpinfo(); ?>",
    ),

    UploadPayload(
        filename="image.php.jpg",
        content_type="image/jpeg",
        content=b"<?php echo 'JPEG'; ?>",
    ),

    UploadPayload(
        filename="test.svg",
        content_type="image/svg+xml",
        content=b"<svg></svg>",
    ),

)


class FileUploadPayloadProvider:

    def generate(
        self,
        vector,
    ) -> Iterable[UploadPayload]:

        return UPLOAD_PAYLOADS