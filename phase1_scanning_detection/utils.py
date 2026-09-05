"""
AVAF PRO
Common Utilities

Shared helper functions used by every engine.
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import re

from urllib.parse import (
    urlparse,
    parse_qsl,
)


# ==========================================================
# URL HELPERS
# ==========================================================

def is_internal(url: str, target: str) -> bool:

    try:
        return (
            urlparse(url).netloc.lower()
            ==
            urlparse(target).netloc.lower()
        )
    except Exception:
        return False


# ==========================================================
# STATIC FILE
# ==========================================================

STATIC_EXTENSIONS = {

    ".jpg", ".jpeg", ".png", ".gif",

    ".svg", ".ico",

    ".css",

    ".woff", ".woff2",

    ".ttf",

    ".eot",

    ".pdf",

    ".zip", ".rar", ".7z",

    ".mp4", ".avi", ".mov",

    ".mp3", ".wav"

}


def is_static_resource(url: str):

    path = urlparse(url).path.lower()

    return any(

        path.endswith(ext)

        for ext in STATIC_EXTENSIONS

    )


# ==========================================================
# QUERY PARAMS
# ==========================================================

def extract_query_params(url):

    return [

        {

            "name": k,

            "value": v

        }

        for k, v in parse_qsl(

            urlparse(url).query,

            keep_blank_values=True

        )

    ]


# ==========================================================
# JSON PARAMS
# ==========================================================

def extract_json_keys(data):

    keys = set()

    def walk(obj):

        if isinstance(obj, dict):

            for k, v in obj.items():

                keys.add(k)

                walk(v)

        elif isinstance(obj, list):

            for item in obj:

                walk(item)

    try:

        parsed = json.loads(data)

        walk(parsed)

    except:

        pass

    return sorted(keys)


# ==========================================================
# HTML HASH
# ==========================================================

def html_hash(html):

    html = re.sub(r"\s+", " ", html)

    html = re.sub(r"\d+", "", html)

    return hashlib.sha256(

        html.encode()

    ).hexdigest()


# ==========================================================
# MIME
# ==========================================================

def guess_mime(url):

    mime, _ = mimetypes.guess_type(url)

    return mime or "application/octet-stream"


# ==========================================================
# CONTENT TYPE
# ==========================================================

def is_json(content_type):

    if not content_type:

        return False

    return "json" in content_type.lower()


def is_html(content_type):

    if not content_type:

        return False

    return "html" in content_type.lower()


# ==========================================================
# SAFE TEXT
# ==========================================================

def safe_text(value):

    if value is None:

        return ""

    return str(value)


# ==========================================================
# GRAPHQL
# ==========================================================

def looks_like_graphql(body):

    if not body:

        return False

    body = body.lower()

    return (

        "query" in body

        or

        "mutation" in body

        or

        "graphql" in body

    )