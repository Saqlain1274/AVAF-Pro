"""
===============================================================================
AVAF Pro
Discovery Models

Canonical data models used by the Phase-1 Discovery Engine.

This module is the single source of truth for:
    - Extractor results/statistics
    - Static DOM discovery
    - Forms and links
    - JavaScript/meta/endpoints
    - Runtime browser state
    - Network observations
    - Attack-surface candidates

IMPORTANT
---------
These are DATA MODELS only.

They do not:
    - Crawl
    - Execute JavaScript
    - Submit forms
    - Inject payloads
    - Validate vulnerabilities
===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar


# =============================================================================
# GENERIC EXTRACTOR MODELS
# =============================================================================

T = TypeVar("T")


@dataclass(slots=True)
class DiscoveryStatistics:
    """
    Statistics shared by all passive discovery extractors.
    """

    total: int = 0
    discovered: int = 0
    ignored: int = 0
    duplicates: int = 0
    errors: int = 0

    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ExtractorResult(Generic[T]):
    """
    Standard result returned by BaseExtractor implementations.
    """

    items: list[T] = field(default_factory=list)

    statistics: DiscoveryStatistics = field(
        default_factory=DiscoveryStatistics
    )

    warnings: list[str] = field(default_factory=list)


# =============================================================================
# LINKS
# =============================================================================

@dataclass(slots=True)
class LinkInfo:
    """
    Static hyperlink discovered from an <a href="..."> element.
    """

    url: str

    text: str = ""
    title: str = ""
    rel: str = ""
    target: str = ""

    internal: bool = False


# =============================================================================
# FORM INPUTS
# =============================================================================

@dataclass(slots=True)
class InputField:
    """
    Standard HTML <input> field.
    """

    name: str = ""

    field_type: str = "text"

    value: str = ""

    placeholder: str = ""

    required: bool = False

    autocomplete: str = ""

    disabled: bool = False

    readonly: bool = False


@dataclass(slots=True)
class ButtonInfo:
    """
    HTML <button> element.
    """

    text: str = ""

    button_type: str = "submit"

    name: str = ""

    value: str = ""


@dataclass(slots=True)
class TextAreaInfo:
    """
    HTML <textarea> element.
    """

    name: str = ""

    value: str = ""

    placeholder: str = ""


@dataclass(slots=True)
class OptionInfo:
    """
    HTML <option> element.
    """

    text: str = ""

    value: str = ""

    selected: bool = False


@dataclass(slots=True)
class SelectInfo:
    """
    HTML <select> element.
    """

    name: str = ""

    multiple: bool = False

    options: list[OptionInfo] = field(
        default_factory=list
    )


# =============================================================================
# FORMS
# =============================================================================

@dataclass(slots=True)
class FormInfo:
    """
    Complete passive representation of an HTML form.
    """

    action: str = ""

    method: str = "GET"

    enctype: str = "application/x-www-form-urlencoded"

    inputs: list[InputField] = field(
        default_factory=list
    )

    buttons: list[ButtonInfo] = field(
        default_factory=list
    )

    textareas: list[TextAreaInfo] = field(
        default_factory=list
    )

    selects: list[SelectInfo] = field(
        default_factory=list
    )


# =============================================================================
# COMPATIBILITY FORM MODEL
# =============================================================================

@dataclass(slots=True)
class FormInput:
    """
    Lightweight form input model retained for compatibility
    with older AVAF Phase-1 modules.
    """

    name: str

    input_type: str

    value: str = ""

    required: bool = False

    placeholder: str = ""


@dataclass(slots=True)
class Form:
    """
    Lightweight legacy form representation.

    New discovery extractors should normally use FormInfo.
    """

    action: str

    method: str

    enctype: str

    inputs: list[FormInput] = field(
        default_factory=list
    )


# =============================================================================
# META TAGS
# =============================================================================

@dataclass(slots=True)
class MetaTag:
    """
    HTML metadata entry.
    """

    name: str = ""

    content: str = ""


# =============================================================================
# JAVASCRIPT
# =============================================================================

@dataclass(slots=True)
class ScriptInfo:
    """
    JavaScript resource discovered from the DOM.
    """

    src: str = ""

    script_type: str = "text/javascript"

    inline: bool = False

    async_script: bool = False

    defer_script: bool = False

    integrity: str = ""

    crossorigin: str = ""

    size: int = 0

    minified: bool = False


# =============================================================================
# ENDPOINT DISCOVERY
# =============================================================================

@dataclass(slots=True)
class EndpointInfo:
    """
    Endpoint discovered passively inside HTML/JavaScript.
    """

    url: str

    category: str = "endpoint"


# =============================================================================
# COOKIES
# =============================================================================

@dataclass(slots=True)
class CookieInfo:
    """
    Browser cookie discovered during runtime collection.
    """

    name: str

    value: str

    domain: str

    path: str

    secure: bool

    http_only: bool

    same_site: str = ""


# =============================================================================
# BROWSER STORAGE
# =============================================================================

@dataclass(slots=True)
class StorageItem:
    """
    localStorage/sessionStorage key-value pair.
    """

    key: str

    value: str


# =============================================================================
# GENERIC HTTP REQUEST
# =============================================================================

@dataclass(slots=True)
class HTTPRequest:
    """
    Generic HTTP request representation used by discovery/runtime models.
    """

    method: str

    url: str

    headers: dict[str, str] = field(
        default_factory=dict
    )

    body: str = ""

    content_type: str = ""

    source: str = ""

    parameters: list[str] = field(
        default_factory=list
    )

    status: int = 0


# =============================================================================
# NETWORK HEADERS
# =============================================================================

@dataclass(slots=True)
class HeaderInfo:
    """
    Single HTTP header.
    """

    name: str

    value: str


# =============================================================================
# NETWORK REQUEST
# =============================================================================

@dataclass(slots=True)
class NetworkRequest:
    """
    Raw browser network request captured by NetworkCollector.
    """

    id: str

    url: str

    method: str

    resource_type: str = ""

    headers: list[HeaderInfo] = field(
        default_factory=list
    )

    post_data: str = ""

    redirected_from: str = ""


# =============================================================================
# NETWORK RESPONSE
# =============================================================================

@dataclass(slots=True)
class NetworkResponse:
    """
    Raw browser network response captured by NetworkCollector.
    """

    request_id: str

    url: str

    status: int

    status_text: str = ""

    mime_type: str = ""

    headers: list[HeaderInfo] = field(
        default_factory=list
    )

    body_size: int = 0


# =============================================================================
# ATTACK SURFACE PARAMETER
# =============================================================================

@dataclass(slots=True)
class AttackParameter:
    """
    Parameter discovered from an HTTP endpoint.

    Phase-1 only records the candidate.

    Phase-2 decides whether/how it should be tested.
    """

    name: str

    value: str = ""

    location: str = ""

    data_type: str = "string"


# =============================================================================
# ATTACK SURFACE ENDPOINT
# =============================================================================

@dataclass(slots=True)
class AttackEndpoint:
    """
    Normalized endpoint that may later become a Phase-2 test candidate.
    """

    url: str

    method: str = "GET"

    source: str = ""

    content_type: str = ""

    authenticated: bool = False

    parameters: list[AttackParameter] = field(
        default_factory=list
    )

# =============================================================================
# STATIC DOM RESULT
# =============================================================================

@dataclass(slots=True)
class StaticDOMResult:
    """
    Complete passive static-DOM discovery result.

    Every extractor-backed field keeps the complete ExtractorResult so
    statistics, warnings, duplicate counts and discovered items are preserved.
    """

    forms: ExtractorResult[FormInfo] = field(
        default_factory=ExtractorResult
    )

    links: ExtractorResult[LinkInfo] = field(
        default_factory=ExtractorResult
    )

    meta: ExtractorResult[MetaTag] = field(
        default_factory=ExtractorResult
    )

    scripts: ExtractorResult[ScriptInfo] = field(
        default_factory=ExtractorResult
    )

    endpoints: ExtractorResult[EndpointInfo] = field(
        default_factory=ExtractorResult
    )

    technologies: ExtractorResult[str] = field(
        default_factory=ExtractorResult
    )

    comments: ExtractorResult[str] = field(
        default_factory=ExtractorResult
    )

    html_size: int = 0
    
# =============================================================================
# RUNTIME RESULT
# =============================================================================

@dataclass(slots=True)
class RuntimeResult:
    """
    Complete runtime discovery result.

    Filled by RuntimeCollector after JavaScript execution.
    """

    # ---------------------------------------------------------
    # Runtime Export
    # ---------------------------------------------------------

    runtime_data: dict[str, Any] = field(
        default_factory=dict
    )

    # Every browser runtime collection during the page lifecycle.
    #
    # Entry 0 = initial application observation
    # Entry 1+ = post-interaction observations
    #
    # This preserves the observation history instead of treating the
    # latest runtime snapshot as the only evidence.
    observations: list[dict[str, Any]] = field(
        default_factory=list
    )

    events: list[dict[str, Any]] = field(
        default_factory=list
    )

    statistics: dict[str, Any] = field(
        default_factory=dict
    )

    # ---------------------------------------------------------
    # Page Information
    # ---------------------------------------------------------

    url: str = ""

    title: str = ""

    dom_hash: str = ""

    # ---------------------------------------------------------
    # Browser Storage
    # ---------------------------------------------------------

    cookies: list[Any] = field(
        default_factory=list
    )

    local_storage: list[Any] = field(
        default_factory=list
    )

    session_storage: list[Any] = field(
        default_factory=list
    )

    indexed_db: list[Any] = field(
        default_factory=list
    )

    # ---------------------------------------------------------
    # Runtime DOM
    # ---------------------------------------------------------

    runtime_forms: list[FormInfo] = field(
        default_factory=list
    )

    dom_mutations: list[Any] = field(
        default_factory=list
    )

    # ---------------------------------------------------------
    # Runtime Navigation
    # ---------------------------------------------------------

    dynamic_routes: list[str] = field(
        default_factory=list
    )

    # ---------------------------------------------------------
    # Runtime Network
    # ---------------------------------------------------------

    xhr_requests: list[HTTPRequest] = field(
        default_factory=list
    )

    fetch_requests: list[HTTPRequest] = field(
        default_factory=list
    )

    graphql_requests: list[HTTPRequest] = field(
        default_factory=list
    )

    websocket_connections: list[str] = field(
        default_factory=list
    )

    # ---------------------------------------------------------
    # Runtime Behaviour
    # ---------------------------------------------------------

    javascript_events: list[Any] = field(
        default_factory=list
    )

# =============================================================================
# NETWORK RESULT
# =============================================================================

@dataclass(slots=True)
class NetworkResult:
    """
    Passive network intelligence collected during crawling.

    ExtractorResult containers are used because NetworkCollector currently
    accesses these members through:

        result.requests.items
        result.responses.items
        result.endpoints.items
    """

    requests: ExtractorResult[NetworkRequest] = field(
        default_factory=ExtractorResult
    )

    responses: ExtractorResult[NetworkResponse] = field(
        default_factory=ExtractorResult
    )

    endpoints: ExtractorResult[AttackEndpoint] = field(
        default_factory=ExtractorResult
    )

    api_endpoints: list[str] = field(
        default_factory=list
    )

    unique_hosts: list[str] = field(
        default_factory=list
    )

    technologies: list[str] = field(
        default_factory=list
    )

    security_headers: dict[str, str] = field(
        default_factory=dict
    )


# =============================================================================
# COMPLETE DISCOVERY RESULT
# =============================================================================

@dataclass(slots=True)
class DiscoveryResult:
    """
    Root result object produced by the Discovery Engine.
    """

    static_dom: StaticDOMResult = field(
        default_factory=StaticDOMResult
    )

    runtime: RuntimeResult = field(
        default_factory=RuntimeResult
    )

    network: NetworkResult = field(
        default_factory=NetworkResult
    )