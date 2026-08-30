"""Response constructors extracted from ``flare.http.server``.

The public ``ok`` / ``ok_json`` / ``bad_request`` /
``not_found`` / ``internal_error`` / ``redirect`` helpers plus the
shared ``String`` -> ``List[UInt8]`` copy. ``flare.http.server``
re-exports every name here, so the public ``flare.http`` /
``flare.prelude`` / ``flare`` surfaces are unchanged.
"""

from std.memory import unsafe_memcpy

from ..response import Response, Status

from .write import _status_reason


@always_inline
def _string_to_bytes(s: String) -> List[UInt8]:
    """Bulk-copy a ``String``'s bytes into a freshly-allocated ``List[UInt8]``.

    Replaces the byte-by-byte append loop ``ok`` / ``ok_json`` / ...
    were doing on the response-building hot path. One allocation, one
    ``memcpy`` — what every Rust framework's ``Bytes::from(String)``
    is doing under the hood.
    """
    var n = s.byte_length()
    var body_bytes = List[UInt8]()
    if n == 0:
        return body_bytes^
    body_bytes.resize(n, UInt8(0))
    var src = s.as_bytes()
    unsafe_memcpy(dest=body_bytes.unsafe_ptr(), src=src.unsafe_ptr(), count=n)
    return body_bytes^


def ok(body: String = "") -> Response:
    """Create a 200 OK response with optional text body.

    Args:
        body: Response body string. Empty by default.

    Returns:
        A ``Response`` with status 200. Sets ``Content-Type: text/plain``
        if body is non-empty.
    """
    var resp = Response(
        status=Status.OK, reason="OK", body=_string_to_bytes(body)
    )
    if body.byte_length() > 0:
        try:
            resp.headers.set("Content-Type", "text/plain; charset=utf-8")
        except:
            pass
    return resp^


def ok_json(body: String) -> Response:
    """Create a 200 OK response with a JSON body.

    Args:
        body: Pre-serialised JSON string to send.

    Returns:
        A ``Response`` with ``Content-Type: application/json``.
    """
    var resp = Response(
        status=Status.OK, reason="OK", body=_string_to_bytes(body)
    )
    try:
        resp.headers.set("Content-Type", "application/json")
    except:
        pass
    return resp^


def bad_request(msg: String = "Bad Request") -> Response:
    """Create a 400 Bad Request response."""
    var resp = Response(
        status=Status.BAD_REQUEST,
        reason="Bad Request",
        body=_string_to_bytes(msg),
    )
    try:
        resp.headers.set("Content-Type", "text/plain")
    except:
        pass
    return resp^


def not_found(path: String = "") -> Response:
    """Create a 404 Not Found response."""
    var msg = "Not Found"
    if path.byte_length() > 0:
        msg = "Not Found: " + path
    var resp = Response(
        status=Status.NOT_FOUND,
        reason="Not Found",
        body=_string_to_bytes(msg),
    )
    try:
        resp.headers.set("Content-Type", "text/plain")
    except:
        pass
    return resp^


def unauthorized(
    msg: String = "Unauthorized", challenge: String = "Bearer"
) -> Response:
    """Create a 401 Unauthorized response.

    Sets ``WWW-Authenticate`` to ``challenge`` (default ``"Bearer"``)
    per RFC 9110 - a 401 MUST carry the challenge so clients know how
    to authenticate. Pass ``challenge=""`` to omit it.
    """
    var resp = Response(
        status=Status.UNAUTHORIZED,
        reason="Unauthorized",
        body=_string_to_bytes(msg),
    )
    try:
        resp.headers.set("Content-Type", "text/plain")
        if challenge.byte_length() > 0:
            resp.headers.set("WWW-Authenticate", challenge)
    except:
        pass
    return resp^


def forbidden(msg: String = "Forbidden") -> Response:
    """Create a 403 Forbidden response.

    Use when the caller is authenticated but not permitted (contrast
    with :func:`unauthorized`, which means *not yet authenticated*).
    """
    var resp = Response(
        status=Status.FORBIDDEN,
        reason="Forbidden",
        body=_string_to_bytes(msg),
    )
    try:
        resp.headers.set("Content-Type", "text/plain")
    except:
        pass
    return resp^


def internal_error(msg: String = "Internal Server Error") -> Response:
    """Create a 500 Internal Server Error response."""
    var resp = Response(
        status=Status.INTERNAL_SERVER_ERROR,
        reason="Internal Server Error",
        body=_string_to_bytes(msg),
    )
    try:
        resp.headers.set("Content-Type", "text/plain")
    except:
        pass
    return resp^


def redirect(url: String, status: Int = 302) -> Response:
    """Create a redirect response (302 Found by default).

    Args:
        url: Target URL for the ``Location`` header.
        status: HTTP status code (301, 302, 307, 308). Default 302.

    Returns:
        A ``Response`` with the ``Location`` header set.
    """
    var resp = Response(status=status, reason=_status_reason(status))
    try:
        resp.headers.set("Location", url)
    except:
        pass
    return resp^
