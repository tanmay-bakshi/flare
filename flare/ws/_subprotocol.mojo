"""Shared RFC 6455 subprotocol parsing and selection."""


def _trim_http_ows(value: String) -> String:
    """Trim only HTTP optional whitespace (SP / HTAB)."""
    var start = 0
    var end = value.byte_length()
    while start < end:
        var byte = value.unsafe_ptr().unsafe_offset(start)[]
        if byte != UInt8(32) and byte != UInt8(9):
            break
        start += 1
    while end > start:
        var byte = value.unsafe_ptr().unsafe_offset(end - 1)[]
        if byte != UInt8(32) and byte != UInt8(9):
            break
        end -= 1
    return String(unsafe_from_utf8=value.as_bytes()[start:end])


def _is_http_token(value: String) -> Bool:
    """Return whether ``value`` is one non-empty RFC 7230 token."""
    if value.byte_length() == 0:
        return False
    for index in range(value.byte_length()):
        var byte = value.unsafe_ptr().unsafe_offset(index)[]
        if (
            (byte >= UInt8(48) and byte <= UInt8(57))
            or (byte >= UInt8(65) and byte <= UInt8(90))
            or (byte >= UInt8(97) and byte <= UInt8(122))
            or byte == UInt8(33)
            or byte == UInt8(35)
            or byte == UInt8(36)
            or byte == UInt8(37)
            or byte == UInt8(38)
            or byte == UInt8(39)
            or byte == UInt8(42)
            or byte == UInt8(43)
            or byte == UInt8(45)
            or byte == UInt8(46)
            or byte == UInt8(94)
            or byte == UInt8(95)
            or byte == UInt8(96)
            or byte == UInt8(124)
            or byte == UInt8(126)
        ):
            continue
        return False
    return True


def _is_subprotocol_token(value: String) -> Bool:
    """Return whether ``value`` is one valid RFC 6455 protocol token."""
    return _is_http_token(value)


def _validated_subprotocol_set(
    protocols: List[String],
) raises -> Dict[String, Bool]:
    """Return the validated protocol tokens as a membership set."""
    var seen = Dict[String, Bool]()
    for index in range(len(protocols)):
        if not _is_subprotocol_token(protocols[index]):
            raise Error("invalid WebSocket subprotocol token")
        if protocols[index] in seen:
            raise Error("duplicate WebSocket subprotocol token")
        seen[protocols[index]] = True
    return seen^


def _validate_subprotocols(protocols: List[String]) raises:
    """Validate a duplicate-free list of RFC 6455 protocol tokens."""
    _ = _validated_subprotocol_set(protocols)


def _render_subprotocols(protocols: List[String]) raises -> String:
    """Render validated protocol offers as one HTTP list field value."""
    _validate_subprotocols(protocols)
    var rendered = String("")
    for index in range(len(protocols)):
        if index > 0:
            rendered += ", "
        rendered += protocols[index]
    return rendered^


def _parse_subprotocol_offers(value: String) raises -> List[String]:
    """Parse one request-list field, ignoring RFC-valid null members."""
    var protocols = List[String]()
    var segment_start = 0
    var length = value.byte_length()
    for cursor in range(length + 1):
        if cursor < length and value.unsafe_ptr().unsafe_offset(
            cursor
        )[] != UInt8(44):
            continue

        var start = segment_start
        var end = cursor
        while start < end and (
            value.unsafe_ptr().unsafe_offset(start)[] == UInt8(32)
            or value.unsafe_ptr().unsafe_offset(start)[] == UInt8(9)
        ):
            start += 1
        while end > start and (
            value.unsafe_ptr().unsafe_offset(end - 1)[] == UInt8(32)
            or value.unsafe_ptr().unsafe_offset(end - 1)[] == UInt8(9)
        ):
            end -= 1
        if start == end:
            segment_start = cursor + 1
            continue

        var protocol = String(unsafe_from_utf8=value.as_bytes()[start:end])
        if not _is_subprotocol_token(protocol):
            raise Error("invalid WebSocket subprotocol offer")
        protocols.append(protocol^)
        segment_start = cursor + 1

    _validate_subprotocols(protocols)
    return protocols^


def _parse_subprotocol_selection(value: String) raises -> String:
    """Parse the response field's singular protocol token grammar."""
    var selected = _trim_http_ows(value)
    if not _is_subprotocol_token(selected):
        raise Error("invalid WebSocket subprotocol selection")
    return selected^


def _contains_subprotocol(protocols: List[String], wanted: String) -> Bool:
    """Return whether ``wanted`` occurs in ``protocols``."""
    for protocol in protocols:
        if protocol == wanted:
            return True
    return False


def _select_subprotocol(
    offered: List[String], supported: List[String]
) raises -> Optional[String]:
    """Select the first server-preferred protocol offered by the client."""
    var offered_set = _validated_subprotocol_set(offered)
    _validate_subprotocols(supported)
    for protocol in supported:
        if protocol in offered_set:
            return Optional[String](protocol)
    return None
