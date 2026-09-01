"""WebSocket client (RFC 6455).

Opening handshake (§4.1):
  1. Parse ``ws://`` / ``wss://`` URL.
  2. Open TCP (ws) or TLS (wss) stream.
  3. Generate a random 16-byte nonce, base64-encode it as ``Sec-WebSocket-Key``.
  4. Send HTTP/1.1 GET with ``Upgrade: websocket`` headers.
  5. Parse the 101 Switching Protocols response.
  6. Verify ``Sec-WebSocket-Accept = base64(SHA-1(key + GUID))``.

SHA-1 is computed via libcrypto (OpenSSL) FFI -- the same library
already bundled by the TLS FFI build step. Base64 (RFC 4648 §4
standard alphabet) is the canonical helper at
:mod:`flare.crypto.base64`; the local ``_base64_encode`` alias
keeps the call sites readable while routing through one source
of truth (this used to ship as three near-identical private
encoders).
"""

from std.collections import Optional
from std.ffi import OwnedDLHandle, c_int
from std.memory import ArcPointer, Pointer
from std.memory.alloc import unsafe_alloc

from ._duplex import (
    WsDuplex,
    WsReceiver,
    WsSender,
    WsShutdown,
    _WsControl,
    _split_stream,
)
from ._message import WsMessage
from ._subprotocol import (
    _contains_subprotocol,
    _is_http_token,
    _parse_subprotocol_selection,
    _render_subprotocols,
    _trim_http_ows,
)
from ._transport import _WsStream
from .frame import (
    WsCloseCode,
    WsFrame,
    WsOpcode,
    WsProtocolError,
    _WsFrameHeader,
    _encode_client_frame,
    _inspect_frame_header,
)
from ..crypto.base64 import base64_encode as _base64_encode
from ..http.url import Url
from ..tls import TlsConfig, TlsStream
from ..tls.stream import (
    _TlsClientHandshake,
    _SSL_IO_WANT_READ,
    _SSL_IO_WANT_WRITE,
    _SSL_IO_CLOSED,
)
from ..tcp import TcpStream
from ..tcp.stream import _TcpConnectAttempt
from ..net import DnsError, IpAddr, NetworkError, SocketAddr, _find_flare_lib
from ..dns.async_resolve import ResolveCancellation, start_resolve
from ..runtime._libc_time import monotonic_now_ns
from ..runtime.event import Event, INTEREST_READ, INTEREST_WRITE
from ..utils.dylib import dl_sym

# RFC 6455 §1.3 magic GUID concatenated with the Sec-WebSocket-Key for SHA-1
comptime _WS_GUID: String = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# OpenSSL SHA-1 digest length (20 bytes)
comptime _SHA1_LEN: Int = 20

# Reactor token used while one opening handshake owns the connection fd.
comptime _WS_CONNECT_TOKEN: UInt64 = 2

# Legacy ``WsClient.connect`` used a 5 second TCP timeout. Its compatibility
# path now applies that same budget to the complete DNS-through-Upgrade dial.
comptime _LEGACY_HANDSHAKE_TIMEOUT_MS: Int = 5000


struct WsHandshakeError(Copyable, Movable, Writable):
    """Raised when the WebSocket opening handshake fails."""

    var message: String

    def __init__(out self, message: String):
        self.message = message

    def write_to[W: Writer, //](self, mut writer: W):
        writer.write("WsHandshakeError: ", self.message)


# ── SHA-1 via libcrypto FFI ───────────────────────────────────────────────────
#
# ``_do_sha1`` takes ``lib`` as a ``read`` (borrow) so Mojo's ASAP destruction
# policy can't reclaim the handle between ``get_function`` and the actual
# ``fn_sha1`` invocation. Without this, the dylib is unmapped and the cached
# function pointer dangles into freed memory by the time we call it. See the
# long discussion in ``flare/http/encoding.mojo`` and the matching idiom on
# the server side in ``flare/ws/server.mojo``.


def _do_sha1(
    read lib: OwnedDLHandle, data_bytes: Span[UInt8, _]
) raises -> List[UInt8]:
    """Invoke SHA-1 with ``lib`` borrowed across both the symbol lookup
    and the call.

    Args:
        lib: Borrowed handle to ``libflare_tls`` (keeps it mapped).
        data_bytes: Input bytes to hash.

    Returns:
        20-byte SHA-1 digest.
    """
    # SHA1(const unsigned char *d, size_t n, unsigned char *md) -> unsigned char*
    var fn_sha1 = dl_sym[def(Int, Int, Int) thin abi("C") -> Int](lib, "SHA1")
    var digest_buf = List[UInt8](capacity=_SHA1_LEN)
    digest_buf.resize(_SHA1_LEN, 0)
    _ = fn_sha1(
        Int(data_bytes.unsafe_ptr()),
        Int(len(data_bytes)),
        Int(digest_buf.unsafe_ptr()),
    )
    return digest_buf^


def _sha1(data: String) raises -> List[UInt8]:
    """Compute SHA-1 of ``data`` using OpenSSL via the TLS shared library.

    Uses the ``SHA1`` function from libcrypto (available via the bundled
    ``libflare_tls.so`` which links both libssl and libcrypto).

    Args:
        data: Input bytes to hash.

    Returns:
        20-byte SHA-1 digest.

    Raises:
        NetworkError: If the SHA-1 function cannot be loaded.
    """
    var lib = OwnedDLHandle(_find_flare_lib())
    return _do_sha1(lib, data.as_bytes())


# ── HTTP upgrade helpers ──────────────────────────────────────────────────────


def _generate_ws_key() -> String:
    """Generate a random 16-byte nonce encoded as base64.

    Reads from ``/dev/urandom`` for cryptographically secure randomness.
    Falls back to a time-seeded deterministic generator if urandom is
    unavailable (should not happen on Linux/macOS).

    Returns:
        24-character base64 string suitable for ``Sec-WebSocket-Key``.
    """
    var nonce = List[UInt8](capacity=16)
    try:
        with open("/dev/urandom", "r") as f:
            var raw = f.read_bytes(16)
            for i in range(16):
                nonce.append(raw[i])
    except:
        # Fallback: use external_call to get some entropy from the clock
        for i in range(16):
            nonce.append(UInt8((i * 37 + 0x42) & 0xFF))
    return _base64_encode(Span[UInt8, _](nonce))


def _compute_accept(key: String) raises -> String:
    """Compute the expected ``Sec-WebSocket-Accept`` header value.

    Per RFC 6455 §4.2.2: base64(SHA-1(key + GUID)).

    Args:
        key: The ``Sec-WebSocket-Key`` value sent in the upgrade request.

    Returns:
        Base64-encoded SHA-1 digest for comparison with the server response.
    """
    var combined = key + _WS_GUID
    var digest = _sha1(combined)
    return _base64_encode(Span[UInt8, _](digest))


def _ws_url_to_http(url: String) raises -> String:
    """Convert ``ws://`` or ``wss://`` URL to ``http://`` or ``https://``.

    Args:
        url: WebSocket URL.

    Returns:
        HTTP URL for use with ``Url.parse()``.

    Raises:
        WsHandshakeError: If the scheme is not ``ws`` or ``wss``.
    """
    if url.startswith("ws://"):
        return "http://" + String(String(unsafe_from_utf8=url.as_bytes()[5:]))
    elif url.startswith("wss://"):
        return "https://" + String(String(unsafe_from_utf8=url.as_bytes()[6:]))
    raise WsHandshakeError("URL must start with ws:// or wss://: " + url)


def _str_find_local(s: String, sub: String) -> Int:
    """Return the index of the first ``sub`` in ``s``, or -1."""
    var n = s.byte_length()
    var m = sub.byte_length()
    if m == 0:
        return 0
    for i in range(n - m + 1):
        var ok = True
        for j in range(m):
            if s.unsafe_ptr()[i + j] != sub.unsafe_ptr()[j]:
                ok = False
                break
        if ok:
            return i
    return -1


def _str_find_from_local(s: String, sub: String, start: Int) -> Int:
    """Return the first ``sub`` index at or after ``start``, or -1."""
    var n = s.byte_length()
    var m = sub.byte_length()
    if start < 0 or start > n:
        return -1
    if m == 0:
        return start
    if m > n - start:
        return -1
    for i in range(start, n - m + 1):
        var ok = True
        for j in range(m):
            if s.unsafe_ptr()[i + j] != sub.unsafe_ptr()[j]:
                ok = False
                break
        if ok:
            return i
    return -1


def _lower_local(s: String) -> String:
    """Return ASCII-lowercase copy of ``s``."""
    var out = String(capacity=s.byte_length())
    for i in range(s.byte_length()):
        var c = s.unsafe_ptr()[i]
        if c >= 65 and c <= 90:
            out += chr(Int(c) + 32)
        else:
            out += chr(Int(c))
    return out^


def _client_subprotocol_offer(
    extra_headers: List[String], subprotocols: List[String]
) raises -> String:
    """Validate and render the client's first-class protocol offer.

    ``Sec-WebSocket-Protocol`` is owned by the typed argument so response
    validation cannot be bypassed through an untracked raw header.
    """
    for header in extra_headers:
        var colon = _str_find_local(header, ":")
        if colon <= 0:
            raise WsHandshakeError("malformed extra HTTP header")
        var field_name = String(unsafe_from_utf8=header.as_bytes()[:colon])
        if not _is_http_token(field_name):
            raise WsHandshakeError("invalid extra HTTP header field name")
        var name = _lower_local(field_name)
        if name == "sec-websocket-protocol":
            raise WsHandshakeError(
                "Sec-WebSocket-Protocol must be supplied through the"
                " subprotocols argument"
            )
    try:
        return _render_subprotocols(subprotocols)
    except error:
        raise WsHandshakeError(String(error))


def _cancel_resolve_address(address: Int):
    """Cancel a boxed resolver capability published in ``_WsControl``."""
    var pointer = Pointer[ResolveCancellation, MutUntrackedOrigin](
        unsafe_from_address=address
    )
    pointer[].cancel()


def _release_resolve_address(address: Int):
    """Destroy a boxed resolver capability exactly once."""
    var pointer = Pointer[ResolveCancellation, MutUntrackedOrigin](
        unsafe_from_address=address
    )
    pointer.unsafe_deinit_pointee()
    pointer.unsafe_free()


def _control_error(control: ArcPointer[_WsControl]) -> NetworkError:
    var message = control[].stopped_message()
    if message == "":
        message = "WebSocket connection stopped"
    return NetworkError(message)


def _expire_handshake(control: ArcPointer[_WsControl]) raises:
    var message = "WebSocket opening handshake deadline expired"
    control[].stop(message)
    raise NetworkError(message)


def _check_connect_running(
    control: ArcPointer[_WsControl], deadline_ns: Int64
) raises:
    if control[].is_stopping():
        raise _control_error(control)
    if monotonic_now_ns() >= deadline_ns:
        _expire_handshake(control)


def _remaining_poll_ms(
    control: ArcPointer[_WsControl], deadline_ns: Int64
) raises -> Int:
    _check_connect_running(control, deadline_ns)
    var remaining_ns = deadline_ns - monotonic_now_ns()
    if remaining_ns <= 0:
        _expire_handshake(control)
    var timeout_ms = Int(remaining_ns // 1_000_000)
    if remaining_ns % 1_000_000 != 0:
        timeout_ms += 1
    # Reactor.poll lowers to a c_int timeout. Short slices also make a clock
    # anomaly observable without weakening the one absolute deadline.
    if timeout_ms > 1000:
        return 1000
    return timeout_ms


def _wait_connect_fd(
    control: ArcPointer[_WsControl],
    fd: c_int,
    interest: Int,
    deadline_ns: Int64,
) raises:
    control[].reactor.modify(fd, interest)
    var events = List[Event]()
    while True:
        var timeout_ms = _remaining_poll_ms(control, deadline_ns)
        _ = control[].reactor.poll(timeout_ms, events)
        _check_connect_running(control, deadline_ns)
        for i in range(len(events)):
            if (
                not events[i].is_wakeup()
                and events[i].token == _WS_CONNECT_TOKEN
            ):
                return


def _unregister_connect_fd(control: ArcPointer[_WsControl], fd: c_int):
    try:
        control[].reactor.unregister(fd)
    except:
        pass


def _close_tcp_owner(
    control: ArcPointer[_WsControl], fd: c_int, mut tcp: TcpStream
):
    if control[].begin_owner_close(fd):
        tcp.close()
        control[].finish_owner_close()


def _close_attempt_owner(
    control: ArcPointer[_WsControl],
    fd: c_int,
    mut attempt: _TcpConnectAttempt,
):
    if control[].begin_owner_close(fd):
        attempt.close()
        control[].finish_owner_close()


def _finish_tcp_attempt(
    control: ArcPointer[_WsControl],
    fd: c_int,
    var attempt: _TcpConnectAttempt,
) raises -> TcpStream:
    """Finish a connected attempt without closing outside owner exclusion."""
    try:
        attempt.prepare_finish()
    except error:
        _unregister_connect_fd(control, fd)
        _close_attempt_owner(control, fd, attempt)
        if control[].is_stopping():
            raise _control_error(control)
        raise error^

    if not control[].begin_owner_close(fd):
        _unregister_connect_fd(control, fd)
        attempt.close()
        raise _control_error(control)

    # The transfer cannot fail or close the fd. Keeping the registration intact
    # avoids an unregister/register gap before TLS or Upgrade takes over.
    var tcp = attempt^.finish()
    control[].finish_owner_close()

    if not control[].attach_fd(fd):
        _unregister_connect_fd(control, fd)
        tcp.close()
        raise _control_error(control)
    return tcp^


def _connect_tcp_candidate(
    control: ArcPointer[_WsControl],
    peer: SocketAddr,
    deadline_ns: Int64,
) raises -> TcpStream:
    var attempt = _TcpConnectAttempt.create(peer)
    var fd = attempt.fd()
    if not control[].attach_fd(fd):
        attempt.close()
        raise _control_error(control)

    try:
        control[].reactor.register(fd, _WS_CONNECT_TOKEN, INTEREST_WRITE)
    except error:
        _close_attempt_owner(control, fd, attempt)
        raise error^

    try:
        var complete = attempt.start()
        if not complete:
            _wait_connect_fd(control, fd, INTEREST_WRITE, deadline_ns)
            attempt.complete_ready()
        _check_connect_running(control, deadline_ns)
    except error:
        _unregister_connect_fd(control, fd)
        _close_attempt_owner(control, fd, attempt)
        if control[].is_stopping():
            raise _control_error(control)
        raise error^

    return _finish_tcp_attempt(control, fd, attempt^)


def _resolve_connect_host(
    control: ArcPointer[_WsControl], host: String, deadline_ns: Int64
) raises -> List[IpAddr]:
    _check_connect_running(control, deadline_ns)
    var request = start_resolve(host)
    var cancellation = request.cancellation()
    var boxed = unsafe_alloc[ResolveCancellation](1)
    boxed.unsafe_write(cancellation^)
    var address = Int(boxed)
    if not control[].install_resolver_request(
        address, _cancel_resolve_address, _release_resolve_address
    ):
        raise _control_error(control)

    var result: List[IpAddr]
    try:
        result = request.wait_until(deadline_ns)
    except error:
        control[].clear_resolver_request(address)
        if control[].is_stopping():
            raise _control_error(control)
        if monotonic_now_ns() >= deadline_ns:
            _expire_handshake(control)
        raise error^
    control[].clear_resolver_request(address)
    _check_connect_running(control, deadline_ns)
    return result^


def _establish_tls(
    control: ArcPointer[_WsControl],
    host: String,
    config: TlsConfig,
    deadline_ns: Int64,
    var tcp: TcpStream,
) raises -> TlsStream:
    var fd = tcp._socket.fd
    var pending: Optional[_TlsClientHandshake]
    try:
        pending = Optional[_TlsClientHandshake](
            _TlsClientHandshake.start(fd, host, config)
        )
    except error:
        _unregister_connect_fd(control, fd)
        _close_tcp_owner(control, fd, tcp)
        if control[].is_stopping():
            raise _control_error(control)
        raise error^

    var handshake = pending.take()
    try:
        while True:
            _check_connect_running(control, deadline_ns)
            var step = handshake.step(host)
            if step == 0:
                break
            var interest = (
                INTEREST_READ if step == _SSL_IO_WANT_READ else INTEREST_WRITE
            )
            _wait_connect_fd(control, fd, interest, deadline_ns)
    except error:
        handshake.close_abortive()
        _unregister_connect_fd(control, fd)
        _close_tcp_owner(control, fd, tcp)
        if control[].is_stopping():
            raise _control_error(control)
        raise error^

    try:
        handshake.prepare_finish(tcp._socket.fd)
    except error:
        handshake.close_abortive()
        _unregister_connect_fd(control, fd)
        _close_tcp_owner(control, fd, tcp)
        if control[].is_stopping():
            raise _control_error(control)
        raise error^

    if not control[].begin_owner_close(fd):
        handshake.close_abortive()
        _unregister_connect_fd(control, fd)
        tcp.close()
        raise _control_error(control)

    var tls = handshake^.finish(tcp^)
    control[].finish_owner_close()

    if not control[].attach_fd(fd):
        _unregister_connect_fd(control, fd)
        tls._close_abortive()
        raise _control_error(control)
    return tls^


def _headers_complete(bytes: List[UInt8]) -> Bool:
    var size = len(bytes)
    return (
        size >= 4
        and bytes[size - 4] == UInt8(13)
        and bytes[size - 3] == UInt8(10)
        and bytes[size - 2] == UInt8(13)
        and bytes[size - 1] == UInt8(10)
    )


def _validate_upgrade_response(
    bytes: List[UInt8],
    expected_accept: String,
    offered_subprotocols: List[String] = [],
) raises -> Optional[String]:
    var response = String(unsafe_from_utf8=Span[UInt8, _](bytes))
    var line_end = _str_find_from_local(response, "\r\n", 0)
    if line_end < 0:
        raise WsHandshakeError("truncated HTTP Upgrade response")
    var status_line = String(unsafe_from_utf8=response.as_bytes()[:line_end])
    if "\r" in status_line or "\n" in status_line:
        raise WsHandshakeError("invalid HTTP Upgrade response line ending")
    if not status_line.startswith("HTTP/1.1 101"):
        raise WsHandshakeError(
            "Expected 101 Switching Protocols, got: " + status_line
        )

    var header_lines = List[String]()
    var line_start = line_end + 2
    while line_start < response.byte_length():
        line_end = _str_find_from_local(response, "\r\n", line_start)
        if line_end < 0:
            raise WsHandshakeError("truncated HTTP Upgrade response")
        if line_end == line_start:
            break
        var line = String(
            unsafe_from_utf8=response.as_bytes()[line_start:line_end]
        )
        if "\r" in line or "\n" in line:
            raise WsHandshakeError("invalid HTTP Upgrade response line ending")
        if line.byte_length() > 0 and (
            line.unsafe_ptr().unsafe_offset(0)[] == UInt8(32)
            or line.unsafe_ptr().unsafe_offset(0)[] == UInt8(9)
        ):
            if len(header_lines) == 0:
                raise WsHandshakeError(
                    "HTTP Upgrade response starts with a folded header"
                )
            var previous_index = len(header_lines) - 1
            var unfolded = (
                header_lines[previous_index] + " " + _trim_http_ows(line)
            )
            header_lines[previous_index] = unfolded^
            line_start = line_end + 2
            continue
        header_lines.append(line^)
        line_start = line_end + 2

    var accept_header = String("")
    var selected_subprotocol = Optional[String]()
    var subprotocol_header_count = 0
    for line in header_lines:
        var colon = _str_find_local(line, ":")
        if colon <= 0:
            raise WsHandshakeError("malformed HTTP Upgrade response header")
        var field_name = String(unsafe_from_utf8=line.as_bytes()[:colon])
        if not _is_http_token(field_name):
            raise WsHandshakeError(
                "invalid HTTP Upgrade response header field name"
            )
        var name = _lower_local(field_name)
        if name == "sec-websocket-accept":
            accept_header = _trim_http_ows(
                String(unsafe_from_utf8=line.as_bytes()[colon + 1 :])
            )
        elif name == "sec-websocket-protocol":
            subprotocol_header_count += 1
            if subprotocol_header_count > 1:
                raise WsHandshakeError(
                    "server returned multiple Sec-WebSocket-Protocol headers"
                )
            var header_value = _trim_http_ows(
                String(unsafe_from_utf8=line.as_bytes()[colon + 1 :])
            )
            try:
                var selected = _parse_subprotocol_selection(header_value)
                selected_subprotocol = Optional[String](selected^)
            except:
                raise WsHandshakeError(
                    "invalid Sec-WebSocket-Protocol response"
                )

    if accept_header != expected_accept:
        raise WsHandshakeError(
            "Sec-WebSocket-Accept mismatch: got '"
            + accept_header
            + "', expected '"
            + expected_accept
            + "'"
        )

    if selected_subprotocol:
        if len(offered_subprotocols) == 0:
            raise WsHandshakeError(
                "server selected a WebSocket subprotocol when none was offered"
            )
        if not _contains_subprotocol(
            offered_subprotocols, selected_subprotocol.value()
        ):
            raise WsHandshakeError(
                "server selected an unoffered WebSocket subprotocol"
            )
    return selected_subprotocol^


def _drive_upgrade(
    control: ArcPointer[_WsControl],
    mut stream: _WsStream,
    request: String,
    expected_accept: String,
    offered_subprotocols: List[String],
    deadline_ns: Int64,
) raises -> Optional[String]:
    var request_bytes = List[UInt8](request.as_bytes())
    var offset = 0
    while offset < len(request_bytes):
        _check_connect_running(control, deadline_ns)
        var written = stream.connect_write_nonblocking(
            Span[UInt8, _](request_bytes)[offset:]
        )
        if written > 0:
            offset += written
            continue
        if written == _SSL_IO_CLOSED:
            raise NetworkError(
                "WebSocket connection closed during opening request"
            )
        var interest = (
            INTEREST_READ if written == _SSL_IO_WANT_READ else INTEREST_WRITE
        )
        _wait_connect_fd(control, stream.fd(), interest, deadline_ns)

    var response = List[UInt8](capacity=512)
    var byte = List[UInt8](capacity=1)
    byte.append(UInt8(0))
    while not _headers_complete(response):
        _check_connect_running(control, deadline_ns)
        var received = stream.connect_read_nonblocking(byte.unsafe_ptr(), 1)
        if received > 0:
            response.append(byte[0])
            continue
        if received == _SSL_IO_CLOSED:
            raise NetworkError(
                "WebSocket connection closed during Upgrade response"
            )
        var interest = (
            INTEREST_WRITE if received == _SSL_IO_WANT_WRITE else INTEREST_READ
        )
        _wait_connect_fd(control, stream.fd(), interest, deadline_ns)

    return _validate_upgrade_response(
        response, expected_accept, offered_subprotocols
    )


def _close_stream_owner(control: ArcPointer[_WsControl], mut stream: _WsStream):
    var fd = stream.fd()
    if control[].begin_owner_close(fd):
        stream.close_abortive()
        control[].finish_owner_close()


def _close_stream_gracefully_owner(
    control: ArcPointer[_WsControl], mut stream: _WsStream
):
    """Attempt protocol shutdown before owner-excluded final reclamation."""
    var fd = stream.fd()
    if fd < c_int(0):
        return
    # SSL_shutdown may wait for the peer's close_notify. The fd stays
    # published so the independent shutdown capability can interrupt it.
    stream.shutdown_graceful()
    if control[].begin_owner_close(fd):
        stream.close_abortive()
        control[].finish_owner_close()


def _opening_deadline_ns(handshake_timeout_ms: Int) raises -> Int64:
    if handshake_timeout_ms <= 0:
        raise WsHandshakeError(
            "handshake_timeout_ms must be a positive explicit timeout"
        )
    if handshake_timeout_ms > Int(Int64.MAX // 1_000_000):
        raise WsHandshakeError("handshake_timeout_ms is too large")
    var now = monotonic_now_ns()
    var budget = Int64(handshake_timeout_ms) * 1_000_000
    if now > Int64.MAX - budget:
        raise WsHandshakeError("handshake deadline overflows Int64")
    return now + budget


def _connect_with_control(
    url: String,
    config: TlsConfig,
    extra_headers: List[String],
    subprotocols: List[String],
    deadline_ns: Int64,
    control: ArcPointer[_WsControl],
) raises -> WsClient:
    """Drive DNS, TCP, TLS, and Upgrade under one cancellation authority."""
    _check_connect_running(control, deadline_ns)
    var http_url = _ws_url_to_http(url)
    var parsed = Url.parse(http_url)
    var key = _generate_ws_key()
    var expected_accept = _compute_accept(key)
    var subprotocol_offer = _client_subprotocol_offer(
        extra_headers, subprotocols
    )
    var tls_config = config.copy()
    if parsed.is_tls() and len(tls_config.alpn) == 0:
        tls_config.alpn = ["http/1.1"]

    var host_header = parsed.host
    if (parsed.scheme == "http" and parsed.port != 80) or (
        parsed.scheme == "https" and parsed.port != 443
    ):
        host_header = host_header + ":" + String(Int(parsed.port))

    var request = (
        "GET "
        + parsed.request_target()
        + " HTTP/1.1\r\n"
        + "Host: "
        + host_header
        + "\r\n"
        + "Upgrade: websocket\r\n"
        + "Connection: Upgrade\r\n"
        + "Sec-WebSocket-Key: "
        + key
        + "\r\n"
        + "Sec-WebSocket-Version: 13\r\n"
    )
    if subprotocol_offer.byte_length() > 0:
        request += "Sec-WebSocket-Protocol: " + subprotocol_offer + "\r\n"
    for i in range(len(extra_headers)):
        if "\r" in extra_headers[i] or "\n" in extra_headers[i]:
            raise WsHandshakeError(
                "extra header lines must not contain CR or LF"
            )
        request += extra_headers[i] + "\r\n"
    request += "\r\n"

    var addresses = _resolve_connect_host(control, parsed.host, deadline_ns)
    if len(addresses) == 0:
        raise DnsError("DNS resolution returned no results for: " + parsed.host)

    var connected = Optional[TcpStream]()
    var last_error = String("")
    for i in range(len(addresses)):
        try:
            connected = Optional[TcpStream](
                _connect_tcp_candidate(
                    control,
                    SocketAddr(addresses[i], parsed.port),
                    deadline_ns,
                )
            )
            break
        except error:
            if control[].is_stopping():
                raise _control_error(control)
            if monotonic_now_ns() >= deadline_ns:
                _expire_handshake(control)
            last_error = String(error)
    if not connected:
        _check_connect_running(control, deadline_ns)
        raise NetworkError(
            "all addresses failed for " + parsed.host + ": " + last_error
        )

    var tcp = connected.take()
    var stream: _WsStream
    if parsed.is_tls():
        var tls = _establish_tls(
            control,
            parsed.host,
            tls_config,
            deadline_ns,
            tcp^,
        )
        stream = _WsStream(tls^)
    else:
        stream = _WsStream(tcp^)

    var negotiated_subprotocol: Optional[String]
    try:
        negotiated_subprotocol = _drive_upgrade(
            control,
            stream,
            request,
            expected_accept,
            subprotocols,
            deadline_ns,
        )
        stream.set_connect_nonblocking(False)
        _check_connect_running(control, deadline_ns)
        control[].reactor.unregister(stream.fd())
        if not control[].claim_publication():
            _close_stream_owner(control, stream)
            raise _control_error(control)
    except error:
        _unregister_connect_fd(control, stream.fd())
        _close_stream_owner(control, stream)
        if control[].is_stopping():
            raise _control_error(control)
        raise error^

    return WsClient(stream^, key^, control, negotiated_subprotocol^)


struct WsConnectAttempt(Movable):
    """Linear opening attempt whose shutdown handle exists before dialing."""

    var _url: String
    var _config: TlsConfig
    var _extra_headers: List[String]
    var _subprotocols: List[String]
    var _deadline_ns: Int64
    var _control: ArcPointer[_WsControl]
    var _shutdown_taken: Bool

    def __init__(
        out self,
        url: String,
        config: TlsConfig,
        extra_headers: List[String],
        subprotocols: List[String],
        deadline_ns: Int64,
        control: ArcPointer[_WsControl],
    ):
        self._url = url
        self._config = config.copy()
        self._extra_headers = extra_headers.copy()
        self._subprotocols = subprotocols.copy()
        self._deadline_ns = deadline_ns
        self._control = control
        self._shutdown_taken = False

    def __deinit__(deinit self):
        self._control[].stop("WebSocket connect attempt abandoned")

    def take_shutdown(mut self) raises -> WsShutdown:
        """Take the independent shutdown capability exactly once."""
        if self._shutdown_taken:
            raise Error("WsConnectAttempt shutdown already taken")
        self._shutdown_taken = True
        return WsShutdown(self._control)

    def connect(deinit self) raises -> WsClient:
        """Consume this attempt and publish only a fully upgraded client."""
        try:
            return _connect_with_control(
                self._url,
                self._config,
                self._extra_headers,
                self._subprotocols,
                self._deadline_ns,
                self._control,
            )
        except error:
            var message = String(error)
            self._control[].stop(message)
            raise error^


struct WsClient(Movable):
    """A WebSocket client connection established via HTTP Upgrade.

    Handles the opening handshake, frame encoding/decoding, masking
    (client→server frames MUST be masked per RFC 6455 §5.3), and
    automatic PONG replies to PING frames.

    This type is ``Movable`` but not ``Copyable``. It supports the context
    manager protocol (``__enter__`` / ``__exit__``) for use with ``with``.

    Fields:
        _stream: Underlying transport (TLS or TCP).
        _key: The ``Sec-WebSocket-Key`` used for this connection.

    Example:
        ```mojo
        with WsClient.connect("wss://echo.websocket.events") as ws:
            ws.send_text("hello")
            var msg = ws.recv_message(max_message_bytes=65536)
            print(msg.as_text())
        ```
    """

    var _stream: _WsStream
    var _key: String
    var _control: ArcPointer[_WsControl]
    var _negotiated_subprotocol: Optional[String]
    var _read_buffer: List[UInt8]
    var _fragment_open: Bool
    var _fragment_bytes: Int

    def __init__(
        out self,
        var stream: _WsStream,
        key: String,
        control: ArcPointer[_WsControl],
        var negotiated_subprotocol: Optional[String] = None,
    ):
        self._stream = stream^
        self._key = key
        self._control = control
        self._negotiated_subprotocol = negotiated_subprotocol^
        self._read_buffer = List[UInt8](capacity=4096)
        self._fragment_open = False
        self._fragment_bytes = 0

    def __deinit__(deinit self):
        _close_stream_owner(self._control, self._stream)

    def split(deinit self, max_message_bytes: Int) raises -> WsDuplex:
        """Split an established connection into two I/O halves and shutdown.

        The receiving application thread is the sole owner of the non-blocking
        socket/TLS state machine. The sending thread hands complete encoded
        frames to that loop and waits for publication. ``WsShutdown`` can be
        retained by teardown code; calling it interrupts the socket and wakes a
        receiver blocked in ``recv``.

        The receiver must be actively driving ``recv`` or ``recv_message``
        while sends are in flight. ``max_message_bytes`` is a required,
        positive cap on each complete inbound message, including fragmented
        totals. No internal thread is created.
        """
        _ = self._key^
        _ = self._negotiated_subprotocol^
        return _split_stream(
            self._stream^,
            self._control,
            max_message_bytes,
            mask_outbound=True,
            expect_masked_inbound=False,
        )

    def negotiated_subprotocol(self) -> Optional[String]:
        """Return the server-selected protocol, if negotiation occurred."""
        return self._negotiated_subprotocol.copy()

    # ── Factory ───────────────────────────────────────────────────────────────

    @staticmethod
    def connect(
        url: String,
        extra_headers: List[String] = [],
        subprotocols: List[String] = [],
    ) raises -> WsClient:
        """Connect to a WebSocket server using default TLS configuration.

        Equivalent to ``WsClient.connect(url, TlsConfig())``.

        Args:
            url: WebSocket URL (``ws://`` or ``wss://``).
            extra_headers: Additional HTTP header lines. Protocol offers must
                use ``subprotocols`` instead.
            subprotocols: Ordered protocol tokens to offer. Any server
                selection must be one of these values.

        Returns:
            A ``WsClient`` with the handshake complete.

        Raises:
            NetworkError: If the TCP/TLS connection fails.
            WsHandshakeError: If the server's Upgrade response is invalid.
        """
        var attempt = WsClient.connect_attempt(
            url,
            _LEGACY_HANDSHAKE_TIMEOUT_MS,
            extra_headers=extra_headers,
            subprotocols=subprotocols,
        )
        return attempt^.connect()

    @staticmethod
    def connect(
        url: String,
        config: TlsConfig,
        extra_headers: List[String] = [],
        subprotocols: List[String] = [],
    ) raises -> WsClient:
        """Connect to a WebSocket server with custom TLS configuration.

        For ``wss://`` URLs, wraps the connection in TLS using ``config``.

        Args:
            url: WebSocket URL (``ws://`` or ``wss://``).
            config: TLS configuration (only used for ``wss://``).
            extra_headers: Additional HTTP header lines. Protocol offers must
                use ``subprotocols`` instead.
            subprotocols: Ordered protocol tokens to offer. Any server
                selection must be one of these values.

        Returns:
            A ``WsClient`` with the handshake complete.

        Raises:
            NetworkError: If the TCP/TLS connection fails.
            WsHandshakeError: If the server's Upgrade response is invalid or
                              ``Sec-WebSocket-Accept`` does not match.
        """
        var attempt = WsClient.connect_attempt(
            url,
            config,
            _LEGACY_HANDSHAKE_TIMEOUT_MS,
            extra_headers=extra_headers,
            subprotocols=subprotocols,
        )
        return attempt^.connect()

    @staticmethod
    def connect_attempt(
        url: String,
        handshake_timeout_ms: Int,
        extra_headers: List[String] = [],
        subprotocols: List[String] = [],
    ) raises -> WsConnectAttempt:
        """Create a cancellable attempt using default TLS configuration.

        ``handshake_timeout_ms`` is required, positive, and covers one
        absolute DNS-through-Upgrade interval. No network operation starts
        until :meth:`WsConnectAttempt.connect` is called.

        ``subprotocols`` is a typed, token-validated offer; supplying the
        corresponding raw header through ``extra_headers`` is rejected.
        """
        var deadline_ns = _opening_deadline_ns(handshake_timeout_ms)
        _ = _client_subprotocol_offer(extra_headers, subprotocols)
        var control = ArcPointer[_WsControl](_WsControl())
        return WsConnectAttempt(
            url,
            TlsConfig(),
            extra_headers,
            subprotocols,
            deadline_ns,
            control,
        )

    @staticmethod
    def connect_attempt(
        url: String,
        config: TlsConfig,
        handshake_timeout_ms: Int,
        extra_headers: List[String] = [],
        subprotocols: List[String] = [],
    ) raises -> WsConnectAttempt:
        """Create a cancellable attempt using a custom TLS configuration.

        ``handshake_timeout_ms`` is required, positive, and covers one
        absolute DNS-through-Upgrade interval. No network operation starts
        until :meth:`WsConnectAttempt.connect` is called.

        ``subprotocols`` is a typed, token-validated offer; supplying the
        corresponding raw header through ``extra_headers`` is rejected.
        """
        var deadline_ns = _opening_deadline_ns(handshake_timeout_ms)
        _ = _client_subprotocol_offer(extra_headers, subprotocols)
        var control = ArcPointer[_WsControl](_WsControl())
        return WsConnectAttempt(
            url,
            config,
            extra_headers,
            subprotocols,
            deadline_ns,
            control,
        )

    # ── Sending ───────────────────────────────────────────────────────────────

    def send_text(self, msg: String) raises:
        """Send a UTF-8 text message (client→server, masked).

        Args:
            msg: The message string. Must be valid UTF-8.

        Raises:
            NetworkError: On I/O failure.
        """
        var frame = WsFrame.text(msg)
        var wire = _encode_client_frame(frame)
        self._stream.write_all(Span[UInt8, _](wire))

    def send_binary(self, data: List[UInt8]) raises:
        """Send a binary message (client→server, masked).

        Args:
            data: The raw binary payload.

        Raises:
            NetworkError: On I/O failure.
        """
        var frame = WsFrame.binary(data)
        var wire = _encode_client_frame(frame)
        self._stream.write_all(Span[UInt8, _](wire))

    def send_frame(self, frame: WsFrame) raises:
        """Send an already-constructed frame.

        Args:
            frame: The frame to send (masked automatically).

        Raises:
            NetworkError: On I/O failure.
        """
        var wire = _encode_client_frame(frame)
        self._stream.write_all(Span[UInt8, _](wire))

    # ── Receiving ─────────────────────────────────────────────────────────────

    def recv(mut self, max_message_bytes: Int) raises -> WsFrame:
        """Receive the next data frame, handling PING transparently.

        Automatically replies to PING frames with a PONG and continues
        reading. CLOSE frames are returned to the caller.

        Returns:
            The next ``WsFrame`` (TEXT, BINARY, or CLOSE).

        Raises:
            NetworkError: On I/O failure.
            WsProtocolError: On protocol violation.
            Error: On truncated frame data.
        """
        while True:
            var frame = self._recv_one(max_message_bytes)
            if frame.opcode == WsOpcode.PING:
                # RFC 6455 §5.5.3: respond with PONG carrying same payload
                var pong = WsFrame.pong(frame.payload)
                var wire = _encode_client_frame(pong)
                self._stream.write_all(Span[UInt8, _](wire))
                continue
            return frame^

    def _reject_inbound(mut self, code: UInt16, message: String) raises:
        try:
            var close = WsFrame.close(code, message)
            var wire = _encode_client_frame(close)
            self._stream.write_all(Span[UInt8, _](wire))
        except:
            pass
        _close_stream_owner(self._control, self._stream)
        raise WsProtocolError(message)

    def _validate_inbound_header(
        mut self, header: _WsFrameHeader, max_message_bytes: Int
    ) raises:
        if header.masked:
            self._reject_inbound(
                WsCloseCode.PROTOCOL_ERROR, "server frame must not be masked"
            )
        if header.opcode == WsOpcode.CONTINUATION:
            if not self._fragment_open:
                self._reject_inbound(
                    WsCloseCode.PROTOCOL_ERROR,
                    "continuation frame without an open message",
                )
            if header.payload_length > max_message_bytes - self._fragment_bytes:
                self._reject_inbound(
                    WsCloseCode.MESSAGE_TOO_BIG, "message_too_big"
                )
            return
        if header.opcode == WsOpcode.TEXT or header.opcode == WsOpcode.BINARY:
            if self._fragment_open:
                self._reject_inbound(
                    WsCloseCode.PROTOCOL_ERROR,
                    "new data frame before fragmented message completion",
                )
            if header.payload_length > max_message_bytes:
                self._reject_inbound(
                    WsCloseCode.MESSAGE_TOO_BIG, "message_too_big"
                )
            return
        if (
            header.opcode != WsOpcode.CLOSE
            and header.opcode != WsOpcode.PING
            and header.opcode != WsOpcode.PONG
        ):
            self._reject_inbound(
                WsCloseCode.PROTOCOL_ERROR, "unknown WebSocket opcode"
            )

    def _record_inbound_fragment(mut self, frame: WsFrame):
        if frame.opcode == WsOpcode.CONTINUATION:
            self._fragment_bytes += len(frame.payload)
            if frame.fin:
                self._fragment_open = False
                self._fragment_bytes = 0
            return
        if (
            frame.opcode == WsOpcode.TEXT or frame.opcode == WsOpcode.BINARY
        ) and not frame.fin:
            self._fragment_open = True
            self._fragment_bytes = len(frame.payload)

    def _recv_one(mut self, max_message_bytes: Int) raises -> WsFrame:
        """Read raw bytes from the stream and decode one frame."""
        if max_message_bytes <= 0:
            raise Error("WebSocket max_message_bytes must be positive")
        var tmp = List[UInt8](capacity=4096)
        tmp.resize(4096, 0)

        while True:
            var inspected = Optional[_WsFrameHeader]()
            try:
                inspected = _inspect_frame_header(
                    Span[UInt8, _](self._read_buffer)
                )
            except error:
                self._reject_inbound(WsCloseCode.PROTOCOL_ERROR, String(error))
            var needed = 14 - len(self._read_buffer)
            if inspected:
                var header = inspected.value().copy()
                self._validate_inbound_header(header, max_message_bytes)
                var total = header.header_length + header.payload_length
                if len(self._read_buffer) >= total:
                    var result = WsFrame.decode_one(
                        Span[UInt8, _](self._read_buffer)
                    )
                    var consumed = result.consumed
                    var frame = result^.take_frame()
                    var remainder = List[UInt8](
                        capacity=len(self._read_buffer) - consumed
                    )
                    for index in range(consumed, len(self._read_buffer)):
                        remainder.append(self._read_buffer[index])
                    self._read_buffer = remainder^
                    self._record_inbound_fragment(frame)
                    return frame^
                needed = total - len(self._read_buffer)
            if needed > len(tmp):
                needed = len(tmp)
            if needed <= 0:
                needed = 1
            var count = self._stream.read(tmp.unsafe_ptr(), needed)
            if count == 0:
                raise NetworkError("WebSocket connection closed unexpectedly")
            for index in range(count):
                self._read_buffer.append(tmp[index])

    def recv_message(mut self, max_message_bytes: Int) raises -> WsMessage:
        """Receive the next complete message as a ``WsMessage``.

        A higher-level alternative to ``recv()`` that returns a
        ``WsMessage`` (Text or Binary) instead of a raw ``WsFrame``.
        PING frames are handled transparently (PONG sent automatically).
        CLOSE frames raise a ``NetworkError``.

        Returns:
            A ``WsMessage`` with ``is_text=True`` for text frames and
            ``is_text=False`` for binary frames.

        Raises:
            NetworkError: If a CLOSE frame is received or I/O fails.
            WsProtocolError: On protocol violation.

        Example:
            ```mojo
            var msg = ws.recv_message(max_message_bytes=65536)
            if msg.is_text:
                print(msg.as_text())
            ```
        """
        var frame = self.recv(max_message_bytes)
        if frame.opcode == WsOpcode.CLOSE:
            raise NetworkError("WebSocket CLOSE received")
        if frame.opcode != WsOpcode.TEXT and frame.opcode != WsOpcode.BINARY:
            raise WsProtocolError("unexpected frame while receiving a message")
        var opcode = frame.opcode
        var message_complete = frame.fin
        var payload = frame.payload.copy()
        while not message_complete:
            frame = self.recv(max_message_bytes)
            if frame.opcode == WsOpcode.PONG:
                continue
            if frame.opcode == WsOpcode.CLOSE:
                raise NetworkError("WebSocket CLOSE received")
            if frame.opcode != WsOpcode.CONTINUATION:
                raise WsProtocolError("fragmented message interrupted")
            message_complete = frame.fin
            for byte in frame.payload:
                payload.append(byte)
        if opcode == WsOpcode.BINARY:
            return WsMessage(payload^)
        var complete = WsFrame(opcode=WsOpcode.TEXT, payload=payload^)
        return WsMessage(complete.text_payload())

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(var self) -> WsClient:
        """Transfer ownership of ``self`` into the ``with`` block.

        Returns:
            This ``WsClient`` (moved).
        """
        return self^

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(mut self):
        """Send a CLOSE frame and close the underlying transport.

        Idempotent — safe to call multiple times.
        """
        if self._stream.fd() < c_int(0):
            return
        try:
            var close_frame = WsFrame.close()
            var wire = _encode_client_frame(close_frame)
            self._stream.write_all(Span[UInt8, _](wire))
        except:
            # OpenSSL forbids SSL_shutdown after a terminal SSL I/O failure.
            _close_stream_owner(self._control, self._stream)
            return
        _close_stream_gracefully_owner(self._control, self._stream)
