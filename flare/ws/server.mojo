"""WebSocket server: upgrades HTTP connections to WebSocket (RFC 6455).

Server-to-client frames MUST NOT be masked (RFC 6455 §5.3).
Client-to-server frames MUST be masked; ``WsConnection.recv`` un-masks
them automatically.

The upgrade handshake (§4.2):
    1. Accept TCP connection.
    2. Read the HTTP GET request and locate ``Sec-WebSocket-Key``.
    3. Compute ``Sec-WebSocket-Accept = base64(SHA-1(key + GUID))``.
    4. Send ``101 Switching Protocols``.
    5. Hand off to ``WsConnection``.
"""

from std.builtin.debug_assert import debug_assert
from std.atomic import Atomic, Ordering
from std.ffi import ErrNo, OwnedDLHandle, c_int, get_errno
from std.memory import ArcPointer, Pointer, UnsafePointer
from std.memory.alloc import unsafe_alloc

from ._duplex import (
    _DuplexSync,
    _split_stream,
    WsDuplex,
    WsPreadmissionRelease,
)
from ._subprotocol import (
    _is_http_token,
    _parse_subprotocol_offers,
    _select_subprotocol,
    _trim_http_ows,
    _validate_subprotocols,
)
from ._transport import _WsStream
from .frame import (
    WsFrame,
    WsOpcode,
    WsCloseCode,
    WsProtocolError,
    _WsFrameHeader,
    _inspect_frame_header,
)
from ..crypto.base64 import base64_encode as _b64_encode_srv
from ..http.response import Status
from ..tcp import TcpListener, TcpStream
from ..net import SocketAddr, NetworkError, _find_flare_lib
from ..net._libc import INVALID_FD, SHUT_RDWR, _shutdown
from ..runtime._thread import ThreadHandle, _OpaquePtr
from ..runtime.event import Event, INTEREST_READ
from ..runtime.reactor import Reactor
from ..runtime.reuseport import bind_reuseport
from ..utils.dylib import dl_sym

# RFC 6455 §1.3 magic GUID
comptime _WS_GUID: String = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
comptime _SHA1_LEN: Int = 20
comptime _WS_LISTENER_TOKEN: UInt64 = 1
comptime _WS_STOP_POLL_MS: Int = 100
comptime _WS_ECONNABORTED_LINUX: Int = 103
comptime _WS_ECONNABORTED_MACOS: Int = 53


# ── SHA-1 helper (same approach as ws/client.mojo) ───────────────────────────


def _do_sha1_srv(
    read lib: OwnedDLHandle, data_bytes: Span[UInt8, _]
) raises -> List[UInt8]:
    """Invoke the SHA-1 C function with ``lib`` borrowed.

    Doing both the symbol lookup and the call inside the borrow keeps
    ``lib`` mapped across the entire FFI surface — matches the
    canonical idiom from ``flare.http.encoding._do_compress`` and
    avoids the ASAP-destruction window where the cached function
    pointer would dangle after the lookup returns. See the long
    discussion in ``flare/http/encoding.mojo``.

    Args:
        lib: Borrowed handle to ``libflare_tls`` (keeps it mapped).
        data_bytes: Input bytes to hash.

    Returns:
        20-byte SHA-1 digest as ``List[UInt8]``.
    """
    var fn_sha1 = dl_sym[def(Int, Int, Int) thin abi("C") -> Int](lib, "SHA1")
    var digest = List[UInt8](capacity=_SHA1_LEN)
    digest.resize(_SHA1_LEN, 0)
    _ = fn_sha1(
        Int(data_bytes.unsafe_ptr()),
        Int(len(data_bytes)),
        Int(digest.unsafe_ptr()),
    )
    return digest^


def _sha1_srv(data: String) raises -> List[UInt8]:
    """Compute SHA-1 via the bundled libflare_tls shared library.

    Args:
        data: Input string to hash.

    Returns:
        20-byte SHA-1 digest.

    Raises:
        NetworkError: If the SHA-1 function cannot be loaded.
    """
    var lib = OwnedDLHandle(_find_flare_lib())
    return _do_sha1_srv(lib, data.as_bytes())


# ── Sec-WebSocket-Accept derivation uses RFC 4648 §4 base64 from
#    flare.crypto.base64 ───────────────────────────────────────────────────────
#
# The standard-alphabet base64 encoder lives in
# :mod:`flare.crypto.base64`; the local ``_b64_encode_srv`` alias
# above keeps the call sites readable while routing through the
# canonical implementation shared with the client (and the
# ``Basic`` auth helper).


def _compute_accept_srv(key: String) raises -> String:
    """Compute ``Sec-WebSocket-Accept`` for ``key``.

    Args:
        key: The ``Sec-WebSocket-Key`` value from the client.

    Returns:
        Base64-encoded SHA-1 of key + RFC 6455 GUID.
    """
    var combined = key + _WS_GUID
    var digest = _sha1_srv(combined)
    return _b64_encode_srv(Span[UInt8, _](digest))


# ── Handshake request reader ──────────────────────────────────────────────────


def _upgrade_headers_complete(bytes: List[UInt8]) -> Bool:
    """Return whether ``bytes`` ends at the HTTP header terminator."""
    var size = len(bytes)
    return (
        size >= 4
        and bytes[size - 4] == UInt8(13)
        and bytes[size - 3] == UInt8(10)
        and bytes[size - 2] == UInt8(13)
        and bytes[size - 1] == UInt8(10)
    )


def _lower_srv(s: String) -> String:
    """Return ASCII-lowercase of ``s``."""
    var out = String(capacity=s.byte_length())
    for i in range(s.byte_length()):
        var c = s.unsafe_ptr()[i]
        if c >= 65 and c <= 90:
            out += chr(Int(c) + 32)
        else:
            out += chr(Int(c))
    return out^


def _str_find_srv(s: String, sub: String) -> Int:
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


@fieldwise_init
struct WsUpgradeRequest(Copyable, Movable):
    """Parsed client HTTP Upgrade request observed during the handshake.

    Fields:
        method: HTTP method from the request line (empty when malformed).
        target: Request-target exactly as the client sent it, path plus
            optional query string (empty when malformed).
        key: The ``Sec-WebSocket-Key`` header value.
        header_names: Every header name in arrival order, lowercased.
        header_values: Header values parallel to ``header_names``, verbatim.
    """

    var method: String
    var target: String
    var key: String
    var header_names: List[String]
    var header_values: List[String]

    def header(self, name: String) -> Optional[String]:
        """Look up the first value for a header, case-insensitively.

        Args:
            name: Header name to look up.

        Returns:
            The first matching header value, or an empty Optional.
        """
        var wanted = _lower_srv(name)
        for i in range(len(self.header_names)):
            if self.header_names[i] == wanted:
                return Optional[String](self.header_values[i].copy())
        return Optional[String]()

    def header_or(self, name: String, default: String) -> String:
        """Look up the first value for a header, with a fallback.

        Args:
            name: Header name to look up.
            default: Value returned when the header is absent.

        Returns:
            The first matching header value, or ``default``.
        """
        var wanted = _lower_srv(name)
        for i in range(len(self.header_names)):
            if self.header_names[i] == wanted:
                return self.header_values[i].copy()
        return default.copy()


def _parse_request_line(line: String) -> Tuple[String, String]:
    """Split an HTTP request line into method and request-target.

    Lenient by design: malformed request lines yield empty strings so the
    established missing-header diagnostics stay the only upgrade failures.

    Args:
        line: The raw request line.

    Returns:
        ``(method, target)``, either component empty when absent.
    """
    var method = String("")
    var target = String("")
    var sp1 = _str_find_srv(line, " ")
    if sp1 > 0:
        method = String(unsafe_from_utf8=line.as_bytes()[:sp1])
        var rest = String(unsafe_from_utf8=line.as_bytes()[sp1 + 1 :])
        var sp2 = _str_find_srv(rest, " ")
        if sp2 > 0:
            target = String(unsafe_from_utf8=rest.as_bytes()[:sp2])
        else:
            target = rest^
    return (method^, target^)


def _parse_ws_upgrade_bytes(data: Span[UInt8, _]) raises -> WsUpgradeRequest:
    """Parse an HTTP WebSocket Upgrade request from a byte buffer.

    Identical logic to ``_read_upgrade_request`` but reads from a
    ``Span[UInt8, _]`` instead of a ``TcpStream``. Suitable for fuzz
    harnesses and unit tests that operate on raw bytes.

    Args:
        data: Raw HTTP/1.1 Upgrade request bytes.

    Returns:
        The parsed ``WsUpgradeRequest``.

    Raises:
        NetworkError: If the request is malformed or missing required headers.
    """
    var pos = 0

    def read_line(data: Span[UInt8, _], mut pos: Int) raises -> String:
        var line = String(capacity=256)
        var saw_cr = False
        while pos < len(data):
            var c = data[pos]
            pos += 1
            if c == 13:
                if saw_cr:
                    raise NetworkError("bare CR in WebSocket Upgrade headers")
                saw_cr = True
                continue
            if c == 10:
                if not saw_cr:
                    raise NetworkError("bare LF in WebSocket Upgrade headers")
                return line^
            if saw_cr:
                raise NetworkError("bare CR in WebSocket Upgrade headers")
            line += chr(Int(c))
        raise NetworkError("truncated WebSocket Upgrade header line")

    var method: String
    var target: String
    (method, target) = _parse_request_line(read_line(data, pos))

    var ws_key = String("")
    var header_names = List[String]()
    var header_values = List[String]()
    var found_upgrade = False
    var found_connection = False
    while True:
        var line = read_line(data, pos)
        if line.byte_length() == 0:
            break
        if line.unsafe_ptr().unsafe_offset(0)[] == UInt8(
            32
        ) or line.unsafe_ptr().unsafe_offset(0)[] == UInt8(9):
            raise NetworkError(
                "folded WebSocket Upgrade headers are not accepted"
            )
        var colon = _str_find_srv(line, ":")
        if colon <= 0:
            raise NetworkError("malformed WebSocket Upgrade header")
        var field_name = String(unsafe_from_utf8=line.as_bytes()[:colon])
        if not _is_http_token(field_name):
            raise NetworkError("invalid WebSocket Upgrade header field name")
        var k = _lower_srv(field_name)
        var v = _trim_http_ows(
            String(unsafe_from_utf8=line.as_bytes()[colon + 1 :])
        )
        header_names.append(k.copy())
        header_values.append(v.copy())
        if k == "sec-websocket-key":
            ws_key = v
        elif k == "upgrade" and _lower_srv(v) == "websocket":
            found_upgrade = True
        elif k == "connection" and "upgrade" in _lower_srv(v):
            found_connection = True

    if not found_upgrade or not found_connection:
        raise NetworkError(
            "WebSocket upgrade request missing Upgrade: websocket or"
            " Connection: Upgrade headers"
        )
    if ws_key.byte_length() == 0:
        raise NetworkError(
            "WebSocket upgrade request missing Sec-WebSocket-Key"
        )
    return WsUpgradeRequest(
        method=method^,
        target=target^,
        key=ws_key^,
        header_names=header_names^,
        header_values=header_values^,
    )


def _read_upgrade_request(mut stream: TcpStream) raises -> WsUpgradeRequest:
    """Read an HTTP upgrade request from a stream.

    Reads until the blank line terminating HTTP headers.

    Args:
        stream: Accepted TCP stream.

    Returns:
        The parsed ``WsUpgradeRequest``.

    Raises:
        NetworkError: If the upgrade request is malformed or missing the key.
    """
    var request = List[UInt8](capacity=512)
    var byte = List[UInt8](capacity=1)
    byte.append(UInt8(0))
    while not _upgrade_headers_complete(request):
        var count = stream.read(byte.unsafe_ptr(), 1)
        if count == 0:
            raise NetworkError("truncated WebSocket Upgrade headers")
        request.append(byte[0])
    return _parse_ws_upgrade_bytes(Span[UInt8, _](request))


def _offered_subprotocols(request: WsUpgradeRequest) raises -> List[String]:
    """Parse all protocol offers from an Upgrade request in arrival order."""
    var offered = List[String]()
    var header_seen = False
    for index in range(len(request.header_names)):
        if request.header_names[index] != "sec-websocket-protocol":
            continue
        header_seen = True
        var field = _parse_subprotocol_offers(request.header_values[index])
        for protocol in field:
            offered.append(protocol)
    if header_seen and len(offered) == 0:
        raise Error("WebSocket subprotocol offer contains no protocol token")
    _validate_subprotocols(offered)
    return offered^


def _negotiate_subprotocol(
    request: WsUpgradeRequest, supported: List[String]
) raises -> Optional[String]:
    """Choose the first server-preferred protocol offered by the peer."""
    var offered = _offered_subprotocols(request)
    return _select_subprotocol(offered, supported)


def _send_upgrade_response(
    mut stream: TcpStream,
    accept: String,
    subprotocol: Optional[String] = None,
) raises:
    """Send the 101 Switching Protocols response.

    Args:
        stream: TCP stream for the client connection.
        accept: The computed ``Sec-WebSocket-Accept`` value.
    """
    var resp = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        + "Upgrade: websocket\r\n"
        + "Connection: Upgrade\r\n"
        + "Sec-WebSocket-Accept: "
        + accept
        + "\r\n"
    )
    if subprotocol:
        resp += "Sec-WebSocket-Protocol: " + subprotocol.value() + "\r\n"
    resp += "\r\n"
    var resp_bytes = resp.as_bytes()
    stream.write_all(Span[UInt8, _](resp_bytes))


# ── WsConnection ──────────────────────────────────────────────────────────────


struct WsConnection(Movable):
    """An accepted WebSocket connection (server side).

    Server-side frames MUST NOT be masked (RFC 6455 §5.3).
    Client-side frames MUST be masked; ``recv`` unmasks them automatically.

    This type is ``Movable`` but not ``Copyable``.

    Fields:
        _stream: The underlying TCP stream.
        _peer: The remote socket address.
        _upgrade: The parsed HTTP Upgrade request that opened this connection.

    Example:
        ```mojo
        def on_connect(conn: WsConnection) raises:
            var frame = conn.recv(max_message_bytes=65536)
            conn.send_text(frame.text_payload()) # echo back

        var srv = WsServer.bind(SocketAddr.localhost(9001))
        srv.serve(on_connect)
        ```
    """

    var _stream: TcpStream
    var _peer: SocketAddr
    var _upgrade: WsUpgradeRequest
    var _negotiated_subprotocol: Optional[String]
    var _preadmission_release: Optional[WsPreadmissionRelease]
    var _read_buffer: List[UInt8]
    var _fragment_open: Bool
    var _fragment_bytes: Int

    def __init__(
        out self,
        var stream: TcpStream,
        peer: SocketAddr,
        var upgrade: WsUpgradeRequest,
        var negotiated_subprotocol: Optional[String] = None,
        var preadmission_release: Optional[WsPreadmissionRelease] = None,
    ):
        self._stream = stream^
        self._peer = peer
        self._upgrade = upgrade^
        self._negotiated_subprotocol = negotiated_subprotocol^
        self._preadmission_release = preadmission_release^
        self._read_buffer = List[UInt8](capacity=4096)
        self._fragment_open = False
        self._fragment_bytes = 0

    def upgrade_request(self) -> WsUpgradeRequest:
        """Return a copy of the parsed HTTP Upgrade request."""
        return self._upgrade.copy()

    def negotiated_subprotocol(self) -> Optional[String]:
        """Return the protocol selected during the opening handshake."""
        return self._negotiated_subprotocol.copy()

    def release_preadmission(mut self):
        """Release shared-listener stop ownership for an unsplit handler."""
        if not self._preadmission_release:
            return
        var release = self._preadmission_release.take()
        release.release()

    def split(deinit self, max_message_bytes: Int) raises -> WsDuplex:
        """Split an accepted connection into sender, receiver, and shutdown.

        The receiver is the sole stream owner. Application sends and automatic
        PONG/CLOSE replies share its serialized owner loop. The required
        ``max_message_bytes`` cap applies to complete inbound messages,
        including fragmented totals, before declared payload allocation.
        """
        _ = self._peer
        _ = self._upgrade^
        _ = self._negotiated_subprotocol^
        return _split_stream(
            _WsStream(self._stream^),
            max_message_bytes,
            mask_outbound=False,
            expect_masked_inbound=True,
            preadmission_release=self._preadmission_release^,
        )

    def __deinit__(deinit self):
        self._stream.close()

    def send_text(self, msg: String) raises:
        """Send a UTF-8 text message to the client.

        Server-to-client frames are NOT masked (RFC 6455 §5.3).

        Args:
            msg: The UTF-8 string to send.

        Raises:
            NetworkError: On I/O failure.
        """
        var frame = WsFrame.text(msg)
        var wire = frame.encode(mask=False)
        self._stream.write_all(Span[UInt8, _](wire))

    def send_binary(self, data: List[UInt8]) raises:
        """Send a binary message to the client.

        Server-to-client frames are NOT masked (RFC 6455 §5.3).

        Args:
            data: The raw binary payload.

        Raises:
            NetworkError: On I/O failure.
        """
        var frame = WsFrame.binary(data)
        var wire = frame.encode(mask=False)
        self._stream.write_all(Span[UInt8, _](wire))

    def send_frame(self, frame: WsFrame) raises:
        """Send an already-constructed frame (server, no masking).

        Args:
            frame: Frame to send. The ``mask`` bit is always ``False``.

        Raises:
            NetworkError: On I/O failure.
        """
        var wire = frame.encode(mask=False)
        self._stream.write_all(Span[UInt8, _](wire))

    def recv(mut self, max_message_bytes: Int) raises -> WsFrame:
        """Receive the next data frame from the client.

        Automatically replies to PING frames with an unmasked PONG and
        continues reading. Returns TEXT or BINARY frames. Client frames
        are unmasked by ``WsFrame.decode_one`` automatically.

        Returns:
            The next complete data frame (TEXT, BINARY, or CLOSE).

        Raises:
            WsProtocolError: If the client sends an unmasked frame.
            NetworkError: On I/O failure.
        """
        while True:
            var frame = self._recv_one(max_message_bytes)
            if frame.opcode == WsOpcode.PING:
                # RFC 6455 §5.5.3: respond with unmasked PONG
                var pong = WsFrame.pong(frame.payload)
                var wire = pong.encode(mask=False)
                self._stream.write_all(Span[UInt8, _](wire))
                continue
            return frame^

    def _reject_inbound(mut self, code: UInt16, message: String) raises:
        try:
            var close = WsFrame.close(code, message)
            var wire = close.encode(mask=False)
            self._stream.write_all(Span[UInt8, _](wire))
        except:
            pass
        self._stream.close()
        raise WsProtocolError(message)

    def _validate_inbound_header(
        mut self, header: _WsFrameHeader, max_message_bytes: Int
    ) raises:
        if not header.masked:
            self._reject_inbound(
                WsCloseCode.PROTOCOL_ERROR, "client frame must be masked"
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
        """Read bytes from stream and decode one complete frame."""
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

    def close(
        mut self,
        code: UInt16 = WsCloseCode.NORMAL,
        reason: String = "",
    ) raises:
        """Best-effort one-way CLOSE for the legacy unsplit connection.

        Use :meth:`split` and ``WsShutdown.close_within`` when shutdown must
        wait for the peer CLOSE under a bounded end-to-end deadline.

        Args:
            code: Close status code (see ``WsCloseCode.*``).
            reason: Optional UTF-8 reason phrase (≤123 bytes).
        """
        var close_frame = WsFrame.close(code, reason)
        var wire = close_frame.encode(mask=False)
        try:
            self._stream.write_all(Span[UInt8, _](wire))
        except:
            pass  # best-effort

    def peer_addr(self) -> SocketAddr:
        """Return the remote socket address.

        Returns:
            The client's ``SocketAddr``.
        """
        return self._peer


# ── WsServer ──────────────────────────────────────────────────────────────────


trait WsHandler(Copyable, Deinitable, Movable):
    """Stateful per-connection WebSocket handler.

    The struct-handler counterpart to the ``def(mut WsConnection)``
    callback: because :meth:`on_connection` takes ``mut self``, the
    handler can carry state (a shared registry, a counter, config) that
    persists across the connections one server instance serves. Mount via
    :meth:`WsServer.serve` (the ``[H: WsHandler]`` overload).

    The trait is protocol-agnostic -- it drives a :class:`WsConnection`,
    which is the h1 carrier today; the same handler will run over the
    WS-over-h2 carrier once that bridge lands (carrier abstraction).
    """

    def on_connection(mut self, var conn: WsConnection) raises -> None:
        """Own one established WebSocket connection through completion."""
        ...


@always_inline
def _load_ws_server_stop(mut cell: UInt8) -> Bool:
    return Atomic[DType.uint8].load[ordering=Ordering.ACQUIRE](
        Pointer(to=cell).unsafe_bitcast[Scalar[DType.uint8]]()
    ) != UInt8(0)


@always_inline
def _store_ws_server_stop(mut cell: UInt8):
    Atomic[DType.uint8].store[ordering=Ordering.RELEASE](
        Pointer(to=cell).unsafe_bitcast[Scalar[DType.uint8]](), UInt8(1)
    )


@always_inline
def _ws_accept_error_is_retryable(error: ErrNo) -> Bool:
    if (
        error == ErrNo.EAGAIN
        or error == ErrNo.EWOULDBLOCK
        or error == ErrNo.EINTR
    ):
        return True
    var code = Int(error.value)
    return code == _WS_ECONNABORTED_LINUX or code == _WS_ECONNABORTED_MACOS


struct _WsServerState(Movable):
    """Shared stop authority and worker result for one stoppable server."""

    var admission: _DuplexSync
    var reactor: Reactor
    var stop_requested: UInt8
    var handshake_fd: c_int
    var worker_error: String

    def __init__(out self, var reactor: Reactor):
        self.admission = _DuplexSync()
        self.reactor = reactor^
        self.stop_requested = UInt8(0)
        self.handshake_fd = INVALID_FD
        self.worker_error = ""

    def is_stopping(mut self) -> Bool:
        return _load_ws_server_stop(self.stop_requested)

    def request_stop(mut self):
        self.admission.lock()
        if _load_ws_server_stop(self.stop_requested):
            self.admission.unlock()
            return
        _store_ws_server_stop(self.stop_requested)
        if self.handshake_fd != INVALID_FD:
            _ = _shutdown(self.handshake_fd, SHUT_RDWR)
        self.admission.unlock()
        try:
            self.reactor.wakeup()
        except:
            pass

    def publish_handshake(mut self, fd: c_int) -> Bool:
        """Publish a worker-owned handshake fd unless stop already won."""
        self.admission.lock()
        var publish = (
            not _load_ws_server_stop(self.stop_requested)
            and self.handshake_fd == INVALID_FD
        )
        if publish:
            self.handshake_fd = fd
        self.admission.unlock()
        return publish

    def clear_handshake(mut self, fd: c_int):
        """Clear ``fd`` before its worker-owned stream can be destroyed."""
        self.admission.lock()
        if self.handshake_fd == fd:
            self.handshake_fd = INVALID_FD
        self.admission.unlock()

    def has_active_handshake(mut self) -> Bool:
        """Observe handshake publication under the admission mutex."""
        self.admission.lock()
        var active = self.handshake_fd != INVALID_FD
        self.admission.unlock()
        return active

    def claim_handler_after_handshake(mut self, fd: c_int) -> Bool:
        """Clear ``fd`` and linearize handler admission against stop."""
        self.admission.lock()
        var owns_handshake = self.handshake_fd == fd
        if owns_handshake:
            self.handshake_fd = INVALID_FD
        var admitted = owns_handshake and not _load_ws_server_stop(
            self.stop_requested
        )
        self.admission.unlock()
        return admitted

    def record_worker_error(mut self, message: String):
        """Record the worker's first fatal loop failure."""
        self.admission.lock()
        if self.worker_error.byte_length() == 0:
            self.worker_error = message
        self.admission.unlock()

    def raise_worker_error(mut self) raises:
        """Surface a fatal poll or accept failure after the join barrier."""
        self.admission.lock()
        var message = self.worker_error.copy()
        self.admission.unlock()
        if message.byte_length() > 0:
            raise Error("WebSocket server worker failed: " + message)


struct WsServerStop(Movable):
    """Independent, idempotent stop capability for a stoppable server."""

    var _state: ArcPointer[_WsServerState]

    def __init__(out self, state: ArcPointer[_WsServerState]):
        self._state = state

    def stop(mut self):
        """Fence new connections and wake the server worker.

        A connection already admitted to ``handler`` is allowed to finish.
        Calling ``stop`` more than once is harmless.
        """
        self._state[].request_stop()


@explicit_destroy(
    "WsServerRuntime must be consumed with join() or stop_and_join()"
)
struct WsServerRuntime(Deinitable where False, Movable):
    """Linear owner of a stoppable WebSocket server worker."""

    var _state: ArcPointer[_WsServerState]
    var _thread: ThreadHandle
    var _stop_taken: Bool

    def __init__(
        out self,
        state: ArcPointer[_WsServerState],
        var thread: ThreadHandle,
    ):
        self._state = state
        self._thread = thread^
        self._stop_taken = False

    def take_stop(mut self) raises -> WsServerStop:
        """Take the independent stop capability exactly once.

        :returns: A stop handle that may be used from another thread.
        :raises Error: If the stop capability was already taken.
        """
        if self._stop_taken:
            raise Error("WsServerRuntime stop already taken")
        self._stop_taken = True
        return WsServerStop(self._state)

    def join(deinit self) raises:
        """Join the worker and surface a fatal loop failure.

        Per-connection upgrade and handler errors stay isolated to their
        connection. A fatal reactor or accept-loop error is raised after the
        thread has acknowledged exit.
        """
        self._thread.join()
        self._state[].raise_worker_error()

    def stop_and_join(deinit self) raises:
        """Request stop, drain any active handler, and join the worker."""
        self._state[].request_stop()
        self._thread.join()
        self._state[].raise_worker_error()


@fieldwise_init
struct _WsThinHandler(Copyable, Movable, WsHandler):
    """Adapt the compatibility thin callback to :trait:`WsHandler`."""

    var handler: def(mut WsConnection) raises thin -> None

    def on_connection(mut self, var conn: WsConnection) raises:
        self.handler(conn)


struct WsServer(Movable):
    """A WebSocket server that upgrades incoming HTTP connections.

    Accepts TCP connections, performs the HTTP Upgrade handshake, and
    calls ``handler`` once per established WebSocket connection.

    This type is ``Movable`` but not ``Copyable``.

    Fields:
        _listener: The bound TCP listener.
        _subprotocols: Supported protocols in server preference order.

    Example:
        ```mojo
        def handle(conn: WsConnection) raises:
            while True:
                var frame = conn.recv(max_message_bytes=65536)
                if frame.opcode == WsOpcode.CLOSE:
                    break
                conn.send_text(frame.text_payload())

        var srv = WsServer.bind(SocketAddr.localhost(9001))
        srv.serve(handle)
        ```
    """

    var _listener: TcpListener
    var _subprotocols: List[String]

    def __init__(
        out self,
        var listener: TcpListener,
        subprotocols: List[String] = [],
    ) raises:
        _validate_subprotocols(subprotocols)
        self._listener = listener^
        self._subprotocols = subprotocols.copy()

    def __deinit__(deinit self):
        self._listener.close()

    @staticmethod
    def bind(
        addr: SocketAddr, subprotocols: List[String] = []
    ) raises -> WsServer:
        """Bind a WebSocket server on ``addr``.

        Args:
            addr: Local address to accept connections on.
            subprotocols: Supported protocol tokens in server preference
                order. The first supported value offered by a client is
                selected.

        Returns:
            A ``WsServer`` ready to call ``serve()``.

        Raises:
            AddressInUse: If the port is already bound.
            NetworkError: For any other OS error.
        """
        _validate_subprotocols(subprotocols)
        var listener = TcpListener.bind(addr)
        return WsServer(listener^, subprotocols)

    def serve(self, handler: def(mut WsConnection) raises thin -> None) raises:
        """Accept WebSocket connections in a single-threaded loop.

        For each accepted TCP connection:
            1. Read the HTTP Upgrade request.
            2. Compute ``Sec-WebSocket-Accept``.
            3. Send ``101 Switching Protocols``.
            4. Call ``handler(conn)``.

        Upgrade errors for individual connections are silently
        skipped; only fatal accept-loop errors propagate.
        For the multi-worker variant (``num_workers >= 2``), see
        :meth:`serve_multicore`.

        Args:
            handler: Callback invoked once per successfully upgraded
                connection.

        Raises:
            NetworkError: On fatal accept-loop errors.
        """
        while True:
            var stream = self._listener.accept()
            var peer = stream.peer_addr()
            _handle_ws_connection(stream^, peer, handler, self._subprotocols)

    def serve(
        mut self,
        handler: def(mut WsConnection) raises thin -> None,
        num_workers: Int,
    ) raises:
        """Accept WebSocket connections across ``num_workers`` threads.

        ``num_workers <= 1`` falls back to the single-threaded
        :meth:`serve` shape (one worker on the current thread).
        ``num_workers >= 2`` binds ``num_workers`` ``SO_REUSEPORT``
        listeners on the same port (kernel-level load balancing
        across worker threads, matching the
        :class:`flare.http.HttpServer` multi-worker shape) and
        spawns one pthread per worker. Each worker runs its own
        single-threaded accept loop, so the per-connection
        upgrade + handler dispatch is unchanged.

        The original :attr:`_listener` (whose port the
        ``SO_REUSEPORT`` listeners bind to) is closed so its
        backlog doesn't accept connections that would never be
        served. Workers are joined before this method returns,
        which today means it never returns: the workers run
        forever (no drain machinery yet). Use ``Ctrl-C`` /
        ``kill`` to terminate.

        Args:
            handler: Per-connection callback (same shape as the
                single-threaded variant). Function pointers are
                trivially copyable so the same value is shared
                across all workers without per-worker context
                packaging.
            num_workers: Worker count. ``<= 0`` is coerced to 1.
                Values > 256 are rejected.

        Raises:
            NetworkError: On listener bind failure for any worker.
            Error: On ``pthread_create`` failure when
                ``num_workers >= 2``.
        """
        if num_workers <= 1:
            self.serve(handler)
            return
        if num_workers > 256:
            raise Error("WsServer.serve: num_workers must be <= 256")
        var addr = self._listener.local_addr()
        # Close the original listener so its backlog doesn't
        # silently swallow connections we never serve. The
        # SO_REUSEPORT listeners below take over the port.
        self._listener.close()
        _ws_serve_multicore(addr, handler, num_workers, self._subprotocols)

    def serve[H: WsHandler](mut self, var handler: H) raises:
        """Accept WebSocket connections, dispatching each to a stateful
        :trait:`WsHandler` struct.

        The struct-handler variant of :meth:`serve`: one ``handler``
        instance serves every connection via ``mut self``, so it can
        accumulate state (connection count, a shared room registry, etc.)
        across connections. Single-threaded; a multi-worker struct-handler
        path (per-worker handler copies over the SO_REUSEPORT listeners)
        is a follow-up -- the ``def`` handler already has ``num_workers``.

        Upgrade errors for individual connections are logged and skipped;
        only fatal accept-loop errors propagate.
        """
        while True:
            var stream = self._listener.accept()
            var peer = stream.peer_addr()
            try:
                var conn = _upgrade_ws_connection(
                    stream^, peer, self._subprotocols
                )
                handler.on_connection(conn^)
            except e:
                print("[ws] connection error: " + String(e))

    def serve_stoppable[
        H: WsHandler
    ](deinit self, var handler: H) raises -> WsServerRuntime:
        """Move this server into a joinable background worker.

        ``WsServerStop.stop`` is an admission fence. It wakes an idle worker
        immediately and prevents another connection from reaching ``handler``.
        If handler admission already won, the worker lets that invocation
        finish before exiting, and ``join`` waits for that drain.
        Multicore serving remains a separate, non-stoppable API.

        :param handler: Stateful handler owned by the worker for its lifetime.
        :returns: A linear runtime that must be consumed by ``join`` or
            ``stop_and_join``.
        :raises Error: If the worker thread cannot be spawned.
        :raises NetworkError: If the listener cannot be registered with the
            worker reactor.
        """
        return _ws_serve_stoppable(
            self._listener^,
            self._subprotocols^,
            handler^,
        )

    def serve_stoppable(
        deinit self,
        handler: def(mut WsConnection) raises thin -> None,
    ) raises -> WsServerRuntime:
        """Move this server into a stoppable worker using a thin callback.

        :param handler: Thin per-connection callback.
        :returns: A linear stoppable runtime.
        """
        var adapted = _WsThinHandler(handler)
        return _ws_serve_stoppable(
            self._listener^,
            self._subprotocols^,
            adapted^,
        )

    def local_addr(self) -> SocketAddr:
        """Return the local address the server is bound to.

        Returns:
            The bound ``SocketAddr``.
        """
        return self._listener.local_addr()

    def close(mut self):
        """Stop accepting connections. Idempotent."""
        self._listener.close()


@fieldwise_init
struct _WsUpgradeResult(Movable):
    """Successful opening-handshake data while the stream stays borrowed."""

    var request: WsUpgradeRequest
    var subprotocol: Optional[String]

    def into_connection(
        deinit self, var stream: TcpStream, peer: SocketAddr
    ) -> WsConnection:
        """Move this result and its stream into a server connection."""
        return WsConnection(
            stream^,
            peer,
            self.request^,
            self.subprotocol^,
        )


def _send_bad_upgrade_response(mut stream: TcpStream):
    """Best-effort HTTP rejection before any WebSocket response is sent."""
    var response = (
        "HTTP/1.1 400 Bad Request\r\n"
        + "Connection: close\r\n"
        + "Content-Length: 0\r\n"
        + "\r\n"
    )
    try:
        stream.write_all(Span[UInt8, _](response.as_bytes()))
    except:
        pass


def _perform_ws_upgrade(
    mut stream: TcpStream,
    subprotocols: List[String] = [],
) raises -> _WsUpgradeResult:
    """Complete the shared handshake while leaving stream ownership outside."""
    var request: WsUpgradeRequest
    try:
        request = _read_upgrade_request(stream)
    except error:
        _send_bad_upgrade_response(stream)
        raise error^

    var subprotocol: Optional[String]
    try:
        subprotocol = _negotiate_subprotocol(request, subprotocols)
    except error:
        _send_bad_upgrade_response(stream)
        raise error^

    var accept = _compute_accept_srv(request.key)
    _send_upgrade_response(stream, accept, subprotocol)
    return _WsUpgradeResult(request^, subprotocol^)


def _upgrade_ws_connection(
    var stream: TcpStream,
    peer: SocketAddr,
    subprotocols: List[String] = [],
) raises -> WsConnection:
    """Upgrade one accepted TCP stream with the shared negotiation path."""
    var result = _perform_ws_upgrade(stream, subprotocols)
    return result^.into_connection(stream^, peer)


def _handle_ws_connection(
    var stream: TcpStream,
    peer: SocketAddr,
    handler: def(mut WsConnection) raises thin -> None,
    subprotocols: List[String] = [],
):
    """Perform the WebSocket handshake and call handler.

    Upgrade errors are swallowed so the accept loop continues.
    """
    try:
        var conn = _upgrade_ws_connection(stream^, peer, subprotocols)
        handler(conn)
    except e:
        print("[ws] connection error: " + String(e))


struct _WsStoppableCtx[H: WsHandler](Movable):
    """Heap-owned listener, negotiation data, handler, and worker state."""

    var listener: TcpListener
    var subprotocols: List[String]
    var handler: Self.H
    var state: ArcPointer[_WsServerState]

    def __init__(
        out self,
        var listener: TcpListener,
        var subprotocols: List[String],
        var handler: Self.H,
        state: ArcPointer[_WsServerState],
    ):
        self.listener = listener^
        self.subprotocols = subprotocols^
        self.handler = handler^
        self.state = state


def _ws_stoppable_accept_loop[
    H: WsHandler
](mut context: _WsStoppableCtx[H]) raises:
    """Run one reactor-backed accept loop until its stop fence wins."""
    var events = List[Event]()
    while True:
        if context.state[].is_stopping():
            return

        # Reconcile periodically because Reactor wake writes may be interrupted.
        var event_count = context.state[].reactor.poll(_WS_STOP_POLL_MS, events)
        if context.state[].is_stopping():
            return

        for index in range(event_count):
            if context.state[].is_stopping():
                return

            var event = events[index]
            if event.is_wakeup() or event.token != _WS_LISTENER_TOKEN:
                continue

            if context.state[].is_stopping():
                return
            var stream: TcpStream
            try:
                stream = context.listener.accept()
            except error:
                var accept_error = get_errno()
                if context.state[].is_stopping():
                    return
                if _ws_accept_error_is_retryable(accept_error):
                    continue
                raise error^
            stream._socket.set_nonblocking(False)
            var handshake_fd = stream._socket.fd
            if not context.state[].publish_handshake(handshake_fd):
                return

            var peer = stream.peer_addr()
            var upgrade: _WsUpgradeResult
            try:
                upgrade = _perform_ws_upgrade(stream, context.subprotocols)
            except error:
                context.state[].clear_handshake(handshake_fd)
                if context.state[].is_stopping():
                    return
                print("[ws] connection error: " + String(error))
                continue

            if not context.state[].claim_handler_after_handshake(handshake_fd):
                return
            var conn = upgrade^.into_connection(stream^, peer)
            try:
                context.handler.on_connection(conn^)
            except error:
                if context.state[].is_stopping():
                    return
                print("[ws] connection error: " + String(error))


def _ws_stoppable_worker_entry[H: WsHandler](arg: _OpaquePtr) -> _OpaquePtr:
    """Run and reclaim one stoppable worker context on every exit path."""
    var context_address = Int(arg)
    debug_assert[assert_mode="safe"](
        context_address != 0,
        "_ws_stoppable_worker_entry: context pointer must be non-NULL",
    )
    var raw = UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=context_address
    )
    var context = raw.unsafe_bitcast[_WsStoppableCtx[H]]()
    try:
        _ws_stoppable_accept_loop(context[])
    except error:
        context[].state[].record_worker_error(String(error))
    context.unsafe_deinit_pointee()
    context.unsafe_free()

    var null_address = 0
    return _OpaquePtr(unsafe_from_address=null_address)


def _ws_serve_stoppable[
    H: WsHandler
](
    var listener: TcpListener,
    var subprotocols: List[String],
    var handler: H,
) raises -> WsServerRuntime:
    """Spawn a stoppable worker after registering its listener fd."""
    listener._socket.set_nonblocking(True)
    var reactor = Reactor()
    reactor.register(listener.as_raw_fd(), _WS_LISTENER_TOKEN, INTEREST_READ)
    var state = ArcPointer[_WsServerState](_WsServerState(reactor^))

    var context = unsafe_alloc[_WsStoppableCtx[H]](1)
    debug_assert[assert_mode="safe"](
        Int(context) != 0,
        "_ws_serve_stoppable: context allocation returned NULL",
    )
    context.unsafe_write(
        _WsStoppableCtx[H](
            listener^,
            subprotocols^,
            handler^,
            state,
        )
    )
    var arg = _OpaquePtr(unsafe_from_address=Int(context))
    var thread: ThreadHandle
    try:
        thread = ThreadHandle.spawn[_ws_stoppable_worker_entry[H]](arg)
    except error:
        context.unsafe_deinit_pointee()
        context.unsafe_free()
        raise error^
    return WsServerRuntime(state, thread^)


# ── Multi-worker WsServer ──────────────────────────────────────────────────


@fieldwise_init
struct _WsWorkerCtx(Movable):
    """Heap-allocated per-worker context for :func:`_ws_serve_multicore`.

    Carries a *fully-bound* per-worker ``SO_REUSEPORT`` listener
    (the parent thread does the bind so the bind itself is
    serialised across workers and there is no concurrent-bind
    race) plus a copy of the ``def`` handler function pointer.
    Mojo ``def`` function pointers are trivially copyable, so
    every worker shares the same callable with no per-worker
    closure state.
    """

    var listener: TcpListener
    var handler: def(mut WsConnection) raises thin -> None
    var subprotocols: List[String]


def _ws_worker_entry(arg: _OpaquePtr) -> _OpaquePtr:
    """``pthread`` start routine for one WebSocket worker.

    Casts ``arg`` back to a ``_WsWorkerCtx`` pointer, runs the
    standard single-threaded WsServer accept loop until either
    ``accept`` raises or the listener is closed. Errors are
    swallowed -- per-connection upgrade errors are already
    handled inside :func:`_handle_ws_connection`; the only way
    out of this loop today is a fatal ``accept`` failure (e.g.
    listener closed during shutdown).
    """
    var ctx_addr = Int(arg)
    debug_assert[assert_mode="safe"](
        ctx_addr != 0,
        "_ws_worker_entry: ctx pointer must be non-NULL",
    )
    var raw = UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=ctx_addr
    )
    var ctx_ptr = raw.unsafe_bitcast[_WsWorkerCtx]()
    try:
        while True:
            var stream = ctx_ptr[].listener.accept()
            var peer = stream.peer_addr()
            _handle_ws_connection(
                stream^,
                peer,
                ctx_ptr[].handler,
                ctx_ptr[].subprotocols,
            )
    except:
        pass
    # UnsafePointer is non-nullable; build C NULL from a runtime 0.
    var null_addr = 0
    return UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=null_addr
    )


def _ws_serve_multicore(
    addr: SocketAddr,
    handler: def(mut WsConnection) raises thin -> None,
    num_workers: Int,
    subprotocols: List[String] = [],
) raises:
    """Spawn ``num_workers`` WebSocket worker threads sharing a port.

    Each worker binds its own ``SO_REUSEPORT`` listener on the
    parent thread (so the binds are serialised, no concurrent-
    bind race), then runs an independent single-threaded accept
    loop. The kernel hashes new 4-tuples across the listener set
    so accept fairness is at the OS level, identical to the
    :class:`flare.http.HttpServer` multi-worker path.

    Workers are spawned via :class:`flare.runtime.ThreadHandle`
    and joined before this function returns. Today the workers
    never exit on their own (no graceful drain machinery for
    WebSocket); use ``Ctrl-C`` to terminate.
    """
    debug_assert[assert_mode="safe"](
        num_workers >= 2 and num_workers <= 256,
        "_ws_serve_multicore: num_workers must be in [2,256]; got ",
        num_workers,
    )
    if num_workers <= 1:
        raise Error("_ws_serve_multicore: num_workers must be >= 2")

    from std.memory import alloc

    # Heap-allocate one _WsWorkerCtx per worker via the native
    # Mojo allocator. We keep the ctx addresses in a List[Int]
    # since List[ThreadHandle] is not legal (ThreadHandle is
    # Movable-only by design -- POSIX forbids double-join, so
    # the type is non-Copyable; see flare/runtime/_thread.mojo).
    # ThreadHandles themselves live in an UnsafePointer-backed
    # array we walk by index.
    var ctx_addrs = List[Int]()
    var threads_ptr = alloc[ThreadHandle](num_workers)
    debug_assert[assert_mode="safe"](
        Int(threads_ptr) != 0,
        "_ws_serve_multicore: alloc[ThreadHandle] returned NULL",
    )

    for i in range(num_workers):
        var listener = bind_reuseport(addr)
        var ctx = _WsWorkerCtx(listener^, handler, subprotocols.copy())
        var ctx_ptr = alloc[_WsWorkerCtx](1)
        debug_assert[assert_mode="safe"](
            Int(ctx_ptr) != 0,
            "_ws_serve_multicore: alloc[_WsWorkerCtx] returned NULL on worker ",
            i,
        )
        ctx_ptr.unsafe_write(ctx^)
        var arg = ctx_ptr.unsafe_bitcast[UInt8]()
        var addr_int = Int(arg)
        ctx_addrs.append(addr_int)
        var th = ThreadHandle.spawn[_ws_worker_entry](
            UnsafePointer[UInt8, MutUntrackedOrigin](
                unsafe_from_address=addr_int
            )
        )
        (threads_ptr + i).unsafe_write(th^)

    # Workers run forever; this join blocks until each pthread
    # exits (normally never, since the per-worker listener
    # stays open). Closing the listener from another thread
    # would unblock the worker's accept call -- the intended
    # graceful-shutdown handle once WsServer grows a drain API.
    for i in range(num_workers):
        (threads_ptr + i)[].join()
    # Free per-worker contexts now the threads are joined.
    for i in range(len(ctx_addrs)):
        debug_assert[assert_mode="safe"](
            ctx_addrs[i] != 0,
            "_ws_serve_multicore: ctx_addrs[i] is null on free; i=",
            i,
        )
        var raw = UnsafePointer[UInt8, MutUntrackedOrigin](
            unsafe_from_address=ctx_addrs[i]
        )
        raw.unsafe_bitcast[_WsWorkerCtx]().unsafe_deinit_pointee()
        raw.free()
    threads_ptr.free()
