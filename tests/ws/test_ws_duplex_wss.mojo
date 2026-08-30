"""Loopback regressions for the public full-duplex WebSocket client API.

The WSS cases connect through real TLS handshakes to scripted peers. Both TLS
and plain peers decode complete RFC 6455 frames, so concurrent sender traffic
and automatic PONG traffic must remain byte-aligned on the wire.
"""

from std.atomic import Atomic, Ordering
from std.memory import UnsafePointer
from std.memory.alloc import unsafe_alloc
from std.testing import assert_equal, assert_true

from flare.net import SocketAddr
from flare.runtime._libc_time import monotonic_now_ms
from flare.runtime._thread import ThreadHandle, _OpaquePtr, current_thread_id
from flare.tcp import TcpListener, TcpStream
from flare.tls import TlsConfig
from flare.tls._server_ffi import (
    ServerCtx,
    SSL_IO_CLOSED,
    SSL_IO_FATAL,
    SSL_IO_WANT_READ,
    SSL_IO_WANT_WRITE,
    server_ssl_do_handshake,
    server_ssl_free,
    server_ssl_new_accept,
    server_ssl_read_ex,
    server_ssl_write_ex,
)
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid
from flare.ws import (
    WsClient,
    WsFrame,
    WsOpcode,
    WsReceiver,
    WsSender,
    WsShutdown,
)
from flare.ws.server import _compute_accept_srv, _parse_ws_upgrade_bytes


comptime _CA_CERTIFICATE: String = "tests/certs/ca.crt"
comptime _SERVER_CERTIFICATE: String = "tests/certs/server.crt"
comptime _SERVER_KEY: String = "tests/certs/server.key"
comptime _RECEIVER_PENDING: UInt8 = UInt8(0)
comptime _RECEIVER_READY: UInt8 = UInt8(1)
comptime _RECEIVER_FAILED: UInt8 = UInt8(2)
comptime _SENDER_PENDING: UInt8 = UInt8(0)
comptime _SENDER_WAITING: UInt8 = UInt8(1)
comptime _SENDER_SUCCEEDED: UInt8 = UInt8(2)
comptime _SENDER_FAILED: UInt8 = UInt8(3)
comptime _PRESSURE_RECEIVER_PENDING: UInt8 = UInt8(0)
comptime _PRESSURE_RECEIVER_INBOUND: UInt8 = UInt8(1)
comptime _PRESSURE_RECEIVER_VALIDATED: UInt8 = UInt8(2)
comptime _PRESSURE_RECEIVER_FAILED: UInt8 = UInt8(3)
comptime _PRESSURE_PAYLOAD_BYTES: Int = 4 * 1024 * 1024
comptime _PRESSURE_SOCKET_BUFFER_BYTES: Int = 4 * 1024
comptime _PRESSURE_DEADLINE_MS: Int = 10_000
comptime _PRESSURE_SERVER_HOLD_US: Int = 250_000
comptime _SERVER_PRESSURE_SALT: Int = 17
comptime _CLIENT_PRESSURE_SALT: Int = 83


def _null_opaque_pointer() -> _OpaquePtr:
    var null_address: Int = 0
    return _OpaquePtr(unsafe_from_address=null_address)


def _is_retry(result: Int) -> Bool:
    return result == SSL_IO_WANT_READ or result == SSL_IO_WANT_WRITE


def _make_pressure_payload(size: Int, salt: Int) -> List[UInt8]:
    var payload = List[UInt8](capacity=size)
    for index in range(size):
        payload.append(UInt8((index * 31 + salt) % 251))
    return payload^


def _validate_pressure_payload(
    payload: List[UInt8], expected_size: Int, salt: Int
) raises:
    if len(payload) != expected_size:
        raise Error(
            "pressure payload length mismatch: got "
            + String(len(payload))
            + ", expected "
            + String(expected_size)
        )
    for index in range(expected_size):
        var expected = UInt8((index * 31 + salt) % 251)
        if payload[index] != expected:
            raise Error("pressure payload mismatch at byte " + String(index))


struct _TlsWebSocketPeer(Movable):
    """Scriptable server-side TLS connection with buffered frame reads."""

    var _context: ServerCtx
    var _stream: TcpStream
    var _ssl_address: Int
    var _input: List[UInt8]

    def __init__(
        out self, listener: TcpListener, constrain_buffers: Bool = False
    ) raises:
        var stream: TcpStream = listener.accept()
        if constrain_buffers:
            stream._socket.set_send_buffer(_PRESSURE_SOCKET_BUFFER_BYTES)
            stream._socket.set_recv_buffer(_PRESSURE_SOCKET_BUFFER_BYTES)
        var context: ServerCtx = ServerCtx.new(_SERVER_CERTIFICATE, _SERVER_KEY)
        var ssl_address: Int = server_ssl_new_accept(
            context, Int(stream._socket.fd)
        )
        if ssl_address == 0:
            raise Error("failed to allocate the server TLS session")
        while True:
            var result: Int = server_ssl_do_handshake(context, ssl_address)
            if result == 0:
                break
            if result < 0:
                server_ssl_free(context, ssl_address)
                raise Error("server TLS handshake failed")
            usleep(1_000)

        self._context = context^
        self._stream = stream^
        self._ssl_address = ssl_address
        self._input = List[UInt8]()

    def __deinit__(deinit self):
        if self._ssl_address == 0:
            return
        try:
            server_ssl_free(self._context, self._ssl_address)
        except:
            pass

    def _read_more(mut self) raises:
        while True:
            var result: Int = server_ssl_read_ex(
                self._context, self._ssl_address, self._input, 4096
            )
            if result > 0:
                return
            if _is_retry(result):
                usleep(1_000)
                continue
            if result == SSL_IO_CLOSED:
                raise Error("TLS peer closed while the server was reading")
            if result == SSL_IO_FATAL:
                raise Error("fatal TLS read failure")
            raise Error("unexpected TLS read result: " + String(result))

    def _write_all(self, bytes: Span[UInt8, _]) raises:
        var offset: Int = 0
        while offset < len(bytes):
            var result: Int = server_ssl_write_ex(
                self._context, self._ssl_address, bytes, offset
            )
            if result > 0:
                offset += result
                continue
            if _is_retry(result):
                usleep(1_000)
                continue
            raise Error("TLS write failed with result: " + String(result))

    def _read_upgrade_response(mut self) raises -> String:
        while True:
            for index in range(len(self._input) - 3):
                if (
                    self._input[index] == UInt8(13)
                    and self._input[index + 1] == UInt8(10)
                    and self._input[index + 2] == UInt8(13)
                    and self._input[index + 3] == UInt8(10)
                ):
                    var request = _parse_ws_upgrade_bytes(
                        Span[UInt8, _](self._input)
                    )
                    var accept: String = _compute_accept_srv(request.key)
                    var response: String = (
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        + "Upgrade: websocket\r\n"
                        + "Connection: Upgrade\r\n"
                        + "Sec-WebSocket-Accept: "
                        + accept
                        + "\r\n\r\n"
                    )
                    self._input.clear()
                    return response^
            self._read_more()

    def accept_upgrade(mut self) raises:
        """Read the client's HTTP Upgrade and emit a valid 101 response."""
        var response = self._read_upgrade_response()
        self._write_all(response.as_bytes())

    def accept_upgrade_with_frame(mut self, frame: WsFrame) raises:
        """Emit HTTP 101 and the first frame in one TLS plaintext write."""
        var response = self._read_upgrade_response()
        var wire = frame.encode(mask=False)
        var combined = List[UInt8](capacity=response.byte_length() + len(wire))
        for byte in response.as_bytes():
            combined.append(byte)
        for byte in wire:
            combined.append(byte)
        self._write_all(Span[UInt8, _](combined))

    def recv_frame(mut self) raises -> WsFrame:
        """Read and remove one complete client frame."""
        while True:
            if len(self._input) > 0:
                try:
                    var decoded = WsFrame.decode_one(
                        Span[UInt8, _](self._input)
                    )
                    var consumed: Int = decoded.consumed
                    var frame: WsFrame = decoded^.take_frame()
                    var remainder = List[UInt8](
                        capacity=len(self._input) - consumed
                    )
                    for index in range(consumed, len(self._input)):
                        remainder.append(self._input[index])
                    self._input = remainder^
                    return frame^
                except error:
                    var message: String = String(error)
                    if (
                        "need at least" not in message
                        and "need " not in message
                        and "truncated" not in message
                    ):
                        raise error^
            self._read_more()

    def send_frame(self, frame: WsFrame) raises:
        """Send one unmasked server frame."""
        var wire: List[UInt8] = frame.encode(mask=False)
        self._write_all(Span[UInt8, _](wire))

    def send_coalesced(self, first: WsFrame, second: WsFrame) raises:
        """Send two complete frames through one plaintext write operation."""
        var first_wire: List[UInt8] = first.encode(mask=False)
        var second_wire: List[UInt8] = second.encode(mask=False)
        var combined = List[UInt8](capacity=len(first_wire) + len(second_wire))
        for byte in first_wire:
            combined.append(byte)
        for byte in second_wire:
            combined.append(byte)
        self._write_all(Span[UInt8, _](combined))


struct _PlainWebSocketPeer(Movable):
    """Scriptable plain WebSocket peer with buffered frame reads."""

    var _stream: TcpStream
    var _input: List[UInt8]

    def __init__(
        out self, listener: TcpListener, constrain_buffers: Bool = False
    ) raises:
        self._stream = listener.accept()
        if constrain_buffers:
            self._stream._socket.set_send_buffer(_PRESSURE_SOCKET_BUFFER_BYTES)
            self._stream._socket.set_recv_buffer(_PRESSURE_SOCKET_BUFFER_BYTES)
        self._input = List[UInt8]()

    def _read_more(mut self) raises:
        var scratch = List[UInt8](capacity=4096)
        scratch.resize(4096, UInt8(0))
        var received: Int = self._stream.read(
            scratch.unsafe_ptr(), len(scratch)
        )
        if received == 0:
            raise Error("plain peer closed while reading")
        for index in range(received):
            self._input.append(scratch[index])

    def accept_upgrade(mut self) raises:
        """Read the client's HTTP Upgrade and emit a valid 101 response."""
        while True:
            for index in range(len(self._input) - 3):
                if (
                    self._input[index] == UInt8(13)
                    and self._input[index + 1] == UInt8(10)
                    and self._input[index + 2] == UInt8(13)
                    and self._input[index + 3] == UInt8(10)
                ):
                    var request = _parse_ws_upgrade_bytes(
                        Span[UInt8, _](self._input)
                    )
                    var accept: String = _compute_accept_srv(request.key)
                    var response: String = (
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        + "Upgrade: websocket\r\n"
                        + "Connection: Upgrade\r\n"
                        + "Sec-WebSocket-Accept: "
                        + accept
                        + "\r\n\r\n"
                    )
                    self._stream.write_all(response.as_bytes())
                    self._input.clear()
                    return
            self._read_more()

    def recv_frame(mut self) raises -> WsFrame:
        """Read and remove one complete client frame."""
        while True:
            if len(self._input) > 0:
                try:
                    var decoded = WsFrame.decode_one(
                        Span[UInt8, _](self._input)
                    )
                    var consumed: Int = decoded.consumed
                    var frame: WsFrame = decoded^.take_frame()
                    var remainder = List[UInt8](
                        capacity=len(self._input) - consumed
                    )
                    for index in range(consumed, len(self._input)):
                        remainder.append(self._input[index])
                    self._input = remainder^
                    return frame^
                except error:
                    var message: String = String(error)
                    if (
                        "need at least" not in message
                        and "need " not in message
                        and "truncated" not in message
                    ):
                        raise error^
            self._read_more()

    def send_frame(self, frame: WsFrame) raises:
        """Send one unmasked server frame."""
        var wire: List[UInt8] = frame.encode(mask=False)
        self._stream.write_all(Span[UInt8, _](wire))


def _run_server(listener: TcpListener) raises:
    var peer = _TlsWebSocketPeer(listener)
    peer.accept_upgrade()

    var ping_payload = List[UInt8]()
    for byte in "ping-proof".as_bytes():
        ping_payload.append(byte)
    peer.send_frame(WsFrame.ping(ping_payload))

    var saw_pong: Bool = False
    var saw_sender_frame: Bool = False
    for _ in range(2):
        var frame: WsFrame = peer.recv_frame()
        if not frame.masked:
            raise Error("client frames must be masked")
        if frame.opcode == WsOpcode.PONG:
            if frame.text_payload() != "ping-proof":
                raise Error("automatic PONG payload mismatch")
            saw_pong = True
            continue
        if frame.opcode == WsOpcode.TEXT:
            if frame.text_payload() != "sender-proof":
                raise Error("sender thread payload mismatch")
            saw_sender_frame = True
            continue
        raise Error("unexpected client opcode: " + String(Int(frame.opcode)))

    if not saw_pong or not saw_sender_frame:
        raise Error("missing aligned PONG or sender frame")
    peer.send_coalesced(
        WsFrame.text("duplex-complete"),
        WsFrame.text("coalesced-followup"),
    )
    usleep(5_000_000)


def _run_terminal_server(listener: TcpListener) raises:
    """Buffer a peer CLOSE behind one application frame, then hold open."""
    var peer = _TlsWebSocketPeer(listener)
    peer.accept_upgrade()
    peer.send_coalesced(
        WsFrame.text("before-close"),
        WsFrame.close(),
    )
    usleep(5_000_000)


def _run_coalesced_upgrade_server(listener: TcpListener) raises:
    var peer = _TlsWebSocketPeer(listener)
    peer.accept_upgrade_with_frame(WsFrame.text("coalesced-upgrade-frame"))
    usleep(5_000_000)


def _run_tls_pressure_server(listener: TcpListener) raises:
    var peer = _TlsWebSocketPeer(listener, constrain_buffers=True)
    peer.accept_upgrade()
    usleep(50_000)
    var payload = _make_pressure_payload(
        _PRESSURE_PAYLOAD_BYTES, _SERVER_PRESSURE_SALT
    )
    peer.send_frame(WsFrame.binary(payload))
    usleep(_PRESSURE_SERVER_HOLD_US)
    var inbound = peer.recv_frame()
    if inbound.opcode != WsOpcode.BINARY:
        raise Error("TLS pressure peer expected one binary frame")
    _validate_pressure_payload(
        inbound.payload, _PRESSURE_PAYLOAD_BYTES, _CLIENT_PRESSURE_SALT
    )
    peer.send_frame(WsFrame.text("tls-pressure-validated"))


def _run_plain_pressure_server(listener: TcpListener) raises:
    var peer = _PlainWebSocketPeer(listener, constrain_buffers=True)
    peer.accept_upgrade()
    usleep(50_000)
    var payload = _make_pressure_payload(
        _PRESSURE_PAYLOAD_BYTES, _SERVER_PRESSURE_SALT
    )
    peer.send_frame(WsFrame.binary(payload))
    usleep(_PRESSURE_SERVER_HOLD_US)
    var inbound = peer.recv_frame()
    if inbound.opcode != WsOpcode.BINARY:
        raise Error("plain pressure peer expected one binary frame")
    _validate_pressure_payload(
        inbound.payload, _PRESSURE_PAYLOAD_BYTES, _CLIENT_PRESSURE_SALT
    )
    peer.send_frame(WsFrame.text("plain-pressure-validated"))


def _spawn_server(listener: TcpListener) -> Int:
    var process_id: Int = fork()
    if process_id == 0:
        try:
            _run_server(listener)
            exit(0)
        except:
            exit(1)
    return process_id


def _spawn_terminal_server(listener: TcpListener) -> Int:
    var process_id: Int = fork()
    if process_id == 0:
        try:
            _run_terminal_server(listener)
            exit(0)
        except:
            exit(1)
    return process_id


def _spawn_coalesced_upgrade_server(listener: TcpListener) -> Int:
    var process_id: Int = fork()
    if process_id == 0:
        try:
            _run_coalesced_upgrade_server(listener)
            exit(0)
        except:
            exit(1)
    return process_id


def _spawn_tls_pressure_server(listener: TcpListener) -> Int:
    var process_id: Int = fork()
    if process_id == 0:
        try:
            _run_tls_pressure_server(listener)
            exit(0)
        except:
            exit(1)
    return process_id


def _run_plain_server(listener: TcpListener) raises:
    """Echo one text frame and keep the peer open until client shutdown."""
    var peer = _PlainWebSocketPeer(listener)
    peer.accept_upgrade()
    var frame: WsFrame = peer.recv_frame()
    if frame.opcode != WsOpcode.TEXT:
        raise Error("plain peer expected one text frame")
    peer.send_frame(WsFrame.text(frame.text_payload()))
    usleep(5_000_000)


def _spawn_plain_server(listener: TcpListener) -> Int:
    var process_id: Int = fork()
    if process_id == 0:
        try:
            _run_plain_server(listener)
            exit(0)
        except:
            exit(1)
    return process_id


def _spawn_plain_pressure_server(listener: TcpListener) -> Int:
    var process_id: Int = fork()
    if process_id == 0:
        try:
            _run_plain_pressure_server(listener)
            exit(0)
        except:
            exit(1)
    return process_id


def _stop_server(process_id: Int):
    _ = kill(process_id, SIGKILL)
    waitpid(process_id)


def _connect(port: UInt16) raises -> WsClient:
    var config: TlsConfig = TlsConfig(ca_bundle=_CA_CERTIFICATE)
    return WsClient.connect(
        "wss://localhost:" + String(Int(port)) + "/duplex", config^
    )


def _connect_plain(port: UInt16) raises -> WsClient:
    return WsClient.connect("ws://127.0.0.1:" + String(Int(port)) + "/duplex")


struct _SenderThreadContext(Movable):
    """Move-only sender plus its pthread-visible result."""

    var sender: WsSender
    var sent: Bool
    var thread_id: UInt64
    var error_message: String

    def __init__(out self, var sender: WsSender):
        self.sender = sender^
        self.sent = False
        self.thread_id = UInt64(0)
        self.error_message = ""


def _sender_thread(argument: _OpaquePtr) -> _OpaquePtr:
    var context = argument.unsafe_bitcast[_SenderThreadContext]()
    context[].thread_id = current_thread_id()
    try:
        context[].sender.send_text("sender-proof")
        context[].sent = True
    except error:
        context[].error_message = String(error)
    return _null_opaque_pointer()


struct _WaitingSenderThreadContext(Movable):
    """Sender whose publication wait is observed across pthreads."""

    var sender: WsSender
    var state_address: Int
    var error_message: String

    def __init__(out self, var sender: WsSender, state_address: Int):
        self.sender = sender^
        self.state_address = state_address
        self.error_message = ""


def _waiting_sender_thread(argument: _OpaquePtr) -> _OpaquePtr:
    var context = argument.unsafe_bitcast[_WaitingSenderThreadContext]()
    _store_state(context[].state_address, _SENDER_WAITING)
    try:
        context[].sender.send_text("must-not-publish")
        _store_state(context[].state_address, _SENDER_SUCCEEDED)
    except error:
        context[].error_message = String(error)
        _store_state(context[].state_address, _SENDER_FAILED)
    return _null_opaque_pointer()


struct _PressureSenderThreadContext(Movable):
    """Large client frame and publication state owned by one sender thread."""

    var sender: WsSender
    var payload: List[UInt8]
    var state_address: Int
    var error_message: String

    def __init__(
        out self,
        var sender: WsSender,
        var payload: List[UInt8],
        state_address: Int,
    ):
        self.sender = sender^
        self.payload = payload^
        self.state_address = state_address
        self.error_message = ""


def _pressure_sender_thread(argument: _OpaquePtr) -> _OpaquePtr:
    var context = argument.unsafe_bitcast[_PressureSenderThreadContext]()
    _store_state(context[].state_address, _SENDER_WAITING)
    try:
        context[].sender.send_binary(context[].payload)
        _store_state(context[].state_address, _SENDER_SUCCEEDED)
    except error:
        context[].error_message = String(error)
        _store_state(context[].state_address, _SENDER_FAILED)
    return _null_opaque_pointer()


def _store_state(address: Int, state: UInt8):
    var pointer = UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=address
    ).unsafe_bitcast[Scalar[DType.uint8]]()
    Atomic[DType.uint8].store[ordering=Ordering.RELEASE](pointer, state)


def _load_state(address: Int) -> UInt8:
    var pointer = UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=address
    ).unsafe_bitcast[Scalar[DType.uint8]]()
    return Atomic[DType.uint8].load[ordering=Ordering.ACQUIRE](pointer)


struct _PressureReceiverThreadContext(Movable):
    """Large server frame, validation ack, and publication-fence evidence."""

    var receiver: WsReceiver
    var state_address: Int
    var sender_state_address: Int
    var validation_text: String
    var sender_waited_after_inbound: Bool
    var error_message: String

    def __init__(
        out self,
        var receiver: WsReceiver,
        state_address: Int,
        sender_state_address: Int,
        validation_text: String,
    ):
        self.receiver = receiver^
        self.state_address = state_address
        self.sender_state_address = sender_state_address
        self.validation_text = validation_text
        self.sender_waited_after_inbound = False
        self.error_message = ""


def _pressure_receiver_thread(argument: _OpaquePtr) -> _OpaquePtr:
    var context = argument.unsafe_bitcast[_PressureReceiverThreadContext]()
    try:
        var inbound = context[].receiver.recv()
        if inbound.opcode != WsOpcode.BINARY:
            raise Error("pressure receiver expected one binary frame")
        context[].sender_waited_after_inbound = (
            _load_state(context[].sender_state_address) == _SENDER_WAITING
        )
        _validate_pressure_payload(
            inbound.payload,
            _PRESSURE_PAYLOAD_BYTES,
            _SERVER_PRESSURE_SALT,
        )
        _store_state(context[].state_address, _PRESSURE_RECEIVER_INBOUND)

        var validation = context[].receiver.recv()
        if (
            validation.opcode != WsOpcode.TEXT
            or validation.text_payload() != context[].validation_text
        ):
            raise Error("pressure peer validation acknowledgment mismatch")
        _store_state(context[].state_address, _PRESSURE_RECEIVER_VALIDATED)
    except error:
        context[].error_message = String(error)
        _store_state(context[].state_address, _PRESSURE_RECEIVER_FAILED)
    return _null_opaque_pointer()


struct _ReceiverThreadContext(Movable):
    """Move-only receiver plus cross-thread observations."""

    var receiver: WsReceiver
    var state_address: Int
    var received_coalesced_frames: Bool
    var interrupted: Bool
    var thread_id: UInt64
    var error_message: String

    def __init__(out self, var receiver: WsReceiver, state_address: Int):
        self.receiver = receiver^
        self.state_address = state_address
        self.received_coalesced_frames = False
        self.interrupted = False
        self.thread_id = UInt64(0)
        self.error_message = ""


def _receiver_thread(argument: _OpaquePtr) -> _OpaquePtr:
    var context = argument.unsafe_bitcast[_ReceiverThreadContext]()
    context[].thread_id = current_thread_id()
    try:
        var first: WsFrame = context[].receiver.recv()
        if (
            first.opcode != WsOpcode.TEXT
            or first.text_payload() != "duplex-complete"
        ):
            raise Error("first coalesced server frame mismatch")

        var second: WsFrame = context[].receiver.recv()
        if (
            second.opcode != WsOpcode.TEXT
            or second.text_payload() != "coalesced-followup"
        ):
            raise Error("second coalesced server frame mismatch")

        context[].received_coalesced_frames = True
        _store_state(context[].state_address, _RECEIVER_READY)
        try:
            _ = context[].receiver.recv()
        except:
            context[].interrupted = True
    except error:
        context[].error_message = String(error)
        _store_state(context[].state_address, _RECEIVER_FAILED)
    return _null_opaque_pointer()


struct _PlainReceiverThreadContext(Movable):
    """Plain-WebSocket receiver plus cross-thread observations."""

    var receiver: WsReceiver
    var state_address: Int
    var received_echo: Bool
    var interrupted: Bool
    var error_message: String

    def __init__(out self, var receiver: WsReceiver, state_address: Int):
        self.receiver = receiver^
        self.state_address = state_address
        self.received_echo = False
        self.interrupted = False
        self.error_message = ""


def _plain_receiver_thread(argument: _OpaquePtr) -> _OpaquePtr:
    var context = argument.unsafe_bitcast[_PlainReceiverThreadContext]()
    try:
        var frame: WsFrame = context[].receiver.recv()
        if (
            frame.opcode != WsOpcode.TEXT
            or frame.text_payload() != "sender-proof"
        ):
            raise Error("plain WebSocket echo mismatch")
        context[].received_echo = True
        _store_state(context[].state_address, _RECEIVER_READY)
        try:
            _ = context[].receiver.recv()
        except:
            context[].interrupted = True
    except error:
        context[].error_message = String(error)
        _store_state(context[].state_address, _RECEIVER_FAILED)
    return _null_opaque_pointer()


def _exercise_pressure_connection(
    var client: WsClient, process_id: Int, validation_text: String
) raises:
    var duplex = client^.split()
    var sender: WsSender = duplex.take_sender()
    var receiver: WsReceiver = duplex.take_receiver()
    var shutdown: WsShutdown = duplex.take_shutdown()

    var sender_state = unsafe_alloc[UInt8](1)
    sender_state.unsafe_write(_SENDER_PENDING)
    var receiver_state = unsafe_alloc[UInt8](1)
    receiver_state.unsafe_write(_PRESSURE_RECEIVER_PENDING)
    var payload = _make_pressure_payload(
        _PRESSURE_PAYLOAD_BYTES, _CLIENT_PRESSURE_SALT
    )
    var sender_context = unsafe_alloc[_PressureSenderThreadContext](1)
    sender_context.unsafe_write(
        _PressureSenderThreadContext(sender^, payload^, Int(sender_state))
    )
    var receiver_context = unsafe_alloc[_PressureReceiverThreadContext](1)
    receiver_context.unsafe_write(
        _PressureReceiverThreadContext(
            receiver^,
            Int(receiver_state),
            Int(sender_state),
            validation_text,
        )
    )

    var sender_argument = _OpaquePtr(unsafe_from_address=Int(sender_context))
    var sender_thread: ThreadHandle = ThreadHandle.spawn[
        _pressure_sender_thread
    ](sender_argument)
    var sender_start_deadline = monotonic_now_ms() + 2_000
    while (
        _load_state(Int(sender_state)) == _SENDER_PENDING
        and monotonic_now_ms() < sender_start_deadline
    ):
        usleep(1_000)

    var receiver_argument = _OpaquePtr(
        unsafe_from_address=Int(receiver_context)
    )
    var receiver_thread: ThreadHandle = ThreadHandle.spawn[
        _pressure_receiver_thread
    ](receiver_argument)

    var deadline = monotonic_now_ms() + _PRESSURE_DEADLINE_MS
    var observed_receiver_state = _load_state(Int(receiver_state))
    var observed_sender_state = _load_state(Int(sender_state))
    while monotonic_now_ms() < deadline:
        if (
            observed_receiver_state == _PRESSURE_RECEIVER_FAILED
            or observed_sender_state == _SENDER_FAILED
        ):
            break
        if (
            observed_receiver_state == _PRESSURE_RECEIVER_VALIDATED
            and observed_sender_state == _SENDER_SUCCEEDED
        ):
            break
        usleep(1_000)
        observed_receiver_state = _load_state(Int(receiver_state))
        observed_sender_state = _load_state(Int(sender_state))

    shutdown.shutdown()
    shutdown.shutdown()
    _stop_server(process_id)
    receiver_thread.join()
    sender_thread.join()

    observed_receiver_state = _load_state(Int(receiver_state))
    observed_sender_state = _load_state(Int(sender_state))
    var sender_error_message = sender_context[].error_message.copy()
    var receiver_error_message = receiver_context[].error_message.copy()
    var sender_waited_after_inbound = (
        receiver_context[].sender_waited_after_inbound
    )
    sender_context.unsafe_deinit_pointee()
    sender_context.unsafe_free()
    receiver_context.unsafe_deinit_pointee()
    receiver_context.unsafe_free()
    sender_state.unsafe_free()
    receiver_state.unsafe_free()

    assert_equal(
        observed_receiver_state,
        _PRESSURE_RECEIVER_VALIDATED,
        "pressure receive failed or timed out: " + receiver_error_message,
    )
    assert_equal(
        observed_sender_state,
        _SENDER_SUCCEEDED,
        "pressure send failed or timed out: " + sender_error_message,
    )
    assert_true(
        sender_waited_after_inbound,
        "sender returned before the peer read its multi-megabyte frame",
    )


def test_public_split_over_wss_is_full_duplex_and_shutdown_safe() raises:
    """Drive one sender thread and one receiver thread through public split.

    The library creates no thread handle: this test constructs exactly the two
    application handles below. The main thread retains independent shutdown,
    waits until both coalesced response frames are consumed, then interrupts a
    third blocked receive and joins both application threads.
    """
    var listener: TcpListener = TcpListener.bind(SocketAddr.localhost(0))
    var port: UInt16 = listener.local_addr().port
    var process_id: Int = _spawn_server(listener)

    var client: WsClient = _connect(port)
    var duplex = client^.split()
    var sender: WsSender = duplex.take_sender()
    var receiver: WsReceiver = duplex.take_receiver()
    var shutdown: WsShutdown = duplex.take_shutdown()

    var receiver_state = unsafe_alloc[UInt8](1)
    receiver_state.unsafe_write(_RECEIVER_PENDING)
    var sender_context = unsafe_alloc[_SenderThreadContext](1)
    sender_context.unsafe_write(_SenderThreadContext(sender^))
    var receiver_context = unsafe_alloc[_ReceiverThreadContext](1)
    receiver_context.unsafe_write(
        _ReceiverThreadContext(receiver^, Int(receiver_state))
    )

    var main_thread_id: UInt64 = current_thread_id()
    var receiver_argument = _OpaquePtr(
        unsafe_from_address=Int(receiver_context)
    )
    var receiver_thread: ThreadHandle = ThreadHandle.spawn[_receiver_thread](
        receiver_argument
    )
    usleep(25_000)
    var sender_argument = _OpaquePtr(unsafe_from_address=Int(sender_context))
    var sender_thread: ThreadHandle = ThreadHandle.spawn[_sender_thread](
        sender_argument
    )

    var deadline: Int = monotonic_now_ms() + 3_000
    var state: UInt8 = _load_state(Int(receiver_state))
    while state == _RECEIVER_PENDING and monotonic_now_ms() < deadline:
        usleep(1_000)
        state = _load_state(Int(receiver_state))

    var shutdown_started_at: Int = monotonic_now_ms()
    shutdown.shutdown()
    shutdown.shutdown()
    receiver_thread.join()
    var shutdown_elapsed: Int = monotonic_now_ms() - shutdown_started_at
    sender_thread.join()
    _stop_server(process_id)

    assert_equal(
        state,
        _RECEIVER_READY,
        "receiver failed: " + receiver_context[].error_message,
    )
    assert_true(
        sender_context[].sent,
        "sender failed: " + sender_context[].error_message,
    )
    assert_true(receiver_context[].received_coalesced_frames)
    assert_true(receiver_context[].interrupted)
    assert_true(
        shutdown_elapsed < 2_000,
        "blocked receive took " + String(shutdown_elapsed) + "ms to stop",
    )
    assert_true(sender_context[].thread_id != UInt64(0))
    assert_true(receiver_context[].thread_id != UInt64(0))
    assert_true(sender_context[].thread_id != receiver_context[].thread_id)
    assert_true(sender_context[].thread_id != main_thread_id)
    assert_true(receiver_context[].thread_id != main_thread_id)

    sender_context.unsafe_deinit_pointee()
    sender_context.unsafe_free()
    receiver_context.unsafe_deinit_pointee()
    receiver_context.unsafe_free()
    receiver_state.unsafe_free()


def test_shutdown_releases_sender_waiting_for_publication() raises:
    """Wake a sender whose frame has no receiver loop to publish it."""
    var listener: TcpListener = TcpListener.bind(SocketAddr.localhost(0))
    var port: UInt16 = listener.local_addr().port
    var process_id: Int = _spawn_server(listener)

    var client: WsClient = _connect(port)
    var duplex = client^.split()
    var sender: WsSender = duplex.take_sender()
    var receiver: WsReceiver = duplex.take_receiver()
    var shutdown: WsShutdown = duplex.take_shutdown()

    var sender_state = unsafe_alloc[UInt8](1)
    sender_state.unsafe_write(_SENDER_PENDING)
    var sender_context = unsafe_alloc[_WaitingSenderThreadContext](1)
    sender_context.unsafe_write(
        _WaitingSenderThreadContext(sender^, Int(sender_state))
    )
    var sender_argument = _OpaquePtr(unsafe_from_address=Int(sender_context))
    var sender_thread: ThreadHandle = ThreadHandle.spawn[
        _waiting_sender_thread
    ](sender_argument)

    var deadline: Int = monotonic_now_ms() + 3_000
    var state: UInt8 = _load_state(Int(sender_state))
    while state == _SENDER_PENDING and monotonic_now_ms() < deadline:
        usleep(1_000)
        state = _load_state(Int(sender_state))

    usleep(25_000)
    var blocked_before_shutdown: Bool = (
        _load_state(Int(sender_state)) == _SENDER_WAITING
    )
    var shutdown_started_at: Int = monotonic_now_ms()
    shutdown.shutdown()
    shutdown.shutdown()
    sender_thread.join()
    var shutdown_elapsed: Int = monotonic_now_ms() - shutdown_started_at
    var receiver_error_message: String = ""
    try:
        _ = receiver.recv()
    except error:
        receiver_error_message = String(error)
    _stop_server(process_id)

    assert_equal(
        state,
        _SENDER_WAITING,
        "sender did not wait before shutdown: "
        + sender_context[].error_message,
    )
    assert_true(
        blocked_before_shutdown,
        "sender returned before independent shutdown",
    )
    assert_equal(
        _load_state(Int(sender_state)),
        _SENDER_FAILED,
        "sender unexpectedly published after shutdown",
    )
    assert_true(
        "WebSocket duplex shut down" in sender_context[].error_message,
        "sender failure did not preserve shutdown cause: "
        + sender_context[].error_message,
    )
    assert_true(
        shutdown_elapsed < 2_000,
        "waiting sender took " + String(shutdown_elapsed) + "ms to stop",
    )
    assert_true(
        "WebSocket duplex stopped" in receiver_error_message,
        "receiver did not retain the stopped endpoint state: "
        + receiver_error_message,
    )

    sender_context.unsafe_deinit_pointee()
    sender_context.unsafe_free()
    sender_state.unsafe_free()


def test_peer_close_releases_sender_without_publishing_later_frame() raises:
    """Fence a pending send behind buffered CLOSE and preserve its cause."""
    var listener: TcpListener = TcpListener.bind(SocketAddr.localhost(0))
    var port: UInt16 = listener.local_addr().port
    var process_id: Int = _spawn_terminal_server(listener)

    var client: WsClient = _connect(port)
    var duplex = client^.split()
    var sender: WsSender = duplex.take_sender()
    var receiver: WsReceiver = duplex.take_receiver()
    var shutdown: WsShutdown = duplex.take_shutdown()

    var before_close: WsFrame = receiver.recv()
    var sender_state = unsafe_alloc[UInt8](1)
    sender_state.unsafe_write(_SENDER_PENDING)
    var sender_context = unsafe_alloc[_WaitingSenderThreadContext](1)
    sender_context.unsafe_write(
        _WaitingSenderThreadContext(sender^, Int(sender_state))
    )
    var sender_argument = _OpaquePtr(unsafe_from_address=Int(sender_context))
    var sender_thread: ThreadHandle = ThreadHandle.spawn[
        _waiting_sender_thread
    ](sender_argument)

    var deadline: Int = monotonic_now_ms() + 3_000
    var state: UInt8 = _load_state(Int(sender_state))
    while state == _SENDER_PENDING and monotonic_now_ms() < deadline:
        usleep(1_000)
        state = _load_state(Int(sender_state))
    usleep(25_000)
    var blocked_before_close: Bool = (
        _load_state(Int(sender_state)) == _SENDER_WAITING
    )

    var terminal: WsFrame = receiver.recv()
    sender_thread.join()
    shutdown.shutdown()
    shutdown.shutdown()
    var receiver_error_message: String = ""
    try:
        _ = receiver.recv()
    except error:
        receiver_error_message = String(error)
    _stop_server(process_id)

    var sender_error_message: String = sender_context[].error_message.copy()
    var final_sender_state: UInt8 = _load_state(Int(sender_state))
    sender_context.unsafe_deinit_pointee()
    sender_context.unsafe_free()
    sender_state.unsafe_free()

    assert_equal(before_close.opcode, WsOpcode.TEXT)
    assert_equal(before_close.text_payload(), "before-close")
    assert_equal(state, _SENDER_WAITING)
    assert_true(blocked_before_close, "sender returned before peer CLOSE")
    assert_equal(terminal.opcode, WsOpcode.CLOSE)
    assert_equal(
        final_sender_state,
        _SENDER_FAILED,
        "sender unexpectedly published after peer CLOSE",
    )
    assert_true(
        "WebSocket CLOSE received" in sender_error_message,
        "sender did not preserve the peer CLOSE cause: " + sender_error_message,
    )
    assert_true(
        "WebSocket duplex stopped" in receiver_error_message,
        "receiver did not retain terminal state after abortive cleanup: "
        + receiver_error_message,
    )


def test_public_split_over_plain_ws_is_full_duplex() raises:
    """Round-trip on plain WebSocket and interrupt its blocked receiver."""
    var listener: TcpListener = TcpListener.bind(SocketAddr.localhost(0))
    var port: UInt16 = listener.local_addr().port
    var process_id: Int = _spawn_plain_server(listener)

    var client: WsClient = _connect_plain(port)
    var duplex = client^.split()
    var sender: WsSender = duplex.take_sender()
    var receiver: WsReceiver = duplex.take_receiver()
    var shutdown: WsShutdown = duplex.take_shutdown()

    var receiver_state = unsafe_alloc[UInt8](1)
    receiver_state.unsafe_write(_RECEIVER_PENDING)
    var sender_context = unsafe_alloc[_SenderThreadContext](1)
    sender_context.unsafe_write(_SenderThreadContext(sender^))
    var receiver_context = unsafe_alloc[_PlainReceiverThreadContext](1)
    receiver_context.unsafe_write(
        _PlainReceiverThreadContext(receiver^, Int(receiver_state))
    )

    var receiver_argument = _OpaquePtr(
        unsafe_from_address=Int(receiver_context)
    )
    var receiver_thread: ThreadHandle = ThreadHandle.spawn[
        _plain_receiver_thread
    ](receiver_argument)
    usleep(25_000)
    var sender_argument = _OpaquePtr(unsafe_from_address=Int(sender_context))
    var sender_thread: ThreadHandle = ThreadHandle.spawn[_sender_thread](
        sender_argument
    )

    var deadline: Int = monotonic_now_ms() + 3_000
    var state: UInt8 = _load_state(Int(receiver_state))
    while state == _RECEIVER_PENDING and monotonic_now_ms() < deadline:
        usleep(1_000)
        state = _load_state(Int(receiver_state))

    shutdown.shutdown()
    shutdown.shutdown()
    receiver_thread.join()
    sender_thread.join()
    _stop_server(process_id)

    var sender_sent: Bool = sender_context[].sent
    var sender_error_message: String = sender_context[].error_message.copy()
    var received_echo: Bool = receiver_context[].received_echo
    var receiver_interrupted: Bool = receiver_context[].interrupted
    var receiver_error_message: String = receiver_context[].error_message.copy()
    sender_context.unsafe_deinit_pointee()
    sender_context.unsafe_free()
    receiver_context.unsafe_deinit_pointee()
    receiver_context.unsafe_free()
    receiver_state.unsafe_free()

    assert_equal(
        state,
        _RECEIVER_READY,
        "plain receiver failed: " + receiver_error_message,
    )
    assert_true(sender_sent, "plain sender failed: " + sender_error_message)
    assert_true(received_echo)
    assert_true(receiver_interrupted)


def test_wss_split_preserves_frame_coalesced_with_upgrade() raises:
    """Keep post-upgrade plaintext buffered inside SSL across the split."""
    var listener: TcpListener = TcpListener.bind(SocketAddr.localhost(0))
    var port: UInt16 = listener.local_addr().port
    var process_id: Int = _spawn_coalesced_upgrade_server(listener)

    var client: WsClient = _connect(port)
    var duplex = client^.split()
    var receiver: WsReceiver = duplex.take_receiver()
    var shutdown: WsShutdown = duplex.take_shutdown()
    var sender: WsSender = duplex.take_sender()
    var frame = receiver.recv()
    shutdown.shutdown()
    shutdown.shutdown()
    _stop_server(process_id)

    assert_equal(frame.opcode, WsOpcode.TEXT)
    assert_equal(frame.text_payload(), "coalesced-upgrade-frame")


def test_wss_split_survives_simultaneous_multimegabyte_backpressure() raises:
    """Drain inbound TLS while an independently published send is blocked."""
    var listener: TcpListener = TcpListener.bind(SocketAddr.localhost(0))
    var port: UInt16 = listener.local_addr().port
    var process_id: Int = _spawn_tls_pressure_server(listener)
    var client: WsClient = _connect(port)
    client._stream._tls._tcp._socket.set_send_buffer(
        _PRESSURE_SOCKET_BUFFER_BYTES
    )
    client._stream._tls._tcp._socket.set_recv_buffer(
        _PRESSURE_SOCKET_BUFFER_BYTES
    )
    _exercise_pressure_connection(client^, process_id, "tls-pressure-validated")


def test_plain_split_survives_simultaneous_multimegabyte_backpressure() raises:
    """Drain inbound TCP while an independently published send is blocked."""
    var listener: TcpListener = TcpListener.bind(SocketAddr.localhost(0))
    var port: UInt16 = listener.local_addr().port
    var process_id: Int = _spawn_plain_pressure_server(listener)
    var client: WsClient = _connect_plain(port)
    client._stream._tcp._socket.set_send_buffer(_PRESSURE_SOCKET_BUFFER_BYTES)
    client._stream._tcp._socket.set_recv_buffer(_PRESSURE_SOCKET_BUFFER_BYTES)
    _exercise_pressure_connection(
        client^, process_id, "plain-pressure-validated"
    )


def main() raises:
    test_public_split_over_wss_is_full_duplex_and_shutdown_safe()
    test_shutdown_releases_sender_waiting_for_publication()
    test_peer_close_releases_sender_without_publishing_later_frame()
    test_public_split_over_plain_ws_is_full_duplex()
    test_wss_split_preserves_frame_coalesced_with_upgrade()
    test_wss_split_survives_simultaneous_multimegabyte_backpressure()
    test_plain_split_survives_simultaneous_multimegabyte_backpressure()
    print("test_ws_duplex_wss: OK")
