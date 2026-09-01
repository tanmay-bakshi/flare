"""Message-bound, server-split, and bounded-close WebSocket regressions."""

from std.memory import ArcPointer
from std.memory.alloc import unsafe_alloc
from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.net import SocketAddr
from flare.runtime._libc_time import monotonic_now_ns
from flare.runtime._thread import ThreadHandle, _OpaquePtr
from flare.tcp import TcpListener, TcpStream
from flare.utils import usleep
from flare.ws import (
    WsCloseCode,
    WsClient,
    WsConnection,
    WsDuplex,
    WsFrame,
    WsOpcode,
    WsReceiver,
    WsShutdown,
    WsUpgradeRequest,
)
from flare.ws._duplex import _split_stream, _WsControl
from flare.ws._transport import _WsStream
from flare.ws.frame import _encode_client_frame


comptime _CAP: Int = 8


def _null_opaque() -> _OpaquePtr:
    var address = 0
    return _OpaquePtr(unsafe_from_address=address)


def _split_server(
    var stream: TcpStream, max_message_bytes: Int
) raises -> WsDuplex:
    var peer = stream.peer_addr()
    var request = WsUpgradeRequest("GET", "/", "key", [], [])
    var connection = WsConnection(stream^, peer, request^)
    return connection^.split(max_message_bytes)


def _read_frame(mut stream: TcpStream) raises -> WsFrame:
    var buffer = List[UInt8](capacity=256)
    var scratch = List[UInt8](capacity=256)
    scratch.resize(256, UInt8(0))
    while True:
        try:
            var result = WsFrame.decode_one(Span[UInt8, _](buffer))
            return result^.take_frame()
        except error:
            var message = String(error)
            if (
                "need at least" not in message
                and "need " not in message
                and "truncated" not in message
            ):
                raise error^
        var count = stream.read(scratch.unsafe_ptr(), len(scratch))
        if count == 0:
            raise Error("peer closed before a complete WebSocket frame")
        for index in range(count):
            buffer.append(scratch[index])


def _close_code(frame: WsFrame) -> UInt16:
    if frame.opcode != WsOpcode.CLOSE or len(frame.payload) < 2:
        return UInt16(0)
    return (UInt16(frame.payload[0]) << 8) | UInt16(frame.payload[1])


def _close_reason(frame: WsFrame) -> String:
    if frame.opcode != WsOpcode.CLOSE or len(frame.payload) <= 2:
        return ""
    var reason = List[UInt8](capacity=len(frame.payload) - 2)
    for index in range(2, len(frame.payload)):
        reason.append(frame.payload[index])
    return String(unsafe_from_utf8=Span[UInt8, _](reason))


def _unmasked_header(
    opcode: UInt8, length: Int, fin: Bool = True
) -> List[UInt8]:
    var first = opcode | (UInt8(0x80) if fin else UInt8(0))
    if length < 126:
        return [first, UInt8(length)]
    return [first, UInt8(126), UInt8(length >> 8), UInt8(length & 0xFF)]


def _masked_header(opcode: UInt8, length: Int, fin: Bool = True) -> List[UInt8]:
    var wire = _unmasked_header(opcode, length, fin)
    wire[1] |= UInt8(0x80)
    wire.append(UInt8(1))
    wire.append(UInt8(2))
    wire.append(UInt8(3))
    wire.append(UInt8(4))
    return wire^


def _expect_oversize(var receiver: WsReceiver, var peer: TcpStream) raises:
    var message = String("")
    try:
        _ = receiver.recv()
    except error:
        message = String(error)
    peer.set_recv_timeout(1_000)
    var close = _read_frame(peer)
    assert_true("message_too_big" in message, message)
    assert_equal(_close_code(close), WsCloseCode.MESSAGE_TOO_BIG)


def _expect_invalid_utf8(
    var receiver: WsReceiver,
    var peer: TcpStream,
    masked_close: Bool,
) raises:
    var message = String("")
    try:
        _ = receiver.recv_message()
    except error:
        message = String(error)
    peer.set_recv_timeout(1_000)
    var close = _read_frame(peer)
    assert_true("invalid_utf8" in message, message)
    assert_equal(close.opcode, WsOpcode.CLOSE)
    assert_equal(close.masked, masked_close)
    assert_equal(_close_code(close), WsCloseCode.INVALID_PAYLOAD)
    assert_equal(_close_reason(close), "invalid_utf8")


def _close_wire(payload: List[UInt8], masked: Bool) raises -> List[UInt8]:
    var frame = WsFrame(opcode=WsOpcode.CLOSE, payload=payload)
    return _encode_client_frame(frame) if masked else frame.encode(mask=False)


def _expect_close_rejection(
    var receiver: WsReceiver,
    var peer: TcpStream,
    masked_close: Bool,
    expected_code: UInt16,
    expected_reason: String,
) raises:
    var message = String("")
    try:
        _ = receiver.recv()
    except error:
        message = String(error)
    peer.set_recv_timeout(1_000)
    var close = _read_frame(peer)
    assert_true(expected_reason in message, message)
    assert_equal(close.opcode, WsOpcode.CLOSE)
    assert_equal(close.masked, masked_close)
    assert_equal(_close_code(close), expected_code)
    assert_equal(_close_reason(close), expected_reason)


def _invalid_text_fragments(masked: Bool) raises -> List[UInt8]:
    var first = WsFrame(
        opcode=WsOpcode.TEXT,
        payload=[UInt8(0xE2)],
        fin=False,
    )
    var continuation = WsFrame(
        opcode=WsOpcode.CONTINUATION,
        payload=[UInt8(0x28), UInt8(0xA1)],
    )
    var wire = _encode_client_frame(first) if masked else first.encode(
        mask=False
    )
    var tail = _encode_client_frame(
        continuation
    ) if masked else continuation.encode(mask=False)
    for byte in tail:
        wire.append(byte)
    return wire^


def _split_codepoint_fragments(masked: Bool) raises -> List[UInt8]:
    var first = WsFrame(
        opcode=WsOpcode.TEXT,
        payload=[UInt8(0xC3)],
        fin=False,
    )
    var continuation = WsFrame(
        opcode=WsOpcode.CONTINUATION,
        payload=[UInt8(0xA9), UInt8(0x21)],
    )
    var wire = _encode_client_frame(first) if masked else first.encode(
        mask=False
    )
    var tail = _encode_client_frame(
        continuation
    ) if masked else continuation.encode(mask=False)
    for byte in tail:
        wire.append(byte)
    return wire^


def test_split_client_preserves_codepoint_across_fragments() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var local = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(
        _WsStream(local^),
        _CAP,
        mask_outbound=True,
        expect_masked_inbound=False,
    )
    var receiver = duplex.take_receiver()
    _ = duplex.take_sender()
    _ = duplex.take_shutdown()

    var wire = _split_codepoint_fragments(masked=False)
    peer.write_all(Span[UInt8, _](wire))
    assert_equal(receiver.recv_message().as_text(), "é!")


def test_split_server_preserves_codepoint_across_fragments() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var peer = TcpStream.connect(listener.local_addr())
    var local = listener.accept()
    var duplex = _split_server(local^, _CAP)
    var receiver = duplex.take_receiver()
    _ = duplex.take_sender()
    _ = duplex.take_shutdown()

    var wire = _split_codepoint_fragments(masked=True)
    peer.write_all(Span[UInt8, _](wire))
    assert_equal(receiver.recv_message().as_text(), "é!")


def test_split_client_rejects_aggregate_invalid_utf8() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var local = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(
        _WsStream(local^),
        _CAP,
        mask_outbound=True,
        expect_masked_inbound=False,
    )
    var receiver = duplex.take_receiver()
    _ = duplex.take_sender()
    _ = duplex.take_shutdown()

    var wire = _invalid_text_fragments(masked=False)
    peer.write_all(Span[UInt8, _](wire))
    _expect_invalid_utf8(receiver^, peer^, masked_close=True)


def test_split_server_rejects_aggregate_invalid_utf8() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var peer = TcpStream.connect(listener.local_addr())
    var local = listener.accept()
    var duplex = _split_server(local^, _CAP)
    var receiver = duplex.take_receiver()
    _ = duplex.take_sender()
    _ = duplex.take_shutdown()

    var wire = _invalid_text_fragments(masked=True)
    peer.write_all(Span[UInt8, _](wire))
    _expect_invalid_utf8(receiver^, peer^, masked_close=False)


def test_unsplit_client_rejects_aggregate_invalid_utf8() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var local = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var control = ArcPointer[_WsControl](_WsControl())
    var stream = _WsStream(local^)
    assert_true(control[].attach_fd(stream.fd()))
    var client = WsClient(stream^, "test-key", control)

    var wire = _invalid_text_fragments(masked=False)
    peer.write_all(Span[UInt8, _](wire))
    var message = String("")
    try:
        _ = client.recv_message(_CAP)
    except error:
        message = String(error)
    peer.set_recv_timeout(1_000)
    var close = _read_frame(peer)
    assert_true("invalid_utf8" in message, message)
    assert_equal(close.opcode, WsOpcode.CLOSE)
    assert_true(close.masked)
    assert_equal(_close_code(close), WsCloseCode.INVALID_PAYLOAD)
    assert_equal(_close_reason(close), "invalid_utf8")


def test_split_server_rejects_one_byte_close_before_echo() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var peer = TcpStream.connect(listener.local_addr())
    var local = listener.accept()
    var duplex = _split_server(local^, _CAP)
    var receiver = duplex.take_receiver()
    _ = duplex.take_sender()
    _ = duplex.take_shutdown()

    var wire = _close_wire([UInt8(0x03)], masked=True)
    peer.write_all(Span[UInt8, _](wire))
    _expect_close_rejection(
        receiver^,
        peer^,
        masked_close=False,
        expected_code=WsCloseCode.PROTOCOL_ERROR,
        expected_reason="invalid_close_payload",
    )


def test_split_client_rejects_reserved_close_before_echo() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var local = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(
        _WsStream(local^),
        _CAP,
        mask_outbound=True,
        expect_masked_inbound=False,
    )
    var receiver = duplex.take_receiver()
    _ = duplex.take_sender()
    _ = duplex.take_shutdown()

    var wire = _close_wire([UInt8(0x03), UInt8(0xED)], masked=False)
    peer.write_all(Span[UInt8, _](wire))
    _expect_close_rejection(
        receiver^,
        peer^,
        masked_close=True,
        expected_code=WsCloseCode.PROTOCOL_ERROR,
        expected_reason="invalid_close_code",
    )


def test_unsplit_client_rejects_invalid_close_reason() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var local = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var control = ArcPointer[_WsControl](_WsControl())
    var stream = _WsStream(local^)
    assert_true(control[].attach_fd(stream.fd()))
    var client = WsClient(stream^, "test-key", control)

    var wire = _close_wire(
        [UInt8(0x03), UInt8(0xE8), UInt8(0xC3), UInt8(0x28)],
        masked=False,
    )
    peer.write_all(Span[UInt8, _](wire))
    var message = String("")
    try:
        _ = client.recv(_CAP)
    except error:
        message = String(error)
    peer.set_recv_timeout(1_000)
    var close = _read_frame(peer)
    assert_true("invalid_close_reason" in message, message)
    assert_true(close.masked)
    assert_equal(_close_code(close), WsCloseCode.INVALID_PAYLOAD)
    assert_equal(_close_reason(close), "invalid_close_reason")


def test_unsplit_server_rejects_invalid_close_reason() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var peer = TcpStream.connect(listener.local_addr())
    var local = listener.accept()
    var address = local.peer_addr()
    var request = WsUpgradeRequest("GET", "/", "key", [], [])
    var connection = WsConnection(local^, address, request^)

    var wire = _close_wire(
        [UInt8(0x03), UInt8(0xE8), UInt8(0xC3), UInt8(0x28)],
        masked=True,
    )
    peer.write_all(Span[UInt8, _](wire))
    var message = String("")
    try:
        _ = connection.recv(_CAP)
    except error:
        message = String(error)
    peer.set_recv_timeout(1_000)
    var close = _read_frame(peer)
    assert_true("invalid_close_reason" in message, message)
    assert_false(close.masked)
    assert_equal(_close_code(close), WsCloseCode.INVALID_PAYLOAD)
    assert_equal(_close_reason(close), "invalid_close_reason")


def test_split_server_echoes_valid_close_payload_unchanged() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var peer = TcpStream.connect(listener.local_addr())
    var local = listener.accept()
    var duplex = _split_server(local^, _CAP)
    var receiver = duplex.take_receiver()
    _ = duplex.take_sender()
    _ = duplex.take_shutdown()

    var expected = WsFrame.close(WsCloseCode.GOING_AWAY, "adiós")
    var wire = _close_wire(expected.payload.copy(), masked=True)
    peer.write_all(Span[UInt8, _](wire))

    var received = receiver.recv()
    peer.set_recv_timeout(1_000)
    var echoed = _read_frame(peer)
    assert_equal(received.opcode, WsOpcode.CLOSE)
    assert_equal(echoed.opcode, WsOpcode.CLOSE)
    assert_false(echoed.masked)
    assert_equal(len(echoed.payload), len(expected.payload))
    for index in range(len(expected.payload)):
        assert_equal(echoed.payload[index], expected.payload[index])


def test_client_rejects_declared_oversize_before_payload() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var local = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(
        _WsStream(local^),
        _CAP,
        mask_outbound=True,
        expect_masked_inbound=False,
    )
    var receiver = duplex.take_receiver()
    _ = duplex.take_sender()
    _ = duplex.take_shutdown()

    var header = _unmasked_header(WsOpcode.TEXT, _CAP + 1)
    peer.write_all(Span[UInt8, _](header))
    _expect_oversize(receiver^, peer^)


def test_server_rejects_declared_oversize_before_payload() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var peer = TcpStream.connect(listener.local_addr())
    var local = listener.accept()
    var duplex = _split_server(local^, _CAP)
    var receiver = duplex.take_receiver()
    _ = duplex.take_sender()
    _ = duplex.take_shutdown()

    var header = _masked_header(WsOpcode.BINARY, _CAP + 1)
    peer.write_all(Span[UInt8, _](header))
    _expect_oversize(receiver^, peer^)


def test_client_counts_fragmented_message_total() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var local = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(
        _WsStream(local^),
        _CAP,
        mask_outbound=True,
        expect_masked_inbound=False,
    )
    var receiver = duplex.take_receiver()
    _ = duplex.take_sender()
    _ = duplex.take_shutdown()

    var first = WsFrame(
        opcode=WsOpcode.TEXT,
        payload=[UInt8(1), UInt8(2), UInt8(3), UInt8(4), UInt8(5), UInt8(6)],
        fin=False,
    ).encode(mask=False)
    peer.write_all(Span[UInt8, _](first))
    var observed = receiver.recv()
    assert_false(observed.fin)

    var continuation = _unmasked_header(WsOpcode.CONTINUATION, 3)
    peer.write_all(Span[UInt8, _](continuation))
    _expect_oversize(receiver^, peer^)


def test_server_counts_fragmented_message_total() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var peer = TcpStream.connect(listener.local_addr())
    var local = listener.accept()
    var duplex = _split_server(local^, _CAP)
    var receiver = duplex.take_receiver()
    _ = duplex.take_sender()
    _ = duplex.take_shutdown()

    var first = _encode_client_frame(
        WsFrame(
            opcode=WsOpcode.BINARY,
            payload=[
                UInt8(1),
                UInt8(2),
                UInt8(3),
                UInt8(4),
                UInt8(5),
                UInt8(6),
            ],
            fin=False,
        )
    )
    peer.write_all(Span[UInt8, _](first))
    var observed = receiver.recv()
    assert_false(observed.fin)

    var continuation = _masked_header(WsOpcode.CONTINUATION, 3)
    peer.write_all(Span[UInt8, _](continuation))
    _expect_oversize(receiver^, peer^)


struct _CloseReceiverContext(Movable):
    var receiver: WsReceiver
    var saw_close: Bool
    var stopped: Bool

    def __init__(out self, var receiver: WsReceiver):
        self.receiver = receiver^
        self.saw_close = False
        self.stopped = False


def _close_receiver_entry(argument: _OpaquePtr) -> _OpaquePtr:
    var context = argument.unsafe_bitcast[_CloseReceiverContext]()
    try:
        var frame = context[].receiver.recv()
        context[].saw_close = frame.opcode == WsOpcode.CLOSE
    except:
        context[].stopped = True
    return _null_opaque()


struct _ReceiverRequestedCloseContext(Movable):
    var receiver: WsReceiver
    var shutdown: WsShutdown
    var request_returned: Bool
    var saw_close: Bool
    var error_message: String

    def __init__(out self, var receiver: WsReceiver, var shutdown: WsShutdown):
        self.receiver = receiver^
        self.shutdown = shutdown^
        self.request_returned = False
        self.saw_close = False
        self.error_message = ""


def _receiver_requested_close_entry(argument: _OpaquePtr) -> _OpaquePtr:
    var context = argument.unsafe_bitcast[_ReceiverRequestedCloseContext]()
    try:
        context[].shutdown.request_close_within(
            1_000, WsCloseCode.POLICY_VIOLATION, "receiver_request"
        )
        context[].request_returned = True
        var frame = context[].receiver.recv()
        context[].saw_close = frame.opcode == WsOpcode.CLOSE
    except error:
        context[].error_message = String(error)
    return _null_opaque()


struct _ClosePeerContext(Movable):
    var stream: TcpStream
    var saw_unmasked_close: Bool
    var code: UInt16
    var reason: String
    var reason_bytes: Int
    var response_delay_us: Int

    def __init__(out self, var stream: TcpStream, response_delay_us: Int = 0):
        self.stream = stream^
        self.saw_unmasked_close = False
        self.code = UInt16(0)
        self.reason = ""
        self.reason_bytes = 0
        self.response_delay_us = response_delay_us


def _close_peer_entry(argument: _OpaquePtr) -> _OpaquePtr:
    var context = argument.unsafe_bitcast[_ClosePeerContext]()
    try:
        var frame = _read_frame(context[].stream)
        context[].saw_unmasked_close = (
            frame.opcode == WsOpcode.CLOSE and not frame.masked
        )
        context[].code = _close_code(frame)
        context[].reason_bytes = len(frame.payload) - 2
        if len(frame.payload) > 2:
            var reason_bytes = List[UInt8](capacity=len(frame.payload) - 2)
            for index in range(2, len(frame.payload)):
                reason_bytes.append(frame.payload[index])
            context[].reason = String(
                unsafe_from_utf8=Span[UInt8, _](reason_bytes)
            )
        if context[].response_delay_us > 0:
            usleep(context[].response_delay_us)
        var response = _encode_client_frame(WsFrame.close())
        context[].stream.write_all(Span[UInt8, _](response))
    except:
        pass
    return _null_opaque()


def test_server_split_bounded_close_waits_for_peer() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var peer = TcpStream.connect(listener.local_addr())
    var local = listener.accept()
    var duplex = _split_server(local^, 64 * 1024)
    _ = duplex.take_sender()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()

    var receiver_context = unsafe_alloc[_CloseReceiverContext](1)
    receiver_context.unsafe_write(_CloseReceiverContext(receiver^))
    var receiver_thread = ThreadHandle.spawn[_close_receiver_entry](
        _OpaquePtr(unsafe_from_address=Int(receiver_context))
    )
    var peer_context = unsafe_alloc[_ClosePeerContext](1)
    peer_context.unsafe_write(_ClosePeerContext(peer^))
    var peer_thread = ThreadHandle.spawn[_close_peer_entry](
        _OpaquePtr(unsafe_from_address=Int(peer_context))
    )

    var reason = (
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        + "🙂tail"
    )
    var acknowledged = shutdown.close_within(
        1_000, WsCloseCode.GOING_AWAY, reason
    )
    receiver_thread.join()
    peer_thread.join()

    assert_true(acknowledged)
    assert_true(receiver_context[].saw_close)
    assert_true(peer_context[].saw_unmasked_close)
    assert_true(peer_context[].reason_bytes <= 123)
    assert_equal(peer_context[].reason_bytes, 120)

    receiver_context.unsafe_deinit_pointee()
    receiver_context.unsafe_free()
    peer_context.unsafe_deinit_pointee()
    peer_context.unsafe_free()


def test_server_split_close_timeout_is_abortive() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var peer = TcpStream.connect(listener.local_addr())
    var local = listener.accept()
    var duplex = _split_server(local^, 64 * 1024)
    _ = duplex.take_sender()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()

    var receiver_context = unsafe_alloc[_CloseReceiverContext](1)
    receiver_context.unsafe_write(_CloseReceiverContext(receiver^))
    var receiver_thread = ThreadHandle.spawn[_close_receiver_entry](
        _OpaquePtr(unsafe_from_address=Int(receiver_context))
    )
    var acknowledged = shutdown.close_within(20, reason="deadline")
    receiver_thread.join()
    peer.close()

    assert_false(acknowledged)
    receiver_context.unsafe_deinit_pointee()
    receiver_context.unsafe_free()


def test_requested_close_is_nonblocking_first_wins_and_fences_sends() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var peer = TcpStream.connect(listener.local_addr())
    var local = listener.accept()
    var duplex = _split_server(local^, 64 * 1024)
    var sender = duplex.take_sender()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()

    var receiver_context = unsafe_alloc[_CloseReceiverContext](1)
    receiver_context.unsafe_write(_CloseReceiverContext(receiver^))
    var receiver_thread = ThreadHandle.spawn[_close_receiver_entry](
        _OpaquePtr(unsafe_from_address=Int(receiver_context))
    )
    var peer_context = unsafe_alloc[_ClosePeerContext](1)
    peer_context.unsafe_write(_ClosePeerContext(peer^, 500_000))
    var peer_thread = ThreadHandle.spawn[_close_peer_entry](
        _OpaquePtr(unsafe_from_address=Int(peer_context))
    )

    var started_ns = monotonic_now_ns()
    shutdown.request_close_within(
        1_000, WsCloseCode.GOING_AWAY, "first_request"
    )
    var request_elapsed_ns = monotonic_now_ns() - started_ns
    shutdown.request_close_within(
        1, WsCloseCode.INTERNAL_ERROR, "later_request"
    )
    shutdown.request_close_within(
        0, WsCloseCode.INTERNAL_ERROR, "invalid_later_request"
    )
    with assert_raises(contains="close has started"):
        sender.send_text("too late")

    receiver_thread.join()
    peer_thread.join()

    assert_true(
        request_elapsed_ns < 250_000_000,
        "request_close_within waited on the delayed peer",
    )
    assert_true(receiver_context[].saw_close)
    assert_true(peer_context[].saw_unmasked_close)
    assert_equal(peer_context[].code, WsCloseCode.GOING_AWAY)
    assert_equal(peer_context[].reason, "first_request")

    receiver_context.unsafe_deinit_pointee()
    receiver_context.unsafe_free()
    peer_context.unsafe_deinit_pointee()
    peer_context.unsafe_free()


def test_requested_close_owner_loop_enforces_deadline() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var peer = TcpStream.connect(listener.local_addr())
    var local = listener.accept()
    var duplex = _split_server(local^, 64 * 1024)
    _ = duplex.take_sender()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()

    var receiver_context = unsafe_alloc[_CloseReceiverContext](1)
    receiver_context.unsafe_write(_CloseReceiverContext(receiver^))
    var receiver_thread = ThreadHandle.spawn[_close_receiver_entry](
        _OpaquePtr(unsafe_from_address=Int(receiver_context))
    )
    var started_ns = monotonic_now_ns()
    shutdown.request_close_within(20, reason="owner_deadline")
    receiver_thread.join()
    var elapsed_ns = monotonic_now_ns() - started_ns
    peer.close()

    assert_true(receiver_context[].stopped)
    assert_true(elapsed_ns >= 10_000_000, "close expired implausibly early")
    assert_true(elapsed_ns < 1_000_000_000, "owner failed to bound close")
    receiver_context.unsafe_deinit_pointee()
    receiver_context.unsafe_free()


def test_receiver_thread_can_request_close_without_deadlock() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var peer = TcpStream.connect(listener.local_addr())
    var local = listener.accept()
    var duplex = _split_server(local^, 64 * 1024)
    _ = duplex.take_sender()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()

    var receiver_context = unsafe_alloc[_ReceiverRequestedCloseContext](1)
    receiver_context.unsafe_write(
        _ReceiverRequestedCloseContext(receiver^, shutdown^)
    )
    var receiver_thread = ThreadHandle.spawn[_receiver_requested_close_entry](
        _OpaquePtr(unsafe_from_address=Int(receiver_context))
    )
    var peer_context = unsafe_alloc[_ClosePeerContext](1)
    peer_context.unsafe_write(_ClosePeerContext(peer^))
    var peer_thread = ThreadHandle.spawn[_close_peer_entry](
        _OpaquePtr(unsafe_from_address=Int(peer_context))
    )

    receiver_thread.join()
    peer_thread.join()

    assert_true(receiver_context[].request_returned)
    assert_true(receiver_context[].saw_close)
    assert_equal(receiver_context[].error_message, "")
    assert_equal(peer_context[].code, WsCloseCode.POLICY_VIOLATION)
    assert_equal(peer_context[].reason, "receiver_request")

    receiver_context.unsafe_deinit_pointee()
    receiver_context.unsafe_free()
    peer_context.unsafe_deinit_pointee()
    peer_context.unsafe_free()


def main() raises:
    test_split_client_preserves_codepoint_across_fragments()
    test_split_server_preserves_codepoint_across_fragments()
    test_split_client_rejects_aggregate_invalid_utf8()
    test_split_server_rejects_aggregate_invalid_utf8()
    test_unsplit_client_rejects_aggregate_invalid_utf8()
    test_split_server_rejects_one_byte_close_before_echo()
    test_split_client_rejects_reserved_close_before_echo()
    test_unsplit_client_rejects_invalid_close_reason()
    test_unsplit_server_rejects_invalid_close_reason()
    test_split_server_echoes_valid_close_payload_unchanged()
    test_client_rejects_declared_oversize_before_payload()
    test_server_rejects_declared_oversize_before_payload()
    test_client_counts_fragmented_message_total()
    test_server_counts_fragmented_message_total()
    test_server_split_bounded_close_waits_for_peer()
    test_server_split_close_timeout_is_abortive()
    test_requested_close_is_nonblocking_first_wins_and_fences_sends()
    test_requested_close_owner_loop_enforces_deadline()
    test_receiver_thread_can_request_close_without_deadlock()
    print("test_ws_duplex_bounds: OK")
