"""Focused publication-timeout tests for the duplex WebSocket sender."""

from std.memory.alloc import unsafe_alloc
from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.net import SocketAddr
from flare.runtime._libc_time import monotonic_now_ns
from flare.runtime._thread import ThreadHandle, _OpaquePtr
from flare.tcp import TcpListener, TcpStream
from flare.utils import usleep
from flare.ws._duplex import (
    _DuplexSync,
    _SEND_WAKE_COMPLETED,
    _SEND_WAKE_DEADLINE,
    _SEND_WAKE_STOPPED,
    _SEND_WAKE_WAITING,
    _classify_send_wake,
    _split_stream,
    WsReceiver,
    WsSender,
)
from flare.ws.frame import WsFrame
from flare.ws._transport import _WsStream


def _null_opaque_pointer() -> _OpaquePtr:
    var null_address = 0
    return _OpaquePtr(unsafe_from_address=null_address)


struct _ReceiverContext(Movable):
    var receiver: WsReceiver
    var stopped: Bool

    def __init__(out self, var receiver: WsReceiver):
        self.receiver = receiver^
        self.stopped = False


struct _TimedSenderContext(Movable):
    var sender: WsSender
    var payload: List[UInt8]
    var timeout_ms: Int
    var published: Bool
    var error_message: String

    def __init__(
        out self,
        var sender: WsSender,
        var payload: List[UInt8],
        timeout_ms: Int,
    ):
        self.sender = sender^
        self.payload = payload^
        self.timeout_ms = timeout_ms
        self.published = False
        self.error_message = ""


def _receiver_thread(argument: _OpaquePtr) -> _OpaquePtr:
    var context = argument.unsafe_bitcast[_ReceiverContext]()
    try:
        _ = context[].receiver.recv()
    except:
        context[].stopped = True
    return _null_opaque_pointer()


def _timed_sender_thread(argument: _OpaquePtr) -> _OpaquePtr:
    var context = argument.unsafe_bitcast[_TimedSenderContext]()
    try:
        context[].published = context[].sender.send_binary_within(
            context[].payload, context[].timeout_ms
        )
    except error:
        context[].error_message = String(error)
    return _null_opaque_pointer()


def _compile_public_duration_surface(
    mut sender: WsSender, timeout_ms: Int
) raises:
    """Keep all three duration-based public methods type-checked."""
    _ = sender.send_text_within("text", timeout_ms)
    _ = sender.send_binary_within([UInt8(1)], timeout_ms)
    _ = sender.send_frame_within(WsFrame.ping(), timeout_ms)


def test_absolute_deadline_expires_condition_wait() raises:
    var sync = _DuplexSync()
    sync.lock()
    var started_ns = monotonic_now_ns()
    var signalled = sync.wait_until(started_ns + 20_000_000)
    var elapsed_ns = monotonic_now_ns() - started_ns
    sync.unlock()

    assert_false(signalled)
    assert_true(elapsed_ns >= 10_000_000, "deadline fired implausibly early")
    assert_true(elapsed_ns < 1_000_000_000, "deadline failed to bound wait")


def test_public_send_expires_without_owner_loop() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 8 * 1024 * 1024)
    var sender = duplex.take_sender()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()

    var started_ns = monotonic_now_ns()
    var published = sender.send_text_within("deadline-proof", 20)
    var elapsed_ns = monotonic_now_ns() - started_ns
    shutdown.shutdown()
    try:
        _ = receiver.recv()
    except:
        pass
    peer.close()

    assert_false(published)
    assert_true(elapsed_ns >= 10_000_000, "send deadline fired too early")
    assert_true(elapsed_ns < 1_000_000_000, "send deadline did not bound wait")


def test_public_send_reports_completed_publication() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 8 * 1024 * 1024)
    var sender = duplex.take_sender()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()

    var context = unsafe_alloc[_ReceiverContext](1)
    context.unsafe_write(_ReceiverContext(receiver^))
    var argument = _OpaquePtr(unsafe_from_address=Int(context))
    var thread = ThreadHandle.spawn[_receiver_thread](argument)
    var published = sender.send_text_within("publication-proof", 1_000)
    shutdown.shutdown()
    thread.join()
    peer.close()

    var receiver_stopped = context[].stopped
    context.unsafe_deinit_pointee()
    context.unsafe_free()
    assert_true(published)
    assert_true(receiver_stopped, "shutdown did not release receiver owner")


def test_active_backpressured_send_expires_then_shuts_down() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    client._socket.set_send_buffer(4 * 1024)
    var peer = listener.accept()
    peer._socket.set_recv_buffer(4 * 1024)
    var duplex = _split_stream(_WsStream(client^), 8 * 1024 * 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()

    var receiver_context = unsafe_alloc[_ReceiverContext](1)
    receiver_context.unsafe_write(_ReceiverContext(receiver^))
    var receiver_argument = _OpaquePtr(
        unsafe_from_address=Int(receiver_context)
    )
    var receiver_thread = ThreadHandle.spawn[_receiver_thread](
        receiver_argument
    )

    var payload = List[UInt8](capacity=4 * 1024 * 1024)
    payload.resize(4 * 1024 * 1024, UInt8(0x5A))
    var timeout_ms = 2_000
    var sender_context = unsafe_alloc[_TimedSenderContext](1)
    sender_context.unsafe_write(
        _TimedSenderContext(sender^, payload^, timeout_ms)
    )
    var sender_argument = _OpaquePtr(unsafe_from_address=Int(sender_context))
    var sender_thread = ThreadHandle.spawn[_timed_sender_thread](
        sender_argument
    )

    var active_seen = False
    var observation_deadline_ns = monotonic_now_ns() + 2_000_000_000
    while monotonic_now_ns() < observation_deadline_ns:
        shared[].control[].sync.lock()
        active_seen = shared[].active_command_id != 0
        shared[].control[].sync.unlock()
        if active_seen:
            break
        usleep(1_000)

    sender_thread.join()
    shutdown.shutdown()
    receiver_thread.join()
    peer.close()

    var published = sender_context[].published
    var error_message = sender_context[].error_message.copy()
    var receiver_stopped = receiver_context[].stopped
    sender_context.unsafe_deinit_pointee()
    sender_context.unsafe_free()
    receiver_context.unsafe_deinit_pointee()
    receiver_context.unsafe_free()

    assert_true(active_seen, "owner never claimed the backpressured send")
    assert_equal(error_message, "")
    assert_false(published)
    assert_true(receiver_stopped, "shutdown did not release active owner")


def test_public_send_validates_timeout() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 8 * 1024 * 1024)
    var sender = duplex.take_sender()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()

    with assert_raises(contains="timeout_ms must be positive"):
        _ = sender.send_text_within("zero", 0)
    with assert_raises(contains="timeout_ms must be positive"):
        _ = sender.send_binary_within([UInt8(1)], -1)
    with assert_raises(contains="deadline overflows Int64"):
        _ = sender.send_frame_within(
            WsFrame.ping(), Int(Int64.MAX // 1_000_000)
        )
    with assert_raises(contains="timeout_ms is too large"):
        _ = sender.send_frame_within(
            WsFrame.ping(), Int(Int64.MAX // 1_000_000) + 1
        )

    shutdown.shutdown()
    try:
        _ = receiver.recv()
    except:
        pass
    peer.close()


def test_completion_wins_expiry_race_at_wake() raises:
    var command_id = Int64(7)
    var deadline_ns = Int64(100)

    assert_equal(
        _classify_send_wake(
            command_id,
            command_id,
            True,
            deadline_ns,
            deadline_ns,
        ),
        _SEND_WAKE_COMPLETED,
    )
    assert_equal(
        _classify_send_wake(
            command_id - 1,
            command_id,
            False,
            deadline_ns,
            deadline_ns,
        ),
        _SEND_WAKE_DEADLINE,
    )
    assert_equal(
        _classify_send_wake(
            command_id - 1,
            command_id,
            True,
            deadline_ns - 1,
            deadline_ns,
        ),
        _SEND_WAKE_STOPPED,
    )
    assert_equal(
        _classify_send_wake(
            command_id - 1,
            command_id,
            False,
            deadline_ns - 1,
            deadline_ns,
        ),
        _SEND_WAKE_WAITING,
    )


def main() raises:
    test_absolute_deadline_expires_condition_wait()
    test_public_send_expires_without_owner_loop()
    test_public_send_reports_completed_publication()
    test_active_backpressured_send_expires_then_shuts_down()
    test_public_send_validates_timeout()
    test_completion_wins_expiry_race_at_wake()
    print("test_ws_duplex_deadline: OK")
