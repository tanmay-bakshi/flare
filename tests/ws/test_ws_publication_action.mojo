"""Deterministic ownership tests for duplex publication actions."""

from std.collections import Optional
from std.memory import ArcPointer, Pointer
from std.memory.alloc import unsafe_alloc
from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.net import SocketAddr
from flare.runtime._libc_time import monotonic_now_ns
from flare.runtime._thread import ThreadHandle, _OpaquePtr
from flare.tcp import TcpListener, TcpStream
from flare.utils import usleep
from flare.ws import (
    WsFrame,
    WsOpcode,
    WsPublicationAction,
    WsReceiver,
    WsSender,
    WsShutdown,
)
from flare.ws._duplex import (
    _DuplexSync,
    _WsControl,
    _WsDuplexState,
    _split_stream,
)
from flare.ws._transport import _WsStream


comptime _SEND_TEXT: Int = 0
comptime _SEND_BINARY: Int = 1
comptime _SEND_FRAME: Int = 2
comptime _WAIT_NS: Int64 = 2_000_000_000
comptime _EXACTLY_ONCE_RUNS: Int = 128
comptime _PRESSURE_SOCKET_BUFFER_BYTES: Int = 4 * 1024
comptime _PRESSURE_PAYLOAD_BYTES: Int = 4 * 1024 * 1024


def _null_opaque_pointer() -> _OpaquePtr:
    var null_address: Int = 0
    return _OpaquePtr(unsafe_from_address=null_address)


struct _ActionState(Movable):
    var sync: _DuplexSync
    var invoked: Int
    var destroyed: Int
    var invoked_before_sender_return: Bool
    var sender_started: Bool
    var sender_returned: Bool
    var sender_published: Bool
    var sender_error: String
    var release_sender: Bool

    def __init__(out self):
        self.sync = _DuplexSync()
        self.invoked = 0
        self.destroyed = 0
        self.invoked_before_sender_return = False
        self.sender_started = False
        self.sender_returned = False
        self.sender_published = False
        self.sender_error = ""
        self.release_sender = False


struct _ActionContext(Movable):
    var state: ArcPointer[_ActionState]

    def __init__(out self, state: ArcPointer[_ActionState]):
        self.state = state


struct _SenderContext(Movable):
    var sender: WsSender
    var state: ArcPointer[_ActionState]
    var mode: Int
    var timeout_ms: Int
    var park_after_return: Bool
    var payload_bytes: Int

    def __init__(
        out self,
        var sender: WsSender,
        state: ArcPointer[_ActionState],
        mode: Int,
        timeout_ms: Int,
        park_after_return: Bool = False,
        payload_bytes: Int = 1,
    ):
        self.sender = sender^
        self.state = state
        self.mode = mode
        self.timeout_ms = timeout_ms
        self.park_after_return = park_after_return
        self.payload_bytes = payload_bytes


struct _ReceiverContext(Movable):
    var receiver: WsReceiver
    var stopped: Bool
    var error_message: String

    def __init__(out self, var receiver: WsReceiver):
        self.receiver = receiver^
        self.stopped = False
        self.error_message = ""


struct _SenderRun(Movable):
    var context: Pointer[_SenderContext, MutUntrackedOrigin]
    var thread: ThreadHandle

    def __init__(
        out self,
        context: Pointer[_SenderContext, MutUntrackedOrigin],
        var thread: ThreadHandle,
    ):
        self.context = context
        self.thread = thread^

    def join_and_destroy(deinit self) raises:
        self.thread.join()
        self.context.unsafe_deinit_pointee()
        self.context.unsafe_free()


struct _ReceiverRun(Movable):
    var context: Pointer[_ReceiverContext, MutUntrackedOrigin]
    var thread: ThreadHandle

    def __init__(
        out self,
        context: Pointer[_ReceiverContext, MutUntrackedOrigin],
        var thread: ThreadHandle,
    ):
        self.context = context
        self.thread = thread^

    def join_and_destroy(deinit self) raises -> Tuple[Bool, String]:
        self.thread.join()
        var result = (
            self.context[].stopped,
            self.context[].error_message.copy(),
        )
        self.context.unsafe_deinit_pointee()
        self.context.unsafe_free()
        return result


def _action_invoke(address: Int):
    var context = Pointer[_ActionContext, MutUntrackedOrigin](
        unsafe_from_address=address
    )
    context[].state[].sync.lock()
    context[].state[].invoked += 1
    context[].state[].invoked_before_sender_return = (
        context[].state[].invoked_before_sender_return
        or not context[].state[].sender_returned
    )
    context[].state[].sync.broadcast()
    context[].state[].sync.unlock()


def _action_destroy(address: Int):
    var context = Pointer[_ActionContext, MutUntrackedOrigin](
        unsafe_from_address=address
    )
    context[].state[].sync.lock()
    context[].state[].destroyed += 1
    context[].state[].sync.broadcast()
    context[].state[].sync.unlock()
    context.unsafe_deinit_pointee()
    context.unsafe_free()


def _action(state: ArcPointer[_ActionState]) -> WsPublicationAction:
    var context = unsafe_alloc[_ActionContext](1)
    context.unsafe_write(_ActionContext(state.copy()))
    return WsPublicationAction(Int(context), _action_invoke, _action_destroy)


def _sender_thread(argument: _OpaquePtr) -> _OpaquePtr:
    var context = argument.unsafe_bitcast[_SenderContext]()
    context[].state[].sync.lock()
    context[].state[].sender_started = True
    context[].state[].sync.broadcast()
    context[].state[].sync.unlock()

    var published = False
    var error_message = String("")
    try:
        var action = _action(context[].state.copy())
        if context[].mode == _SEND_TEXT:
            published = context[].sender.send_text_within(
                "publication", context[].timeout_ms, action^
            )
        elif context[].mode == _SEND_BINARY:
            var payload = List[UInt8](capacity=context[].payload_bytes)
            payload.resize(context[].payload_bytes, UInt8(0x42))
            published = context[].sender.send_binary_within(
                payload, context[].timeout_ms, action^
            )
        else:
            published = context[].sender.send_frame_within(
                WsFrame.ping(), context[].timeout_ms, action^
            )
    except error:
        error_message = String(error)

    context[].state[].sync.lock()
    context[].state[].sender_published = published
    context[].state[].sender_error = error_message^
    context[].state[].sender_returned = True
    context[].state[].sync.broadcast()
    while context[].park_after_return and not context[].state[].release_sender:
        context[].state[].sync.wait()
    context[].state[].sync.unlock()
    return _null_opaque_pointer()


def _receiver_thread(argument: _OpaquePtr) -> _OpaquePtr:
    var context = argument.unsafe_bitcast[_ReceiverContext]()
    try:
        while True:
            _ = context[].receiver.recv()
    except error:
        context[].error_message = String(error)
        context[].stopped = True
    return _null_opaque_pointer()


def _counts(state: ArcPointer[_ActionState]) -> Tuple[Int, Int]:
    state[].sync.lock()
    var counts = (state[].invoked, state[].destroyed)
    state[].sync.unlock()
    return counts


def _assert_counts(
    state: ArcPointer[_ActionState], invoked: Int, destroyed: Int
) raises:
    var actual_invoked, actual_destroyed = _counts(state)
    assert_equal(actual_invoked, invoked)
    assert_equal(actual_destroyed, destroyed)


def _wait_for_sender_started(state: ArcPointer[_ActionState]) raises:
    var deadline_ns = monotonic_now_ns() + _WAIT_NS
    state[].sync.lock()
    while not state[].sender_started:
        if not state[].sync.wait_until(deadline_ns):
            state[].sync.unlock()
            raise Error("sender did not start")
    state[].sync.unlock()


def _wait_for_sender_return(state: ArcPointer[_ActionState]) raises:
    var deadline_ns = monotonic_now_ns() + _WAIT_NS
    state[].sync.lock()
    while not state[].sender_returned:
        if not state[].sync.wait_until(deadline_ns):
            state[].sync.unlock()
            raise Error("sender did not return")
    state[].sync.unlock()


def _release_sender(state: ArcPointer[_ActionState]):
    state[].sync.lock()
    state[].release_sender = True
    state[].sync.broadcast()
    state[].sync.unlock()


def _sender_result(
    state: ArcPointer[_ActionState],
) -> Tuple[Bool, String, Bool]:
    state[].sync.lock()
    var result = (
        state[].sender_published,
        state[].sender_error.copy(),
        state[].invoked_before_sender_return,
    )
    state[].sync.unlock()
    return result


def _wait_for_pending(shared: ArcPointer[_WsDuplexState]) raises:
    var deadline_ns = monotonic_now_ns() + _WAIT_NS
    while monotonic_now_ns() < deadline_ns:
        shared[].control[].sync.lock()
        var pending = shared[].control[].pending_command_id != 0
        shared[].control[].sync.unlock()
        if pending:
            return
        usleep(100)
    raise Error("sender command did not become pending")


def _active_command_id(shared: ArcPointer[_WsDuplexState]) -> Int64:
    shared[].control[].sync.lock()
    var command_id = shared[].active_command_id
    shared[].control[].sync.unlock()
    return command_id


def _drive_active_to_backpressure(
    mut receiver: WsReceiver, shared: ArcPointer[_WsDuplexState]
) raises:
    receiver._load_outbound(True)
    assert_true(
        _active_command_id(shared) > 0,
        "owner did not claim the publication action",
    )
    var deadline_ns = monotonic_now_ns() + _WAIT_NS
    while monotonic_now_ns() < deadline_ns:
        var written = receiver._write_once()
        if written <= 0:
            assert_true(
                _active_command_id(shared) > 0,
                "publication completed before backpressure",
            )
            return
        if _active_command_id(shared) == 0:
            raise Error("publication completed before backpressure")
    raise Error("owner did not encounter socket backpressure")


def _spawn_sender(
    var sender: WsSender,
    state: ArcPointer[_ActionState],
    timeout_ms: Int,
    mode: Int = _SEND_TEXT,
    park_after_return: Bool = False,
    payload_bytes: Int = 1,
) raises -> _SenderRun:
    var context = unsafe_alloc[_SenderContext](1)
    context.unsafe_write(
        _SenderContext(
            sender^,
            state.copy(),
            mode,
            timeout_ms,
            park_after_return,
            payload_bytes,
        )
    )
    var argument = _OpaquePtr(unsafe_from_address=Int(context))
    var thread = ThreadHandle.spawn[_sender_thread](argument)
    _wait_for_sender_started(state)
    return _SenderRun(context, thread^)


def _spawn_receiver(
    var receiver: WsReceiver,
) raises -> _ReceiverRun:
    var context = unsafe_alloc[_ReceiverContext](1)
    context.unsafe_write(_ReceiverContext(receiver^))
    var argument = _OpaquePtr(unsafe_from_address=Int(context))
    var thread = ThreadHandle.spawn[_receiver_thread](argument)
    return _ReceiverRun(context, thread^)


def _close_idle_receiver(var shutdown: WsShutdown, var receiver: WsReceiver):
    shutdown.shutdown()
    try:
        _ = receiver.recv()
    except:
        pass


def _read_peer_frame(mut stream: TcpStream) raises -> WsFrame:
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
            raise Error("peer closed before publication completed")
        for index in range(count):
            buffer.append(scratch[index])


def _drop_receiver(var receiver: WsReceiver):
    pass


def test_all_bounded_overloads_publish_actions() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var receiver_run = _spawn_receiver(receiver^)
    var state = ArcPointer[_ActionState](_ActionState())

    var text_action = _action(state.copy())
    assert_true(sender.send_text_within("text", 1_000, text_action^))
    var binary_action = _action(state.copy())
    assert_true(sender.send_binary_within([UInt8(1)], 1_000, binary_action^))
    var frame_action = _action(state.copy())
    assert_true(sender.send_frame_within(WsFrame.ping(), 1_000, frame_action^))

    assert_true(sender.send_text_within("action-less", 1_000))
    assert_true(sender.send_binary_within([UInt8(2)], 1_000))
    assert_true(sender.send_frame_within(WsFrame.ping(), 1_000))
    _assert_counts(state, 3, 3)

    shutdown.shutdown()
    var receiver_stopped, _ = receiver_run^.join_and_destroy()
    assert_true(receiver_stopped)
    peer.close()


def test_pre_enqueue_timeout_encoding_and_id_exhaustion_destroy() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())

    with assert_raises(contains="timeout_ms must be positive"):
        var timeout_action = _action(state.copy())
        _ = sender.send_text_within("timeout", 0, timeout_action^)

    var oversized_control = List[UInt8](capacity=126)
    oversized_control.resize(126, UInt8(0))
    with assert_raises(contains="Control frame payload"):
        var encoding_action = _action(state.copy())
        _ = sender.send_frame_within(
            WsFrame(opcode=WsOpcode.PING, payload=oversized_control),
            1_000,
            encoding_action^,
        )

    shared[].control[].sync.lock()
    shared[].next_command_id = Int64.MAX
    shared[].control[].sync.unlock()
    with assert_raises(contains="command ids exhausted"):
        var exhausted_action = _action(state.copy())
        _ = sender.send_text_within("exhausted", 1_000, exhausted_action^)

    _assert_counts(state, 0, 3)
    _close_idle_receiver(shutdown^, receiver^)
    peer.close()


def test_already_past_internal_deadline_rejects_and_destroys() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var wire = shared[].encode_outbound(WsFrame.text("already-past"))
    var action = _action(state.copy())

    assert_false(
        shared[].send_until(
            wire^,
            monotonic_now_ns() - 1,
            Optional[WsPublicationAction](action^),
        )
    )
    _assert_counts(state, 0, 1)

    _close_idle_receiver(shutdown^, receiver^)
    peer.close()


def test_pre_enqueue_stopped_and_local_close_destroy() raises:
    var stopped_listener = TcpListener.bind(SocketAddr.localhost(0))
    var stopped_client = TcpStream.connect(stopped_listener.local_addr())
    var stopped_peer = stopped_listener.accept()
    var stopped_duplex = _split_stream(_WsStream(stopped_client^), 1024)
    var stopped_sender = stopped_duplex.take_sender()
    var stopped_receiver = stopped_duplex.take_receiver()
    var stopped_shutdown = stopped_duplex.take_shutdown()
    var stopped_state = ArcPointer[_ActionState](_ActionState())
    stopped_shutdown.shutdown()
    with assert_raises(contains="shut down"):
        var stopped_action = _action(stopped_state.copy())
        _ = stopped_sender.send_text_within("stopped", 1_000, stopped_action^)
    _assert_counts(stopped_state, 0, 1)
    try:
        _ = stopped_receiver.recv()
    except:
        pass
    stopped_peer.close()

    var close_listener = TcpListener.bind(SocketAddr.localhost(0))
    var close_client = TcpStream.connect(close_listener.local_addr())
    var close_peer = close_listener.accept()
    var close_duplex = _split_stream(_WsStream(close_client^), 1024)
    var close_sender = close_duplex.take_sender()
    var close_receiver = close_duplex.take_receiver()
    var close_shutdown = close_duplex.take_shutdown()
    var close_state = ArcPointer[_ActionState](_ActionState())
    close_shutdown.request_close_within(1_000)
    with assert_raises(contains="close has started"):
        var close_action = _action(close_state.copy())
        _ = close_sender.send_text_within("closed", 1_000, close_action^)
    _assert_counts(close_state, 0, 1)
    _close_idle_receiver(close_shutdown^, close_receiver^)
    close_peer.close()


def test_second_sender_rejection_destroys_only_rejected_action() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var second_sender = WsSender(shared.copy())
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var first_state = ArcPointer[_ActionState](_ActionState())
    var rejected_state = ArcPointer[_ActionState](_ActionState())
    var sender_run = _spawn_sender(sender^, first_state.copy(), 1_000)
    _wait_for_pending(shared)

    with assert_raises(contains="exactly one sending thread"):
        var rejected_action = _action(rejected_state.copy())
        _ = second_sender.send_text_within("second", 1_000, rejected_action^)
    _assert_counts(rejected_state, 0, 1)
    _assert_counts(first_state, 0, 0)

    shutdown.shutdown()
    _wait_for_sender_return(first_state)
    sender_run^.join_and_destroy()
    _assert_counts(first_state, 0, 1)
    try:
        _ = receiver.recv()
    except:
        pass
    peer.close()


def test_pending_deadline_destroys_without_invoke() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var action = _action(state.copy())

    var published = sender.send_text_within("pending", 20, action^)

    assert_false(published)
    _assert_counts(state, 0, 1)
    _close_idle_receiver(shutdown^, receiver^)
    peer.close()


def test_pending_shutdown_destroys_before_sender_wakes() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var sender_run = _spawn_sender(sender^, state.copy(), 1_000)
    _wait_for_pending(shared)

    shutdown.shutdown()
    _wait_for_sender_return(state)
    _assert_counts(state, 0, 1)
    var published, error_message, _ = _sender_result(state)
    assert_false(published)
    assert_true("shut down" in error_message)

    sender_run^.join_and_destroy()
    try:
        _ = receiver.recv()
    except:
        pass
    peer.close()


def test_retained_preconnect_shutdown_destroys_pending_action() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var control = ArcPointer[_WsControl](_WsControl())
    var retained_shutdown = WsShutdown(control)
    var duplex = _split_stream(_WsStream(client^), control, 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var established_shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var sender_run = _spawn_sender(sender^, state.copy(), 1_000)
    _wait_for_pending(shared)

    retained_shutdown.shutdown()
    _wait_for_sender_return(state)
    _assert_counts(state, 0, 1)
    var published, error_message, _ = _sender_result(state)
    assert_false(published)
    assert_true("shut down" in error_message)

    sender_run^.join_and_destroy()
    established_shutdown.shutdown()
    try:
        _ = receiver.recv()
    except:
        pass
    peer.close()


def test_retained_close_expiry_destroys_pending_action() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var sender_run = _spawn_sender(sender^, state.copy(), 1_000)
    _wait_for_pending(shared)
    shutdown.request_close_within(20)

    var expired = Optional[String]()
    var deadline_ns = monotonic_now_ns() + _WAIT_NS
    while not expired and monotonic_now_ns() < deadline_ns:
        expired = shared[].expire_requested_close()
        if not expired:
            usleep(100)
    assert_true(expired is not None, "retained close did not expire")
    _wait_for_sender_return(state)
    _assert_counts(state, 0, 1)

    sender_run^.join_and_destroy()
    try:
        _ = receiver.recv()
    except:
        pass
    peer.close()


def test_active_terminate_destroys_before_sender_wakes() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var sender_run = _spawn_sender(sender^, state.copy(), 1_000)
    _wait_for_pending(shared)
    receiver._load_outbound(True)

    receiver._terminate("owner terminated")
    _wait_for_sender_return(state)
    _assert_counts(state, 0, 1)
    var published, error_message, _ = _sender_result(state)
    assert_false(published)
    assert_true("owner terminated" in error_message)

    sender_run^.join_and_destroy()
    shutdown.shutdown()
    peer.close()


def test_active_fail_destroys_before_sender_wakes() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var sender_run = _spawn_sender(sender^, state.copy(), 1_000)
    _wait_for_pending(shared)
    receiver._load_outbound(True)

    with assert_raises(contains="owner failed"):
        receiver._fail("owner failed")
    _wait_for_sender_return(state)
    _assert_counts(state, 0, 1)
    var published, error_message, _ = _sender_result(state)
    assert_false(published)
    assert_true("owner failed" in error_message)

    sender_run^.join_and_destroy()
    shutdown.shutdown()
    peer.close()


def test_active_receiver_deinit_destroys_before_sender_wakes() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var sender_run = _spawn_sender(sender^, state.copy(), 1_000)
    _wait_for_pending(shared)
    receiver._load_outbound(True)

    _drop_receiver(receiver^)
    _wait_for_sender_return(state)
    _assert_counts(state, 0, 1)
    var published, error_message, _ = _sender_result(state)
    assert_false(published)
    assert_true("receiver closed" in error_message)

    sender_run^.join_and_destroy()
    shutdown.shutdown()
    peer.close()


def test_peer_close_destroys_backpressured_active_action() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    client._socket.set_send_buffer(_PRESSURE_SOCKET_BUFFER_BYTES)
    var peer = listener.accept()
    peer._socket.set_recv_buffer(_PRESSURE_SOCKET_BUFFER_BYTES)
    var duplex = _split_stream(_WsStream(client^), 8 * 1024 * 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var sender_run = _spawn_sender(
        sender^,
        state.copy(),
        10_000,
        _SEND_BINARY,
        False,
        _PRESSURE_PAYLOAD_BYTES,
    )
    _wait_for_pending(shared)
    _drive_active_to_backpressure(receiver, shared)

    var close_wire = WsFrame.close().encode(mask=False)
    peer.write_all(Span[UInt8, _](close_wire))
    var close = receiver.recv()
    assert_equal(close.opcode, WsOpcode.CLOSE)

    _wait_for_sender_return(state)
    _assert_counts(state, 0, 1)
    var published, error_message, _ = _sender_result(state)
    assert_false(published)
    assert_true("CLOSE received" in error_message)

    sender_run^.join_and_destroy()
    shutdown.shutdown()
    peer.close()


def test_read_side_socket_failure_destroys_active_action() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    client._socket.set_send_buffer(_PRESSURE_SOCKET_BUFFER_BYTES)
    var peer = listener.accept()
    peer._socket.set_recv_buffer(_PRESSURE_SOCKET_BUFFER_BYTES)
    var duplex = _split_stream(_WsStream(client^), 8 * 1024 * 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var sender_run = _spawn_sender(
        sender^,
        state.copy(),
        10_000,
        _SEND_BINARY,
        False,
        _PRESSURE_PAYLOAD_BYTES,
    )
    _wait_for_pending(shared)
    _drive_active_to_backpressure(receiver, shared)

    peer.close()
    var read_failed = False
    try:
        _ = receiver.recv()
    except:
        read_failed = True
    assert_true(read_failed, "peer close did not fail the raw receive path")

    _wait_for_sender_return(state)
    _assert_counts(state, 0, 1)
    var published, error_message, _ = _sender_result(state)
    assert_false(published)
    assert_true(
        "receive" in error_message or "closed unexpectedly" in error_message
    )

    sender_run^.join_and_destroy()
    shutdown.shutdown()


def test_write_side_socket_failure_destroys_active_action() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    client._socket.set_send_buffer(_PRESSURE_SOCKET_BUFFER_BYTES)
    var peer = listener.accept()
    peer._socket.set_recv_buffer(_PRESSURE_SOCKET_BUFFER_BYTES)
    var duplex = _split_stream(_WsStream(client^), 8 * 1024 * 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var sender_run = _spawn_sender(
        sender^,
        state.copy(),
        10_000,
        _SEND_BINARY,
        False,
        _PRESSURE_PAYLOAD_BYTES,
    )
    _wait_for_pending(shared)
    _drive_active_to_backpressure(receiver, shared)

    peer.close()
    var write_failed = False
    var deadline_ns = monotonic_now_ns() + _WAIT_NS
    while not write_failed and monotonic_now_ns() < deadline_ns:
        try:
            _ = receiver._write_once()
        except:
            write_failed = True
        if not write_failed:
            usleep(100)
    assert_true(write_failed, "peer close did not fail the raw send path")

    _wait_for_sender_return(state)
    _assert_counts(state, 0, 1)
    var published, error_message, _ = _sender_result(state)
    assert_false(published)
    assert_true("send" in error_message)

    sender_run^.join_and_destroy()
    shutdown.shutdown()


def test_requested_close_expiry_destroys_active_action() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var sender_run = _spawn_sender(sender^, state.copy(), 1_000)
    _wait_for_pending(shared)
    receiver._load_outbound(True)
    shutdown.request_close_within(20)

    var deadline_ns = monotonic_now_ns() + _WAIT_NS
    while (
        shared[].requested_close_poll_timeout_ms() != 0
        and monotonic_now_ns() < deadline_ns
    ):
        usleep(100)
    with assert_raises(contains="deadline expired"):
        receiver._check_running()
    _wait_for_sender_return(state)
    _assert_counts(state, 0, 1)
    var published, error_message, _ = _sender_result(state)
    assert_false(published)
    assert_true("deadline expired" in error_message)

    sender_run^.join_and_destroy()
    peer.close()


def test_publication_after_false_invokes_and_destroys() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var sender_run = _spawn_sender(sender^, state.copy(), 20)
    _wait_for_pending(shared)
    receiver._load_outbound(True)

    _wait_for_sender_return(state)
    sender_run^.join_and_destroy()
    var published, error_message, _ = _sender_result(state)
    assert_false(published)
    assert_equal(error_message, "")
    _assert_counts(state, 0, 0)

    assert_true(receiver._write_once() > 0)
    _assert_counts(state, 1, 1)

    _close_idle_receiver(shutdown^, receiver^)
    peer.close()


def test_stop_after_false_destroys_owner_held_action() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var sender_run = _spawn_sender(sender^, state.copy(), 20)
    _wait_for_pending(shared)
    receiver._load_outbound(True)

    _wait_for_sender_return(state)
    sender_run^.join_and_destroy()
    _assert_counts(state, 0, 0)
    shutdown.shutdown()
    with assert_raises(contains="stopped"):
        receiver._check_running()
    _assert_counts(state, 0, 1)

    try:
        _ = receiver.recv()
    except:
        pass
    peer.close()


def test_owner_invokes_before_sender_completion_and_immediate_reply() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var sender_run = _spawn_sender(
        sender^, state.copy(), 1_000, park_after_return=True
    )
    _wait_for_pending(shared)

    receiver._load_outbound(True)
    assert_true(receiver._write_once() > 0)
    var outbound = _read_peer_frame(peer)
    assert_equal(outbound.opcode, WsOpcode.TEXT)
    var reply_wire = WsFrame.binary([UInt8(0x7A)]).encode(mask=False)
    peer.write_all(Span[UInt8, _](reply_wire))
    var reply = receiver.recv()
    _wait_for_sender_return(state)

    assert_equal(reply.opcode, WsOpcode.BINARY)
    assert_equal(len(reply.payload), 1)
    assert_equal(reply.payload[0], UInt8(0x7A))
    var published, error_message, invoked_before_return = _sender_result(state)
    assert_true(published)
    assert_equal(error_message, "")
    assert_true(invoked_before_return)
    _assert_counts(state, 1, 1)

    _release_sender(state)
    sender_run^.join_and_destroy()
    _close_idle_receiver(shutdown^, receiver^)
    peer.close()


def test_requested_close_waits_behind_publication_action() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var shared = sender._shared.copy()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var state = ArcPointer[_ActionState](_ActionState())
    var sender_run = _spawn_sender(sender^, state.copy(), 1_000)
    _wait_for_pending(shared)
    shutdown.request_close_within(1_000)

    assert_false(shared[].take_requested_close() is not None)
    receiver._load_outbound(True)
    assert_false(shared[].take_requested_close() is not None)
    assert_true(receiver._write_once() > 0)
    var close_wire = shared[].take_requested_close()
    assert_true(close_wire is not None)

    _wait_for_sender_return(state)
    sender_run^.join_and_destroy()
    _assert_counts(state, 1, 1)
    _close_idle_receiver(shutdown^, receiver^)
    peer.close()


def test_exactly_once_settlement_loop() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var duplex = _split_stream(_WsStream(client^), 1024)
    var sender = duplex.take_sender()
    var receiver = duplex.take_receiver()
    var shutdown = duplex.take_shutdown()
    var receiver_run = _spawn_receiver(receiver^)
    var state = ArcPointer[_ActionState](_ActionState())

    for index in range(_EXACTLY_ONCE_RUNS):
        var action = _action(state.copy())
        assert_true(
            sender.send_binary_within([UInt8(index % 251)], 1_000, action^)
        )

    _assert_counts(state, _EXACTLY_ONCE_RUNS, _EXACTLY_ONCE_RUNS)
    shutdown.shutdown()
    var receiver_stopped, _ = receiver_run^.join_and_destroy()
    assert_true(receiver_stopped)
    peer.close()


def main() raises:
    test_all_bounded_overloads_publish_actions()
    test_pre_enqueue_timeout_encoding_and_id_exhaustion_destroy()
    test_already_past_internal_deadline_rejects_and_destroys()
    test_pre_enqueue_stopped_and_local_close_destroy()
    test_second_sender_rejection_destroys_only_rejected_action()
    test_pending_deadline_destroys_without_invoke()
    test_pending_shutdown_destroys_before_sender_wakes()
    test_retained_preconnect_shutdown_destroys_pending_action()
    test_retained_close_expiry_destroys_pending_action()
    test_active_terminate_destroys_before_sender_wakes()
    test_active_fail_destroys_before_sender_wakes()
    test_active_receiver_deinit_destroys_before_sender_wakes()
    test_peer_close_destroys_backpressured_active_action()
    test_read_side_socket_failure_destroys_active_action()
    test_write_side_socket_failure_destroys_active_action()
    test_requested_close_expiry_destroys_active_action()
    test_publication_after_false_invokes_and_destroys()
    test_stop_after_false_destroys_owner_held_action()
    test_owner_invokes_before_sender_completion_and_immediate_reply()
    test_requested_close_waits_behind_publication_action()
    test_exactly_once_settlement_loop()
    print("test_ws_publication_action: OK")
