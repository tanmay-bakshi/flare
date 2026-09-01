"""Full-duplex WebSocket endpoints backed by one transport owner loop."""

from std.atomic import Atomic, Ordering
from std.collections import Optional
from std.ffi import c_int, external_call
from std.memory import ArcPointer, Pointer, stack_allocation
from std.memory.alloc import unsafe_alloc
from std.os import abort
from std.sys.info import CompilationTarget

from ._message import WsMessage
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
from ..net import NetworkError
from ..net._libc import INVALID_FD, _shutdown, SHUT_RDWR
from ..runtime.event import Event, INTEREST_READ, INTEREST_WRITE
from ..runtime._libc_time import monotonic_now_ns
from ..runtime.reactor import Reactor
from ..tls.stream import (
    _SSL_IO_WANT_READ,
    _SSL_IO_WANT_WRITE,
    _SSL_IO_CLOSED,
)


comptime _DUPLEX_SYNC_BYTES: Int = 128
comptime _DUPLEX_SYNC_ALIGNMENT: Int = 16
comptime _OUTBOUND_PLAINTEXT_CHUNK: Int = 16 * 1024
comptime _WS_STREAM_TOKEN: UInt64 = 1
comptime _SyncPointer = Pointer[UInt8, MutUntrackedOrigin]
comptime _TimespecPointer = Pointer[Int64, MutUntrackedOrigin]
comptime _CLOCK_MONOTONIC: c_int = c_int(1)
comptime _ETIMEDOUT: c_int = (
    c_int(60) if CompilationTarget.is_macos() else c_int(110)
)
comptime _SEND_WAKE_WAITING: Int = 0
comptime _SEND_WAKE_COMPLETED: Int = 1
comptime _SEND_WAKE_STOPPED: Int = 2
comptime _SEND_WAKE_DEADLINE: Int = 3
comptime _OUTBOUND_CONTROL_ID: Int64 = -1
comptime _OUTBOUND_REQUESTED_CLOSE_ID: Int64 = -2
comptime _MAX_REACTOR_TIMEOUT_MS: Int = 2_147_483_647


def _null_sync_pointer() -> _SyncPointer:
    var null_address = 0
    return _SyncPointer(unsafe_from_address=null_address)


def _require_pthread_success(operation: StringLiteral, result: c_int):
    if result == c_int(0):
        return
    abort(String(operation) + " failed with rc=" + String(Int(result)))


# The pthread calls provide runtime exclusion, but Mojo cannot infer a
# language-level memory barrier through raw FFI. Keep every cross-thread
# predicate and publication marker atomic; the mutex still protects compound
# state and condition waits.
@always_inline
def _load_i64(mut cell: Int64) -> Int64:
    return Atomic[DType.int64].load[ordering=Ordering.ACQUIRE](
        Pointer(to=cell).unsafe_bitcast[Scalar[DType.int64]]()
    )


@always_inline
def _store_i64(mut cell: Int64, value: Int64):
    Atomic[DType.int64].store[ordering=Ordering.RELEASE](
        Pointer(to=cell).unsafe_bitcast[Scalar[DType.int64]](), value
    )


@always_inline
def _load_u8(mut cell: UInt8) -> UInt8:
    return Atomic[DType.uint8].load[ordering=Ordering.ACQUIRE](
        Pointer(to=cell).unsafe_bitcast[Scalar[DType.uint8]]()
    )


@always_inline
def _store_u8(mut cell: UInt8, value: UInt8):
    Atomic[DType.uint8].store[ordering=Ordering.RELEASE](
        Pointer(to=cell).unsafe_bitcast[Scalar[DType.uint8]](), value
    )


struct _DuplexSync(Movable):
    """Mutex and condition storage shared by duplex endpoints."""

    var mutex: _SyncPointer
    var condition: _SyncPointer

    def __init__(out self):
        self.mutex = unsafe_alloc[UInt8](
            _DUPLEX_SYNC_BYTES, alignment=_DUPLEX_SYNC_ALIGNMENT
        )
        self.condition = unsafe_alloc[UInt8](
            _DUPLEX_SYNC_BYTES, alignment=_DUPLEX_SYNC_ALIGNMENT
        )
        var mutex_result = external_call[
            "pthread_mutex_init",
            c_int,
            _SyncPointer,
            _SyncPointer,
        ](self.mutex, _null_sync_pointer())
        _require_pthread_success("pthread_mutex_init", mutex_result)
        comptime if CompilationTarget.is_linux():
            # Bind the condition variable to CLOCK_MONOTONIC once. This keeps
            # absolute deadline waits on the caller's timebase without relying
            # on pthread_cond_clockwait, whose glibc availability starts at
            # 2.30 and is newer than flare's supported Linux floor.
            var condition_attr = unsafe_alloc[UInt8](
                _DUPLEX_SYNC_BYTES, alignment=_DUPLEX_SYNC_ALIGNMENT
            )
            var attr_init_result = external_call[
                "pthread_condattr_init", c_int, _SyncPointer
            ](condition_attr)
            _require_pthread_success("pthread_condattr_init", attr_init_result)
            var attr_clock_result = external_call[
                "pthread_condattr_setclock", c_int, _SyncPointer, c_int
            ](condition_attr, _CLOCK_MONOTONIC)
            _require_pthread_success(
                "pthread_condattr_setclock", attr_clock_result
            )
            var condition_result = external_call[
                "pthread_cond_init",
                c_int,
                _SyncPointer,
                _SyncPointer,
            ](self.condition, condition_attr)
            _require_pthread_success("pthread_cond_init", condition_result)
            var attr_destroy_result = external_call[
                "pthread_condattr_destroy", c_int, _SyncPointer
            ](condition_attr)
            _require_pthread_success(
                "pthread_condattr_destroy", attr_destroy_result
            )
            condition_attr.unsafe_free()
        else:
            var condition_result = external_call[
                "pthread_cond_init",
                c_int,
                _SyncPointer,
                _SyncPointer,
            ](self.condition, _null_sync_pointer())
            _require_pthread_success("pthread_cond_init", condition_result)

    def __deinit__(deinit self):
        var condition_result = external_call[
            "pthread_cond_destroy", c_int, _SyncPointer
        ](self.condition)
        _require_pthread_success("pthread_cond_destroy", condition_result)
        var mutex_result = external_call[
            "pthread_mutex_destroy", c_int, _SyncPointer
        ](self.mutex)
        _require_pthread_success("pthread_mutex_destroy", mutex_result)
        self.condition.unsafe_free()
        self.mutex.unsafe_free()

    def lock(self):
        var result = external_call["pthread_mutex_lock", c_int, _SyncPointer](
            self.mutex
        )
        _require_pthread_success("pthread_mutex_lock", result)

    def unlock(self):
        var result = external_call["pthread_mutex_unlock", c_int, _SyncPointer](
            self.mutex
        )
        _require_pthread_success("pthread_mutex_unlock", result)

    def wait(self):
        var result = external_call[
            "pthread_cond_wait",
            c_int,
            _SyncPointer,
            _SyncPointer,
        ](self.condition, self.mutex)
        _require_pthread_success("pthread_cond_wait", result)

    def wait_until(self, deadline_ns: Int64) -> Bool:
        """Wait through one absolute monotonic deadline.

        The mutex remains locked on return. ``True`` means the condition was
        signalled; ``False`` means the deadline expired. Callers must always
        re-check their predicate because either return can race a publication.
        """
        var remaining_ns = deadline_ns - monotonic_now_ns()
        if remaining_ns <= 0:
            return False

        var timeout = stack_allocation[2, Int64]()
        var timeout_pointer = _TimespecPointer(unsafe_from_address=Int(timeout))
        var result: c_int
        comptime if CompilationTarget.is_macos():
            # Darwin's portable pthread condition clock is realtime-only. Its
            # relative extension preserves the caller's monotonic timebase.
            timeout.unsafe_offset(0).unsafe_write(remaining_ns // 1_000_000_000)
            timeout.unsafe_offset(1).unsafe_write(remaining_ns % 1_000_000_000)
            result = external_call[
                "pthread_cond_timedwait_relative_np",
                c_int,
                _SyncPointer,
                _SyncPointer,
                _TimespecPointer,
            ](self.condition, self.mutex, timeout_pointer)
        else:
            timeout.unsafe_offset(0).unsafe_write(deadline_ns // 1_000_000_000)
            timeout.unsafe_offset(1).unsafe_write(deadline_ns % 1_000_000_000)
            result = external_call[
                "pthread_cond_timedwait",
                c_int,
                _SyncPointer,
                _SyncPointer,
                _TimespecPointer,
            ](self.condition, self.mutex, timeout_pointer)

        if result == c_int(0):
            return True
        if result == _ETIMEDOUT:
            return False
        _require_pthread_success("pthread condition timed wait", result)
        return False

    def broadcast(self):
        var result = external_call[
            "pthread_cond_broadcast", c_int, _SyncPointer
        ](self.condition)
        _require_pthread_success("pthread_cond_broadcast", result)


struct _WsWriteCommand(Movable):
    """One encoded frame handed from the sender to the stream owner."""

    var id: Int64
    var wire: List[UInt8]

    def __init__(out self, id: Int64, var wire: List[UInt8]):
        self.id = id
        self.wire = wire^

    def take_wire(mut self) -> List[UInt8]:
        """Move the frame bytes out while leaving a valid command."""
        var wire = self.wire^
        self.wire = List[UInt8]()
        return wire^


def _ignore_resolver_hook(_address: Int):
    """Default hook used while no resolver request is active."""
    pass


def _classify_send_wake(
    completed_command_id: Int64,
    command_id: Int64,
    stopping: Bool,
    now_ns: Int64,
    deadline_ns: Int64,
) -> Int:
    """Classify one publication-fence observation under its mutex."""
    if completed_command_id >= command_id:
        return _SEND_WAKE_COMPLETED
    if stopping:
        return _SEND_WAKE_STOPPED
    if deadline_ns != 0 and now_ns >= deadline_ns:
        return _SEND_WAKE_DEADLINE
    return _SEND_WAKE_WAITING


def _send_deadline_ns(timeout_ms: Int) raises -> Int64:
    """Convert one public send timeout into this module's clock domain."""
    if timeout_ms <= 0:
        raise Error("WebSocket send timeout_ms must be positive")
    if timeout_ms > Int(Int64.MAX // 1_000_000):
        raise Error("WebSocket send timeout_ms is too large")
    var now_ns = monotonic_now_ns()
    var timeout_ns = Int64(timeout_ms) * 1_000_000
    if now_ns > Int64.MAX - timeout_ns:
        raise Error("WebSocket send deadline overflows Int64")
    return now_ns + timeout_ns


struct _WsControl(Movable):
    """Connection-wide cancellation authority from dial through duplex I/O.

    The stream remains owned by the thread driving the current connection
    phase. This control plane publishes only its current fd, never ownership of
    that fd, so cross-thread shutdown can interrupt I/O without racing a close
    against descriptor reuse. Owner-side final resource release holds ``sync``
    while clearing and closing the fd through ``begin_owner_close`` /
    ``finish_owner_close``; potentially blocking protocol shutdown exchanges
    run while the fd remains published and the mutex remains available.
    """

    var sync: _DuplexSync
    var reactor: Reactor
    var raw_fd: c_int
    var stopping: UInt8
    var owner_closed: UInt8
    var failure_message: String
    var active_resolver_address: Int
    var active_resolver_cancel: def(Int) thin -> None
    var active_resolver_release: def(Int) thin -> None

    def __init__(out self) raises:
        self.sync = _DuplexSync()
        self.reactor = Reactor()
        self.raw_fd = INVALID_FD
        self.stopping = UInt8(0)
        self.owner_closed = UInt8(1)
        self.failure_message = ""
        self.active_resolver_address = 0
        self.active_resolver_cancel = _ignore_resolver_hook
        self.active_resolver_release = _ignore_resolver_hook

    def is_stopping(mut self) -> Bool:
        return _load_u8(self.stopping) != UInt8(0)

    def attach_fd(mut self, fd: c_int) -> Bool:
        """Publish an owner-held fd unless cancellation already won."""
        self.sync.lock()
        if self.is_stopping():
            self.sync.unlock()
            return False
        if self.raw_fd != INVALID_FD and self.raw_fd != fd:
            self.sync.unlock()
            return False
        self.raw_fd = fd
        _store_u8(self.owner_closed, UInt8(0))
        self.sync.unlock()
        return True

    def begin_owner_close(mut self, expected_fd: c_int) -> Bool:
        """Clear ``expected_fd`` while retaining the lock for its close.

        A True result leaves ``sync`` locked. The owner must close the fd
        without raising and then call :meth:`finish_owner_close`. Keeping the
        lock across those two operations makes a concurrent ``shutdown`` wait
        until the descriptor is closed, so it can never target a reused fd.
        """
        self.sync.lock()
        if (
            _load_u8(self.owner_closed) != UInt8(0)
            or self.raw_fd != expected_fd
        ):
            self.sync.unlock()
            return False
        self.raw_fd = INVALID_FD
        _store_u8(self.owner_closed, UInt8(1))
        return True

    def finish_owner_close(mut self):
        """Complete a successful :meth:`begin_owner_close` operation."""
        self.sync.broadcast()
        self.sync.unlock()

    def install_resolver_request(
        mut self,
        address: Int,
        cancel: def(Int) thin -> None,
        release: def(Int) thin -> None,
    ) -> Bool:
        """Publish the one resolver request cancellation may abandon."""
        self.sync.lock()
        if self.is_stopping():
            cancel(address)
            release(address)
            self.sync.unlock()
            return False
        if self.active_resolver_address != 0:
            cancel(address)
            release(address)
            self.sync.unlock()
            return False
        self.active_resolver_address = address
        self.active_resolver_cancel = cancel
        self.active_resolver_release = release
        self.sync.unlock()
        return True

    def clear_resolver_request(mut self, expected_address: Int):
        """Remove the active resolver hook when its owner regains control."""
        self.sync.lock()
        if self.active_resolver_address == expected_address:
            self.active_resolver_release(expected_address)
            self.active_resolver_address = 0
            self.active_resolver_cancel = _ignore_resolver_hook
            self.active_resolver_release = _ignore_resolver_hook
        self.sync.unlock()

    def claim_publication(mut self) -> Bool:
        """Linearize successful connection publication against shutdown."""
        self.sync.lock()
        var publish = not self.is_stopping()
        self.sync.unlock()
        return publish

    def stopped_message(mut self) -> String:
        """Return the first terminal message under the control lock."""
        self.sync.lock()
        var message = self.failure_message.copy()
        self.sync.unlock()
        return message^

    def _stop_locked(mut self, message: String):
        """Fix terminal state while the caller holds ``sync``."""
        if not self.is_stopping():
            self.failure_message = message
            _store_u8(self.stopping, UInt8(1))
            if self.active_resolver_address != 0:
                self.active_resolver_cancel(self.active_resolver_address)
                self.active_resolver_release(self.active_resolver_address)
            self.active_resolver_address = 0
            self.active_resolver_cancel = _ignore_resolver_hook
            self.active_resolver_release = _ignore_resolver_hook
            if (
                _load_u8(self.owner_closed) == UInt8(0)
                and self.raw_fd != INVALID_FD
            ):
                _ = _shutdown(self.raw_fd, SHUT_RDWR)
        self.sync.broadcast()

    def _wake_owner(mut self):
        """Wake the current connection phase after publishing control state."""
        try:
            self.reactor.wakeup()
        except:
            pass

    def stop(mut self, message: String):
        """Fix terminal state and interrupt whichever connect phase is live."""
        self.sync.lock()
        self._stop_locked(message)
        self.sync.unlock()
        self._wake_owner()


struct _WsDuplexState(Movable):
    """Duplex command state; the receiver exclusively owns stream I/O."""

    var control: ArcPointer[_WsControl]
    var stream: _WsStream
    var next_command_id: Int64
    var pending_command_id: Int64
    var pending_wire: List[UInt8]
    var active_command_id: Int64
    var completed_command_id: Int64
    var mask_outbound: Bool
    var expect_masked_inbound: Bool
    var max_message_bytes: Int
    var local_close_started: UInt8
    var local_close_published: UInt8
    var peer_close_received: UInt8
    var requested_close_deadline_ns: Int64
    var requested_close_wire: List[UInt8]
    var requested_close_taken: UInt8
    var requested_close_timed_out: UInt8

    def __init__(
        out self,
        var stream: _WsStream,
        control: ArcPointer[_WsControl],
        mask_outbound: Bool,
        expect_masked_inbound: Bool,
        max_message_bytes: Int,
    ) raises:
        if max_message_bytes <= 0:
            raise Error("WebSocket max_message_bytes must be positive")
        var raw_fd = stream.fd()
        if not control[].attach_fd(raw_fd):
            if control[].begin_owner_close(raw_fd):
                stream.close_abortive()
                control[].finish_owner_close()
            else:
                stream.close_abortive()
            raise NetworkError("WebSocket duplex stopped before publication")
        try:
            stream.prepare_duplex()
        except error:
            if control[].begin_owner_close(raw_fd):
                stream.close_abortive()
                control[].finish_owner_close()
            raise error^
        try:
            control[].reactor.register(raw_fd, _WS_STREAM_TOKEN, INTEREST_READ)
        except error:
            if control[].begin_owner_close(raw_fd):
                stream.close_abortive()
                control[].finish_owner_close()
            raise error^
        self.control = control
        self.stream = stream^
        self.next_command_id = 0
        self.pending_command_id = 0
        self.pending_wire = List[UInt8]()
        self.active_command_id = 0
        self.completed_command_id = 0
        self.mask_outbound = mask_outbound
        self.expect_masked_inbound = expect_masked_inbound
        self.max_message_bytes = max_message_bytes
        self.local_close_started = UInt8(0)
        self.local_close_published = UInt8(0)
        self.peer_close_received = UInt8(0)
        self.requested_close_deadline_ns = 0
        self.requested_close_wire = List[UInt8]()
        self.requested_close_taken = UInt8(0)
        self.requested_close_timed_out = UInt8(0)

    def encode_outbound(self, frame: WsFrame) raises -> List[UInt8]:
        """Encode one frame according to this endpoint's RFC 6455 role."""
        if self.mask_outbound:
            return _encode_client_frame(frame)
        return frame.encode(mask=False)

    def request_close_within(
        mut self, timeout_ms: Int, code: UInt16, reason: String
    ) raises:
        """Retain the first bounded CLOSE request and wake the stream owner."""
        self.control[].sync.lock()
        if _load_u8(self.local_close_started) != UInt8(0) or self.is_stopping():
            self.control[].sync.unlock()
            return
        var deadline_ns: Int64
        var wire: List[UInt8]
        try:
            deadline_ns = _send_deadline_ns(timeout_ms)
            var frame = WsFrame.close(code, reason)
            wire = self.encode_outbound(frame)
        except error:
            self.control[].sync.unlock()
            raise error^
        self.requested_close_wire = wire^
        _store_i64(self.requested_close_deadline_ns, deadline_ns)
        _store_u8(self.local_close_started, UInt8(1))
        self.control[].sync.broadcast()
        self.control[].sync.unlock()
        self.control[]._wake_owner()

    def take_requested_close(mut self) -> Optional[List[UInt8]]:
        """Move the retained CLOSE into the owner after earlier sends drain."""
        self.control[].sync.lock()
        if (
            _load_i64(self.requested_close_deadline_ns) == 0
            or _load_u8(self.requested_close_taken) != UInt8(0)
            or _load_i64(self.pending_command_id) != 0
            or _load_i64(self.active_command_id) != 0
            or self.is_stopping()
        ):
            self.control[].sync.unlock()
            return Optional[List[UInt8]]()
        var wire = self.requested_close_wire^
        self.requested_close_wire = List[UInt8]()
        _store_u8(self.requested_close_taken, UInt8(1))
        self.control[].sync.unlock()
        return Optional[List[UInt8]](wire^)

    def note_requested_close_published(mut self):
        """Publish that every retained CLOSE byte reached the transport."""
        self.control[].sync.lock()
        _store_u8(self.local_close_published, UInt8(1))
        self.control[].sync.broadcast()
        self.control[].sync.unlock()

    def requested_close_poll_timeout_ms(mut self) -> Int:
        """Return the bounded owner wait imposed by a retained CLOSE."""
        self.control[].sync.lock()
        var deadline_ns = _load_i64(self.requested_close_deadline_ns)
        var terminal = (
            deadline_ns == 0
            or _load_u8(self.peer_close_received) != UInt8(0)
            or self.is_stopping()
        )
        self.control[].sync.unlock()
        if terminal:
            return -1
        var remaining_ns = deadline_ns - monotonic_now_ns()
        if remaining_ns <= 0:
            return 0
        var timeout_ms = Int(remaining_ns // 1_000_000)
        if remaining_ns % 1_000_000 != 0:
            timeout_ms += 1
        if timeout_ms > _MAX_REACTOR_TIMEOUT_MS:
            return _MAX_REACTOR_TIMEOUT_MS
        return timeout_ms

    def expire_requested_close(mut self) -> Optional[String]:
        """Atomically let an elapsed retained deadline stop the connection."""
        self.control[].sync.lock()
        var deadline_ns = _load_i64(self.requested_close_deadline_ns)
        if (
            deadline_ns == 0
            or _load_u8(self.peer_close_received) != UInt8(0)
            or self.is_stopping()
            or monotonic_now_ns() < deadline_ns
        ):
            self.control[].sync.unlock()
            return Optional[String]()
        var message = (
            "WebSocket close publication deadline expired" if _load_u8(
                self.local_close_published
            )
            == UInt8(0) else "WebSocket close handshake deadline expired"
        )
        _store_u8(self.requested_close_timed_out, UInt8(1))
        self.requested_close_wire.clear()
        self.pending_wire.clear()
        _store_i64(self.pending_command_id, 0)
        self.control[]._stop_locked(message)
        self.control[].sync.unlock()
        self.control[]._wake_owner()
        return Optional[String](message^)

    def wait_for_requested_close(mut self) raises -> Bool:
        """Wait for the retained close request's terminal handshake truth."""
        self.control[].sync.lock()
        while True:
            if _load_u8(self.peer_close_received) != UInt8(0):
                self.control[].sync.unlock()
                return True
            if _load_u8(self.requested_close_timed_out) != UInt8(0):
                self.control[].sync.unlock()
                return False
            if self.is_stopping():
                var message = self.control[].failure_message.copy()
                self.control[].sync.unlock()
                raise NetworkError(
                    message if message != "" else "WebSocket close interrupted"
                )
            var deadline_ns = _load_i64(self.requested_close_deadline_ns)
            if deadline_ns == 0:
                self.control[].sync.unlock()
                raise NetworkError("WebSocket close already started")
            if monotonic_now_ns() >= deadline_ns:
                self.control[].sync.unlock()
                var expired = self.expire_requested_close()
                if expired:
                    return False
                self.control[].sync.lock()
                continue
            _ = self.control[].sync.wait_until(deadline_ns)

    def note_peer_close(mut self) -> Bool:
        """Publish peer CLOSE and report whether an echo is still owed."""
        self.control[].sync.lock()
        _store_u8(self.peer_close_received, UInt8(1))
        var echo = _load_u8(self.local_close_published) == UInt8(0)
        if _load_u8(self.local_close_started) == UInt8(0):
            _store_u8(self.local_close_started, UInt8(1))
        self.control[].sync.broadcast()
        self.control[].sync.unlock()
        return echo

    def send(mut self, var wire: List[UInt8]) raises:
        """Queue one frame and wait for owner-loop publication."""
        var published = self._send(wire^, 0)
        if not published:
            abort("untimed WebSocket send reached a deadline")

    def send_until(
        mut self, var wire: List[UInt8], deadline_ns: Int64
    ) raises -> Bool:
        """Wait through an absolute monotonic publication deadline."""
        if deadline_ns <= 0:
            raise Error(
                "WebSocket send deadline must be a positive absolute "
                "monotonic timestamp"
            )
        return self._send(wire^, deadline_ns)

    def _send(
        mut self,
        var wire: List[UInt8],
        deadline_ns: Int64,
    ) raises -> Bool:
        self.control[].sync.lock()
        if self.is_stopping():
            var message = self.control[].failure_message.copy()
            self.control[].sync.unlock()
            raise NetworkError(
                message if message != "" else "WebSocket duplex is stopped"
            )
        if _load_u8(self.local_close_started) != UInt8(0):
            self.control[].sync.unlock()
            raise NetworkError("WebSocket close has started")
        if deadline_ns != 0 and monotonic_now_ns() >= deadline_ns:
            self.control[].sync.unlock()
            return False
        if (
            _load_i64(self.pending_command_id) != 0
            or _load_i64(self.active_command_id) != 0
        ):
            self.control[].sync.unlock()
            raise NetworkError(
                "WsSender supports exactly one sending thread per connection"
            )
        self.next_command_id += 1
        var command_id = self.next_command_id
        self.pending_wire = wire^
        _store_i64(self.pending_command_id, command_id)
        self.control[].sync.unlock()

        try:
            self.control[].reactor.wakeup()
        except:
            pass

        self.control[].sync.lock()
        while True:
            var now_ns = monotonic_now_ns() if deadline_ns != 0 else Int64(0)
            var wake = _classify_send_wake(
                self.load_completed_command_id(),
                command_id,
                self.is_stopping(),
                now_ns,
                deadline_ns,
            )
            if wake == _SEND_WAKE_COMPLETED:
                self.control[].sync.unlock()
                return True
            if wake == _SEND_WAKE_STOPPED:
                var message = self.control[].failure_message.copy()
                self.control[].sync.unlock()
                raise NetworkError(
                    message if message != "" else "WebSocket send interrupted"
                )
            if wake == _SEND_WAKE_DEADLINE:
                self.control[].sync.unlock()
                return False
            if deadline_ns == 0:
                self.control[].sync.wait()
            else:
                _ = self.control[].sync.wait_until(deadline_ns)

    def take_pending(mut self) -> Optional[_WsWriteCommand]:
        """Move one queued command into the owner loop."""
        self.control[].sync.lock()
        var command_id = _load_i64(self.pending_command_id)
        if command_id == 0:
            self.control[].sync.unlock()
            return Optional[_WsWriteCommand]()
        var wire = self.pending_wire^
        self.pending_wire = List[UInt8]()
        var command = _WsWriteCommand(command_id, wire^)
        _store_i64(self.active_command_id, command_id)
        _store_i64(self.pending_command_id, 0)
        self.control[].sync.unlock()
        return Optional[_WsWriteCommand](command^)

    def complete(mut self, command_id: Int64):
        """Acknowledge a command after every frame byte reaches the fd."""
        self.control[].sync.lock()
        if _load_i64(self.active_command_id) == command_id:
            _store_i64(self.active_command_id, 0)
            _store_i64(self.completed_command_id, command_id)
            self.control[].sync.broadcast()
        self.control[].sync.unlock()

    def is_stopping(mut self) -> Bool:
        return self.control[].is_stopping()

    def load_completed_command_id(mut self) -> Int64:
        return _load_i64(self.completed_command_id)

    def stop(mut self, message: String):
        """Fix terminal state, interrupt the fd, and wake all waiters."""
        self.control[].stop(message)
        self.control[].sync.lock()
        if self.is_stopping():
            self.pending_wire.clear()
            _store_i64(self.pending_command_id, 0)
        self.control[].sync.broadcast()
        self.control[].sync.unlock()

    def close_from_owner(mut self):
        """Reclaim TLS and socket state on its sole owning thread."""
        var raw_fd = self.stream.fd()
        if self.control[].begin_owner_close(raw_fd):
            self.stream.close_abortive()
            self.control[].finish_owner_close()


struct WsSender(Movable):
    """Sending half of a split WebSocket connection.

    Exactly one application thread owns this handle. Calls remain synchronous:
    a send returns only after the receiver-owned I/O loop has published the
    entire encoded frame or reports a terminal connection failure.
    """

    var _shared: ArcPointer[_WsDuplexState]

    def __init__(out self, shared: ArcPointer[_WsDuplexState]):
        self._shared = shared

    def send_text(mut self, message: String) raises:
        """Send one masked UTF-8 text frame."""
        self.send_frame(WsFrame.text(message))

    def send_text_within(
        mut self, message: String, timeout_ms: Int
    ) raises -> Bool:
        """Send text within a positive millisecond publication timeout."""
        return self.send_frame_within(WsFrame.text(message), timeout_ms)

    def send_binary(mut self, data: List[UInt8]) raises:
        """Send one masked binary frame."""
        self.send_frame(WsFrame.binary(data))

    def send_binary_within(
        mut self, data: List[UInt8], timeout_ms: Int
    ) raises -> Bool:
        """Send binary data within a positive millisecond timeout."""
        return self.send_frame_within(WsFrame.binary(data), timeout_ms)

    def send_frame(mut self, frame: WsFrame) raises:
        """Send one frame through the receiver-owned stream."""
        var wire = self._shared[].encode_outbound(frame)
        self._shared[].send(wire^)

    def send_frame_within(
        mut self, frame: WsFrame, timeout_ms: Int
    ) raises -> Bool:
        """Send one frame within a positive millisecond timeout.

        Returns ``True`` only when full publication is observed under the
        duplex mutex. ``False`` means publication was not observed when the
        internally computed deadline won. The command may finish racing that
        observation, so the caller MUST immediately shut down the connection
        after ``False`` and must never attempt another send.
        """
        var deadline_ns = _send_deadline_ns(timeout_ms)
        var wire = self._shared[].encode_outbound(frame)
        return self._shared[].send_until(wire^, deadline_ns)


struct WsShutdown(Movable):
    """Independent shutdown handle spanning connect and duplex I/O."""

    var _control: ArcPointer[_WsControl]
    var _shared: Optional[ArcPointer[_WsDuplexState]]

    def __init__(out self, control: ArcPointer[_WsControl]):
        self._control = control
        self._shared = Optional[ArcPointer[_WsDuplexState]]()

    def __init__(
        out self,
        control: ArcPointer[_WsControl],
        shared: ArcPointer[_WsDuplexState],
    ):
        self._control = control
        self._shared = Optional[ArcPointer[_WsDuplexState]](shared)

    def shutdown(mut self):
        """Interrupt the socket and wake a receiver blocked in its reactor."""
        self._control[].stop("WebSocket duplex shut down")

    def request_close_within(
        mut self,
        timeout_ms: Int,
        code: UInt16 = WsCloseCode.NORMAL,
        reason: String = "",
    ) raises:
        """Request one bounded close without waiting on the stream owner.

        The first request fences application sends and retains its close frame
        and deadline. Later requests are no-ops. The receiver-owned I/O loop
        publishes the frame and completes or expires the handshake.
        """
        if not self._shared:
            raise Error("WebSocket close requires an established split")
        self._shared.value()[].request_close_within(timeout_ms, code, reason)

    def close_within(
        mut self,
        timeout_ms: Int,
        code: UInt16 = WsCloseCode.NORMAL,
        reason: String = "",
    ) raises -> Bool:
        """Close a split connection within one end-to-end handshake bound.

        This authority fences the application sender, waits for its one
        in-flight publication, serializes CLOSE behind it, and then waits for
        the peer CLOSE. ``False`` means the deadline won and SHUT_RDWR fired.
        """
        self.request_close_within(timeout_ms, code, reason)
        return self._shared.value()[].wait_for_requested_close()


struct WsPreadmissionRelease(Movable):
    """Idempotent release of shared-listener pre-admission stop ownership."""

    var _context: Int
    var _release: def(Int) thin -> None
    var _released: Bool

    def __init__(
        out self,
        context: Int,
        release: def(Int) thin -> None,
    ):
        self._context = context
        self._release = release
        self._released = False

    def __deinit__(deinit self):
        self.release()

    def release(mut self):
        """Release the retained fd ledger entry at most once."""
        if self._released:
            return
        self._released = True
        self._release(self._context)


struct WsReceiver(Movable):
    """Receiving half and sole I/O owner of a split WebSocket connection.

    The application keeps this handle in its reader thread and continuously
    drives :meth:`recv` or :meth:`recv_message`. That same loop publishes
    sender commands and automatic PONG frames, so OpenSSL is never entered
    concurrently from two threads.
    """

    var _shared: ArcPointer[_WsDuplexState]
    var _read_buffer: List[UInt8]
    var _scratch: List[UInt8]
    var _out_wire: List[UInt8]
    var _out_offset: Int
    var _out_command_id: Int64
    var _read_retry_want_write: Bool
    var _write_retry_interest: Int
    var _control_wire: List[UInt8]
    var _control_pending: Bool
    var _events: List[Event]
    var _fragment_open: Bool
    var _fragment_bytes: Int

    def __init__(out self, shared: ArcPointer[_WsDuplexState]):
        self._shared = shared
        self._read_buffer = List[UInt8](capacity=4096)
        self._scratch = List[UInt8](capacity=4096)
        self._scratch.resize(4096, UInt8(0))
        self._out_wire = List[UInt8]()
        self._out_offset = 0
        self._out_command_id = 0
        self._read_retry_want_write = False
        self._write_retry_interest = 0
        self._control_wire = List[UInt8]()
        self._control_pending = False
        self._events = List[Event]()
        self._fragment_open = False
        self._fragment_bytes = 0

    def __deinit__(deinit self):
        self._shared[].stop("WebSocket receiver closed")
        self._shared[].close_from_owner()

    def _load_outbound(mut self, include_application: Bool):
        if self._out_command_id != 0:
            return
        if self._control_pending:
            var control_wire = self._control_wire^
            self._control_wire = List[UInt8]()
            self._out_wire = control_wire^
            self._control_pending = False
            self._out_offset = 0
            self._out_command_id = _OUTBOUND_CONTROL_ID
            return
        if include_application:
            var pending = self._shared[].take_pending()
            if pending:
                var command = pending.take()
                self._out_command_id = command.id
                self._out_wire = command.take_wire()
                self._out_offset = 0
                return
        var requested_close = self._shared[].take_requested_close()
        if not requested_close:
            return
        self._out_command_id = _OUTBOUND_REQUESTED_CLOSE_ID
        self._out_wire = requested_close.take()
        self._out_offset = 0

    def _fail(mut self, message: String) raises:
        self._terminate(message)
        raise NetworkError(message)

    def _terminate(mut self, message: String):
        self._shared[].stop(message)
        self._shared[].close_from_owner()

    def _check_running(mut self) raises:
        var expired = self._shared[].expire_requested_close()
        if expired:
            var message = expired.take()
            self._shared[].close_from_owner()
            raise NetworkError(message^)
        if self._shared[].is_stopping():
            self._shared[].close_from_owner()
            raise NetworkError("WebSocket duplex stopped")

    def _read_once(mut self) raises -> Int:
        var received: Int = 0
        try:
            received = self._shared[].stream.read_nonblocking(
                self._scratch.unsafe_ptr(), len(self._scratch)
            )
        except error:
            self._fail(String(error))
        if received > 0:
            self._read_retry_want_write = False
            for index in range(received):
                self._read_buffer.append(self._scratch[index])
            return received
        if received == _SSL_IO_WANT_READ:
            self._read_retry_want_write = False
            return received
        if received == _SSL_IO_WANT_WRITE:
            self._read_retry_want_write = True
            return received
        if received == _SSL_IO_CLOSED:
            self._fail("WebSocket connection closed unexpectedly")
        self._fail("WebSocket TLS failure during receive")
        return 0

    def _write_once(mut self) raises -> Int:
        var remaining = len(self._out_wire) - self._out_offset
        var chunk_size = (
            remaining if remaining
            < _OUTBOUND_PLAINTEXT_CHUNK else _OUTBOUND_PLAINTEXT_CHUNK
        )
        var bytes = Span[UInt8, _](
            unsafe_ptr=self._out_wire.unsafe_ptr().unsafe_offset(
                self._out_offset
            ),
            length=chunk_size,
        )
        var written: Int = 0
        try:
            written = self._shared[].stream.write_nonblocking(bytes)
        except error:
            self._fail(String(error))
        if written > 0:
            self._write_retry_interest = 0
            self._out_offset += written
            if self._out_offset == len(self._out_wire):
                var completed_id = self._out_command_id
                self._out_wire.clear()
                self._out_offset = 0
                self._out_command_id = 0
                if completed_id > 0:
                    self._shared[].complete(completed_id)
                elif completed_id == _OUTBOUND_REQUESTED_CLOSE_ID:
                    self._shared[].note_requested_close_published()
            return written
        if written == _SSL_IO_WANT_READ:
            self._write_retry_interest = INTEREST_READ
            return written
        if written == _SSL_IO_WANT_WRITE:
            self._write_retry_interest = INTEREST_WRITE
            return written
        if written == _SSL_IO_CLOSED:
            self._fail("WebSocket connection closed during send")
        self._fail("WebSocket TLS failure during send")
        return 0

    def _poll(mut self, interest: Int) raises:
        try:
            self._shared[].control[].reactor.modify(
                self._shared[].control[].raw_fd, interest
            )
            var timeout_ms = self._shared[].requested_close_poll_timeout_ms()
            _ = self._shared[].control[].reactor.poll(timeout_ms, self._events)
        except error:
            self._fail(String(error))

    def _read_poll_interest(self, result: Int) -> Int:
        var interest = (
            INTEREST_WRITE if result == _SSL_IO_WANT_WRITE else INTEREST_READ
        )
        if self._shared[].stream.has_pending_network_output():
            interest |= INTEREST_WRITE
        return interest

    def _write_poll_interest(self) -> Int:
        var interest = self._write_retry_interest
        if not self._shared[].stream.write_blocks_receive():
            interest |= INTEREST_READ
        if self._shared[].stream.has_pending_network_output():
            interest |= INTEREST_WRITE
        return interest

    def _drive_receive_once(mut self) raises:
        """Make one fair read or write step while waiting for a frame."""
        while True:
            self._check_running()

            if self._read_retry_want_write:
                var received = self._read_once()
                if received > 0:
                    self._service_one_outbound_step()
                    return
                if self._read_retry_want_write:
                    self._poll(self._read_poll_interest(received))
                    continue

            if self._out_command_id != 0:
                if not self._shared[].stream.write_blocks_receive():
                    var received = self._read_once()
                    if received > 0:
                        self._service_one_outbound_step()
                        return
                    if received == _SSL_IO_WANT_WRITE:
                        self._poll(self._read_poll_interest(received))
                        continue
                var written = self._write_once()
                if written > 0:
                    return
                self._poll(self._write_poll_interest())
                continue

            var received = self._read_once()
            if received > 0:
                self._service_one_outbound_step()
                return
            if received == _SSL_IO_WANT_WRITE:
                self._poll(self._read_poll_interest(received))
                continue

            self._load_outbound(True)
            if self._out_command_id != 0:
                var written = self._write_once()
                if written > 0:
                    return
                self._poll(self._write_poll_interest())
                continue

            self._poll(self._read_poll_interest(received))

    def _drive_outbound_once(mut self, include_application: Bool) raises:
        """Advance one selected frame without admitting later commands."""
        while True:
            self._check_running()

            if self._read_retry_want_write:
                var received = self._read_once()
                if received <= 0 and self._read_retry_want_write:
                    self._poll(self._read_poll_interest(received))
                    continue

            self._load_outbound(include_application)
            if self._out_command_id == 0:
                return
            if not self._shared[].stream.write_blocks_receive():
                var received = self._read_once()
                if received == _SSL_IO_WANT_WRITE:
                    self._poll(self._read_poll_interest(received))
                    continue
            var written = self._write_once()
            if written > 0:
                return
            self._poll(self._write_poll_interest())

    def _service_one_outbound_step(mut self) raises:
        """Give one sender frame bounded progress before returning a frame."""
        if self._read_retry_want_write:
            return
        self._load_outbound(True)
        if self._out_command_id == 0:
            return
        _ = self._write_once()

    def _flush_control(mut self) raises:
        """Finish the active frame and one PONG, excluding later sends."""
        while self._out_command_id != 0 or self._control_pending:
            self._drive_outbound_once(False)

    def _publish_terminal_control_once(mut self):
        """Give a terminal control frame one non-blocking publication step."""
        try:
            self._load_outbound(False)
            if self._out_command_id != 0:
                _ = self._write_once()
        except:
            pass

    def _reject(mut self, code: UInt16, message: String) raises:
        """Publish a truthful protocol CLOSE before terminal shutdown."""
        try:
            var close = WsFrame.close(code, message)
            self._control_wire = self._shared[].encode_outbound(close)
            self._control_pending = True
            self._publish_terminal_control_once()
        except:
            pass
        self._terminate(message)
        raise WsProtocolError(message)

    def _validate_header(mut self) raises -> Bool:
        """Validate declared size and fragmentation before payload allocation.
        """
        var inspected: Optional[_WsFrameHeader]
        try:
            inspected = _inspect_frame_header(Span[UInt8, _](self._read_buffer))
        except error:
            self._reject(WsCloseCode.PROTOCOL_ERROR, String(error))
            return False
        if not inspected:
            return False
        var header = inspected.value().copy()
        if header.masked != self._shared[].expect_masked_inbound:
            self._reject(
                WsCloseCode.PROTOCOL_ERROR,
                (
                    "client frame must be masked" if self._shared[].expect_masked_inbound else "server frame must not be masked"
                ),
            )
            return False

        var opcode = header.opcode
        if opcode == WsOpcode.CONTINUATION:
            if not self._fragment_open:
                self._reject(
                    WsCloseCode.PROTOCOL_ERROR,
                    "continuation frame without an open message",
                )
                return False
            if (
                header.payload_length
                > self._shared[].max_message_bytes - self._fragment_bytes
            ):
                self._reject(WsCloseCode.MESSAGE_TOO_BIG, "message_too_big")
                return False
        elif opcode == WsOpcode.TEXT or opcode == WsOpcode.BINARY:
            if self._fragment_open:
                self._reject(
                    WsCloseCode.PROTOCOL_ERROR,
                    "new data frame before fragmented message completion",
                )
                return False
            if header.payload_length > self._shared[].max_message_bytes:
                self._reject(WsCloseCode.MESSAGE_TOO_BIG, "message_too_big")
                return False
        elif (
            opcode != WsOpcode.CLOSE
            and opcode != WsOpcode.PING
            and opcode != WsOpcode.PONG
        ):
            self._reject(WsCloseCode.PROTOCOL_ERROR, "unknown WebSocket opcode")
            return False

        return (
            len(self._read_buffer)
            >= header.header_length + header.payload_length
        )

    def _record_fragment(mut self, frame: WsFrame):
        """Advance complete-message accounting after one decoded data frame."""
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

    def _try_decode(mut self) raises -> Optional[WsFrame]:
        if len(self._read_buffer) == 0:
            return Optional[WsFrame]()
        if not self._validate_header():
            return Optional[WsFrame]()
        try:
            var result = WsFrame.decode_one(Span[UInt8, _](self._read_buffer))
            var consumed = result.consumed
            var frame = result^.take_frame()
            var remainder = List[UInt8](
                capacity=len(self._read_buffer) - consumed
            )
            for index in range(consumed, len(self._read_buffer)):
                remainder.append(self._read_buffer[index])
            self._read_buffer = remainder^
            self._record_fragment(frame)
            return Optional[WsFrame](frame^)
        except error:
            var message = String(error)
            if (
                "need at least" in message
                or "need " in message
                or "truncated" in message
            ):
                return Optional[WsFrame]()
            self._terminate(message)
            raise error^

    def recv(mut self) raises -> WsFrame:
        """Receive the next non-PING frame and serialize automatic PONGs."""
        while True:
            var decoded = self._try_decode()
            if not decoded:
                self._drive_receive_once()
                continue
            var frame = decoded.take()
            if frame.opcode == WsOpcode.PING:
                var pong = WsFrame.pong(frame.payload)
                self._control_wire = self._shared[].encode_outbound(pong)
                self._control_pending = True
                self._flush_control()
                continue
            if frame.opcode == WsOpcode.CLOSE:
                var echo = self._shared[].note_peer_close()
                if echo:
                    var response = WsFrame(
                        opcode=WsOpcode.CLOSE, payload=frame.payload
                    )
                    try:
                        self._control_wire = self._shared[].encode_outbound(
                            response
                        )
                        self._control_pending = True
                        self._publish_terminal_control_once()
                    except:
                        pass
                self._terminate("WebSocket CLOSE received")
                return frame^
            self._service_one_outbound_step()
            return frame^

    def recv_message(mut self) raises -> WsMessage:
        """Receive one complete text or binary message."""
        var frame: WsFrame
        while True:
            frame = self.recv()
            if frame.opcode == WsOpcode.PONG:
                continue
            break
        if frame.opcode == WsOpcode.CLOSE:
            raise NetworkError("WebSocket CLOSE received")
        if frame.opcode != WsOpcode.TEXT and frame.opcode != WsOpcode.BINARY:
            self._terminate("unexpected frame while receiving a message")
            raise WsProtocolError("unexpected frame while receiving a message")
        var opcode = frame.opcode
        var message_complete = frame.fin
        var payload = frame.payload.copy()
        while not message_complete:
            frame = self.recv()
            if frame.opcode == WsOpcode.PONG:
                continue
            if frame.opcode == WsOpcode.CLOSE:
                raise NetworkError("WebSocket CLOSE received")
            if frame.opcode != WsOpcode.CONTINUATION:
                self._terminate("fragmented message interrupted")
                raise WsProtocolError("fragmented message interrupted")
            message_complete = frame.fin
            for byte in frame.payload:
                payload.append(byte)
        if opcode == WsOpcode.BINARY:
            return WsMessage(payload^)
        try:
            var complete = WsFrame(opcode=WsOpcode.TEXT, payload=payload^)
            return WsMessage(complete.text_payload())
        except error:
            self._terminate(String(error))
            raise error^


struct WsDuplex(Movable):
    """Move-only carrier returned by client or accepted-server ``split``.

    Mojo tuples cannot transfer several move-only elements by destructuring.
    This carrier gives each endpoint an explicit one-time take operation while
    preserving the connection's linear ownership in the type system.
    """

    var _sender: Optional[WsSender]
    var _receiver: Optional[WsReceiver]
    var _shutdown: Optional[WsShutdown]
    var _preadmission_release: Optional[WsPreadmissionRelease]

    def __init__(
        out self,
        var sender: WsSender,
        var receiver: WsReceiver,
        var shutdown: WsShutdown,
        var preadmission_release: Optional[WsPreadmissionRelease] = None,
    ):
        self._sender = Optional[WsSender](sender^)
        self._receiver = Optional[WsReceiver](receiver^)
        self._shutdown = Optional[WsShutdown](shutdown^)
        self._preadmission_release = preadmission_release^

    def take_sender(mut self) raises -> WsSender:
        """Take the sending endpoint exactly once."""
        if not self._sender:
            raise Error("WsDuplex sender already taken")
        return self._sender.take()

    def take_receiver(mut self) raises -> WsReceiver:
        """Take the receiving endpoint exactly once."""
        if not self._receiver:
            raise Error("WsDuplex receiver already taken")
        return self._receiver.take()

    def take_shutdown(mut self) raises -> WsShutdown:
        """Take the independent shutdown endpoint exactly once."""
        if not self._shutdown:
            raise Error("WsDuplex shutdown already taken")
        return self._shutdown.take()

    def take_preadmission_release(mut self) raises -> WsPreadmissionRelease:
        """Take shared-listener ownership release exactly once.

        Register the duplex shutdown handle with the next lifecycle owner
        before calling ``release()``. If not taken, destroying this carrier
        conservatively releases the ledger entry at connection close.
        """
        if not self._preadmission_release:
            raise Error("WebSocket pre-admission release is unavailable")
        return self._preadmission_release.take()


def _split_stream(
    var stream: _WsStream,
    control: ArcPointer[_WsControl],
    max_message_bytes: Int,
    mask_outbound: Bool = True,
    expect_masked_inbound: Bool = False,
    var preadmission_release: Optional[WsPreadmissionRelease] = None,
) raises -> WsDuplex:
    """Create duplex endpoints under an existing connection authority."""
    var shared = ArcPointer[_WsDuplexState](
        _WsDuplexState(
            stream^,
            control,
            mask_outbound,
            expect_masked_inbound,
            max_message_bytes,
        )
    )
    var sender = WsSender(shared)
    var receiver = WsReceiver(shared)
    var shutdown = WsShutdown(control, shared)
    return WsDuplex(sender^, receiver^, shutdown^, preadmission_release^)


def _split_stream(
    var stream: _WsStream,
    max_message_bytes: Int,
    mask_outbound: Bool = True,
    expect_masked_inbound: Bool = False,
    var preadmission_release: Optional[WsPreadmissionRelease] = None,
) raises -> WsDuplex:
    """Create duplex endpoints for the blocking-connect compatibility path."""
    var control = ArcPointer[_WsControl](_WsControl())
    return _split_stream(
        stream^,
        control,
        max_message_bytes,
        mask_outbound,
        expect_masked_inbound,
        preadmission_release^,
    )
