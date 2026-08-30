"""Full-duplex WebSocket endpoints backed by one transport owner loop."""

from std.atomic import Atomic, Ordering
from std.collections import Optional
from std.ffi import c_int, external_call
from std.memory import ArcPointer, Pointer
from std.memory.alloc import unsafe_alloc
from std.os import abort

from ._message import WsMessage
from ._transport import _WsStream
from .frame import WsFrame, WsOpcode, _encode_client_frame
from ..net import NetworkError
from ..net._libc import _shutdown, SHUT_RDWR
from ..runtime.event import Event, INTEREST_READ, INTEREST_WRITE
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


struct _WsDuplexState(Movable):
    """Shared control plane; the receiver exclusively owns stream I/O."""

    var sync: _DuplexSync
    var stream: _WsStream
    var reactor: Reactor
    var raw_fd: c_int
    var stopping: UInt8
    var owner_closed: UInt8
    var failure_message: String
    var next_command_id: Int64
    var pending_command_id: Int64
    var pending_wire: List[UInt8]
    var active_command_id: Int64
    var completed_command_id: Int64

    def __init__(out self, var stream: _WsStream) raises:
        stream.prepare_duplex()
        var raw_fd = stream.fd()
        var reactor = Reactor()
        reactor.register(raw_fd, _WS_STREAM_TOKEN, INTEREST_READ)
        self.sync = _DuplexSync()
        self.stream = stream^
        self.reactor = reactor^
        self.raw_fd = raw_fd
        self.stopping = UInt8(0)
        self.owner_closed = UInt8(0)
        self.failure_message = ""
        self.next_command_id = 0
        self.pending_command_id = 0
        self.pending_wire = List[UInt8]()
        self.active_command_id = 0
        self.completed_command_id = 0

    def send(mut self, var wire: List[UInt8]) raises:
        """Queue one frame and wait for owner-loop publication."""
        self.sync.lock()
        if self.is_stopping():
            var message = self.failure_message.copy()
            self.sync.unlock()
            raise NetworkError(
                message if message != "" else "WebSocket duplex is stopped"
            )
        if (
            _load_i64(self.pending_command_id) != 0
            or _load_i64(self.active_command_id) != 0
        ):
            self.sync.unlock()
            raise NetworkError(
                "WsSender supports exactly one sending thread per connection"
            )
        self.next_command_id += 1
        var command_id = self.next_command_id
        self.pending_wire = wire^
        _store_i64(self.pending_command_id, command_id)
        self.sync.unlock()

        try:
            self.reactor.wakeup()
        except:
            pass

        self.sync.lock()
        while (
            self.load_completed_command_id() < command_id
            and not self.is_stopping()
        ):
            self.sync.wait()
        if self.load_completed_command_id() >= command_id:
            self.sync.unlock()
            return
        var message = self.failure_message.copy()
        self.sync.unlock()
        raise NetworkError(
            message if message != "" else "WebSocket send interrupted"
        )

    def take_pending(mut self) -> Optional[_WsWriteCommand]:
        """Move one queued command into the owner loop."""
        self.sync.lock()
        var command_id = _load_i64(self.pending_command_id)
        if command_id == 0:
            self.sync.unlock()
            return Optional[_WsWriteCommand]()
        var wire = self.pending_wire^
        self.pending_wire = List[UInt8]()
        var command = _WsWriteCommand(command_id, wire^)
        _store_i64(self.active_command_id, command_id)
        _store_i64(self.pending_command_id, 0)
        self.sync.unlock()
        return Optional[_WsWriteCommand](command^)

    def complete(mut self, command_id: Int64):
        """Acknowledge a command after every frame byte reaches the fd."""
        self.sync.lock()
        if _load_i64(self.active_command_id) == command_id:
            _store_i64(self.active_command_id, 0)
            _store_i64(self.completed_command_id, command_id)
            self.sync.broadcast()
        self.sync.unlock()

    def is_stopping(mut self) -> Bool:
        return _load_u8(self.stopping) != UInt8(0)

    def load_completed_command_id(mut self) -> Int64:
        return _load_i64(self.completed_command_id)

    def stop(mut self, message: String):
        """Fix terminal state, interrupt the fd, and wake all waiters."""
        self.sync.lock()
        if not self.is_stopping():
            self.failure_message = message
            self.pending_wire.clear()
            _store_i64(self.pending_command_id, 0)
            _store_u8(self.stopping, UInt8(1))
            if _load_u8(self.owner_closed) == UInt8(0):
                _ = _shutdown(self.raw_fd, SHUT_RDWR)
        self.sync.broadcast()
        self.sync.unlock()
        try:
            self.reactor.wakeup()
        except:
            pass

    def close_from_owner(mut self):
        """Reclaim TLS and socket state on its sole owning thread."""
        self.sync.lock()
        if _load_u8(self.owner_closed) == UInt8(0):
            _store_u8(self.owner_closed, UInt8(1))
            self.stream.close_abortive()
        self.sync.broadcast()
        self.sync.unlock()


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

    def send_binary(mut self, data: List[UInt8]) raises:
        """Send one masked binary frame."""
        self.send_frame(WsFrame.binary(data))

    def send_frame(mut self, frame: WsFrame) raises:
        """Send one frame through the receiver-owned stream."""
        var wire = _encode_client_frame(frame)
        self._shared[].send(wire^)


struct WsShutdown(Movable):
    """Independent, idempotent shutdown handle for a split connection."""

    var _shared: ArcPointer[_WsDuplexState]

    def __init__(out self, shared: ArcPointer[_WsDuplexState]):
        self._shared = shared

    def shutdown(mut self):
        """Interrupt the socket and wake a receiver blocked in its reactor."""
        self._shared[].stop("WebSocket duplex shut down")


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
            self._out_command_id = -1
            return
        if not include_application:
            return
        var pending = self._shared[].take_pending()
        if not pending:
            return
        var command = pending.take()
        self._out_command_id = command.id
        self._out_wire = command.take_wire()
        self._out_offset = 0

    def _fail(mut self, message: String) raises:
        self._terminate(message)
        raise NetworkError(message)

    def _terminate(mut self, message: String):
        self._shared[].stop(message)
        self._shared[].close_from_owner()

    def _check_running(mut self) raises:
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
            self._shared[].reactor.modify(self._shared[].raw_fd, interest)
            _ = self._shared[].reactor.poll(-1, self._events)
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

    def _try_decode(mut self) raises -> Optional[WsFrame]:
        if len(self._read_buffer) == 0:
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
                self._control_wire = _encode_client_frame(pong)
                self._control_pending = True
                self._flush_control()
                continue
            if frame.opcode == WsOpcode.CLOSE:
                self._terminate("WebSocket CLOSE received")
                return frame^
            self._service_one_outbound_step()
            return frame^

    def recv_message(mut self) raises -> WsMessage:
        """Receive one complete text or binary message."""
        var frame = self.recv()
        if frame.opcode == WsOpcode.CLOSE:
            raise NetworkError("WebSocket CLOSE received")
        if frame.opcode == WsOpcode.BINARY:
            return WsMessage(frame.payload)
        try:
            return WsMessage(frame.text_payload())
        except error:
            self._terminate(String(error))
            raise error^


struct WsDuplex(Movable):
    """Move-only carrier returned by :meth:`WsClient.split`.

    Mojo tuples cannot transfer several move-only elements by destructuring.
    This carrier gives each endpoint an explicit one-time take operation while
    preserving the connection's linear ownership in the type system.
    """

    var _sender: Optional[WsSender]
    var _receiver: Optional[WsReceiver]
    var _shutdown: Optional[WsShutdown]

    def __init__(
        out self,
        var sender: WsSender,
        var receiver: WsReceiver,
        var shutdown: WsShutdown,
    ):
        self._sender = Optional[WsSender](sender^)
        self._receiver = Optional[WsReceiver](receiver^)
        self._shutdown = Optional[WsShutdown](shutdown^)

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


def _split_stream(var stream: _WsStream) raises -> WsDuplex:
    """Create public duplex endpoints around one stream-owner state."""
    var shared = ArcPointer[_WsDuplexState](_WsDuplexState(stream^))
    var sender = WsSender(shared)
    var receiver = WsReceiver(shared)
    var shutdown = WsShutdown(shared)
    return WsDuplex(sender^, receiver^, shutdown^)
