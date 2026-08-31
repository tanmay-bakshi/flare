"""Bounded, drain-first HTTP and WebSocket serving on one listener."""

from std.atomic import Atomic, Ordering
from std.ffi import c_int, get_errno
from std.memory import ArcPointer, UnsafePointer, alloc
from std.memory.alloc import unsafe_alloc

from flare.http._server.parse import _parse_http_request_bytes
from flare.http._server.write import _write_response_buffered
from flare.http.handler import Handler
from flare.http.proto.ascii import ascii_eq_ignore_case
from flare.http.request import Request
from flare.http.response import Response, Status
from flare.http.router import _path_only
from flare.net import SocketAddr
from flare.net._libc import INVALID_FD, SHUT_RDWR, _shutdown
from flare.runtime._libc_time import monotonic_now_ns
from flare.runtime._thread import ThreadHandle, _OpaquePtr
from flare.runtime.event import Event, INTEREST_READ
from flare.runtime.reactor import Reactor
from flare.tcp import TcpListener, TcpStream
from flare.ws._duplex import _DuplexSync
from flare.ws.server import (
    WsConnection,
    WsUpgradeRequest,
    _compute_accept_srv,
    _negotiate_subprotocol,
    _parse_ws_upgrade_bytes,
    _send_upgrade_response,
    _upgrade_headers_complete,
    _ws_accept_error_is_retryable,
)

from .routes import HttpWsRoutes, _HttpWsDispatch


comptime _LISTENER_TOKEN: UInt64 = 1
comptime _POLL_MS: Int = 100
comptime _SLOT_FREE: Int = 0
comptime _SLOT_RUNNING: Int = 1
comptime _SLOT_DONE: Int = 2
comptime _SLOT_REAPING: Int = 3
comptime _RESERVE_FULL: Int = -1
comptime _RESERVE_STOPPED: Int = -2
comptime _MAX_I64: Int64 = 9_223_372_036_854_775_807


def _null_opaque() -> _OpaquePtr:
    var zero = 0
    return _OpaquePtr(unsafe_from_address=zero)


@always_inline
def _load_i64_pointer(
    cell: UnsafePointer[Int64, MutUntrackedOrigin],
) -> Int64:
    return Atomic[DType.int64].load[ordering=Ordering.ACQUIRE](
        cell.unsafe_bitcast[Scalar[DType.int64]]()
    )


@always_inline
def _store_i64_pointer(
    cell: UnsafePointer[Int64, MutUntrackedOrigin], value: Int64
):
    Atomic[DType.int64].store[ordering=Ordering.RELEASE](
        cell.unsafe_bitcast[Scalar[DType.int64]](), value
    )


@always_inline
def _load_u8_pointer(
    cell: UnsafePointer[UInt8, MutUntrackedOrigin],
) -> UInt8:
    return Atomic[DType.uint8].load[ordering=Ordering.ACQUIRE](
        cell.unsafe_bitcast[Scalar[DType.uint8]]()
    )


@always_inline
def _store_u8_pointer(
    cell: UnsafePointer[UInt8, MutUntrackedOrigin], value: UInt8
):
    Atomic[DType.uint8].store[ordering=Ordering.RELEASE](
        cell.unsafe_bitcast[Scalar[DType.uint8]](), value
    )


def _header_has_token(value: String, token: StringSlice) -> Bool:
    var start = 0
    var length = value.byte_length()
    for cursor in range(length + 1):
        if cursor < length and value.unsafe_ptr()[cursor] != UInt8(44):
            continue
        var left = start
        var right = cursor
        while left < right and (
            value.unsafe_ptr()[left] == UInt8(32)
            or value.unsafe_ptr()[left] == UInt8(9)
        ):
            left += 1
        while right > left and (
            value.unsafe_ptr()[right - 1] == UInt8(32)
            or value.unsafe_ptr()[right - 1] == UInt8(9)
        ):
            right -= 1
        var member = String(unsafe_from_utf8=value.as_bytes()[left:right])
        if ascii_eq_ignore_case(member, token):
            return True
        start = cursor + 1
    return False


def _is_websocket_upgrade(request: Request) -> Bool:
    return _header_has_token(
        request.headers.get("upgrade"), "websocket"
    ) and _header_has_token(request.headers.get("connection"), "upgrade")


def _send_status(
    mut stream: TcpStream,
    status: Int,
    reason: String,
    advertise_upgrade: Bool = False,
):
    try:
        var response = Response(status=status, reason=reason)
        if advertise_upgrade:
            response.headers.set("Upgrade", "websocket")
        _write_response_buffered(stream, response^, keep_alive=False)
    except:
        pass


def _send_saturated(mut stream: TcpStream, timeout_ms: Int):
    try:
        stream.set_send_timeout(timeout_ms)
    except:
        return
    _send_status(stream, Status.SERVICE_UNAVAILABLE, "Service Unavailable")


@fieldwise_init
struct _HeaderResult(Movable):
    var bytes: List[UInt8]
    var error_status: Int


def _read_headers(
    mut stream: TcpStream,
    timeout_ms: Int,
    max_header_bytes: Int,
) -> _HeaderResult:
    var now = monotonic_now_ns()
    var duration_ns = Int64(timeout_ms) * 1_000_000
    if duration_ns > _MAX_I64 - now:
        return _HeaderResult(List[UInt8](), Status.REQUEST_TIMEOUT)
    var deadline = now + duration_ns
    var request = List[UInt8](capacity=min(max_header_bytes, 1024))
    var byte = List[UInt8](capacity=1)
    byte.append(UInt8(0))

    while True:
        var remaining_ns = deadline - monotonic_now_ns()
        if remaining_ns <= 0:
            return _HeaderResult(request^, Status.REQUEST_TIMEOUT)
        var remaining_ms = Int(remaining_ns // 1_000_000)
        if remaining_ns % 1_000_000 != 0:
            remaining_ms += 1
        try:
            stream.set_recv_timeout(remaining_ms)
            var count = stream.read(byte.unsafe_ptr(), 1)
            if count == 0:
                return _HeaderResult(request^, Status.BAD_REQUEST)
        except:
            return _HeaderResult(request^, Status.REQUEST_TIMEOUT)
        request.append(byte[0])
        if _upgrade_headers_complete(request):
            try:
                stream.set_recv_timeout(0)
            except:
                return _HeaderResult(request^, Status.BAD_REQUEST)
            return _HeaderResult(request^, 0)
        if len(request) >= max_header_bytes:
            return _HeaderResult(request^, Status.HEADER_FIELDS_TOO_LARGE)


struct _HttpWsServerState(Movable):
    """Admission fence, pre-admission socket ledger, and worker ledger."""

    var sync: _DuplexSync
    # Cross-thread markers live in stable heap cells. Direct atomic access to
    # these pointers remains valid when the owning state and its ArcPointer
    # handles move; taking Pointer(to=field) would instead project through the
    # current handle expression and would not establish stable shared storage.
    var stopping: UnsafePointer[UInt8, MutUntrackedOrigin]
    var slot_states: UnsafePointer[Int64, MutUntrackedOrigin]
    var preadmission_fds: UnsafePointer[Int64, MutUntrackedOrigin]
    var slot_capacity: Int
    var worker_error: String
    var worker_error_ready: UnsafePointer[UInt8, MutUntrackedOrigin]

    def __init__(out self, max_connections: Int):
        self.sync = _DuplexSync()
        self.stopping = unsafe_alloc[UInt8](1)
        self.stopping.unsafe_write(UInt8(0))
        self.slot_states = unsafe_alloc[Int64](max_connections)
        self.preadmission_fds = unsafe_alloc[Int64](max_connections)
        self.slot_capacity = max_connections
        for index in range(max_connections):
            self.slot_states.unsafe_offset(index).unsafe_write(
                Int64(_SLOT_FREE)
            )
            self.preadmission_fds.unsafe_offset(index).unsafe_write(
                Int64(INVALID_FD)
            )
        self.worker_error = ""
        self.worker_error_ready = unsafe_alloc[UInt8](1)
        self.worker_error_ready.unsafe_write(UInt8(0))

    def __deinit__(deinit self):
        self.stopping.unsafe_deinit_pointee()
        self.stopping.unsafe_free()
        for index in range(self.slot_capacity):
            self.slot_states.unsafe_offset(index).unsafe_deinit_pointee()
            self.preadmission_fds.unsafe_offset(index).unsafe_deinit_pointee()
        self.slot_states.unsafe_free()
        self.preadmission_fds.unsafe_free()
        self.worker_error_ready.unsafe_deinit_pointee()
        self.worker_error_ready.unsafe_free()

    def is_stopping(mut self) -> Bool:
        return _load_u8_pointer(self.stopping) != UInt8(0)

    def request_stop(mut self):
        self.sync.lock()
        if not self.is_stopping():
            _store_u8_pointer(self.stopping, UInt8(1))
            for index in range(self.slot_capacity):
                var fd = _load_i64_pointer(
                    self.preadmission_fds.unsafe_offset(index)
                )
                if fd != Int64(INVALID_FD):
                    _ = _shutdown(c_int(fd), SHUT_RDWR)
        self.sync.unlock()

    def reserve(mut self, fd: c_int) -> Int:
        self.sync.lock()
        if self.is_stopping():
            self.sync.unlock()
            return _RESERVE_STOPPED
        for index in range(self.slot_capacity):
            var slot = self.slot_states.unsafe_offset(index)
            if _load_i64_pointer(slot) != Int64(_SLOT_FREE):
                continue
            _store_i64_pointer(slot, Int64(_SLOT_RUNNING))
            _store_i64_pointer(
                self.preadmission_fds.unsafe_offset(index), Int64(fd)
            )
            self.sync.unlock()
            return index
        self.sync.unlock()
        return _RESERVE_FULL

    def cancel_unspawned(mut self, slot: Int):
        self.sync.lock()
        _store_i64_pointer(
            self.slot_states.unsafe_offset(slot), Int64(_SLOT_FREE)
        )
        _store_i64_pointer(
            self.preadmission_fds.unsafe_offset(slot), Int64(INVALID_FD)
        )
        self.sync.unlock()

    def claim_after_parse(mut self, slot: Int, fd: c_int) -> Bool:
        self.sync.lock()
        var owns = _load_i64_pointer(
            self.preadmission_fds.unsafe_offset(slot)
        ) == Int64(fd)
        if owns:
            _store_i64_pointer(
                self.preadmission_fds.unsafe_offset(slot), Int64(INVALID_FD)
            )
        var admitted = owns and not self.is_stopping()
        self.sync.unlock()
        return admitted

    def complete(mut self, slot: Int):
        self.sync.lock()
        _store_i64_pointer(
            self.preadmission_fds.unsafe_offset(slot), Int64(INVALID_FD)
        )
        _store_i64_pointer(
            self.slot_states.unsafe_offset(slot), Int64(_SLOT_DONE)
        )
        self.sync.unlock()

    def take_done(mut self, slot: Int) -> Bool:
        self.sync.lock()
        var cell = self.slot_states.unsafe_offset(slot)
        var done = _load_i64_pointer(cell) == Int64(_SLOT_DONE)
        if done:
            _store_i64_pointer(cell, Int64(_SLOT_REAPING))
        self.sync.unlock()
        return done

    def mark_free(mut self, slot: Int):
        self.sync.lock()
        _store_i64_pointer(
            self.slot_states.unsafe_offset(slot), Int64(_SLOT_FREE)
        )
        self.sync.unlock()

    def active(mut self) -> Int:
        self.sync.lock()
        var count = self._active_locked()
        self.sync.unlock()
        return count

    def _active_locked(mut self) -> Int:
        var count = 0
        for index in range(self.slot_capacity):
            if _load_i64_pointer(
                self.slot_states.unsafe_offset(index)
            ) == Int64(_SLOT_RUNNING):
                count += 1
        return count

    def record_worker_error(mut self, message: String):
        self.sync.lock()
        if _load_u8_pointer(self.worker_error_ready) == UInt8(0):
            self.worker_error = message
            _store_u8_pointer(self.worker_error_ready, UInt8(1))
        self.sync.unlock()

    def raise_worker_error(mut self) raises:
        self.sync.lock()
        var ready = _load_u8_pointer(self.worker_error_ready) != UInt8(0)
        var message = self.worker_error.copy() if ready else String("")
        self.sync.unlock()
        if message.byte_length() > 0:
            raise Error("HTTP/WS server worker failed: " + message)


struct _ConnectionContext[H: Handler & Copyable](Movable):
    var stream: Optional[TcpStream]
    var routes: _HttpWsDispatch[Self.H]
    var state: ArcPointer[_HttpWsServerState]
    var slot: Int
    var header_timeout_ms: Int
    var max_header_bytes: Int

    def __init__(
        out self,
        var stream: TcpStream,
        var routes: _HttpWsDispatch[Self.H],
        state: ArcPointer[_HttpWsServerState],
        slot: Int,
        header_timeout_ms: Int,
        max_header_bytes: Int,
    ):
        self.stream = stream^
        self.routes = routes^
        self.state = state
        self.slot = slot
        self.header_timeout_ms = header_timeout_ms
        self.max_header_bytes = max_header_bytes


def _serve_connection[
    H: Handler & Copyable
](mut context: _ConnectionContext[H]):
    var fd = context.stream.value()._socket.fd
    var header = _read_headers(
        context.stream.value(),
        context.header_timeout_ms,
        context.max_header_bytes,
    )
    if header.error_status != 0:
        if context.state[].claim_after_parse(context.slot, fd):
            if header.error_status == Status.HEADER_FIELDS_TOO_LARGE:
                _send_status(
                    context.stream.value(),
                    header.error_status,
                    "Request Header Fields Too Large",
                )
            elif header.error_status == Status.REQUEST_TIMEOUT:
                _send_status(
                    context.stream.value(),
                    header.error_status,
                    "Request Timeout",
                )
            else:
                _send_status(
                    context.stream.value(), header.error_status, "Bad Request"
                )
        return

    var request: Request
    try:
        request = _parse_http_request_bytes(
            Span[UInt8, _](header.bytes),
            max_header_size=context.max_header_bytes,
            max_body_size=0,
            max_uri_length=context.max_header_bytes,
            peer=context.stream.value().peer_addr(),
        )
    except:
        if context.state[].claim_after_parse(context.slot, fd):
            _send_status(
                context.stream.value(), Status.BAD_REQUEST, "Bad Request"
            )
        return

    var path = _path_only(request.url)
    var ws_index = context.routes._ws_index(path)
    var is_upgrade = _is_websocket_upgrade(request)

    if is_upgrade and ws_index >= 0:
        var ws_request: WsUpgradeRequest
        var subprotocol: Optional[String]
        var accept: String
        try:
            ws_request = _parse_ws_upgrade_bytes(Span[UInt8, _](header.bytes))
            subprotocol = _negotiate_subprotocol(
                ws_request, context.routes._ws_subprotocols(ws_index)
            )
            accept = _compute_accept_srv(ws_request.key)
        except:
            if context.state[].claim_after_parse(context.slot, fd):
                _send_status(
                    context.stream.value(), Status.BAD_REQUEST, "Bad Request"
                )
            return
        if not context.state[].claim_after_parse(context.slot, fd):
            return
        try:
            _send_upgrade_response(context.stream.value(), accept, subprotocol)
            var stream = context.stream.take()
            var connection = WsConnection(
                stream^,
                request.peer,
                ws_request^,
                subprotocol^,
            )
            context.routes._serve_ws(ws_index, connection)
        except:
            pass
        return

    if not context.state[].claim_after_parse(context.slot, fd):
        return
    if is_upgrade:
        _send_status(context.stream.value(), Status.BAD_REQUEST, "Bad Request")
        return
    if not is_upgrade and ws_index >= 0:
        _send_status(
            context.stream.value(),
            426,
            "Upgrade Required",
            advertise_upgrade=True,
        )
        return
    try:
        var response = context.routes._serve_http(request^)
        _write_response_buffered(
            context.stream.value(), response^, keep_alive=False
        )
    except:
        _send_status(
            context.stream.value(),
            Status.INTERNAL_SERVER_ERROR,
            "Internal Server Error",
        )


def _connection_entry[H: Handler & Copyable](arg: _OpaquePtr) -> _OpaquePtr:
    var pointer = UnsafePointer[_ConnectionContext[H], MutUntrackedOrigin](
        unsafe_from_address=Int(arg)
    )
    var state = pointer[].state.copy()
    var slot = pointer[].slot
    _serve_connection(pointer[])
    state[].complete(slot)
    pointer.unsafe_deinit_pointee()
    pointer.unsafe_free()
    return _null_opaque()


struct _AcceptContext[H: Handler & Copyable](Movable):
    var listener: TcpListener
    var reactor: Reactor
    var routes: _HttpWsDispatch[Self.H]
    var state: ArcPointer[_HttpWsServerState]
    var threads: UnsafePointer[ThreadHandle, MutUntrackedOrigin]
    var has_thread: List[Bool]
    var header_timeout_ms: Int
    var max_header_bytes: Int

    def __init__(
        out self,
        var listener: TcpListener,
        var reactor: Reactor,
        var routes: _HttpWsDispatch[Self.H],
        state: ArcPointer[_HttpWsServerState],
        max_connections: Int,
        header_timeout_ms: Int,
        max_header_bytes: Int,
    ):
        self.listener = listener^
        self.reactor = reactor^
        self.routes = routes^
        self.state = state
        self.threads = alloc[ThreadHandle](max_connections)
        self.has_thread = List[Bool]()
        for _ in range(max_connections):
            self.has_thread.append(False)
        self.header_timeout_ms = header_timeout_ms
        self.max_header_bytes = max_header_bytes

    def __deinit__(deinit self):
        for index in range(len(self.has_thread)):
            if self.has_thread[index]:
                try:
                    self.threads.unsafe_offset(index)[].join()
                except:
                    pass
                self.threads.unsafe_offset(index).unsafe_deinit_pointee()
        self.threads.unsafe_free()


def _reap_done[H: Handler & Copyable](mut context: _AcceptContext[H]) raises:
    for slot in range(len(context.has_thread)):
        if not context.has_thread[slot] or not context.state[].take_done(slot):
            continue
        context.threads.unsafe_offset(slot)[].join()
        context.threads.unsafe_offset(slot).unsafe_deinit_pointee()
        context.has_thread[slot] = False
        context.state[].mark_free(slot)


def _run_accept_loop[
    H: Handler & Copyable
](mut context: _AcceptContext[H]) raises:
    var events = List[Event]()
    var listener_open = True
    while True:
        _reap_done(context)
        if context.state[].is_stopping():
            if listener_open:
                try:
                    context.reactor.unregister(context.listener.as_raw_fd())
                except:
                    pass
                context.listener.close()
                listener_open = False
            if context.state[].active() == 0:
                _reap_done(context)
                return
            _ = context.reactor.poll(_POLL_MS, events)
            continue

        var event_count = context.reactor.poll(_POLL_MS, events)
        for event_index in range(event_count):
            var event = events[event_index]
            if event.is_wakeup() or event.token != _LISTENER_TOKEN:
                continue
            var stream: TcpStream
            try:
                stream = context.listener.accept()
            except error:
                var accept_error = get_errno()
                if context.state[].is_stopping():
                    continue
                if _ws_accept_error_is_retryable(accept_error):
                    continue
                raise error^
            stream._socket.set_nonblocking(False)
            var slot = context.state[].reserve(stream._socket.fd)
            if slot == _RESERVE_STOPPED:
                stream.close()
                continue
            if slot == _RESERVE_FULL:
                _send_saturated(stream, context.header_timeout_ms)
                stream.close()
                continue

            var pointer = unsafe_alloc[_ConnectionContext[H]](1)
            pointer.unsafe_write(
                _ConnectionContext[H](
                    stream^,
                    context.routes.copy(),
                    context.state.copy(),
                    slot,
                    context.header_timeout_ms,
                    context.max_header_bytes,
                )
            )
            try:
                var thread = ThreadHandle.spawn[_connection_entry[H]](
                    _OpaquePtr(unsafe_from_address=Int(pointer))
                )
                context.threads.unsafe_offset(slot).unsafe_write(thread^)
                context.has_thread[slot] = True
            except error:
                pointer.unsafe_deinit_pointee()
                pointer.unsafe_free()
                context.state[].cancel_unspawned(slot)
                raise error^


def _accept_entry[H: Handler & Copyable](arg: _OpaquePtr) -> _OpaquePtr:
    var pointer = UnsafePointer[_AcceptContext[H], MutUntrackedOrigin](
        unsafe_from_address=Int(arg)
    )
    try:
        _run_accept_loop(pointer[])
    except error:
        pointer[].state[].record_worker_error(String(error))
        pointer[].state[].request_stop()
        try:
            _run_accept_loop(pointer[])
        except drain_error:
            pointer[].state[].record_worker_error(String(drain_error))
    pointer.unsafe_deinit_pointee()
    pointer.unsafe_free()
    return _null_opaque()


struct HttpWsServerStop(Movable):
    """Independent, idempotent request-admission fence."""

    var _state: ArcPointer[_HttpWsServerState]

    def __init__(out self, state: ArcPointer[_HttpWsServerState]):
        self._state = state

    def stop(mut self):
        self._state[].request_stop()


@explicit_destroy(
    "HttpWsServerRuntime must be consumed with join() or stop_and_join()"
)
struct HttpWsServerRuntime(Deinitable where False, Movable):
    """Linear owner of the accept worker and all connection workers."""

    var _state: ArcPointer[_HttpWsServerState]
    var _thread: ThreadHandle
    var _stop_taken: Bool

    def __init__(
        out self,
        state: ArcPointer[_HttpWsServerState],
        var thread: ThreadHandle,
    ):
        self._state = state
        self._thread = thread^
        self._stop_taken = False

    def take_stop(mut self) raises -> HttpWsServerStop:
        if self._stop_taken:
            raise Error("HttpWsServerRuntime stop already taken")
        self._stop_taken = True
        return HttpWsServerStop(self._state.copy())

    def join(deinit self) raises:
        self._thread.join()
        self._state[].raise_worker_error()

    def stop_and_join(deinit self) raises:
        self._state[].request_stop()
        self._thread.join()
        self._state[].raise_worker_error()


struct HttpWsServer(Movable):
    """One TCP listener dispatching HTTP and WebSocket work by path."""

    var _listener: TcpListener
    var _max_connections: Int
    var _header_timeout_ms: Int
    var _max_header_bytes: Int

    def __init__(
        out self,
        var listener: TcpListener,
        max_connections: Int,
        header_timeout_ms: Int,
        max_header_bytes: Int,
    ):
        self._listener = listener^
        self._max_connections = max_connections
        self._header_timeout_ms = header_timeout_ms
        self._max_header_bytes = max_header_bytes

    def __deinit__(deinit self):
        self._listener.close()

    @staticmethod
    def bind(
        addr: SocketAddr,
        max_connections: Int,
        header_timeout_ms: Int,
        max_header_bytes: Int,
    ) raises -> HttpWsServer:
        if max_connections <= 0:
            raise Error("max_connections must be positive")
        if header_timeout_ms <= 0:
            raise Error("header_timeout_ms must be positive")
        if max_header_bytes <= 0:
            raise Error("max_header_bytes must be positive")
        if Int64(header_timeout_ms) > _MAX_I64 // 1_000_000:
            raise Error("header_timeout_ms is too large")
        return HttpWsServer(
            TcpListener.bind(addr),
            max_connections,
            header_timeout_ms,
            max_header_bytes,
        )

    def local_addr(self) -> SocketAddr:
        return self._listener.local_addr()

    def serve_stoppable[
        H: Handler & Copyable
    ](deinit self, var routes: HttpWsRoutes[H],) raises -> HttpWsServerRuntime:
        """Launch the bounded server and return its acknowledged lifecycle."""
        self._listener._socket.set_nonblocking(True)
        var reactor = Reactor()
        reactor.register(
            self._listener.as_raw_fd(), _LISTENER_TOKEN, INTEREST_READ
        )
        var state = ArcPointer[_HttpWsServerState](
            _HttpWsServerState(self._max_connections)
        )
        var dispatch = routes^._freeze()
        var pointer = unsafe_alloc[_AcceptContext[H]](1)
        pointer.unsafe_write(
            _AcceptContext[H](
                self._listener^,
                reactor^,
                dispatch^,
                state.copy(),
                self._max_connections,
                self._header_timeout_ms,
                self._max_header_bytes,
            )
        )
        var thread: ThreadHandle
        try:
            thread = ThreadHandle.spawn[_accept_entry[H]](
                _OpaquePtr(unsafe_from_address=Int(pointer))
            )
        except error:
            pointer.unsafe_deinit_pointee()
            pointer.unsafe_free()
            raise error^
        return HttpWsServerRuntime(state.copy(), thread^)
