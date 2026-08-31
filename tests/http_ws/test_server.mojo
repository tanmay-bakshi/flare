"""Loopback conformance for the shared HTTP and WebSocket listener."""

from std.memory import ArcPointer, UnsafePointer
from std.memory.alloc import unsafe_alloc
from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.http import Handler, Request, Response, ok
from flare.http_ws import (
    HttpWsRoutes,
    HttpWsServer,
    HttpWsServerRuntime,
    HttpWsServerStop,
)
from flare.net import SocketAddr
from flare.runtime._libc_time import monotonic_now_ms
from flare.runtime._thread import ThreadHandle, _OpaquePtr
from flare.tcp import TcpStream
from flare.utils import usleep
from flare.ws import WsClient, WsConnection, WsHandler, WsOpcode
from flare.ws._duplex import _DuplexSync


comptime _WAIT_MS = 2_000


def _null_opaque_pointer() -> _OpaquePtr:
    var null_address = 0
    return _OpaquePtr(unsafe_from_address=null_address)


struct _Probe(Movable):
    """Mutex-guarded routing and connection observations."""

    var _sync: _DuplexSync
    var _http_calls: Int
    var _ws_a_entered: Int
    var _ws_b_entered: Int
    var _ws_active: Int
    var _ws_completed: Int

    def __init__(out self):
        self._sync = _DuplexSync()
        self._http_calls = 0
        self._ws_a_entered = 0
        self._ws_b_entered = 0
        self._ws_active = 0
        self._ws_completed = 0

    def record_http(mut self):
        self._sync.lock()
        self._http_calls += 1
        self._sync.unlock()

    def enter_ws(mut self, route: Int):
        self._sync.lock()
        if route == 1:
            self._ws_a_entered += 1
        else:
            self._ws_b_entered += 1
        self._ws_active += 1
        self._sync.unlock()

    def leave_ws(mut self):
        self._sync.lock()
        self._ws_active -= 1
        self._ws_completed += 1
        self._sync.unlock()

    def http_calls(mut self) -> Int:
        self._sync.lock()
        var value = self._http_calls
        self._sync.unlock()
        return value

    def ws_a_entered(mut self) -> Int:
        self._sync.lock()
        var value = self._ws_a_entered
        self._sync.unlock()
        return value

    def ws_b_entered(mut self) -> Int:
        self._sync.lock()
        var value = self._ws_b_entered
        self._sync.unlock()
        return value

    def ws_entered(mut self) -> Int:
        self._sync.lock()
        var value = self._ws_a_entered + self._ws_b_entered
        self._sync.unlock()
        return value

    def ws_active(mut self) -> Int:
        self._sync.lock()
        var value = self._ws_active
        self._sync.unlock()
        return value

    def ws_completed(mut self) -> Int:
        self._sync.lock()
        var value = self._ws_completed
        self._sync.unlock()
        return value


@fieldwise_init
struct _HttpHandler(Copyable, Handler, Movable):
    """HTTP handler that records dispatch and echoes the request target."""

    var probe: ArcPointer[_Probe]

    def serve(self, request: Request) raises -> Response:
        self.probe[].record_http()
        return ok(request.url)


@fieldwise_init
struct _WebSocketHandler(Copyable, Movable, WsHandler):
    """WebSocket handler that remains active until its peer closes."""

    var route: Int
    var probe: ArcPointer[_Probe]

    def on_connection(mut self, mut connection: WsConnection) raises:
        self.probe[].enter_ws(self.route)
        try:
            while True:
                var frame = connection.recv()
                if frame.opcode == WsOpcode.CLOSE:
                    break
                if frame.text_payload() == "fail":
                    raise Error("intentional per-connection failure")
                connection.send_text("route=" + String(self.route))
        except error:
            self.probe[].leave_ws()
            raise error^
        self.probe[].leave_ws()


def _routes(probe: ArcPointer[_Probe]) raises -> HttpWsRoutes[_HttpHandler]:
    var routes = HttpWsRoutes[_HttpHandler](_HttpHandler(probe.copy()))
    routes.websocket("/ws/a", _WebSocketHandler(1, probe.copy()))
    routes.websocket("/ws/b", _WebSocketHandler(2, probe.copy()))
    return routes^


def _url(port: UInt16, path: String) -> String:
    return "ws://127.0.0.1:" + String(Int(port)) + path


def _connect_eventually(url: String) raises -> WsClient:
    var deadline = monotonic_now_ms() + _WAIT_MS
    var last_error = String("")
    while monotonic_now_ms() < deadline:
        try:
            var client = WsClient.connect(url)
            return client^
        except error:
            last_error = String(error)
            usleep(1_000)
    raise Error("timed out waiting for connection admission: " + last_error)


def _send_get(mut stream: TcpStream, path: String) raises:
    var request = (
        "GET "
        + path
        + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    stream.write_all(Span[UInt8, _](request.as_bytes()))


def _send_upgrade(mut stream: TcpStream, path: String) raises:
    var request = (
        "GET "
        + path
        + " HTTP/1.1\r\n"
        + "Host: 127.0.0.1\r\n"
        + "Upgrade: websocket\r\n"
        + "Connection: Upgrade\r\n"
        + "Sec-WebSocket-Version: 13\r\n"
        + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        + "\r\n"
    )
    stream.write_all(Span[UInt8, _](request.as_bytes()))


def _try_read(mut stream: TcpStream) -> String:
    var buffer = List[UInt8](capacity=2048)
    buffer.resize(2048, 0)
    try:
        var count = stream.read(buffer.unsafe_ptr(), len(buffer))
        if count <= 0:
            return ""
        return String(unsafe_from_utf8=Span[UInt8, _](buffer)[0:count])
    except:
        return ""


def _read_response(
    mut stream: TcpStream, timeout_ms: Int = 1_000
) raises -> String:
    stream._socket.set_nonblocking(True)
    var response = String("")
    var deadline = monotonic_now_ms() + timeout_ms
    while monotonic_now_ms() < deadline:
        var chunk = _try_read(stream)
        if chunk.byte_length() > 0:
            response += chunk
            if "\r\n\r\n" in response:
                return response^
        usleep(1_000)
    return response^


def _wait_for_close(mut stream: TcpStream, timeout_ms: Int) raises -> Bool:
    stream._socket.set_nonblocking(True)
    var buffer = List[UInt8](capacity=2048)
    buffer.resize(2048, 0)
    var deadline = monotonic_now_ms() + timeout_ms
    while monotonic_now_ms() < deadline:
        try:
            var count = stream.read(buffer.unsafe_ptr(), len(buffer))
            if count == 0:
                return True
        except:
            pass
        usleep(1_000)
    return False


def _raw_get(port: UInt16, path: String) raises -> String:
    var stream = TcpStream.connect(SocketAddr.localhost(port))
    _send_get(stream, path)
    var response = _read_response(stream)
    stream.close()
    return response^


def _raw_upgrade(port: UInt16, path: String) raises -> String:
    var stream = TcpStream.connect(SocketAddr.localhost(port))
    _send_upgrade(stream, path)
    var response = _read_response(stream)
    stream.close()
    return response^


def _late_upgrade(port: UInt16, path: String) -> String:
    try:
        return _raw_upgrade(port, path)
    except:
        return ""


def _wait_for_active(probe: ArcPointer[_Probe], expected: Int) raises:
    var deadline = monotonic_now_ms() + _WAIT_MS
    while monotonic_now_ms() < deadline:
        if probe[].ws_active() == expected:
            return
        usleep(1_000)
    raise Error(
        "timed out waiting for active WebSocket handlers: expected "
        + String(expected)
        + ", got "
        + String(probe[].ws_active())
    )


def test_requires_positive_resource_bounds() raises:
    with assert_raises():
        _ = HttpWsServer.bind(
            SocketAddr.localhost(0),
            max_connections=0,
            header_timeout_ms=100,
            max_header_bytes=1024,
        )
    with assert_raises():
        _ = HttpWsServer.bind(
            SocketAddr.localhost(0),
            max_connections=1,
            header_timeout_ms=0,
            max_header_bytes=1024,
        )
    with assert_raises():
        _ = HttpWsServer.bind(
            SocketAddr.localhost(0),
            max_connections=1,
            header_timeout_ms=100,
            max_header_bytes=0,
        )
    with assert_raises():
        _ = HttpWsServer.bind(
            SocketAddr.localhost(0),
            max_connections=-1,
            header_timeout_ms=100,
            max_header_bytes=1024,
        )
    with assert_raises():
        _ = HttpWsServer.bind(
            SocketAddr.localhost(0),
            max_connections=1,
            header_timeout_ms=-1,
            max_header_bytes=1024,
        )
    with assert_raises():
        _ = HttpWsServer.bind(
            SocketAddr.localhost(0),
            max_connections=1,
            header_timeout_ms=100,
            max_header_bytes=-1,
        )
    with assert_raises():
        _ = HttpWsServer.bind(
            SocketAddr.localhost(0),
            max_connections=1,
            header_timeout_ms=9_223_372_036_855,
            max_header_bytes=1024,
        )


def test_dispatch_matrix_and_route_identity() raises:
    var probe = ArcPointer[_Probe](_Probe())
    var server = HttpWsServer.bind(
        SocketAddr.localhost(0),
        max_connections=8,
        header_timeout_ms=1_000,
        max_header_bytes=4096,
    )
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable(_routes(probe.copy()))

    var ws_path_http: String
    var http_path_upgrade: String
    var health: String
    try:
        ws_path_http = _raw_get(port, "/ws/a")
        http_path_upgrade = _raw_upgrade(port, "/healthz")
        health = _raw_get(port, "/healthz")

        var first = WsClient.connect(_url(port, "/ws/a"))
        first.send_text("which")
        assert_equal(first.recv().text_payload(), "route=1")
        first.close()

        var second = WsClient.connect(_url(port, "/ws/b"))
        second.send_text("which")
        assert_equal(second.recv().text_payload(), "route=2")
        second.close()
        _wait_for_active(probe.copy(), 0)
    except error:
        runtime^.stop_and_join()
        raise error^
    runtime^.stop_and_join()

    assert_true(" 426 " in ws_path_http, ws_path_http)
    assert_true(" 400 " in http_path_upgrade, http_path_upgrade)
    assert_false(" 101 " in http_path_upgrade, http_path_upgrade)
    assert_true(" 200 " in health, health)
    assert_equal(probe[].http_calls(), 1)
    assert_equal(probe[].ws_a_entered(), 1)
    assert_equal(probe[].ws_b_entered(), 1)


def test_concurrent_websockets_do_not_block_http() raises:
    var probe = ArcPointer[_Probe](_Probe())
    var server = HttpWsServer.bind(
        SocketAddr.localhost(0),
        max_connections=4,
        header_timeout_ms=1_000,
        max_header_bytes=4096,
    )
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable(_routes(probe.copy()))

    try:
        var first = WsClient.connect(_url(port, "/ws/a"))
        var second = WsClient.connect(_url(port, "/ws/b"))
        _wait_for_active(probe.copy(), 2)
        var health = _raw_get(port, "/healthz")
        assert_true(" 200 " in health, health)
        assert_equal(probe[].ws_active(), 2)
        first.close()
        second.close()
        _wait_for_active(probe.copy(), 0)
    except error:
        runtime^.stop_and_join()
        raise error^
    runtime^.stop_and_join()
    assert_equal(probe[].ws_completed(), 2)


def test_saturation_returns_503_before_upgrade_and_recovers() raises:
    var probe = ArcPointer[_Probe](_Probe())
    var server = HttpWsServer.bind(
        SocketAddr.localhost(0),
        max_connections=2,
        header_timeout_ms=1_000,
        max_header_bytes=4096,
    )
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable(_routes(probe.copy()))
    var saturated: String

    try:
        var first = WsClient.connect(_url(port, "/ws/a"))
        var second = WsClient.connect(_url(port, "/ws/b"))
        _wait_for_active(probe.copy(), 2)
        saturated = _raw_upgrade(port, "/ws/a")
        assert_equal(probe[].ws_entered(), 2)

        first.close()
        _wait_for_active(probe.copy(), 1)
        var recovered = _connect_eventually(_url(port, "/ws/a"))
        _wait_for_active(probe.copy(), 2)
        recovered.close()
        second.close()
        _wait_for_active(probe.copy(), 0)
    except error:
        runtime^.stop_and_join()
        raise error^
    runtime^.stop_and_join()

    assert_true(" 503 " in saturated, saturated)
    assert_false(" 101 " in saturated, saturated)
    assert_equal(probe[].ws_entered(), 3)


def test_partial_handshakes_count_toward_saturation() raises:
    var probe = ArcPointer[_Probe](_Probe())
    var server = HttpWsServer.bind(
        SocketAddr.localhost(0),
        max_connections=2,
        header_timeout_ms=2_000,
        max_header_bytes=4096,
    )
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable(_routes(probe.copy()))
    var saturated: String
    try:
        var first = TcpStream.connect(SocketAddr.localhost(port))
        var second = TcpStream.connect(SocketAddr.localhost(port))
        var partial = "GET /ws/a HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        first.write_all(Span[UInt8, _](partial.as_bytes()))
        second.write_all(Span[UInt8, _](partial.as_bytes()))
        var admission_deadline = monotonic_now_ms() + _WAIT_MS
        while runtime._state[].active() < 2:
            if monotonic_now_ms() >= admission_deadline:
                raise Error("partial handshakes were not both admitted")
            usleep(1_000)
        saturated = _raw_upgrade(port, "/ws/a")
        first.close()
        usleep(50_000)
        var recovered = _connect_eventually(_url(port, "/ws/a"))
        _wait_for_active(probe.copy(), 1)
        recovered.close()
        _wait_for_active(probe.copy(), 0)
        second.close()
    except error:
        runtime^.stop_and_join()
        raise error^
    runtime^.stop_and_join()

    assert_true(" 503 " in saturated, saturated)
    assert_false(" 101 " in saturated, saturated)
    assert_equal(probe[].ws_entered(), 1)
    assert_equal(probe[].http_calls(), 0)


def test_header_limit_rejects_before_dispatch() raises:
    var probe = ArcPointer[_Probe](_Probe())
    var server = HttpWsServer.bind(
        SocketAddr.localhost(0),
        max_connections=2,
        header_timeout_ms=1_000,
        max_header_bytes=128,
    )
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable(_routes(probe.copy()))
    var response: String
    var closed: Bool
    try:
        var stream = TcpStream.connect(SocketAddr.localhost(port))
        var request = (
            "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Large: "
            + ("x" * 512)
            + "\r\n\r\n"
        )
        stream.write_all(Span[UInt8, _](request.as_bytes()))
        response = _read_response(stream)
        closed = _wait_for_close(stream, 500)
        stream.close()
    except error:
        runtime^.stop_and_join()
        raise error^
    runtime^.stop_and_join()

    assert_false(" 200 " in response, response)
    assert_false(" 101 " in response, response)
    assert_true(closed, "oversized request connection remained open")
    assert_equal(probe[].http_calls(), 0)
    assert_equal(probe[].ws_entered(), 0)


def test_header_deadline_is_absolute_across_trickle_reads() raises:
    var probe = ArcPointer[_Probe](_Probe())
    var server = HttpWsServer.bind(
        SocketAddr.localhost(0),
        max_connections=2,
        header_timeout_ms=100,
        max_header_bytes=4096,
    )
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable(_routes(probe.copy()))
    var closed: Bool
    try:
        var stream = TcpStream.connect(SocketAddr.localhost(port))
        var prefix = "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        for index in range(5):
            try:
                var offset = index * 4
                var chunk = List[UInt8]()
                for byte_index in range(offset, offset + 4):
                    chunk.append(prefix.as_bytes()[byte_index])
                stream.write_all(Span[UInt8, _](chunk))
            except:
                break
            usleep(40_000)
        closed = _wait_for_close(stream, 500)
        stream.close()
    except error:
        runtime^.stop_and_join()
        raise error^
    runtime^.stop_and_join()

    assert_true(
        closed,
        "absolute header deadline did not expire during trickle reads",
    )
    assert_equal(probe[].http_calls(), 0)
    assert_equal(probe[].ws_entered(), 0)


struct _JoinResult(Movable):
    """Mutex-guarded completion result shared with a join thread."""

    var _sync: _DuplexSync
    var done: Bool
    var error_message: String

    def __init__(out self):
        self._sync = _DuplexSync()
        self.done = False
        self.error_message = ""

    def finish(mut self, error_message: String):
        self._sync.lock()
        self.error_message = error_message
        self.done = True
        self._sync.unlock()

    def is_done(mut self) -> Bool:
        self._sync.lock()
        var value = self.done
        self._sync.unlock()
        return value

    def error(mut self) -> String:
        self._sync.lock()
        var value = self.error_message.copy()
        self._sync.unlock()
        return value^


@fieldwise_init
struct _JoinContext(Movable):
    """Runtime allocation and shared result owned by a join thread."""

    var runtime_address: Int
    var result: ArcPointer[_JoinResult]


def _join_thread(argument: _OpaquePtr) -> _OpaquePtr:
    var context_pointer = argument.unsafe_bitcast[_JoinContext]()
    var context = context_pointer.take_pointee()
    context_pointer.unsafe_free()
    var runtime_pointer = UnsafePointer[
        HttpWsServerRuntime, MutUntrackedOrigin
    ](unsafe_from_address=context.runtime_address)
    var runtime = runtime_pointer.take_pointee()
    runtime_pointer.unsafe_free()
    var error_message = String("")
    try:
        runtime^.join()
    except error:
        error_message = String(error)
    context.result[].finish(error_message^)
    return _null_opaque_pointer()


def test_drain_first_stop_fences_admission_and_waits_for_handlers() raises:
    var probe = ArcPointer[_Probe](_Probe())
    var server = HttpWsServer.bind(
        SocketAddr.localhost(0),
        max_connections=4,
        header_timeout_ms=2_000,
        max_header_bytes=4096,
    )
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable(_routes(probe.copy()))
    var stop: HttpWsServerStop
    try:
        stop = runtime.take_stop()
    except error:
        runtime^.stop_and_join()
        raise error^

    var first: WsClient
    var second: WsClient
    try:
        first = WsClient.connect(_url(port, "/ws/a"))
        second = WsClient.connect(_url(port, "/ws/b"))
        _wait_for_active(probe.copy(), 2)
    except error:
        stop.stop()
        runtime^.join()
        raise error^

    stop.stop()
    var result = ArcPointer[_JoinResult](_JoinResult())
    var runtime_pointer = unsafe_alloc[HttpWsServerRuntime](1)
    runtime_pointer.unsafe_write(runtime^)
    var context = unsafe_alloc[_JoinContext](1)
    context.unsafe_write(_JoinContext(Int(runtime_pointer), result.copy()))
    var argument = _OpaquePtr(unsafe_from_address=Int(context))
    var join_thread = ThreadHandle.spawn[_join_thread](argument)

    usleep(100_000)
    var blocked_while_active = not result[].is_done()
    var late = _late_upgrade(port, "/ws/a")
    var entered_after_stop = probe[].ws_entered()
    first.close()
    second.close()
    join_thread.join()

    var join_error = result[].error()
    var joined = result[].is_done()
    var active_after_join = stop._state[].active()

    assert_true(blocked_while_active, "join returned before handlers drained")
    assert_false(" 101 " in late, late)
    assert_equal(entered_after_stop, 2)
    assert_true(joined, "join thread did not acknowledge completion")
    assert_equal(join_error, "")
    assert_equal(active_after_join, 0)
    assert_equal(probe[].ws_active(), 0)
    assert_equal(probe[].ws_completed(), 2)


def test_idle_and_stalled_header_stop_join_promptly() raises:
    var idle_probe = ArcPointer[_Probe](_Probe())
    var idle_server = HttpWsServer.bind(
        SocketAddr.localhost(0),
        max_connections=2,
        header_timeout_ms=5_000,
        max_header_bytes=4096,
    )
    var idle_runtime = idle_server^.serve_stoppable(_routes(idle_probe.copy()))
    var idle_started = monotonic_now_ms()
    idle_runtime^.stop_and_join()
    var idle_elapsed = monotonic_now_ms() - idle_started

    var stalled_probe = ArcPointer[_Probe](_Probe())
    var stalled_server = HttpWsServer.bind(
        SocketAddr.localhost(0),
        max_connections=2,
        header_timeout_ms=5_000,
        max_header_bytes=4096,
    )
    var stalled_port = stalled_server.local_addr().port
    var stalled_runtime = stalled_server^.serve_stoppable(
        _routes(stalled_probe.copy())
    )
    var stalled: TcpStream
    try:
        stalled = TcpStream.connect(SocketAddr.localhost(stalled_port))
        var partial = "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        stalled.write_all(Span[UInt8, _](partial.as_bytes()))
        var admission_deadline = monotonic_now_ms() + _WAIT_MS
        while stalled_runtime._state[].active() < 1:
            if monotonic_now_ms() >= admission_deadline:
                raise Error("stalled header was not admitted")
            usleep(1_000)
    except error:
        stalled_runtime^.stop_and_join()
        raise error^
    var stalled_started = monotonic_now_ms()
    stalled_runtime^.stop_and_join()
    var stalled_elapsed = monotonic_now_ms() - stalled_started
    stalled.close()

    assert_true(idle_elapsed < 1_000, "idle stop did not join promptly")
    assert_true(
        stalled_elapsed < 1_000, "stalled-header stop did not join promptly"
    )


def test_handler_failure_isolated_to_one_connection() raises:
    var probe = ArcPointer[_Probe](_Probe())
    var server = HttpWsServer.bind(
        SocketAddr.localhost(0),
        max_connections=4,
        header_timeout_ms=1_000,
        max_header_bytes=4096,
    )
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable(_routes(probe.copy()))

    try:
        var failed = WsClient.connect(_url(port, "/ws/a"))
        failed.send_text("fail")
        try:
            _ = failed.recv()
        except:
            pass
        failed.close()
        _wait_for_active(probe.copy(), 0)
        var health = _raw_get(port, "/healthz")
        assert_true(" 200 " in health, health)
    except error:
        runtime^.stop_and_join()
        raise error^
    runtime^.stop_and_join()
    assert_equal(probe[].ws_entered(), 1)
    assert_equal(probe[].ws_completed(), 1)
    assert_equal(probe[].http_calls(), 1)


def test_worker_error_surfaces_only_from_join() raises:
    var probe = ArcPointer[_Probe](_Probe())
    var server = HttpWsServer.bind(
        SocketAddr.localhost(0),
        max_connections=2,
        header_timeout_ms=1_000,
        max_header_bytes=4096,
    )
    var runtime = server^.serve_stoppable(_routes(probe.copy()))
    var stop: HttpWsServerStop
    try:
        stop = runtime.take_stop()
    except error:
        runtime^.stop_and_join()
        raise error^

    runtime._state[].record_worker_error("fatal-accept-probe")
    stop.stop()
    var message = String("")
    try:
        runtime^.join()
    except error:
        message = String(error)
    assert_true("fatal-accept-probe" in message, message)


def main() raises:
    test_requires_positive_resource_bounds()
    test_dispatch_matrix_and_route_identity()
    test_concurrent_websockets_do_not_block_http()
    test_saturation_returns_503_before_upgrade_and_recovers()
    test_partial_handshakes_count_toward_saturation()
    test_header_limit_rejects_before_dispatch()
    test_header_deadline_is_absolute_across_trickle_reads()
    test_drain_first_stop_fences_admission_and_waits_for_handlers()
    test_idle_and_stalled_header_stop_join_promptly()
    test_handler_failure_isolated_to_one_connection()
    test_worker_error_surfaces_only_from_join()
    print("test_http_ws_server: 11 passed")
