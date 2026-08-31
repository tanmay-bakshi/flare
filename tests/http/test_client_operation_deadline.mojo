"""Whole-operation deadline tests for the blocking HTTP client."""

from std.memory import UnsafePointer
from std.memory.alloc import unsafe_alloc
from std.testing import assert_equal, assert_raises, assert_true

from flare.http import HttpClient, HttpServer, Method, Request, Response
from flare.http._server.responses import ok, redirect
from flare.net import SocketAddr
from flare.runtime._libc_time import monotonic_now_ms
from flare.runtime._thread import ThreadHandle, _OpaquePtr, _null_ptr
from flare.tcp import TcpListener
from flare.testing import fork_server, kill_forked_server
from flare.utils import usleep


comptime _IMMEDIATE: Int = 0
comptime _TRICKLE: Int = 1


struct _ServerContext(Movable):
    var listener: TcpListener
    var mode: Int

    def __init__(out self, var listener: TcpListener, mode: Int):
        self.listener = listener^
        self.mode = mode


def _serve_once(argument: _OpaquePtr) -> _OpaquePtr:
    var pointer = argument.unsafe_bitcast[_ServerContext]()
    var context = pointer.unsafe_take_pointee()
    pointer.unsafe_free()
    try:
        var stream = context.listener.accept()
        var request = List[UInt8](capacity=4096)
        request.resize(4096, UInt8(0))
        _ = stream.read(request.unsafe_ptr(), len(request))
        var head = (
            "HTTP/1.1 200 OK\r\n"
            + "Content-Length: 5\r\n"
            + "Connection: close\r\n\r\n"
        )
        stream.write_all(Span[UInt8, _](head.as_bytes()))
        var body = String("hello")
        if context.mode == _IMMEDIATE:
            stream.write_all(Span[UInt8, _](body.as_bytes()))
        else:
            for index in range(body.byte_length()):
                var byte = List[UInt8](capacity=1)
                byte.append(body.as_bytes()[index])
                stream.write_all(Span[UInt8, _](byte))
                usleep(40_000)
        stream.close()
    except:
        pass
    context.listener.close()
    return _null_ptr()


@explicit_destroy("_Server must be consumed with join()")
struct _Server(Deinitable where False, Movable):
    var port: UInt16
    var thread: ThreadHandle

    def __init__(out self, port: UInt16, var thread: ThreadHandle):
        self.port = port
        self.thread = thread^

    def join(deinit self) raises:
        self.thread.join()


def _start_server(mode: Int) raises -> _Server:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var context = unsafe_alloc[_ServerContext](1)
    context.unsafe_write(_ServerContext(listener^, mode))
    var thread: ThreadHandle
    try:
        thread = ThreadHandle.spawn[_serve_once](
            _OpaquePtr(unsafe_from_address=Int(context))
        )
    except error:
        context.unsafe_deinit_pointee()
        context.unsafe_free()
        raise error^
    return _Server(port, thread^)


def _url(port: UInt16) -> String:
    return "http://127.0.0.1:" + String(Int(port)) + "/"


def _slow_redirect(request: Request) raises -> Response:
    usleep(60_000)
    if request.url.startswith("/start"):
        return redirect("/finish", 302)
    return ok("done")


def _pooled(request: Request) raises -> Response:
    if request.url.startswith("/slow"):
        usleep(150_000)
    return ok(request.url)


def test_rejects_non_positive_duration_before_io() raises:
    with HttpClient() as client:
        with assert_raises():
            _ = client.send_within(
                Request(method=Method.GET, url="http://127.0.0.1:1/"),
                0,
            )
        with assert_raises():
            _ = client.send_within(
                Request(method=Method.GET, url="http://127.0.0.1:1/"),
                -1,
            )
        with assert_raises():
            _ = client.send_within(
                Request(method=Method.GET, url="http://127.0.0.1:1/"),
                9_223_372_036_855,
            )


def test_successful_loopback_request_within_budget() raises:
    var server = _start_server(_IMMEDIATE)
    try:
        with HttpClient() as client:
            var response = client.send_within(
                Request(method=Method.GET, url=_url(server.port)),
                1_000,
            )
            assert_equal(response.status, 200)
            assert_equal(response.text(), "hello")
    except error:
        server^.join()
        raise error^
    server^.join()


def test_trickling_response_cannot_reset_total_budget() raises:
    var server = _start_server(_TRICKLE)
    var started = monotonic_now_ms()
    var failed = False
    try:
        with HttpClient(timeout_ms=1_000) as client:
            _ = client.send_within(
                Request(method=Method.GET, url=_url(server.port)),
                110,
            )
    except:
        failed = True
    var elapsed = monotonic_now_ms() - started
    server^.join()
    assert_true(failed, "trickling response escaped its operation deadline")
    assert_true(elapsed < 600, "operation deadline did not bound the read")


def test_redirects_share_the_original_budget() raises:
    var http = HttpServer.bind(SocketAddr.localhost(0))
    var port = http.local_addr().port
    var pid = fork_server(http^, _slow_redirect)
    var failed = False
    var started = monotonic_now_ms()
    try:
        with HttpClient(timeout_ms=1_000) as client:
            _ = client.send_within(
                Request(
                    method=Method.GET,
                    url=_url(port) + "start",
                ),
                100,
            )
    except:
        failed = True
    var elapsed = monotonic_now_ms() - started
    kill_forked_server(pid)
    assert_true(failed, "redirect minted a new operation budget")
    assert_true(elapsed < 600, "redirect exceeded its operation bound")


def test_pooled_stream_does_not_retain_completed_deadline() raises:
    var http = HttpServer.bind(SocketAddr.localhost(0))
    var port = http.local_addr().port
    var pid = fork_server(http^, _pooled)
    var base = _url(port)
    try:
        with HttpClient().with_pool() as client:
            var first = client.send_within(
                Request(method=Method.GET, url=base + "first"),
                1_000,
            )
            assert_equal(first.status, 200)
            usleep(1_050_000)
            var second = client.get(base + "slow")
            assert_equal(second.status, 200)
            assert_equal(second.text(), "/slow")
    except error:
        kill_forked_server(pid)
        raise error^
    kill_forked_server(pid)


def main() raises:
    test_rejects_non_positive_duration_before_io()
    test_successful_loopback_request_within_budget()
    test_trickling_response_cannot_reset_total_budget()
    test_redirects_share_the_original_budget()
    test_pooled_stream_does_not_retain_completed_deadline()
    print("test_client_operation_deadline: 5 passed")
