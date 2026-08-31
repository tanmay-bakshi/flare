"""Real-loopback coverage for the stoppable WebSocket server runtime."""

from std.atomic import Atomic, Ordering
from std.memory import ArcPointer, Pointer
from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.net import SocketAddr
from flare.runtime._libc_time import monotonic_now_ms
from flare.runtime.reactor import Reactor
from flare.tcp import TcpListener, TcpStream
from flare.utils import usleep
from flare.ws import (
    WsClient,
    WsConnection,
    WsFrame,
    WsHandler,
    WsOpcode,
    WsServer,
    WsServerStop,
)
from flare.ws.server import _WsServerState


struct _Probe(Movable):
    """Atomic counters shared between the worker handler and test thread."""

    var entered: Int64
    var completed: Int64

    def __init__(out self):
        self.entered = 0
        self.completed = 0

    def load_entered(mut self) -> Int64:
        return Atomic[DType.int64].load[ordering=Ordering.ACQUIRE](
            Pointer(to=self.entered).unsafe_bitcast[Scalar[DType.int64]]()
        )

    def load_completed(mut self) -> Int64:
        return Atomic[DType.int64].load[ordering=Ordering.ACQUIRE](
            Pointer(to=self.completed).unsafe_bitcast[Scalar[DType.int64]]()
        )

    def add_entered(mut self):
        var next_value = self.load_entered() + 1
        Atomic[DType.int64].store[ordering=Ordering.RELEASE](
            Pointer(to=self.entered).unsafe_bitcast[Scalar[DType.int64]](),
            next_value,
        )

    def add_completed(mut self):
        var next_value = self.load_completed() + 1
        Atomic[DType.int64].store[ordering=Ordering.RELEASE](
            Pointer(to=self.completed).unsafe_bitcast[Scalar[DType.int64]](),
            next_value,
        )


@fieldwise_init
struct _CountingEcho(Copyable, Movable, WsHandler):
    """Echo handler with state retained across accepted connections."""

    var total: Int
    var probe: ArcPointer[_Probe]

    def on_connection(mut self, mut connection: WsConnection) raises:
        self.probe[].add_entered()
        while True:
            var frame = connection.recv()
            if frame.opcode == WsOpcode.CLOSE:
                break
            if frame.text_payload() == "fail":
                raise Error("intentional handler failure")
            self.total += 1
            connection.send_text("count=" + String(self.total))
        self.probe[].add_completed()


def _thin_echo(mut connection: WsConnection) raises:
    var frame = connection.recv()
    if frame.opcode == WsOpcode.TEXT:
        connection.send_text(frame.text_payload())


def _url(port: UInt16) -> String:
    return "ws://127.0.0.1:" + String(Int(port)) + "/ws"


def _queue_upgrade_and_close(port: UInt16) raises -> TcpStream:
    var stream = TcpStream.connect(SocketAddr.localhost(port))
    var request = (
        "GET /late HTTP/1.1\r\n"
        + "Host: 127.0.0.1\r\n"
        + "Upgrade: websocket\r\n"
        + "Connection: Upgrade\r\n"
        + "Sec-WebSocket-Version: 13\r\n"
        + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        + "\r\n"
    )
    stream.write_all(Span[UInt8, _](request.as_bytes()))
    var close_wire = WsFrame.close().encode(mask=True)
    stream.write_all(Span[UInt8, _](close_wire))
    return stream^


def test_immediate_stop() raises:
    var server = WsServer.bind(SocketAddr.localhost(0))
    var runtime = server^.serve_stoppable(_thin_echo)
    runtime^.stop_and_join()


def test_stateful_echo_then_idle_stop_and_join() raises:
    var probe = ArcPointer[_Probe](_Probe())
    var server = WsServer.bind(SocketAddr.localhost(0))
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable[_CountingEcho](
        _CountingEcho(0, probe)
    )
    var stop: WsServerStop
    try:
        stop = runtime.take_stop()
    except error:
        runtime^.stop_and_join()
        raise error^

    try:
        var first = WsClient.connect(_url(port))
        first.send_text("one")
        assert_equal(first.recv().text_payload(), "count=1")
        first.close()

        for _ in range(100):
            if probe[].load_completed() == 1:
                break
            usleep(1_000)
        assert_equal(probe[].load_completed(), 1)

        var second = WsClient.connect(_url(port))
        second.send_text("two")
        assert_equal(second.recv().text_payload(), "count=2")
        second.close()

        for _ in range(100):
            if probe[].load_completed() == 2:
                break
            usleep(1_000)
        assert_equal(probe[].load_completed(), 2)

        var failed = WsClient.connect(_url(port))
        failed.send_text("fail")
        var handler_failed = False
        try:
            _ = failed.recv()
        except:
            handler_failed = True
        failed.close()
        assert_true(handler_failed)

        var third = WsClient.connect(_url(port))
        third.send_text("three")
        assert_equal(third.recv().text_payload(), "count=3")
        third.close()

        for _ in range(100):
            if probe[].load_completed() == 3:
                break
            usleep(1_000)
        assert_equal(probe[].load_completed(), 3)
    except error:
        stop.stop()
        try:
            runtime^.join()
        except:
            pass
        raise error^
    stop.stop()
    runtime^.join()
    assert_equal(probe[].load_entered(), 4)
    assert_equal(probe[].load_completed(), 3)


def test_independent_stop_is_idempotent_and_take_is_one_shot() raises:
    var server = WsServer.bind(SocketAddr.localhost(0))
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable(_thin_echo)
    var stop: WsServerStop
    try:
        stop = runtime.take_stop()
    except error:
        runtime^.stop_and_join()
        raise error^
    var rejected_second_take = False
    try:
        _ = runtime.take_stop()
    except error:
        rejected_second_take = "already taken" in String(error)
    try:
        var client = WsClient.connect(_url(port))
        client.send_text("thin")
        assert_equal(client.recv().text_payload(), "thin")
        client.close()
    except error:
        stop.stop()
        try:
            runtime^.join()
        except:
            pass
        raise error^
    stop.stop()
    stop.stop()
    runtime^.join()
    for _ in range(100_000):
        stop.stop()
    assert_true(rejected_second_take)


def test_stop_interrupts_stalled_opening_handshake() raises:
    var server = WsServer.bind(SocketAddr.localhost(0))
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable(_thin_echo)
    var client: TcpStream
    try:
        client = TcpStream.connect(SocketAddr.localhost(port))
        var partial_upgrade = (
            "GET /never HTTP/1.1\r\n"
            + "Host: 127.0.0.1\r\n"
            + "Upgrade: websocket\r\n"
        )
        client.write_all(Span[UInt8, _](partial_upgrade.as_bytes()))
        for _ in range(1_000):
            if runtime._state[].has_active_handshake():
                break
            usleep(1_000)
        assert_true(
            runtime._state[].has_active_handshake(),
            "worker never published the stalled handshake fd",
        )
    except error:
        runtime^.stop_and_join()
        raise error^

    var started_ms = monotonic_now_ms()
    runtime^.stop_and_join()
    var elapsed_ms = monotonic_now_ms() - started_ms
    client.close()
    assert_true(
        elapsed_ms < 1_000,
        "stop_and_join must interrupt a stalled WebSocket Upgrade",
    )


def test_stop_fences_handler_claim_after_handshake_publication() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var peer = listener.accept()
    var state = _WsServerState(Reactor())
    var fd = client._socket.fd

    assert_true(state.publish_handshake(fd))
    state.request_stop()
    assert_false(state.claim_handler_after_handshake(fd))

    client.close()
    peer.close()
    listener.close()


def test_join_surfaces_worker_error_ledger_after_barrier() raises:
    var server = WsServer.bind(SocketAddr.localhost(0))
    var runtime = server^.serve_stoppable(_thin_echo)
    runtime._state[].record_worker_error("fatal-probe")
    with assert_raises(contains="fatal-probe"):
        runtime^.stop_and_join()


def test_stop_during_handler_drains_and_fences_new_admission() raises:
    var probe = ArcPointer[_Probe](_Probe())
    var server = WsServer.bind(SocketAddr.localhost(0))
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable[_CountingEcho](
        _CountingEcho(0, probe)
    )
    var stop: WsServerStop
    try:
        stop = runtime.take_stop()
    except error:
        runtime^.stop_and_join()
        raise error^

    try:
        var first = WsClient.connect(_url(port))
        first.send_text("active")
        assert_equal(first.recv().text_payload(), "count=1")
        assert_equal(probe[].load_entered(), 1)

        stop.stop()
        var late_connection = _queue_upgrade_and_close(port)
        first.close()
        late_connection.close()
    except error:
        stop.stop()
        try:
            runtime^.join()
        except:
            pass
        raise error^
    runtime^.join()
    assert_equal(probe[].load_entered(), 1)
    assert_equal(probe[].load_completed(), 1)


def main() raises:
    test_immediate_stop()
    test_stateful_echo_then_idle_stop_and_join()
    test_independent_stop_is_idempotent_and_take_is_one_shot()
    test_stop_interrupts_stalled_opening_handshake()
    test_stop_fences_handler_claim_after_handshake_publication()
    test_join_surfaces_worker_error_ledger_after_barrier()
    test_stop_during_handler_drains_and_fences_new_admission()
    print("test_ws_stoppable: 7 passed")
