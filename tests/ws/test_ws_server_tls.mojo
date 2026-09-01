"""Public TLS-backed WebSocket server lifecycle over loopback."""

from std.testing import assert_equal, assert_true
from std.memory.alloc import unsafe_alloc

from flare.net import SocketAddr
from flare.runtime._libc_time import monotonic_now_ms
from flare.runtime._thread import ThreadHandle, _OpaquePtr
from flare.tcp import TcpStream
from flare.tls import TlsConfig, TlsServerConfig, TlsStream
from flare.utils import usleep
from flare.ws import (
    WsClient,
    WsConnection,
    WsHandler,
    WsOpcode,
    WsReceiver,
    WsServer,
    WsServerStop,
)


comptime _CA_CERTIFICATE: String = "tests/certs/ca.crt"
comptime _SERVER_CERTIFICATE: String = "tests/certs/server.crt"
comptime _SERVER_KEY: String = "tests/certs/server.key"
comptime _MAX_MESSAGE_BYTES: Int = 64 * 1024


def _null_opaque() -> _OpaquePtr:
    var zero = 0
    return _OpaquePtr(unsafe_from_address=zero)


struct _SplitReceiverContext(Movable):
    var receiver: WsReceiver
    var received_text: Bool
    var error_message: String

    def __init__(out self, var receiver: WsReceiver):
        self.receiver = receiver^
        self.received_text = False
        self.error_message = ""


def _split_receiver_entry(argument: _OpaquePtr) -> _OpaquePtr:
    var context = argument.unsafe_bitcast[_SplitReceiverContext]()
    try:
        while True:
            var frame = context[].receiver.recv()
            if frame.opcode == WsOpcode.CLOSE:
                return _null_opaque()
            if frame.opcode != WsOpcode.TEXT:
                raise Error("TLS WebSocket split expected a text frame")
            context[].received_text = True
    except error:
        context[].error_message = String(error)
    return _null_opaque()


struct _DelayedTlsCloseContext(Movable):
    var stream: TlsStream

    def __init__(out self, var stream: TlsStream):
        self.stream = stream^


def _delayed_tls_close_entry(argument: _OpaquePtr) -> _OpaquePtr:
    var context = argument.unsafe_bitcast[_DelayedTlsCloseContext]()
    usleep(1_200_000)
    context[].stream.close()
    return _null_opaque()


@fieldwise_init
struct _UnsplitEcho(Copyable, Movable, WsHandler):
    def on_connection(mut self, var connection: WsConnection) raises:
        var frame = connection.recv(_MAX_MESSAGE_BYTES)
        if frame.opcode != WsOpcode.TEXT:
            raise Error("TLS WebSocket echo expected a text frame")
        connection.send_text(frame.text_payload())


@fieldwise_init
struct _SplitEcho(Copyable, Movable, WsHandler):
    var expected_subprotocol: String

    def on_connection(mut self, var connection: WsConnection) raises:
        var selected = connection.negotiated_subprotocol()
        if not selected or selected.value() != self.expected_subprotocol:
            raise Error("TLS WebSocket subprotocol mismatch")

        var duplex = connection^.split(_MAX_MESSAGE_BYTES)
        var sender = duplex.take_sender()
        var receiver = duplex.take_receiver()
        var shutdown = duplex.take_shutdown()
        var context = unsafe_alloc[_SplitReceiverContext](1)
        context.unsafe_write(_SplitReceiverContext(receiver^))
        var thread = ThreadHandle.spawn[_split_receiver_entry](
            _OpaquePtr(unsafe_from_address=Int(context))
        )
        if not sender.send_text_within("ready", 1_000):
            shutdown.shutdown()
        thread.join()
        var received_text = context[].received_text
        var error_message = context[].error_message.copy()
        context.unsafe_deinit_pointee()
        context.unsafe_free()
        _ = shutdown^
        if error_message.byte_length() > 0:
            raise Error(error_message)
        if not received_text:
            raise Error("TLS WebSocket split received no text")


def _server_config(handshake_timeout_ms: Int = 5_000) raises -> TlsServerConfig:
    return TlsServerConfig(
        cert_file=_SERVER_CERTIFICATE,
        key_file=_SERVER_KEY,
        handshake_timeout_ms=handshake_timeout_ms,
    )


def _client_config() -> TlsConfig:
    return TlsConfig(ca_bundle=_CA_CERTIFICATE)


def _url(port: UInt16) -> String:
    return "wss://localhost:" + String(Int(port)) + "/secure"


def test_bind_tls_split_round_trip_and_reuse() raises:
    var server = WsServer.bind_tls(
        SocketAddr.localhost(0),
        _server_config(),
        subprotocols=["events.v1"],
    )
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable[_SplitEcho](_SplitEcho("events.v1"))
    var stop: WsServerStop
    try:
        stop = runtime.take_stop()
    except error:
        runtime^.stop_and_join()
        raise error^

    try:
        for index in range(2):
            var client = WsClient.connect(
                _url(port),
                _client_config(),
                subprotocols=["events.v1"],
            )
            var selected = client.negotiated_subprotocol()
            assert_true(selected is not None)
            assert_equal(selected.value(), "events.v1")
            assert_equal(
                client.recv(_MAX_MESSAGE_BYTES).text_payload(), "ready"
            )
            client.send_text("secure-message-" + String(index))
            client.close()
    except error:
        stop.stop()
        try:
            runtime^.join()
        except:
            pass
        raise error^

    stop.stop()
    runtime^.join()


def test_stop_interrupts_tls_handshake() raises:
    var server = WsServer.bind_tls(
        SocketAddr.localhost(0), _server_config(handshake_timeout_ms=5_000)
    )
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable[_SplitEcho](_SplitEcho("unused"))
    var client: TcpStream
    try:
        client = TcpStream.connect(SocketAddr.localhost(port))
        for _ in range(1_000):
            if runtime._state[].has_active_handshake():
                break
            usleep(1_000)
        assert_true(
            runtime._state[].has_active_handshake(),
            "worker never published the TLS handshake fd",
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
        "stop_and_join must interrupt a stalled TLS ClientHello",
    )


def test_handshake_timeout_does_not_bound_established_io() raises:
    var server = WsServer.bind_tls(
        SocketAddr.localhost(0), _server_config(handshake_timeout_ms=200)
    )
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable[_UnsplitEcho](_UnsplitEcho())
    var stop: WsServerStop
    try:
        stop = runtime.take_stop()
    except error:
        runtime^.stop_and_join()
        raise error^

    try:
        var client = WsClient.connect(_url(port), _client_config())
        usleep(300_000)
        client.send_text("after-handshake-deadline")
        assert_equal(
            client.recv(_MAX_MESSAGE_BYTES).text_payload(),
            "after-handshake-deadline",
        )
        client.close()
    except error:
        stop.stop()
        try:
            runtime^.join()
        except:
            pass
        raise error^
    stop.stop()
    runtime^.join()


def test_failed_tls_handshake_releases_admission_and_server_recovers() raises:
    var server = WsServer.bind_tls(SocketAddr.localhost(0), _server_config())
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable[_UnsplitEcho](_UnsplitEcho())
    var stop: WsServerStop
    try:
        stop = runtime.take_stop()
    except error:
        runtime^.stop_and_join()
        raise error^

    try:
        var invalid = TcpStream.connect(SocketAddr.localhost(port))
        for _ in range(1_000):
            if runtime._state[].has_active_handshake():
                break
            usleep(1_000)
        assert_true(
            runtime._state[].has_active_handshake(),
            "worker never published the failing TLS handshake fd",
        )
        invalid.write_all(Span[UInt8, _]("not-tls".as_bytes()))
        invalid.close()
        for _ in range(1_000):
            if not runtime._state[].has_active_handshake():
                break
            usleep(1_000)
        assert_true(
            not runtime._state[].has_active_handshake(),
            "failed TLS handshake left its stop slot published",
        )

        var client = WsClient.connect(_url(port), _client_config())
        client.send_text("after-failed-handshake")
        assert_equal(
            client.recv(_MAX_MESSAGE_BYTES).text_payload(),
            "after-failed-handshake",
        )
        client.close()
    except error:
        stop.stop()
        try:
            runtime^.join()
        except:
            pass
        raise error^
    stop.stop()
    runtime^.join()


def test_invalid_upgrade_cannot_hide_a_blocking_tls_close_from_stop() raises:
    var server = WsServer.bind_tls(SocketAddr.localhost(0), _server_config())
    var port = server.local_addr().port
    var runtime = server^.serve_stoppable[_UnsplitEcho](_UnsplitEcho())
    var client: TlsStream
    try:
        client = TlsStream.connect("localhost", port, _client_config())
        for _ in range(1_000):
            if runtime._state[].has_active_handshake():
                break
            usleep(1_000)
        assert_true(
            runtime._state[].has_active_handshake(),
            "worker never published the post-TLS Upgrade fd",
        )
        client.write_all(Span[UInt8, _]("GET /bad HTTP/1.1\r\n\r\n".as_bytes()))
        for _ in range(1_000):
            if not runtime._state[].has_active_handshake():
                break
            usleep(1_000)
        assert_true(
            not runtime._state[].has_active_handshake(),
            "invalid Upgrade did not release its stop slot",
        )
    except error:
        runtime^.stop_and_join()
        raise error^

    var context = unsafe_alloc[_DelayedTlsCloseContext](1)
    context.unsafe_write(_DelayedTlsCloseContext(client^))
    var closer: ThreadHandle
    try:
        closer = ThreadHandle.spawn[_delayed_tls_close_entry](
            _OpaquePtr(unsafe_from_address=Int(context))
        )
    except error:
        context.unsafe_deinit_pointee()
        context.unsafe_free()
        runtime^.stop_and_join()
        raise error^
    var started_ms = monotonic_now_ms()
    runtime^.stop_and_join()
    var elapsed_ms = monotonic_now_ms() - started_ms
    closer.join()
    context.unsafe_deinit_pointee()
    context.unsafe_free()
    assert_true(
        elapsed_ms < 1_000,
        "stop lost the fd before TLS Upgrade cleanup became nonblocking",
    )


def test_bind_tls_rejects_invalid_credentials() raises:
    var rejected = False
    try:
        _ = WsServer.bind_tls(
            SocketAddr.localhost(0),
            TlsServerConfig(
                cert_file="tests/certs/missing.crt",
                key_file=_SERVER_KEY,
            ),
        )
    except:
        rejected = True
    assert_true(rejected, "TLS server credentials must fail at bind")


def main() raises:
    test_bind_tls_split_round_trip_and_reuse()
    test_stop_interrupts_tls_handshake()
    test_handshake_timeout_does_not_bound_established_io()
    test_failed_tls_handshake_releases_admission_and_server_recovers()
    test_invalid_upgrade_cannot_hide_a_blocking_tls_close_from_stop()
    test_bind_tls_rejects_invalid_credentials()
    print("test_ws_server_tls: 6 passed")
