"""WebSocket-over-HTTP/2 full round-trip (RFC 8441), sans-I/O.

Pairs a client :class:`Http2ClientConnection` with a server
:class:`Http2Connection` (enable_connect_protocol) and shuttles bytes
between them -- no sockets. Proves the complete server bridge: the client
opens an Extended CONNECT tunnel, the server surfaces + accepts it with a
200 (stream stays open), a client-masked WS frame is read + unmasked
server-side, and an unmasked server reply is read client-side.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.http2 import Http2Connection, Http2Config
from flare.http2.client import Http2ClientConfig, Http2ClientConnection
from flare.ws.client_h2 import WsOverH2Stream, bootstrap_ws_over_h2
from flare.ws.server_h2 import WsOverH2ServerStream
from flare.ws.frame import WsCloseCode, WsFrame, WsOpcode


def _shuttle(
    mut client: Http2ClientConnection, mut server: Http2Connection
) raises:
    var iters = 0
    while True:
        if iters > 64:
            raise Error("shuttle: too many iterations")
        iters += 1
        var made = False
        var c_out = client.drain()
        if len(c_out) > 0:
            server.feed(Span[UInt8, _](c_out))
            made = True
        var s_out = server.drain()
        if len(s_out) > 0:
            client.feed(Span[UInt8, _](s_out))
            made = True
        if not made:
            return


def _open_tunnel(
    mut client: Http2ClientConnection, mut server: Http2Connection
) raises -> Int:
    """Open and accept one extended-CONNECT WebSocket tunnel."""
    _shuttle(client, server)
    assert_true(
        client.peer_supports_extended_connect(),
        "server must advertise SETTINGS_ENABLE_CONNECT_PROTOCOL",
    )

    var stream_id = client.next_stream_id()
    bootstrap_ws_over_h2(
        client,
        stream_id,
        String("example.com"),
        String("/chat"),
        String("AAAA"),
    )
    _shuttle(client, server)

    var pending = server.take_extended_connect_streams()
    assert_equal(len(pending), 1)
    assert_equal(pending[0], stream_id)
    server.accept_ws_over_h2(stream_id)
    assert_equal(len(server.take_extended_connect_streams()), 0)
    _shuttle(client, server)
    return stream_id


def _close_code(frame: WsFrame) -> UInt16:
    """Read the status code from a validated CLOSE frame."""
    return (UInt16(frame.payload[0]) << 8) | UInt16(frame.payload[1])


def _close_reason(frame: WsFrame) -> String:
    """Read the reason from a validated CLOSE frame."""
    var reason = Span[UInt8, _](frame.payload)[2:]
    return String(unsafe_from_utf8=reason)


def _new_client() raises -> Http2ClientConnection:
    """Create an h2 client that advertises extended CONNECT."""
    var ccfg = Http2ClientConfig()
    ccfg.enable_connect_protocol = True
    return Http2ClientConnection.with_config(ccfg^)


def _new_server() raises -> Http2Connection:
    """Create an h2 server that advertises extended CONNECT."""
    var scfg = Http2Config()
    scfg.enable_connect_protocol = True
    return Http2Connection.with_config(scfg^)


def test_text_round_trip() raises:
    """Exchange masked and unmasked text through the paired h2 drivers."""
    var client = _new_client()
    var server = _new_server()
    var stream_id = _open_tunnel(client, server)

    var client_ws = WsOverH2Stream(stream_id)
    client_ws.send_frame(client, WsFrame.text("ping"))
    _shuttle(client, server)

    var server_ws = WsOverH2ServerStream(stream_id)
    var got = server_ws.try_pull_frame(server)
    assert_true(Bool(got), "server must decode the client frame")
    assert_equal(got.value().opcode, WsOpcode.TEXT)
    assert_equal(got.value().text_payload(), "ping")

    server_ws.send_frame(server, WsFrame.text("pong"))
    _shuttle(client, server)

    var back = client_ws.try_pull_frame(client)
    assert_true(Bool(back), "client must decode the server reply")
    assert_equal(back.value().opcode, WsOpcode.TEXT)
    assert_equal(back.value().text_payload(), "pong")


def test_valid_close_is_delivered_unchanged() raises:
    """A valid peer CLOSE remains observable with its original payload."""
    var client = _new_client()
    var server = _new_server()
    var stream_id = _open_tunnel(client, server)
    var client_ws = WsOverH2Stream(stream_id)
    var server_ws = WsOverH2ServerStream(stream_id)

    server_ws.send_frame(
        server,
        WsFrame.close(WsCloseCode.GOING_AWAY, "maintenance"),
    )
    _shuttle(client, server)

    var received = client_ws.try_pull_frame(client)
    assert_true(received is not None)
    var close = received.take()
    assert_equal(close.opcode, WsOpcode.CLOSE)
    assert_false(close.masked)
    assert_equal(_close_code(close), WsCloseCode.GOING_AWAY)
    assert_equal(_close_reason(close), "maintenance")
    assert_true(client_ws.is_closed())


def test_server_rejects_malformed_close_before_delivery() raises:
    """The h2 server answers a one-byte CLOSE payload with truthful 1002."""
    var client = _new_client()
    var server = _new_server()
    var stream_id = _open_tunnel(client, server)
    var client_ws = WsOverH2Stream(stream_id)
    var server_ws = WsOverH2ServerStream(stream_id)

    client_ws.send_frame(
        client,
        WsFrame(opcode=WsOpcode.CLOSE, payload=[UInt8(0x03)]),
    )
    _shuttle(client, server)

    var error_message = String("")
    try:
        _ = server_ws.try_pull_frame(server)
    except error:
        error_message = String(error)
    assert_true("invalid_close_payload" in error_message, error_message)
    assert_true(server_ws.is_closed())

    _shuttle(client, server)
    var response = client_ws.try_pull_frame(client)
    assert_true(response is not None)
    var close = response.take()
    assert_equal(close.opcode, WsOpcode.CLOSE)
    assert_false(close.masked)
    assert_equal(_close_code(close), WsCloseCode.PROTOCOL_ERROR)
    assert_equal(_close_reason(close), "invalid_close_payload")


def test_client_rejects_invalid_close_reason_before_delivery() raises:
    """The h2 client answers an invalid UTF-8 CLOSE reason with 1007."""
    var client = _new_client()
    var server = _new_server()
    var stream_id = _open_tunnel(client, server)
    var client_ws = WsOverH2Stream(stream_id)
    var server_ws = WsOverH2ServerStream(stream_id)

    server_ws.send_frame(
        server,
        WsFrame(
            opcode=WsOpcode.CLOSE,
            payload=[
                UInt8(0x03),
                UInt8(0xE8),
                UInt8(0xC3),
                UInt8(0x28),
            ],
        ),
    )
    _shuttle(client, server)

    var error_message = String("")
    try:
        _ = client_ws.try_pull_frame(client)
    except error:
        error_message = String(error)
    assert_true("invalid_close_reason" in error_message, error_message)
    assert_true(client_ws.is_closed())

    _shuttle(client, server)
    var response = server_ws.try_pull_frame(server)
    assert_true(response is not None)
    var close = response.take()
    assert_equal(close.opcode, WsOpcode.CLOSE)
    assert_true(close.masked)
    assert_equal(_close_code(close), WsCloseCode.INVALID_PAYLOAD)
    assert_equal(_close_reason(close), "invalid_close_reason")


def main() raises:
    print("test_ws_h2_roundtrip")
    test_text_round_trip()
    test_valid_close_is_delivered_unchanged()
    test_server_rejects_malformed_close_before_delivery()
    test_client_rejects_invalid_close_reason_before_delivery()
    print("test_ws_h2_roundtrip: 4 passed")
