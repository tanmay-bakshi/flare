"""Hermetic RFC 6455 subprotocol negotiation regressions."""

from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.net import SocketAddr
from flare.utils import SIGKILL, exit, fork, kill, waitpid
from flare.ws import WsClient, WsConnection, WsServer
from flare.ws.client import _validate_upgrade_response
from flare.ws._subprotocol import _parse_subprotocol_offers
from flare.ws.server import _negotiate_subprotocol, _parse_ws_upgrade_bytes
from flare.tcp import TcpListener, TcpStream


def _report_subprotocol(mut connection: WsConnection) raises:
    var selected = connection.negotiated_subprotocol()
    if selected:
        connection.send_text(selected.value())
    else:
        connection.send_text("")


def _spawn_server(var server: WsServer) -> Int:
    var pid = fork()
    if pid == 0:
        try:
            server.serve(_report_subprotocol)
        except:
            pass
        exit()
    return pid


def _stop_server(pid: Int):
    _ = kill(pid, SIGKILL)
    waitpid(pid)


def _upgrade_response(subprotocol_line: String = "") -> List[UInt8]:
    var response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        + "Upgrade: websocket\r\n"
        + "Connection: Upgrade\r\n"
        + "Sec-WebSocket-Accept: accepted\r\n"
    )
    if subprotocol_line.byte_length() > 0:
        response += subprotocol_line + "\r\n"
    response += "\r\n"
    return List[UInt8](response.as_bytes())


def _upgrade_request(subprotocol_lines: String) -> List[UInt8]:
    var request = (
        "GET /chat HTTP/1.1\r\n"
        + "Host: 127.0.0.1\r\n"
        + "Upgrade: websocket\r\n"
        + "Connection: Upgrade\r\n"
        + "Sec-WebSocket-Version: 13\r\n"
        + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        + subprotocol_lines
        + "\r\n"
    )
    return List[UInt8](request.as_bytes())


def test_client_and_server_expose_selected_subprotocol() raises:
    var server = WsServer.bind(
        SocketAddr.localhost(0),
        subprotocols=["chat.v2", "chat.v1"],
    )
    var port = server.local_addr().port
    var pid = _spawn_server(server^)
    var failure = String("")
    try:
        var client = WsClient.connect(
            "ws://127.0.0.1:" + String(Int(port)) + "/chat",
            subprotocols=["chat.v1", "chat.v2"],
        )
        var selected = client.negotiated_subprotocol()
        assert_true(selected)
        assert_equal(selected.value(), "chat.v2")
        assert_equal(client.recv(8 * 1024 * 1024).text_payload(), "chat.v2")
    except error:
        failure = String(error)
    _stop_server(pid)
    if failure.byte_length() > 0:
        raise Error(failure)


def test_client_accepts_server_without_selection() raises:
    var server = WsServer.bind(
        SocketAddr.localhost(0), subprotocols=["chat.v2"]
    )
    var port = server.local_addr().port
    var pid = _spawn_server(server^)
    var failure = String("")
    try:
        var client = WsClient.connect(
            "ws://127.0.0.1:" + String(Int(port)) + "/chat",
            subprotocols=["chat.v1"],
        )
        assert_false(client.negotiated_subprotocol())
        assert_equal(client.recv(8 * 1024 * 1024).text_payload(), "")
    except error:
        failure = String(error)
    _stop_server(pid)
    if failure.byte_length() > 0:
        raise Error(failure)


def test_client_rejects_unoffered_selection() raises:
    var response = _upgrade_response("Sec-WebSocket-Protocol: chat.v2")
    with assert_raises(contains="unoffered WebSocket subprotocol"):
        _ = _validate_upgrade_response(response, "accepted", ["chat.v1"])


def test_client_rejects_unsolicited_selection() raises:
    var response = _upgrade_response("Sec-WebSocket-Protocol: chat.v1")
    with assert_raises(contains="when none was offered"):
        _ = _validate_upgrade_response(response, "accepted")


def test_client_rejects_multiple_server_selections() raises:
    var response = _upgrade_response("Sec-WebSocket-Protocol: chat.v1, chat.v2")
    with assert_raises(contains="invalid Sec-WebSocket-Protocol response"):
        _ = _validate_upgrade_response(
            response, "accepted", ["chat.v1", "chat.v2"]
        )

    var repeated = _upgrade_response(
        "Sec-WebSocket-Protocol: chat.v1\r\nSec-WebSocket-Protocol: chat.v1"
    )
    with assert_raises(contains="multiple Sec-WebSocket-Protocol"):
        _ = _validate_upgrade_response(repeated, "accepted", ["chat.v1"])


def test_request_lists_accept_null_members() raises:
    var offered = _parse_subprotocol_offers(", \tchat.v1, , chat.v2,")
    assert_equal(len(offered), 2)
    assert_equal(offered[0], "chat.v1")
    assert_equal(offered[1], "chat.v2")


def test_server_combines_repeated_offer_fields() raises:
    var request_bytes = _upgrade_request(
        "Sec-WebSocket-Protocol: , chat.v1,\r\n"
        + "Sec-WebSocket-Protocol: chat.v2,,\r\n"
    )
    var request = _parse_ws_upgrade_bytes(Span[UInt8, _](request_bytes))
    var selected = _negotiate_subprotocol(request, ["chat.v2", "chat.v1"])
    assert_true(selected)
    assert_equal(selected.value(), "chat.v2")

    var duplicate_bytes = _upgrade_request(
        "Sec-WebSocket-Protocol: chat.v1\r\n"
        + "Sec-WebSocket-Protocol: chat.v1\r\n"
    )
    var duplicate = _parse_ws_upgrade_bytes(Span[UInt8, _](duplicate_bytes))
    with assert_raises(contains="duplicate WebSocket subprotocol token"):
        _ = _negotiate_subprotocol(duplicate, ["chat.v1"])

    var empty_bytes = _upgrade_request("Sec-WebSocket-Protocol: , ,\r\n")
    var empty = _parse_ws_upgrade_bytes(Span[UInt8, _](empty_bytes))
    with assert_raises(contains="contains no protocol token"):
        _ = _negotiate_subprotocol(empty, ["chat.v1"])


def test_response_selection_is_one_ows_trimmed_token() raises:
    var response = _upgrade_response("Sec-WebSocket-Protocol:\t chat.v1 \t")
    var selected = _validate_upgrade_response(response, "accepted", ["chat.v1"])
    assert_true(selected)
    assert_equal(selected.value(), "chat.v1")

    var null_members = _upgrade_response("Sec-WebSocket-Protocol: , chat.v1,")
    with assert_raises(contains="invalid Sec-WebSocket-Protocol response"):
        _ = _validate_upgrade_response(null_members, "accepted", ["chat.v1"])


def test_response_rejects_ctl_without_reflecting_it() raises:
    var protocol_line = String("Sec-WebSocket-Protocol: ")
    protocol_line += chr(11)
    protocol_line += "private-marker"
    var response = _upgrade_response(protocol_line)
    var detail = String("")
    try:
        _ = _validate_upgrade_response(response, "accepted", ["private-marker"])
    except error:
        detail = String(error)
    assert_true("invalid Sec-WebSocket-Protocol response" in detail)
    assert_false("private-marker" in detail)


def test_response_unfolds_protocol_header_before_validation() raises:
    var valid = _upgrade_response("Sec-WebSocket-Protocol: chat.v1\r\n \t")
    var selected = _validate_upgrade_response(valid, "accepted", ["chat.v1"])
    assert_true(selected)
    assert_equal(selected.value(), "chat.v1")

    var response = _upgrade_response(
        "Sec-WebSocket-Protocol: chat.v1\r\n chat.v2"
    )
    with assert_raises(contains="invalid Sec-WebSocket-Protocol response"):
        _ = _validate_upgrade_response(response, "accepted", ["chat.v1"])

    var bare_cr = _upgrade_response("X-Test: ok\r\n more\rbad")
    with assert_raises(contains="invalid HTTP Upgrade response line ending"):
        _ = _validate_upgrade_response(bare_cr, "accepted")


def test_server_rejects_folded_protocol_header() raises:
    var request = _upgrade_request(
        "Sec-WebSocket-Protocol: chat.v1\r\n private-marker\r\n"
    )
    with assert_raises(contains="folded WebSocket Upgrade headers"):
        _ = _parse_ws_upgrade_bytes(Span[UInt8, _](request))


def test_server_rejects_bare_cr_in_protocol_offer() raises:
    var request = _upgrade_request("Sec-WebSocket-Protocol: chat.\r1\r\n")
    with assert_raises(contains="bare CR in WebSocket Upgrade headers"):
        _ = _parse_ws_upgrade_bytes(Span[UInt8, _](request))


def test_header_field_names_reject_whitespace_before_colon() raises:
    var response = _upgrade_response("Sec-WebSocket-Protocol \t: chat.v1")
    with assert_raises(contains="invalid HTTP Upgrade response header"):
        _ = _validate_upgrade_response(response, "accepted", ["chat.v1"])

    var request = _upgrade_request("Sec-WebSocket-Protocol \t: chat.v1\r\n")
    with assert_raises(contains="invalid WebSocket Upgrade header"):
        _ = _parse_ws_upgrade_bytes(Span[UInt8, _](request))


def test_server_diagnostics_do_not_reflect_invalid_offer() raises:
    var protocol = String("")
    protocol += chr(11)
    protocol += "private-marker"
    var request_bytes = _upgrade_request(
        "Sec-WebSocket-Protocol: " + protocol + "\r\n"
    )
    var request = _parse_ws_upgrade_bytes(Span[UInt8, _](request_bytes))
    var detail = String("")
    try:
        _ = _negotiate_subprotocol(request, ["chat.v1"])
    except error:
        detail = String(error)
    assert_true("invalid WebSocket subprotocol offer" in detail)
    assert_false("private-marker" in detail)


def test_server_sends_bad_request_for_invalid_offer() raises:
    var server = WsServer.bind(
        SocketAddr.localhost(0), subprotocols=["chat.v1"]
    )
    var port = server.local_addr().port
    var pid = _spawn_server(server^)
    var failure = String("")
    try:
        var stream = TcpStream.connect(SocketAddr.localhost(port))
        var request = _upgrade_request(
            "Sec-WebSocket-Protocol: not a token\r\n"
        )
        stream.write_all(Span[UInt8, _](request))
        var response = List[UInt8](capacity=512)
        response.resize(512, UInt8(0))
        var count = stream.read(response.unsafe_ptr(), len(response))
        var text = String(unsafe_from_utf8=Span[UInt8, _](response)[:count])
        assert_true(text.startswith("HTTP/1.1 400 Bad Request\r\n"))
        stream.close()
    except error:
        failure = String(error)
    _stop_server(pid)
    if failure.byte_length() > 0:
        raise Error(failure)


def test_subprotocol_inputs_are_typed_and_token_validated() raises:
    with assert_raises(contains="invalid WebSocket subprotocol token"):
        _ = WsClient.connect_attempt(
            "ws://127.0.0.1:1/chat",
            1000,
            subprotocols=["not a token"],
        )
    with assert_raises(contains="subprotocols argument"):
        _ = WsClient.connect_attempt(
            "ws://127.0.0.1:1/chat",
            1000,
            extra_headers=["Sec-WebSocket-Protocol: chat.v1"],
        )
    with assert_raises(contains="duplicate WebSocket subprotocol token"):
        _ = WsServer.bind(
            SocketAddr.localhost(0),
            subprotocols=["chat.v1", "chat.v1"],
        )
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    with assert_raises(contains="invalid WebSocket subprotocol token"):
        _ = WsServer(listener^, ["not a token"])


def test_no_offer_keeps_negotiated_protocol_empty() raises:
    var response = _upgrade_response()
    var selected = _validate_upgrade_response(response, "accepted")
    assert_false(selected)


def main() raises:
    test_client_and_server_expose_selected_subprotocol()
    test_client_accepts_server_without_selection()
    test_client_rejects_unoffered_selection()
    test_client_rejects_unsolicited_selection()
    test_client_rejects_multiple_server_selections()
    test_request_lists_accept_null_members()
    test_server_combines_repeated_offer_fields()
    test_response_selection_is_one_ows_trimmed_token()
    test_response_rejects_ctl_without_reflecting_it()
    test_response_unfolds_protocol_header_before_validation()
    test_server_rejects_folded_protocol_header()
    test_server_rejects_bare_cr_in_protocol_offer()
    test_header_field_names_reject_whitespace_before_colon()
    test_server_diagnostics_do_not_reflect_invalid_offer()
    test_server_sends_bad_request_for_invalid_offer()
    test_subprotocol_inputs_are_typed_and_token_validated()
    test_no_offer_keeps_negotiated_protocol_empty()
    print("test_ws_subprotocol: 17 passed")
