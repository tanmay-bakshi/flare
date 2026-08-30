"""RFC 6455 frame conformance fixtures without a JSON dependency.

The typed cases mirror the tracked corpus under ``conformance/ws`` and run
through :meth:`flare.ws.frame.WsFrame.decode_one`, the production decoder.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.ws.frame import WsFrame
from tests.conformance.corpus import snapshot_corpus


@fieldwise_init
struct _WsFixture(Copyable, Movable):
    """One WebSocket wire-frame case.

    :ivar name: Stable Autobahn-style fixture identifier.
    :ivar spec: RFC citation carried by the source corpus.
    :ivar input_hex: Space-separated wire bytes.
    :ivar accept: Whether decoding must succeed.
    :ivar expected_opcode: Decoded opcode for accepted frames.
    :ivar expected_fin: Decoded FIN bit for accepted frames.
    :ivar expected_masked: Decoded MASK bit, when specified by the source.
    :ivar expected_payload_hex: Expected unmasked payload, when asserted.
    :ivar expected_payload_len: Expected payload length, or ``-1``.
    :ivar expected_close_code: Expected close code, or ``-1``.
    """

    var name: String
    var spec: String
    var input_hex: String
    var accept: Bool
    var expected_opcode: Int
    var expected_fin: Bool
    var expected_masked: Optional[Bool]
    var expected_payload_hex: String
    var expected_payload_len: Int
    var expected_close_code: Int


def _digit(c: UInt8) raises -> Int:
    if c >= UInt8(ord("0")) and c <= UInt8(ord("9")):
        return Int(c) - ord("0")
    if c >= UInt8(ord("a")) and c <= UInt8(ord("f")):
        return Int(c) - ord("a") + 10
    if c >= UInt8(ord("A")) and c <= UInt8(ord("F")):
        return Int(c) - ord("A") + 10
    raise Error("conformance/ws: invalid hex digit")


def _decode_hex(s: String) raises -> List[UInt8]:
    """Decode space-separated hex pairs into an owned byte list."""
    var out = List[UInt8]()
    var p = s.unsafe_ptr()
    var n = s.byte_length()
    var i = 0
    while i < n:
        var c = p[unsafe_offset=i]
        if (
            c == UInt8(ord(" "))
            or c == UInt8(ord("\t"))
            or c == UInt8(ord("\n"))
            or c == UInt8(ord("\r"))
        ):
            i += 1
            continue
        if i + 1 >= n:
            raise Error("conformance/ws: dangling hex digit")
        var hi = _digit(c)
        var lo = _digit(p[unsafe_offset=i + 1])
        out.append(UInt8((hi << 4) | lo))
        i += 2
    return out^


def _fixture(
    name: String,
    spec: String,
    input_hex: String,
    accept: Bool,
    expected_opcode: Int = -1,
    expected_fin: Bool = True,
    expected_masked: Optional[Bool] = None,
    expected_payload_hex: String = "",
    expected_payload_len: Int = -1,
    expected_close_code: Int = -1,
) -> _WsFixture:
    """Construct one fixture with compact defaults for reject cases."""
    return _WsFixture(
        name=name,
        spec=spec,
        input_hex=input_hex,
        accept=accept,
        expected_opcode=expected_opcode,
        expected_fin=expected_fin,
        expected_masked=expected_masked,
        expected_payload_hex=expected_payload_hex,
        expected_payload_len=expected_payload_len,
        expected_close_code=expected_close_code,
    )


def _fixtures() -> List[_WsFixture]:
    """Return the complete typed mirror of ``conformance/ws``."""
    var payload_126 = (
        "82 7e 00 7e 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d "
        "0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f "
        "20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 "
        "32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f 40 41 42 43 "
        "44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 "
        "56 57 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65 66 67 "
        "68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 "
        "7a 7b 7c 7d"
    )
    var cases = List[_WsFixture]()
    cases.append(
        _fixture(
            "7.1.1_close_normal_closure",
            "RFC 6455 sections 5.5.1 and 7.4.1",
            "88 02 03 e8",
            True,
            8,
            expected_payload_hex="03 e8",
            expected_payload_len=2,
            expected_close_code=1000,
        )
    )
    cases.append(
        _fixture(
            "7.7.1_close_normal_with_reason",
            "RFC 6455 section 5.5.1",
            "88 09 03 e8 67 6f 6f 64 62 79 65",
            True,
            8,
            expected_payload_hex="03 e8 67 6f 6f 64 62 79 65",
            expected_payload_len=9,
            expected_close_code=1000,
        )
    )
    cases.append(
        _fixture(
            "5.1.2_continuation_final_frame",
            "RFC 6455 section 5.4",
            "80 02 67 65",
            True,
            0,
            expected_payload_hex="67 65",
            expected_payload_len=2,
        )
    )
    cases.append(
        _fixture(
            "1.1.6_extended_length_16bit",
            "RFC 6455 section 5.2",
            payload_126,
            True,
            2,
            expected_payload_len=126,
        )
    )
    cases.append(
        _fixture(
            "5.5.1_fragmented_control_frame",
            "RFC 6455 section 5.4",
            "09 00",
            False,
        )
    )
    cases.append(
        _fixture(
            "5.1.1_fragmented_text_first_frame",
            "RFC 6455 section 5.4",
            "01 03 66 72 61",
            True,
            1,
            expected_fin=False,
            expected_payload_hex="66 72 61",
            expected_payload_len=3,
        )
    )
    cases.append(
        _fixture(
            "2.1.1_ping_with_payload",
            "RFC 6455 section 5.5.2",
            "89 05 48 65 6c 6c 6f",
            True,
            9,
            expected_payload_hex="48 65 6c 6c 6f",
            expected_payload_len=5,
        )
    )
    cases.append(
        _fixture(
            "2.7.1_pong_empty_payload",
            "RFC 6455 section 5.5.3",
            "8a 00",
            True,
            10,
            expected_payload_len=0,
        )
    )
    cases.append(
        _fixture(
            "3.1.1_rsv1_without_negotiated_extension",
            "RFC 6455 section 5.2",
            "c1 05 48 65 6c 6c 6f",
            False,
        )
    )
    cases.append(
        _fixture(
            "1.2.1_single_binary_frame_unmasked",
            "RFC 6455 section 5.6",
            "82 03 ff 00 7f",
            True,
            2,
            expected_payload_hex="ff 00 7f",
            expected_payload_len=3,
        )
    )
    cases.append(
        _fixture(
            "1.1.2_single_text_frame_masked",
            "RFC 6455 sections 5.3 and 5.6",
            "81 85 37 fa 21 3d 7f 9f 4d 51 58",
            True,
            1,
            expected_masked=Optional[Bool](True),
            expected_payload_hex="48 65 6c 6c 6f",
            expected_payload_len=5,
        )
    )
    cases.append(
        _fixture(
            "1.1.1_single_text_frame_unmasked",
            "RFC 6455 section 5.6",
            "81 05 48 65 6c 6c 6f",
            True,
            1,
            expected_payload_hex="48 65 6c 6c 6f",
            expected_payload_len=5,
        )
    )
    cases.append(
        _fixture(
            "1.1.7_truncated_frame",
            "RFC 6455 section 5.2",
            "81 05 48 65 6c",
            False,
        )
    )
    return cases^


def _validate_fixture(fixture: _WsFixture) raises:
    """Run one typed fixture through the production frame decoder."""
    assert_true(fixture.name.byte_length() > 0)
    assert_true(fixture.spec.byte_length() > 0)
    var bytes = _decode_hex(fixture.input_hex)
    assert_true(len(bytes) >= 2)

    if fixture.accept:
        var result = WsFrame.decode_one(Span[UInt8, _](bytes))
        assert_equal(Int(result.frame.opcode), fixture.expected_opcode)
        assert_equal(result.frame.fin, fixture.expected_fin)
        if fixture.expected_masked:
            assert_equal(result.frame.masked, fixture.expected_masked.value())
        if fixture.expected_payload_len >= 0:
            assert_equal(
                len(result.frame.payload), fixture.expected_payload_len
            )
        if fixture.expected_payload_hex.byte_length() > 0:
            var expected = _decode_hex(fixture.expected_payload_hex)
            assert_equal(len(result.frame.payload), len(expected))
            for index in range(len(expected)):
                assert_equal(result.frame.payload[index], expected[index])
        if fixture.expected_close_code >= 0:
            assert_true(len(result.frame.payload) >= 2)
            var close_code = (Int(result.frame.payload[0]) << 8) | Int(
                result.frame.payload[1]
            )
            assert_equal(close_code, fixture.expected_close_code)
        return

    var raised = False
    try:
        _ = WsFrame.decode_one(Span[UInt8, _](bytes))
    except:
        raised = True
    assert_true(raised)


def test_all_ws_fixtures_validate() raises:
    var cases = _fixtures()
    assert_equal(len(cases), 13)
    for index in range(len(cases)):
        _validate_fixture(cases[index])


def test_accept_and_reject_fixtures_both_present() raises:
    var cases = _fixtures()
    var seen_accept = False
    var seen_reject = False
    for index in range(len(cases)):
        if cases[index].accept:
            seen_accept = True
        else:
            seen_reject = True
    assert_true(seen_accept)
    assert_true(seen_reject)


def test_typed_fixtures_match_checked_in_corpus() raises:
    """Fail when a corpus file changes without updating the typed mirror."""
    var filenames = List[String]()
    filenames.append("rfc6455_close_normal_accept.json")
    filenames.append("rfc6455_close_with_reason_accept.json")
    filenames.append("rfc6455_continuation_final_frame_accept.json")
    filenames.append("rfc6455_extended_length_16bit_accept.json")
    filenames.append("rfc6455_fragmented_control_frame_reject.json")
    filenames.append("rfc6455_fragmented_text_first_frame_accept.json")
    filenames.append("rfc6455_ping_with_payload_accept.json")
    filenames.append("rfc6455_pong_empty_accept.json")
    filenames.append("rfc6455_rsv1_without_extension_reject.json")
    filenames.append("rfc6455_single_binary_frame_unmasked_accept.json")
    filenames.append("rfc6455_single_text_frame_masked_accept.json")
    filenames.append("rfc6455_single_text_frame_unmasked_accept.json")
    filenames.append("rfc6455_truncated_frame_reject.json")
    var snapshot = snapshot_corpus("conformance/ws", filenames^)
    assert_equal(snapshot.json_file_count, 13)
    assert_equal(snapshot.fingerprint, UInt64(12147995275496332846))


def main() raises:
    test_all_ws_fixtures_validate()
    test_accept_and_reject_fixtures_both_present()
    test_typed_fixtures_match_checked_in_corpus()
    print("test_conformance_ws: OK")
