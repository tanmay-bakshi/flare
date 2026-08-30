"""HTTP/1.1 conformance fixtures without a JSON runtime dependency.

The cases mirror every fixture under ``conformance/h1/`` as typed Mojo
values. Keeping the corpus declarative preserves the parser coverage while
allowing :mod:`flare.http` to remain independent of any JSON implementation.
"""

from std.testing import (
    assert_equal,
    assert_false,
    assert_not_equal,
    assert_true,
)

from flare.http.proto import H1LeniencyConfig
from flare.http.server import _parse_http_request_bytes
from tests.conformance.corpus import snapshot_corpus


@fieldwise_init
struct _H1Fixture(Copyable, Movable):
    """One HTTP/1.1 parser case.

    :ivar name: Stable fixture identifier.
    :ivar spec: RFC citation carried by the source corpus.
    :ivar input_hex: Space-separated wire bytes.
    :ivar accept: Whether strict-or-configured parsing must succeed.
    :ivar leniency: Per-case parser relaxations.
    :ivar expected_method: Method for an accepted request.
    :ivar expected_uri: Request target for an accepted request.
    :ivar expected_version: HTTP version for an accepted request.
    """

    var name: String
    var spec: String
    var input_hex: String
    var accept: Bool
    var leniency: H1LeniencyConfig
    var expected_method: String
    var expected_uri: String
    var expected_version: String


def _digit(c: UInt8) raises -> Int:
    if c >= UInt8(ord("0")) and c <= UInt8(ord("9")):
        return Int(c) - ord("0")
    if c >= UInt8(ord("a")) and c <= UInt8(ord("f")):
        return Int(c) - ord("a") + 10
    if c >= UInt8(ord("A")) and c <= UInt8(ord("F")):
        return Int(c) - ord("A") + 10
    raise Error("conformance: invalid hex digit")


def _decode_hex(s: String) raises -> List[UInt8]:
    """Decode space-separated hex pairs into a byte buffer.

    Whitespace between pairs is collapsed. Empty hex strings yield
    an empty buffer; dangling half-pairs raise.
    """
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
            raise Error("conformance: dangling hex digit")
        var c2 = p[unsafe_offset=i + 1]
        var hi = _digit(c)
        var lo = _digit(c2)
        out.append(UInt8((hi << 4) | lo))
        i += 2
    return out^


def _validate_fixture(fixture: _H1Fixture) raises:
    """Run one typed fixture through the production parser."""
    assert_true(fixture.name.byte_length() > 0)
    assert_true(fixture.spec.byte_length() > 0)

    var bytes = _decode_hex(fixture.input_hex)
    assert_true(len(bytes) > 0)

    if fixture.accept:
        assert_true(fixture.expected_method.byte_length() > 0)
        assert_true(fixture.expected_uri.byte_length() > 0)
        assert_true(fixture.expected_version.byte_length() > 0)

        var req = _parse_http_request_bytes(
            Span[UInt8, _](bytes), leniency=fixture.leniency.copy()
        )
        assert_equal(req.method, fixture.expected_method)
        assert_equal(req.url, fixture.expected_uri)
        assert_equal(req.version, fixture.expected_version)
    else:
        var raised = False
        try:
            _ = _parse_http_request_bytes(
                Span[UInt8, _](bytes), leniency=fixture.leniency.copy()
            )
        except:
            raised = True
        assert_true(raised)


def _fixture(
    name: String,
    spec: String,
    input_hex: String,
    accept: Bool,
    leniency: H1LeniencyConfig = H1LeniencyConfig(),
    expected_method: String = "",
    expected_uri: String = "",
    expected_version: String = "",
) -> _H1Fixture:
    """Construct one fixture without repeating default expectations."""
    return _H1Fixture(
        name=name,
        spec=spec,
        input_hex=input_hex,
        accept=accept,
        leniency=leniency.copy(),
        expected_method=expected_method,
        expected_uri=expected_uri,
        expected_version=expected_version,
    )


def _fixtures() -> List[_H1Fixture]:
    """Return the complete typed mirror of ``conformance/h1``."""
    var canonical_get = (
        "47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a "
        "48 6f 73 74 3a 20 65 78 61 6d 70 6c 65 2e 63 6f 6d "
        "0d 0a 0d 0a"
    )
    var leading = (
        "0d 0a 0d 0a 47 45 54 20 2f 20 48 54 54 50 2f 31 2e "
        "31 0d 0a 48 6f 73 74 3a 20 78 0d 0a 0d 0a"
    )
    var lf_only = (
        "47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0a 48 6f "
        "73 74 3a 20 65 78 61 6d 70 6c 65 2e 63 6f 6d 0a 0a"
    )
    var mixed_method_strict = (
        "47 65 74 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a 48 "
        "6f 73 74 3a 20 65 78 61 6d 70 6c 65 2e 63 6f 6d 0d "
        "0a 0d 0a"
    )
    var mixed_method_lenient = (
        "47 65 74 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a 48 "
        "6f 73 74 3a 20 78 0d 0a 0d 0a"
    )
    var duplicate_length = (
        "50 4f 53 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a "
        "48 6f 73 74 3a 20 78 0d 0a 43 6f 6e 74 65 6e 74 2d "
        "4c 65 6e 67 74 68 3a 20 35 0d 0a 43 6f 6e 74 65 6e "
        "74 2d 4c 65 6e 67 74 68 3a 20 35 0d 0a 0d 0a 68 65 "
        "6c 6c 6f"
    )
    var obs_fold_strict = (
        "47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a 58 "
        "2d 4d 79 3a 20 76 61 6c 75 65 31 0d 0a 20 76 61 6c "
        "75 65 32 0d 0a 0d 0a"
    )
    var obs_fold_lenient = (
        "47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a 58 "
        "2d 4d 79 3a 20 76 61 6c 75 65 31 0d 0a 20 76 61 6c "
        "75 65 32 0d 0a 48 6f 73 74 3a 20 78 0d 0a 0d 0a"
    )
    var obs_text = (
        "47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a 58 "
        "2d 48 69 3a 20 61 c3 a9 62 0d 0a 48 6f 73 74 3a 20 "
        "78 0d 0a 0d 0a"
    )
    var ows_colon_strict = (
        "47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a 48 "
        "6f 73 74 20 3a 20 65 78 61 6d 70 6c 65 2e 63 6f 6d "
        "0d 0a 0d 0a"
    )
    var ows_colon_lenient = (
        "47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a 48 "
        "6f 73 74 20 3a 20 78 0d 0a 0d 0a"
    )
    var post = (
        "50 4f 53 54 20 2f 73 75 62 6d 69 74 20 48 54 54 50 "
        "2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 65 78 61 6d 70 "
        "6c 65 2e 63 6f 6d 0d 0a 43 6f 6e 74 65 6e 74 2d 4c "
        "65 6e 67 74 68 3a 20 35 0d 0a 0d 0a 68 65 6c 6c 6f"
    )
    var te_with_length = (
        "50 4f 53 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a "
        "48 6f 73 74 3a 20 78 0d 0a 43 6f 6e 74 65 6e 74 2d "
        "4c 65 6e 67 74 68 3a 20 35 0d 0a 54 72 61 6e 73 66 "
        "65 72 2d 45 6e 63 6f 64 69 6e 67 3a 20 63 68 75 6e "
        "6b 65 64 0d 0a 0d 0a 30 0d 0a 0d 0a"
    )
    var cases = List[_H1Fixture]()
    cases.append(
        _fixture(
            "empty_request",
            "RFC 9112 section 3",
            "0d 0a 0d 0a",
            False,
        )
    )
    cases.append(
        _fixture(
            "get_simple",
            "RFC 9112 section 3",
            canonical_get,
            True,
            expected_method="GET",
            expected_uri="/",
            expected_version="HTTP/1.1",
        )
    )
    cases.append(
        _fixture(
            "leading_whitespace_strict",
            "RFC 9112 section 2.2",
            leading,
            False,
        )
    )
    cases.append(
        _fixture(
            "leading_whitespace_lenient",
            "RFC 9112 section 2.2",
            leading,
            True,
            H1LeniencyConfig(allow_leading_whitespace_before_request_line=True),
            "GET",
            "/",
            "HTTP/1.1",
        )
    )
    cases.append(
        _fixture(
            "lf_only_line_endings_strict",
            "RFC 9112 section 2.2",
            lf_only,
            False,
        )
    )
    cases.append(
        _fixture(
            "lf_only_line_endings_lenient",
            "RFC 9112 section 2.2",
            lf_only,
            True,
            H1LeniencyConfig(allow_lf_only_line_endings=True),
            "GET",
            "/",
            "HTTP/1.1",
        )
    )
    cases.append(
        _fixture(
            "mixed_case_method_strict",
            "RFC 9110 section 9.1",
            mixed_method_strict,
            False,
        )
    )
    cases.append(
        _fixture(
            "mixed_case_method_lenient",
            "RFC 9110 section 9.1",
            mixed_method_lenient,
            True,
            H1LeniencyConfig(allow_mixed_case_method=True),
            "GET",
            "/",
            "HTTP/1.1",
        )
    )
    cases.append(
        _fixture(
            "multiple_content_length_strict",
            "RFC 9112 section 6.3.5",
            duplicate_length,
            False,
        )
    )
    cases.append(
        _fixture(
            "multiple_content_length_lenient",
            "RFC 9112 section 6.3.5",
            duplicate_length,
            True,
            H1LeniencyConfig(allow_multiple_content_length=True),
            "POST",
            "/",
            "HTTP/1.1",
        )
    )
    cases.append(
        _fixture(
            "obs_fold_strict",
            "RFC 9112 section 5.2",
            obs_fold_strict,
            False,
        )
    )
    cases.append(
        _fixture(
            "obs_fold_lenient",
            "RFC 9112 section 5.2",
            obs_fold_lenient,
            True,
            H1LeniencyConfig(allow_obs_fold=True),
            "GET",
            "/",
            "HTTP/1.1",
        )
    )
    cases.append(
        _fixture(
            "obs_text_in_field_value_strict",
            "RFC 9112 section 5.5",
            obs_text,
            False,
        )
    )
    cases.append(
        _fixture(
            "obs_text_in_field_value_lenient",
            "RFC 9112 section 5.5",
            obs_text,
            True,
            H1LeniencyConfig(accept_obs_text_in_field_value=True),
            "GET",
            "/",
            "HTTP/1.1",
        )
    )
    cases.append(
        _fixture(
            "ows_before_colon_strict",
            "RFC 9112 section 5.1",
            ows_colon_strict,
            False,
        )
    )
    cases.append(
        _fixture(
            "ows_before_colon_lenient",
            "RFC 9112 section 5.1",
            ows_colon_lenient,
            True,
            H1LeniencyConfig(allow_ows_around_colon=True),
            "GET",
            "/",
            "HTTP/1.1",
        )
    )
    cases.append(
        _fixture(
            "post_with_content_length",
            "RFC 9112 section 6.2",
            post,
            True,
            expected_method="POST",
            expected_uri="/submit",
            expected_version="HTTP/1.1",
        )
    )
    cases.append(
        _fixture(
            "te_chunked_with_cl_strict",
            "RFC 9112 section 6.3",
            te_with_length,
            False,
        )
    )
    cases.append(
        _fixture(
            "te_chunked_with_cl_lenient",
            "RFC 9112 section 6.3",
            te_with_length,
            True,
            H1LeniencyConfig(allow_te_chunked_when_cl_present=True),
            "POST",
            "/",
            "HTTP/1.1",
        )
    )
    return cases^


def test_all_h1_fixtures_validate() raises:
    var cases = _fixtures()
    assert_equal(len(cases), 19)
    for i in range(len(cases)):
        _validate_fixture(cases[i])


def test_source_distinct_leniency_pairs_keep_distinct_inputs() raises:
    var cases = _fixtures()
    assert_not_equal(
        cases[6].input_hex,
        cases[7].input_hex,
        "mixed-case method fixtures have source-distinct wire bytes",
    )
    assert_not_equal(
        cases[10].input_hex,
        cases[11].input_hex,
        "obs-fold fixtures have source-distinct wire bytes",
    )
    assert_not_equal(
        cases[14].input_hex,
        cases[15].input_hex,
        "OWS-before-colon fixtures have source-distinct wire bytes",
    )


def test_typed_fixtures_match_checked_in_corpus() raises:
    """Fail when a corpus file changes without updating the typed mirror."""
    var filenames = List[String]()
    filenames.append("rfc9112_empty_request_reject.json")
    filenames.append("rfc9112_get_simple_accept.json")
    filenames.append("rfc9112_leading_whitespace_lenient_accept.json")
    filenames.append("rfc9112_leading_whitespace_reject.json")
    filenames.append("rfc9112_lf_only_line_endings_lenient_accept.json")
    filenames.append("rfc9112_lf_only_line_endings_reject.json")
    filenames.append("rfc9112_mixed_case_method_lenient_accept.json")
    filenames.append("rfc9112_mixed_case_method_reject.json")
    filenames.append("rfc9112_multiple_content_length_lenient_accept.json")
    filenames.append("rfc9112_multiple_content_length_reject.json")
    filenames.append("rfc9112_obs_fold_lenient_accept.json")
    filenames.append("rfc9112_obs_fold_reject.json")
    filenames.append("rfc9112_obs_text_in_field_value_lenient_accept.json")
    filenames.append("rfc9112_obs_text_in_field_value_reject.json")
    filenames.append("rfc9112_ows_before_colon_lenient_accept.json")
    filenames.append("rfc9112_ows_before_colon_reject.json")
    filenames.append("rfc9112_post_with_content_length_accept.json")
    filenames.append("rfc9112_te_chunked_with_cl_lenient_accept.json")
    filenames.append("rfc9112_te_chunked_with_cl_reject.json")
    var snapshot = snapshot_corpus("conformance/h1", filenames^)
    assert_equal(snapshot.json_file_count, 19)
    assert_equal(snapshot.fingerprint, UInt64(12522971779793625960))


def test_leniency_overlay_flips_strict_default() raises:
    var cfg = H1LeniencyConfig(allow_lf_only_line_endings=True)
    assert_true(cfg.allow_lf_only_line_endings)
    assert_false(cfg.allow_mixed_case_method)
    assert_true(cfg.any_enabled())


def test_strict_overlay_keeps_strict() raises:
    var cfg = H1LeniencyConfig()
    assert_false(cfg.any_enabled())


def main() raises:
    test_all_h1_fixtures_validate()
    test_source_distinct_leniency_pairs_keep_distinct_inputs()
    test_typed_fixtures_match_checked_in_corpus()
    test_leniency_overlay_flips_strict_default()
    test_strict_overlay_keeps_strict()
    print("test_conformance_h1: OK")
