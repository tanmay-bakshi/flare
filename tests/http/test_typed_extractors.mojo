"""Tests for optional typed path extractors.

- ``OptionalPath{Int,Str,Float,Bool}`` yield ``None`` when the route did
  not capture the parameter, the parsed value when it did, and propagate
  a parse error on a present-but-malformed capture.
"""

from std.testing import assert_equal, assert_false, assert_raises, TestSuite

from flare.http import (
    Method,
    OptionalPathInt,
    OptionalPathStr,
    Request,
)


# ── OptionalPath* ───────────────────────────────────────────────────────────


def test_optional_path_int_absent_is_none() raises:
    var req = Request(method=Method.GET, url="/items")
    var x = OptionalPathInt["id"].extract(req)
    assert_false(Bool(x.value))


def test_optional_path_int_present_parses() raises:
    var req = Request(method=Method.GET, url="/items/7")
    req.params_mut()["id"] = "7"
    var x = OptionalPathInt["id"].extract(req)
    assert_equal(x.value.value(), 7)


def test_optional_path_int_present_malformed_raises() raises:
    var req = Request(method=Method.GET, url="/items/abc")
    req.params_mut()["id"] = "abc"
    with assert_raises():
        _ = OptionalPathInt["id"].extract(req)


def test_optional_path_str_present() raises:
    var req = Request(method=Method.GET, url="/u/ada")
    req.params_mut()["name"] = "ada"
    var x = OptionalPathStr["name"].extract(req)
    assert_equal(x.value.value(), String("ada"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
