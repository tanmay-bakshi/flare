"""Optional path extractors.

Split out of :mod:`flare.http.extract` to keep that file within the
file-size budget. Holds the ``OptionalPath{Int,Str,Float,Bool}``
concretes for path captures that may be absent. ``flare.http.extract``
re-exports all of them.
"""

from std.collections import Optional

from ._extract_core import (
    Extractor,
    _parse_bool_param,
    _parse_float64_param,
    _parse_int_param,
)
from .request import Request


# ── Optional path concretes ─────────────────────────────────────────────────
#
# ``OptionalPath*`` mirror ``OptionalQuery*``: ``value`` is ``None`` when the
# route did not capture ``name`` (rather than raising as the required ``Path*``
# do). A parse error on a *present* capture still propagates -> 400. These let
# a single handler serve overlapping routes (e.g. ``/items`` and
# ``/items/:id``) without a separate struct per arity.


@fieldwise_init
struct OptionalPathInt[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional path parameter as ``Optional[Int]``. ``value`` is
    ``None`` when the route did not capture ``name``."""

    var value: Optional[Int]

    def __init__(out self):
        self.value = Optional[Int]()

    def apply(mut self, req: Request) raises:
        if not req.has_param(String(Self.name)):
            self.value = Optional[Int]()
            return
        self.value = Optional[Int](
            _parse_int_param(req.param(String(Self.name)))
        )

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct OptionalPathStr[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional path parameter as ``Optional[String]``."""

    var value: Optional[String]

    def __init__(out self):
        self.value = Optional[String]()

    def apply(mut self, req: Request) raises:
        if not req.has_param(String(Self.name)):
            self.value = Optional[String]()
            return
        self.value = Optional[String](req.param(String(Self.name)))

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct OptionalPathFloat[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional path parameter as ``Optional[Float64]``."""

    var value: Optional[Float64]

    def __init__(out self):
        self.value = Optional[Float64]()

    def apply(mut self, req: Request) raises:
        if not req.has_param(String(Self.name)):
            self.value = Optional[Float64]()
            return
        self.value = Optional[Float64](
            _parse_float64_param(req.param(String(Self.name)))
        )

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^


@fieldwise_init
struct OptionalPathBool[name: StaticString](
    Copyable, Defaultable, Extractor, Movable
):
    """Optional path parameter as ``Optional[Bool]``."""

    var value: Optional[Bool]

    def __init__(out self):
        self.value = Optional[Bool]()

    def apply(mut self, req: Request) raises:
        if not req.has_param(String(Self.name)):
            self.value = Optional[Bool]()
            return
        self.value = Optional[Bool](
            _parse_bool_param(req.param(String(Self.name)))
        )

    @staticmethod
    def extract(req: Request) raises -> Self:
        var out = Self()
        out.apply(req)
        return out^
