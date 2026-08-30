"""Example: optional typed path extractors.

``OptionalPath{Int,Str,Float,Bool}`` represents a path parameter that may or
may not be captured by the route (``None`` when absent), so one handler can
serve ``/items`` and ``/items/:id``.

Pure construction + a couple of in-process ``serve`` calls so the
example doubles as a smoke test under ``pixi run``.

Run:
    pixi run mojo -I . examples/intermediate/typed_extractors.mojo
"""

from flare.http import (
    Extracted,
    Handler,
    Method,
    OptionalPathInt,
    Request,
    Response,
    ok,
)


@fieldwise_init
struct ListOrGetItem(Copyable, Defaultable, Handler, Movable):
    """Serves both ``/items`` (list) and ``/items/:id`` (single)."""

    var id: OptionalPathInt["id"]

    def __init__(out self):
        self.id = OptionalPathInt["id"]()

    def serve(self, req: Request) raises -> Response:
        if self.id.value:
            return ok("item " + String(self.id.value.value()))
        return ok("all items")


def main() raises:
    print("=== flare: typed extractors ===")
    print()

    var items = Extracted[ListOrGetItem]()
    var list_req = Request(method=Method.GET, url="/items")
    print("GET /items     ->", items.serve(list_req).text())

    var get_req = Request(method=Method.GET, url="/items/42")
    get_req.params_mut()["id"] = "42"
    print("GET /items/42  ->", items.serve(get_req).text())
