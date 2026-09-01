"""Typed HTTP and WebSocket routes for one shared listener."""

from std.memory import ArcPointer

from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response
from flare.runtime.pool import Pool
from flare.ws.server import (
    WsConnection,
    WsHandler,
    WsUpgradeDecision,
    WsUpgradeGuard,
    WsUpgradeRequest,
)
from flare.ws._subprotocol import _validate_subprotocols


comptime _WsServeThunk = def(Int, var WsConnection) raises thin -> None
comptime _WsDestroyThunk = def(Int) thin -> None
comptime _WsGuardThunk = def(
    Int, WsUpgradeRequest
) raises thin -> WsUpgradeDecision


def _serve_ws_route[
    W: WsHandler
](address: Int, var connection: WsConnection) raises:
    """Copy one registered handler and run one connection through it."""
    var handler = Pool[W].get_ptr(address)[].copy()
    handler.on_connection(connection^)


def _destroy_ws_route[W: WsHandler](address: Int):
    Pool[W].free(address)


def _decide_ws_route_guard[
    G: WsUpgradeGuard
](address: Int, request: WsUpgradeRequest) raises -> WsUpgradeDecision:
    """Copy one registered guard and decide one parsed Upgrade request."""
    var guard = Pool[G].get_ptr(address)[].copy()
    return guard.decide(request)


def _destroy_ws_route_guard[G: WsUpgradeGuard](address: Int):
    Pool[G].free(address)


def _valid_route_path(path: String) -> Bool:
    if path.byte_length() == 0 or path.unsafe_ptr()[0] != UInt8(47):
        return False
    for index in range(path.byte_length()):
        if path.unsafe_ptr()[index] == UInt8(63):
            return False
    return True


struct _WsRouteRegistry(Movable):
    """Shared immutable-after-build registry of heterogeneous handlers."""

    var paths: List[String]
    var handler_addresses: List[Int]
    var serve_thunks: List[_WsServeThunk]
    var destroy_thunks: List[_WsDestroyThunk]
    # A route stores -1 when no guard was registered. Guard prototypes are
    # packed separately so absence is not represented by an allow-all hook.
    var guard_indices: List[Int]
    var guard_addresses: List[Int]
    var guard_thunks: List[_WsGuardThunk]
    var guard_destroy_thunks: List[_WsDestroyThunk]
    var subprotocols: List[List[String]]

    def __init__(out self):
        self.paths = List[String]()
        self.handler_addresses = List[Int]()
        self.serve_thunks = List[_WsServeThunk]()
        self.destroy_thunks = List[_WsDestroyThunk]()
        self.guard_indices = List[Int]()
        self.guard_addresses = List[Int]()
        self.guard_thunks = List[_WsGuardThunk]()
        self.guard_destroy_thunks = List[_WsDestroyThunk]()
        self.subprotocols = List[List[String]]()

    def __deinit__(deinit self):
        for index in range(len(self.handler_addresses)):
            self.destroy_thunks[index](self.handler_addresses[index])
        for index in range(len(self.guard_addresses)):
            self.guard_destroy_thunks[index](self.guard_addresses[index])


@fieldwise_init
struct _HttpWsDispatch[H: Handler & Copyable](Copyable, Movable):
    """Immutable worker-facing snapshot of one completed route table."""

    var _http_handler: Self.H
    var _ws: ArcPointer[_WsRouteRegistry]

    def _ws_index(self, path: String) -> Int:
        for index in range(len(self._ws[].paths)):
            if self._ws[].paths[index] == path:
                return index
        return -1

    def _ws_subprotocols(self, index: Int) -> List[String]:
        return self._ws[].subprotocols[index].copy()

    def _ws_has_guard(self, index: Int) -> Bool:
        return self._ws[].guard_indices[index] >= 0

    def _decide_ws_upgrade(
        self, index: Int, request: WsUpgradeRequest
    ) raises -> WsUpgradeDecision:
        var guard_index = self._ws[].guard_indices[index]
        if guard_index < 0:
            raise Error("WebSocket route has no Upgrade guard")
        var address = self._ws[].guard_addresses[guard_index]
        return self._ws[].guard_thunks[guard_index](address, request)

    def _serve_http(self, var request: Request) raises -> Response:
        return self._http_handler.serve(request^).lower()

    def _serve_ws(self, index: Int, var connection: WsConnection) raises:
        var address = self._ws[].handler_addresses[index]
        self._ws[].serve_thunks[index](address, connection^)


struct HttpWsRoutes[H: Handler & Copyable](Movable):
    """One-shot route builder for HTTP and heterogeneous WS handlers.

    Serving consumes the builder and freezes its boxed prototypes behind an
    immutable worker-facing snapshot. A caller therefore cannot retain a
    second builder that mutates the shared registry after workers begin.
    Each accepted connection receives its own copy of the selected handler.
    """

    var _http_handler: Self.H
    var _ws: ArcPointer[_WsRouteRegistry]

    def __init__(out self, var http_handler: Self.H):
        self._http_handler = http_handler^
        self._ws = ArcPointer[_WsRouteRegistry](_WsRouteRegistry())

    def _path_exists(self, path: String) -> Bool:
        for registered in self._ws[].paths:
            if registered == path:
                return True
        return False

    def websocket[
        W: WsHandler
    ](
        mut self,
        path: String,
        var handler: W,
        subprotocols: List[String] = List[String](),
    ) raises:
        """Declare an exact WebSocket path and its handler prototype."""
        if not _valid_route_path(path):
            raise Error(
                "WebSocket route path must be an absolute path without a query"
            )
        if self._path_exists(path):
            raise Error("duplicate WebSocket route path: " + path)
        _validate_subprotocols(subprotocols)
        var address = Pool[W].alloc_move(handler^)
        self._ws[].paths.append(path)
        self._ws[].handler_addresses.append(address)
        self._ws[].serve_thunks.append(_serve_ws_route[W])
        self._ws[].destroy_thunks.append(_destroy_ws_route[W])
        self._ws[].guard_indices.append(-1)
        self._ws[].subprotocols.append(subprotocols.copy())

    def websocket_guarded[
        W: WsHandler, G: WsUpgradeGuard
    ](
        mut self,
        path: String,
        var handler: W,
        var guard: G,
        subprotocols: List[String] = List[String](),
    ) raises:
        """Declare an exact WebSocket path protected by an Upgrade guard."""
        if not _valid_route_path(path):
            raise Error(
                "WebSocket route path must be an absolute path without a query"
            )
        if self._path_exists(path):
            raise Error("duplicate WebSocket route path: " + path)
        _validate_subprotocols(subprotocols)
        var handler_address = Pool[W].alloc_move(handler^)
        var guard_address = Pool[G].alloc_move(guard^)
        var guard_index = len(self._ws[].guard_addresses)
        self._ws[].paths.append(path)
        self._ws[].handler_addresses.append(handler_address)
        self._ws[].serve_thunks.append(_serve_ws_route[W])
        self._ws[].destroy_thunks.append(_destroy_ws_route[W])
        self._ws[].guard_indices.append(guard_index)
        self._ws[].guard_addresses.append(guard_address)
        self._ws[].guard_thunks.append(_decide_ws_route_guard[G])
        self._ws[].guard_destroy_thunks.append(_destroy_ws_route_guard[G])
        self._ws[].subprotocols.append(subprotocols.copy())

    def _freeze(deinit self) -> _HttpWsDispatch[Self.H]:
        return _HttpWsDispatch[Self.H](self._http_handler^, self._ws^)
