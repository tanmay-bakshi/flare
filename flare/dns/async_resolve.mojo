"""Off-reactor DNS resolution + happy-eyeballs ordering.

``getaddrinfo(3)`` is a blocking syscall with no portable cancellation API.
:func:`start_resolve` submits it to flare's fixed process-wide resolver pool
and returns independently owned wait and cancellation capabilities. A caller
can abandon immediately while libc finishes on its pool worker; the eventual
result is destroyed without publication. :func:`resolve_async` retains the
older synchronous facade over that machinery.

:func:`order_happy_eyeballs` reorders a resolved address list into the
RFC 8305 connection-attempt order (interleave IPv6 / IPv4) so a dialer
can race families without one stalling the other.

The synchronous :func:`flare.dns.resolve` remains the only hostname
validation, ``getaddrinfo``, and address-conversion truth. The pool is a
generic callback runner and does not interpret DNS data.
"""

from std.atomic import Atomic, Ordering
from std.memory import Pointer, UnsafePointer
from std.memory.alloc import unsafe_alloc

from ..http.cancel import Cancel
from ..net import IpAddr
from ..net.error import AddressParseError
from ..runtime.resolver_pool import (
    ResolverJob,
    ResolverWaitStatus,
    submit_resolver_job,
)
from .resolver import resolve


struct _ResolveCtx(Movable):
    """Heap handoff cell owned by one native resolver job."""

    var host: String
    var result: List[IpAddr]
    var error: String
    var success: Bool
    var ready: Int64

    def __init__(out self, host: String):
        self.host = host
        self.result = List[IpAddr]()
        self.error = "resolve_async: resolution failed"
        self.success = False
        self.ready = 0


@always_inline
def _store_ready(mut ready: Int64, value: Int64):
    Atomic[DType.int64].store[ordering=Ordering.RELEASE](
        Pointer(to=ready).unsafe_bitcast[Scalar[DType.int64]](), value
    )


@always_inline
def _load_ready(mut ready: Int64) -> Int64:
    return Atomic[DType.int64].load[ordering=Ordering.ACQUIRE](
        Pointer(to=ready).unsafe_bitcast[Scalar[DType.int64]]()
    )


def _resolve_job_run(context: Int):
    """Run ``resolve`` on a pool worker without crossing an exception."""
    var ctx = UnsafePointer[_ResolveCtx, MutUntrackedOrigin](
        unsafe_from_address=context
    )
    try:
        var addrs = resolve(ctx[].host)
        ctx[].result = addrs^
        ctx[].success = True
    except e:
        ctx[].error = String(e)
    _store_ready(ctx[].ready, 1)


def _resolve_job_cleanup(context: Int):
    """Destroy a completed or abandoned handoff cell exactly once."""
    var ctx = UnsafePointer[_ResolveCtx, MutUntrackedOrigin](
        unsafe_from_address=context
    )
    ctx.unsafe_deinit_pointee()
    ctx.unsafe_free()


struct ResolveCancellation(Movable):
    """Independent cancellation capability for an in-flight resolve."""

    var _job: ResolverJob

    def __init__(out self, var job: ResolverJob):
        self._job = job^

    def cancel(mut self):
        """Abandon the request and wake its waiter immediately."""
        self._job.cancel()


struct ResolveRequest(Movable):
    """Linear waiter for one process-pool resolver request."""

    var _job: ResolverJob
    var _context: Int
    var _settled: Bool

    def __init__(out self, var job: ResolverJob, context: Int):
        self._job = job^
        self._context = context
        self._settled = False

    def __deinit__(deinit self):
        if not self._settled:
            self._job.cancel()

    def cancellation(self) raises -> ResolveCancellation:
        """Return another handle that can cancel this request."""
        return ResolveCancellation(self._job.clone())

    def cancel(mut self):
        """Abandon this request."""
        self._job.cancel()

    def wait_until(mut self, deadline_ns: Int64) raises -> List[IpAddr]:
        """Wait until completion or an absolute monotonic deadline.

        ``deadline_ns == 0`` waits without a deadline. Every terminal result
        consumes this waiter; a second wait is an API error.
        """
        if self._settled:
            raise Error("resolve request already settled")
        var status = self._job.wait_until(deadline_ns)
        self._settled = True
        if status == ResolverWaitStatus.CANCELLED:
            raise Error("resolve_async: cancelled mid-flight")
        if status == ResolverWaitStatus.DEADLINE:
            raise Error("resolve_async: deadline expired")
        if status == ResolverWaitStatus.SHUTDOWN:
            raise Error("resolve_async: resolver runtime shut down")
        if status != ResolverWaitStatus.COMPLETED:
            raise Error("resolve_async: resolver job failed")

        var ctx = UnsafePointer[_ResolveCtx, MutUntrackedOrigin](
            unsafe_from_address=self._context
        )
        if _load_ready(ctx[].ready) != 1:
            raise Error("resolve_async: completed without a published result")
        if not ctx[].success:
            raise Error(ctx[].error)
        return ctx[].result.copy()


def start_resolve(host: String) raises -> ResolveRequest:
    """Submit ``host`` to the process-wide resolver pool."""
    if host.byte_length() == 0:
        raise AddressParseError("empty hostname")
    var context = unsafe_alloc[_ResolveCtx](1)
    context.unsafe_write(_ResolveCtx(host))
    var job = submit_resolver_job(
        _resolve_job_run,
        _resolve_job_cleanup,
        Int(context),
    )
    return ResolveRequest(job^, Int(context))


def resolve_async(host: String, cancel: Cancel) raises -> List[IpAddr]:
    """Resolve ``host`` on a pool thread, off the reactor stack.

    Same result as :func:`flare.dns.resolve`, with ``getaddrinfo`` running on
    the fixed process-wide resolver pool. The existing ``Cancel`` vocabulary
    remains a pre-flight / post-flight boundary; callers needing prompt
    in-flight cancellation use :func:`start_resolve` and its cancellation
    handle.

    Args:
        host: Hostname or numeric IP string.
        cancel: Per-request cancel token (use ``Cancel.never()`` for an
            uncancellable call).

    Returns:
        A non-empty ``List[IpAddr]`` (OS-preference order; pass through
        :func:`order_happy_eyeballs` for connection-attempt order).

    Raises:
        AddressParseError: empty ``host``.
        DnsError / Error: resolver failure (propagated from the worker),
            or cancellation.
    """
    if cancel.cancelled():
        raise Error("resolve_async: cancelled")
    if host.byte_length() == 0:
        raise AddressParseError("empty hostname")

    var request = start_resolve(host)
    var result = request.wait_until(0)
    if cancel.cancelled():
        raise Error("resolve_async: cancelled mid-flight")
    return result^


def order_happy_eyeballs(addrs: List[IpAddr]) -> List[IpAddr]:
    """Reorder ``addrs`` into RFC 8305 connection-attempt order.

    Interleaves the IPv6 and IPv4 results (``v6[0], v4[0], v6[1],
    v4[1], ...``) preserving each family's relative order, so a dialer
    can race the two families without one family's slow first address
    starving the other. Returns a new list; the input is unchanged.
    """
    var v6 = List[IpAddr]()
    var v4 = List[IpAddr]()
    for i in range(len(addrs)):
        if addrs[i].is_v6():
            v6.append(addrs[i].copy())
        else:
            v4.append(addrs[i].copy())
    var out = List[IpAddr](capacity=len(addrs))
    var i = 0
    while i < len(v6) or i < len(v4):
        if i < len(v6):
            out.append(v6[i].copy())
        if i < len(v4):
            out.append(v4[i].copy())
        i += 1
    return out^
