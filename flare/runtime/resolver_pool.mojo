"""Process-wide fixed worker pool for blocking resolver jobs.

The native queue owns exactly ``worker_count`` long-lived threads. Mojo jobs
remain the only place hostname validation, ``getaddrinfo``, and address
conversion occur; this module supplies only the generic run/cleanup boundary.

Cancellation abandons a request immediately. If its worker is already inside
libc, the worker remains occupied until libc returns and the late result is
destroyed without publication. The fixed pool bounds that damage, while an
absolute monotonic deadline bounds caller-visible waiting. c-ares is the named
escalation if operational evidence ever shows resolver-slot wedging matters;
it is not used pre-emptively because doing so would trade away full system
resolution semantics.
"""

from std.ffi import CStringSlice, OwnedDLHandle, c_int
from std.memory import UnsafePointer

from ..utils.dylib import dl_sym, find_flare_lib


comptime _JobCallback = def(Int) thin -> None


@fieldwise_init
struct ResolverWaitStatus(Equatable, ImplicitlyCopyable, Movable, Writable):
    """Terminal status returned by a resolver job wait."""

    comptime COMPLETED = Self(1)
    comptime CANCELLED = Self(2)
    comptime DEADLINE = Self(3)
    comptime SHUTDOWN = Self(4)
    comptime FAILED = Self(-1)

    var value: Int


struct _ResolverPoolLib(Movable):
    """Loaded native shim and cached resolver-pool entry points."""

    comptime _Callback = _JobCallback

    var _lib: OwnedDLHandle
    var _configure: def(c_int) thin abi("C") -> c_int
    var _worker_count: def() thin abi("C") -> c_int
    var _started: def() thin abi("C") -> c_int
    var _now_ns: def() thin abi("C") -> Int64
    var _submit: def(
        Self._Callback,
        Self._Callback,
        Int,
    ) thin abi("C") -> Int
    var _clone: def(Int) thin abi("C") -> Int
    var _release: def(Int) thin abi("C") -> None
    var _wait: def(Int, Int64) thin abi("C") -> c_int
    var _cancel: def(Int) thin abi("C") -> None
    var _shutdown: def() thin abi("C") -> c_int
    var _last_error: def() thin abi("C") -> UnsafePointer[
        UInt8, MutUntrackedOrigin
    ]

    def __init__(out self) raises:
        self._lib = OwnedDLHandle(find_flare_lib("tls"))
        self._configure = dl_sym[def(c_int) thin abi("C") -> c_int](
            self._lib, "flare_resolver_pool_configure"
        )
        self._worker_count = dl_sym[def() thin abi("C") -> c_int](
            self._lib, "flare_resolver_pool_worker_count"
        )
        self._started = dl_sym[def() thin abi("C") -> c_int](
            self._lib, "flare_resolver_pool_started"
        )
        self._now_ns = dl_sym[def() thin abi("C") -> Int64](
            self._lib, "flare_resolver_monotonic_now_ns"
        )
        self._submit = dl_sym[
            def(Self._Callback, Self._Callback, Int) thin abi("C") -> Int
        ](self._lib, "flare_resolver_job_submit")
        self._clone = dl_sym[def(Int) thin abi("C") -> Int](
            self._lib, "flare_resolver_job_clone"
        )
        self._release = dl_sym[def(Int) thin abi("C") -> None](
            self._lib, "flare_resolver_job_release"
        )
        self._wait = dl_sym[def(Int, Int64) thin abi("C") -> c_int](
            self._lib, "flare_resolver_job_wait"
        )
        self._cancel = dl_sym[def(Int) thin abi("C") -> None](
            self._lib, "flare_resolver_job_cancel"
        )
        self._shutdown = dl_sym[def() thin abi("C") -> c_int](
            self._lib, "flare_resolver_pool_shutdown"
        )
        self._last_error = dl_sym[
            def() thin abi("C") -> UnsafePointer[UInt8, MutUntrackedOrigin]
        ](self._lib, "flare_resolver_pool_last_error")

    def error(self) -> String:
        var pointer = self._last_error()
        return String(
            StringSlice(
                unsafe_from_utf8=CStringSlice(
                    unsafe_from_ptr=pointer.unsafe_bitcast[Int8]()
                )
            )
        )


struct ResolverJob(Movable):
    """One native request handle with deterministic release."""

    var _ffi: _ResolverPoolLib
    var _handle: Int

    def __init__(out self, var ffi: _ResolverPoolLib, handle: Int):
        self._ffi = ffi^
        self._handle = handle

    def __deinit__(deinit self):
        if self._handle != 0:
            self._ffi._release(self._handle)

    def clone(self) raises -> Self:
        """Create an independently owned handle to the same request."""
        var ffi = _ResolverPoolLib()
        var handle = self._ffi._clone(self._handle)
        if handle == 0:
            raise Error("resolver job clone failed: " + self._ffi.error())
        return Self(ffi^, handle)

    def cancel(mut self):
        """Abandon the request and wake every waiter."""
        self._ffi._cancel(self._handle)

    def wait_until(mut self, deadline_ns: Int64) raises -> ResolverWaitStatus:
        """Wait through an absolute ``CLOCK_MONOTONIC`` deadline.

        A zero deadline waits without a time limit. Expiry abandons the job;
        work already running completes only for cleanup.
        """
        var status = Int(self._ffi._wait(self._handle, deadline_ns))
        if status == ResolverWaitStatus.FAILED.value:
            raise Error("resolver job wait failed: " + self._ffi.error())
        return ResolverWaitStatus(status)


def submit_resolver_job(
    run: _JobCallback,
    cleanup: _JobCallback,
    context: Int,
) raises -> ResolverJob:
    """Submit one job, transferring ``context`` to ``cleanup``.

    Cleanup runs exactly once even when native submission fails.
    """
    var transferred = False
    try:
        var ffi = _ResolverPoolLib()
        transferred = True
        var handle = ffi._submit(run, cleanup, context)
        if handle == 0:
            raise Error("resolver job submission failed: " + ffi.error())
        return ResolverJob(ffi^, handle)
    except error:
        if not transferred:
            cleanup(context)
        raise error^


def configure_resolver_pool(worker_count: Int = 2) raises:
    """Set the fixed process-wide worker count before first submission."""
    if worker_count < 1 or worker_count > 32:
        raise Error("resolver worker count must be in 1..32")
    var ffi = _ResolverPoolLib()
    if ffi._configure(c_int(worker_count)) != c_int(0):
        raise Error("resolver pool configuration failed: " + ffi.error())


def resolver_pool_worker_count() raises -> Int:
    """Return the configured or active fixed worker count."""
    var ffi = _ResolverPoolLib()
    return Int(ffi._worker_count())


def resolver_pool_started() raises -> Bool:
    """Return whether lazy first use has started the worker threads."""
    var ffi = _ResolverPoolLib()
    return ffi._started() != c_int(0)


def resolver_monotonic_now_ns() raises -> Int64:
    """Read the deadline clock used by native resolver waits."""
    var ffi = _ResolverPoolLib()
    var now = ffi._now_ns()
    if now < 0:
        raise Error("resolver monotonic clock read failed")
    return now


def shutdown_resolver_pool() raises:
    """Terminally stop the resolver runtime and join every worker.

    The operation is acknowledged and idempotent. A worker currently wedged
    inside libc is joined when libc returns; no session request needs to wait
    for that worker because cancellation and deadlines abandon independently.
    """
    var ffi = _ResolverPoolLib()
    if ffi._shutdown() != c_int(0):
        raise Error("resolver pool shutdown failed: " + ffi.error())
