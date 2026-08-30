"""Lifecycle and abandonment tests for the process-wide resolver pool."""

from std.atomic import Atomic, Ordering
from std.memory import UnsafePointer
from std.memory.alloc import unsafe_alloc
from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
)

from flare.runtime import (
    configure_resolver_pool,
    resolver_monotonic_now_ns,
    resolver_pool_started,
    resolver_pool_worker_count,
    shutdown_resolver_pool,
)
from flare.runtime._libc_time import libc_nanosleep_ms
from flare.runtime.resolver_pool import (
    ResolverJob,
    ResolverWaitStatus,
    submit_resolver_job,
)


struct _JobContext(Movable):
    var gate: Int
    var started: Int
    var ran: Int
    var cleaned: Int

    def __init__(
        out self,
        gate: Int,
        started: Int,
        ran: Int,
        cleaned: Int,
    ):
        self.gate = gate
        self.started = started
        self.ran = ran
        self.cleaned = cleaned


def _new_cell(value: Int64 = 0) -> Int:
    var pointer = unsafe_alloc[Int64](1)
    pointer.unsafe_write(value)
    return Int(pointer)


def _free_cell(address: Int):
    var pointer = UnsafePointer[Int64, MutUntrackedOrigin](
        unsafe_from_address=address
    )
    pointer.unsafe_deinit_pointee()
    pointer.unsafe_free()


def _load_cell(address: Int) -> Int64:
    var pointer = UnsafePointer[Int64, MutUntrackedOrigin](
        unsafe_from_address=address
    ).unsafe_bitcast[Scalar[DType.int64]]()
    return Atomic[DType.int64].load[ordering=Ordering.ACQUIRE](pointer)


def _store_cell(address: Int, value: Int64):
    var pointer = UnsafePointer[Int64, MutUntrackedOrigin](
        unsafe_from_address=address
    ).unsafe_bitcast[Scalar[DType.int64]]()
    Atomic[DType.int64].store[ordering=Ordering.RELEASE](pointer, value)


def _job_run(context: Int):
    var job = UnsafePointer[_JobContext, MutUntrackedOrigin](
        unsafe_from_address=context
    )
    _store_cell(job[].started, 1)
    while _load_cell(job[].gate) == 0:
        _ = libc_nanosleep_ms(1)
    _store_cell(job[].ran, 1)


def _job_cleanup(context: Int):
    var job = UnsafePointer[_JobContext, MutUntrackedOrigin](
        unsafe_from_address=context
    )
    _store_cell(job[].cleaned, 1)
    job.unsafe_deinit_pointee()
    job.unsafe_free()


def _submit_job(
    gate: Int,
    started: Int,
    ran: Int,
    cleaned: Int,
) raises -> ResolverJob:
    var context = unsafe_alloc[_JobContext](1)
    context.unsafe_write(_JobContext(gate, started, ran, cleaned))
    return submit_resolver_job(_job_run, _job_cleanup, Int(context))


def _finish_job(var job: ResolverJob) raises -> ResolverWaitStatus:
    return job.wait_until(0)


def _wait_for_value(address: Int, value: Int64) raises:
    for _ in range(2_000):
        if _load_cell(address) == value:
            return
        _ = libc_nanosleep_ms(1)
    raise Error("timed out waiting for resolver-pool test state")


def _exercise_queued_cancel(
    gate: Int,
    started: Int,
    ran: Int,
    cleaned: Int,
) raises:
    var job = _submit_job(gate, started, ran, cleaned)
    job.cancel()
    assert_equal(job.wait_until(0), ResolverWaitStatus.CANCELLED)


def _exercise_queued_deadline(
    gate: Int,
    started: Int,
    ran: Int,
    cleaned: Int,
) raises:
    var job = _submit_job(gate, started, ran, cleaned)
    var before = resolver_monotonic_now_ns()
    var status = job.wait_until(before + 20_000_000)
    var elapsed = resolver_monotonic_now_ns() - before
    assert_equal(status, ResolverWaitStatus.DEADLINE)
    assert_true(elapsed >= 10_000_000)
    assert_true(elapsed < 1_000_000_000)


def _exercise_running_cancel(
    gate: Int,
    started: Int,
    ran: Int,
    cleaned: Int,
) raises:
    var job = _submit_job(gate, started, ran, cleaned)
    _wait_for_value(started, 1)
    var before = resolver_monotonic_now_ns()
    job.cancel()
    assert_equal(job.wait_until(0), ResolverWaitStatus.CANCELLED)
    var elapsed = resolver_monotonic_now_ns() - before
    assert_true(elapsed < 1_000_000_000)


def _exercise_running_deadline(
    gate: Int,
    started: Int,
    ran: Int,
    cleaned: Int,
) raises:
    var job = _submit_job(gate, started, ran, cleaned)
    _wait_for_value(started, 1)
    var before = resolver_monotonic_now_ns()
    assert_equal(
        job.wait_until(before + 20_000_000),
        ResolverWaitStatus.DEADLINE,
    )
    var elapsed = resolver_monotonic_now_ns() - before
    assert_true(elapsed >= 10_000_000)
    assert_true(elapsed < 1_000_000_000)


def _submit_after_shutdown(cleaned: Int) raises:
    var gate = _new_cell(1)
    var started = _new_cell()
    var ran = _new_cell()
    with assert_raises():
        var rejected = _submit_job(gate, started, ran, cleaned)
        _ = rejected^
    _free_cell(ran)
    _free_cell(started)
    _free_cell(gate)


def test_resolver_pool_lifecycle() raises:
    with assert_raises():
        configure_resolver_pool(0)
    with assert_raises():
        configure_resolver_pool(33)

    configure_resolver_pool(1)
    assert_equal(resolver_pool_worker_count(), 1)
    assert_false(resolver_pool_started())

    var open_gate = _new_cell()
    var blocker_started = _new_cell()
    var blocker_ran = _new_cell()
    var blocker_cleaned = _new_cell()
    var blocker = _submit_job(
        open_gate,
        blocker_started,
        blocker_ran,
        blocker_cleaned,
    )
    _wait_for_value(blocker_started, 1)
    assert_true(resolver_pool_started())
    with assert_raises():
        configure_resolver_pool(2)

    var cancel_started = _new_cell()
    var cancel_ran = _new_cell()
    var cancel_cleaned = _new_cell()
    _exercise_queued_cancel(
        open_gate,
        cancel_started,
        cancel_ran,
        cancel_cleaned,
    )

    var deadline_started = _new_cell()
    var deadline_ran = _new_cell()
    var deadline_cleaned = _new_cell()
    _exercise_queued_deadline(
        open_gate,
        deadline_started,
        deadline_ran,
        deadline_cleaned,
    )

    assert_equal(_load_cell(cancel_started), 0)
    assert_equal(_load_cell(deadline_started), 0)
    _wait_for_value(cancel_cleaned, 1)
    _wait_for_value(deadline_cleaned, 1)
    assert_equal(_load_cell(blocker_ran), 0)

    _store_cell(open_gate, 1)
    assert_equal(_finish_job(blocker^), ResolverWaitStatus.COMPLETED)
    assert_equal(_load_cell(blocker_ran), 1)
    _wait_for_value(blocker_cleaned, 1)
    assert_equal(_load_cell(cancel_ran), 0)
    assert_equal(_load_cell(deadline_ran), 0)

    var running_cancel_gate = _new_cell()
    var running_cancel_started = _new_cell()
    var running_cancel_ran = _new_cell()
    var running_cancel_cleaned = _new_cell()
    _exercise_running_cancel(
        running_cancel_gate,
        running_cancel_started,
        running_cancel_ran,
        running_cancel_cleaned,
    )
    assert_equal(_load_cell(running_cancel_ran), 0)
    assert_equal(_load_cell(running_cancel_cleaned), 0)
    _store_cell(running_cancel_gate, 1)
    _wait_for_value(running_cancel_cleaned, 1)
    assert_equal(_load_cell(running_cancel_ran), 1)

    var running_deadline_gate = _new_cell()
    var running_deadline_started = _new_cell()
    var running_deadline_ran = _new_cell()
    var running_deadline_cleaned = _new_cell()
    _exercise_running_deadline(
        running_deadline_gate,
        running_deadline_started,
        running_deadline_ran,
        running_deadline_cleaned,
    )
    assert_equal(_load_cell(running_deadline_ran), 0)
    assert_equal(_load_cell(running_deadline_cleaned), 0)
    _store_cell(running_deadline_gate, 1)
    _wait_for_value(running_deadline_cleaned, 1)
    assert_equal(_load_cell(running_deadline_ran), 1)

    shutdown_resolver_pool()
    shutdown_resolver_pool()
    assert_false(resolver_pool_started())
    with assert_raises():
        configure_resolver_pool(1)

    var rejected_cleaned = _new_cell()
    _submit_after_shutdown(rejected_cleaned)
    assert_equal(_load_cell(rejected_cleaned), 1)

    _free_cell(rejected_cleaned)
    _free_cell(running_deadline_cleaned)
    _free_cell(running_deadline_ran)
    _free_cell(running_deadline_started)
    _free_cell(running_deadline_gate)
    _free_cell(running_cancel_cleaned)
    _free_cell(running_cancel_ran)
    _free_cell(running_cancel_started)
    _free_cell(running_cancel_gate)
    _free_cell(deadline_cleaned)
    _free_cell(deadline_ran)
    _free_cell(deadline_started)
    _free_cell(cancel_cleaned)
    _free_cell(cancel_ran)
    _free_cell(cancel_started)
    _free_cell(blocker_cleaned)
    _free_cell(blocker_ran)
    _free_cell(blocker_started)
    _free_cell(open_gate)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
