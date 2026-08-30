/**
 * Process-wide fixed worker pool for blocking resolver jobs.
 *
 * The pool is intentionally generic. Mojo owns hostname validation,
 * getaddrinfo, address conversion, and result storage; the native layer owns
 * only process-wide thread lifetime, queueing, cancellation, and deadline
 * waits.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*flare_resolver_job_fn)(intptr_t context);

enum flare_resolver_wait_status {
    FLARE_RESOLVER_WAIT_COMPLETED = 1,
    FLARE_RESOLVER_WAIT_CANCELLED = 2,
    FLARE_RESOLVER_WAIT_DEADLINE = 3,
    FLARE_RESOLVER_WAIT_SHUTDOWN = 4,
    FLARE_RESOLVER_WAIT_FAILED = -1,
};

/* Configure before the first submission. Worker counts are limited to 1..32. */
int flare_resolver_pool_configure(int worker_count);

/* Introspection used by the runtime wrapper and lifecycle tests. */
int flare_resolver_pool_worker_count(void);
int flare_resolver_pool_started(void);
int64_t flare_resolver_monotonic_now_ns(void);

/*
 * Submit one job. The cleanup callback runs exactly once, after neither the
 * pool nor any request handle can observe context again. Ownership transfers
 * at call entry, so cleanup also runs exactly once when submission fails.
 */
void* flare_resolver_job_submit(
    flare_resolver_job_fn run,
    flare_resolver_job_fn cleanup,
    intptr_t context
);

/* Each clone is an independently releasable handle to the same request. */
void* flare_resolver_job_clone(void* handle);
void flare_resolver_job_release(void* handle);

/*
 * deadline_ns is an absolute CLOCK_MONOTONIC deadline. Zero waits without a
 * deadline. Expiry abandons the request; late completion is not published.
 */
int flare_resolver_job_wait(void* handle, int64_t deadline_ns);
void flare_resolver_job_cancel(void* handle);

/* Terminal, acknowledged, and idempotent. Joins every fixed worker. */
int flare_resolver_pool_shutdown(void);

/* Thread-local diagnostic for the most recent failing native operation. */
const char* flare_resolver_pool_last_error(void);

#ifdef __cplusplus
}
#endif
