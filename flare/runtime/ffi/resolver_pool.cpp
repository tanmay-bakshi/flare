/**
 * Process-wide resolver worker pool.
 *
 * getaddrinfo has no portable cancellation API. A cancelled caller abandons
 * its request immediately while a worker already inside libc finishes in the
 * background; its completion is discarded. A genuinely wedged lookup can
 * therefore occupy one fixed slot until libc returns. The pool bounds that
 * damage, and the caller's absolute deadline bounds session-visible waiting.
 * If operational evidence shows slot wedging matters, the named escalation is
 * c-ares, accepted together with its different system-resolution semantics.
 */

#include "resolver_pool.h"

#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <dlfcn.h>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <time.h>

namespace {

constexpr int kDefaultWorkerCount = 2;
constexpr int kMinWorkerCount = 1;
constexpr int kMaxWorkerCount = 32;

thread_local std::string last_error;

enum class RequestState {
    queued,
    running,
    completed,
    cancelled,
    deadline,
    shutdown,
};

int64_t monotonic_now_ns() {
    struct timespec now = {};
    if (::clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    return static_cast<int64_t>(now.tv_sec) * 1'000'000'000LL
        + static_cast<int64_t>(now.tv_nsec);
}

class Request final {
public:
    Request(
        flare_resolver_job_fn run,
        flare_resolver_job_fn cleanup,
        intptr_t context
    )
        : run_(run), cleanup_(cleanup), context_(context) {}

    ~Request() {
        if (cleanup_ != nullptr) {
            cleanup_(context_);
        }
    }

    Request(const Request&) = delete;
    Request& operator=(const Request&) = delete;

    bool begin() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ != RequestState::queued) {
            return false;
        }
        state_ = RequestState::running;
        return true;
    }

    void run() {
        run_(context_);
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ == RequestState::running) {
            state_ = RequestState::completed;
        }
        condition_.notify_all();
    }

    void cancel(RequestState reason) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (
            state_ == RequestState::queued
            || state_ == RequestState::running
        ) {
            state_ = reason;
            condition_.notify_all();
        }
    }

    int wait(int64_t deadline_ns) {
        std::unique_lock<std::mutex> lock(mutex_);
        while (
            state_ == RequestState::queued
            || state_ == RequestState::running
        ) {
            if (deadline_ns == 0) {
                condition_.wait(lock);
                continue;
            }

            const int64_t now_ns = monotonic_now_ns();
            if (now_ns < 0) {
                last_error = "clock_gettime(CLOCK_MONOTONIC) failed";
                return FLARE_RESOLVER_WAIT_FAILED;
            }
            if (now_ns >= deadline_ns) {
                state_ = RequestState::deadline;
                condition_.notify_all();
                return FLARE_RESOLVER_WAIT_DEADLINE;
            }
            condition_.wait_for(
                lock,
                std::chrono::nanoseconds(deadline_ns - now_ns)
            );
        }
        return wait_status(state_);
    }

private:
    static int wait_status(RequestState state) {
        switch (state) {
            case RequestState::completed:
                return FLARE_RESOLVER_WAIT_COMPLETED;
            case RequestState::cancelled:
                return FLARE_RESOLVER_WAIT_CANCELLED;
            case RequestState::deadline:
                return FLARE_RESOLVER_WAIT_DEADLINE;
            case RequestState::shutdown:
                return FLARE_RESOLVER_WAIT_SHUTDOWN;
            case RequestState::queued:
            case RequestState::running:
                break;
        }
        return FLARE_RESOLVER_WAIT_FAILED;
    }

    std::mutex mutex_;
    std::condition_variable condition_;
    RequestState state_ = RequestState::queued;
    flare_resolver_job_fn run_;
    flare_resolver_job_fn cleanup_;
    intptr_t context_;
};

using RequestPtr = std::shared_ptr<Request>;

struct RequestHandle final {
    explicit RequestHandle(RequestPtr request) : request(std::move(request)) {}
    RequestPtr request;
};

class ResolverPool final {
public:
    explicit ResolverPool(int worker_count) {
        workers_.reserve(static_cast<std::size_t>(worker_count));
        try {
            for (int index = 0; index < worker_count; ++index) {
                workers_.emplace_back([this] { worker_loop(); });
            }
        } catch (...) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                stopping_ = true;
            }
            condition_.notify_all();
            for (std::thread& worker : workers_) {
                if (worker.joinable()) {
                    worker.join();
                }
            }
            throw;
        }
    }

    ResolverPool(const ResolverPool&) = delete;
    ResolverPool& operator=(const ResolverPool&) = delete;

    bool submit(const RequestPtr& request) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_) {
            return false;
        }
        auto position = queue_.insert(queue_.end(), request);
        try {
            queued_.emplace(request.get(), position);
            requests_.emplace(request.get(), request);
        } catch (...) {
            queued_.erase(request.get());
            requests_.erase(request.get());
            queue_.erase(position);
            throw;
        }
        condition_.notify_one();
        return true;
    }

    void abandon_queued(Request* request) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto queued = queued_.find(request);
        if (queued == queued_.end()) {
            return;
        }
        queue_.erase(queued->second);
        queued_.erase(queued);
        requests_.erase(request);
    }

    void shutdown() {
        std::vector<RequestPtr> live;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                return;
            }
            stopping_ = true;
            live.reserve(requests_.size());
            for (const auto& entry : requests_) {
                if (RequestPtr request = entry.second.lock()) {
                    live.push_back(std::move(request));
                }
            }
            queue_.clear();
            queued_.clear();
        }

        for (const RequestPtr& request : live) {
            request->cancel(RequestState::shutdown);
        }
        live.clear();
        condition_.notify_all();

        for (std::thread& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        workers_.clear();

        std::lock_guard<std::mutex> lock(mutex_);
        requests_.clear();
    }

private:
    void worker_loop() {
        while (true) {
            RequestPtr request;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                condition_.wait(lock, [this] {
                    return stopping_ || !queue_.empty();
                });
                if (stopping_) {
                    return;
                }
                request = std::move(queue_.front());
                queued_.erase(request.get());
                queue_.pop_front();
            }

            if (request->begin()) {
                request->run();
            }

            std::lock_guard<std::mutex> lock(mutex_);
            requests_.erase(request.get());
        }
    }

    std::mutex mutex_;
    std::condition_variable condition_;
    bool stopping_ = false;
    std::list<RequestPtr> queue_;
    std::unordered_map<Request*, std::list<RequestPtr>::iterator> queued_;
    std::unordered_map<Request*, std::weak_ptr<Request>> requests_;
    std::vector<std::thread> workers_;
};

struct RuntimeState final {
    std::mutex mutex;
    std::condition_variable condition;
    int worker_count = kDefaultWorkerCount;
    bool started = false;
    bool shutting_down = false;
    bool terminal = false;
    bool exit_handler_registered = false;
    std::unique_ptr<ResolverPool> pool;
    // Successful configuration or first start pins the DSO for process
    // lifetime. Otherwise a short-lived configuration handle could unload
    // RuntimeState before first use, or explicit shutdown could reload a fresh
    // non-terminal runtime on a later public call.
    void* self_pin = nullptr;
};

RuntimeState& runtime_state() {
    static RuntimeState* state = new RuntimeState();
    return *state;
}

bool pin_library(RuntimeState& state) {
    if (state.self_pin != nullptr) {
        return true;
    }
    Dl_info info = {};
    if (
        ::dladdr(
            reinterpret_cast<void*>(&flare_resolver_pool_configure),
            &info
        ) == 0
        || info.dli_fname == nullptr
    ) {
        last_error = "dladdr could not locate the flare runtime library";
        return false;
    }
    state.self_pin = ::dlopen(info.dli_fname, RTLD_NOW | RTLD_LOCAL);
    if (state.self_pin == nullptr) {
        const char* error = ::dlerror();
        last_error = error == nullptr
            ? "dlopen could not pin the flare runtime library"
            : error;
        return false;
    }
    return true;
}

void release_start_pin(RuntimeState& state, bool was_already_pinned) {
    if (was_already_pinned || state.self_pin == nullptr) {
        return;
    }
    ::dlclose(state.self_pin);
    state.self_pin = nullptr;
}

void shutdown_runtime() {
    RuntimeState& state = runtime_state();
    std::unique_ptr<ResolverPool> pool;
    {
        std::unique_lock<std::mutex> lock(state.mutex);
        while (state.shutting_down) {
            state.condition.wait(lock);
        }
        state.terminal = true;
        if (!state.started) {
            return;
        }
        state.shutting_down = true;
        state.started = false;
        pool = std::move(state.pool);
    }

    pool->shutdown();
    pool.reset();

    {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.shutting_down = false;
        state.condition.notify_all();
    }
}

void shutdown_at_exit() {
    shutdown_runtime();
}

bool ensure_started(RuntimeState& state) {
    if (state.terminal) {
        last_error = "resolver runtime is shut down";
        return false;
    }
    if (state.started) {
        return true;
    }
    const bool was_already_pinned = state.self_pin != nullptr;
    if (!pin_library(state)) {
        return false;
    }
    try {
        state.pool = std::make_unique<ResolverPool>(state.worker_count);
    } catch (const std::exception& error) {
        last_error = error.what();
        release_start_pin(state, was_already_pinned);
        return false;
    } catch (...) {
        last_error = "failed to start resolver worker pool";
        release_start_pin(state, was_already_pinned);
        return false;
    }
    state.started = true;
    if (!state.exit_handler_registered) {
        if (std::atexit(shutdown_at_exit) != 0) {
            state.pool->shutdown();
            state.pool.reset();
            state.started = false;
            release_start_pin(state, was_already_pinned);
            last_error = "failed to register resolver runtime shutdown";
            return false;
        }
        state.exit_handler_registered = true;
    }
    return true;
}

void abandon_queued_request(Request* request) {
    RuntimeState& state = runtime_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.pool != nullptr) {
        state.pool->abandon_queued(request);
    }
}

}  // namespace

extern "C" {

int flare_resolver_pool_configure(int worker_count) {
    last_error.clear();
    if (worker_count < kMinWorkerCount || worker_count > kMaxWorkerCount) {
        last_error = "resolver worker count must be in 1..32";
        return -1;
    }
    RuntimeState& state = runtime_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.terminal) {
        last_error = "resolver runtime is shut down";
        return -3;
    }
    if (state.started) {
        last_error = "resolver pool is already started";
        return -2;
    }
    if (!pin_library(state)) {
        return -4;
    }
    state.worker_count = worker_count;
    return 0;
}

int flare_resolver_pool_worker_count(void) {
    RuntimeState& state = runtime_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    return state.worker_count;
}

int flare_resolver_pool_started(void) {
    RuntimeState& state = runtime_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    return state.started ? 1 : 0;
}

int64_t flare_resolver_monotonic_now_ns(void) {
    return monotonic_now_ns();
}

void* flare_resolver_job_submit(
    flare_resolver_job_fn run,
    flare_resolver_job_fn cleanup,
    intptr_t context
) {
    last_error.clear();
    if (run == nullptr || cleanup == nullptr) {
        last_error = "resolver job callbacks must not be null";
        if (cleanup != nullptr) {
            cleanup(context);
        }
        return nullptr;
    }
    bool request_owns_context = false;
    try {
        RequestPtr request = std::make_shared<Request>(run, cleanup, context);
        request_owns_context = true;
        auto handle = std::make_unique<RequestHandle>(request);
        RuntimeState& state = runtime_state();
        bool submitted = false;
        {
            std::lock_guard<std::mutex> lock(state.mutex);
            if (!ensure_started(state)) {
                submitted = false;
            } else if (!state.pool->submit(request)) {
                last_error = "resolver pool rejected the job during shutdown";
                submitted = false;
            } else {
                submitted = true;
            }
        }
        if (!submitted) {
            return nullptr;
        }
        return handle.release();
    } catch (const std::exception& error) {
        if (!request_owns_context) {
            cleanup(context);
        }
        last_error = error.what();
        return nullptr;
    } catch (...) {
        if (!request_owns_context) {
            cleanup(context);
        }
        last_error = "failed to submit resolver job";
        return nullptr;
    }
}

void* flare_resolver_job_clone(void* opaque) {
    last_error.clear();
    if (opaque == nullptr) {
        last_error = "cannot clone a null resolver job";
        return nullptr;
    }
    try {
        auto* handle = static_cast<RequestHandle*>(opaque);
        return new RequestHandle(handle->request);
    } catch (const std::exception& error) {
        last_error = error.what();
        return nullptr;
    } catch (...) {
        last_error = "failed to clone resolver job";
        return nullptr;
    }
}

void flare_resolver_job_release(void* opaque) {
    delete static_cast<RequestHandle*>(opaque);
}

int flare_resolver_job_wait(void* opaque, int64_t deadline_ns) {
    last_error.clear();
    if (opaque == nullptr) {
        last_error = "cannot wait on a null resolver job";
        return FLARE_RESOLVER_WAIT_FAILED;
    }
    auto* handle = static_cast<RequestHandle*>(opaque);
    int status = handle->request->wait(deadline_ns);
    if (status == FLARE_RESOLVER_WAIT_DEADLINE) {
        abandon_queued_request(handle->request.get());
    }
    return status;
}

void flare_resolver_job_cancel(void* opaque) {
    if (opaque == nullptr) {
        return;
    }
    auto* handle = static_cast<RequestHandle*>(opaque);
    handle->request->cancel(RequestState::cancelled);
    abandon_queued_request(handle->request.get());
}

int flare_resolver_pool_shutdown(void) {
    last_error.clear();
    shutdown_runtime();
    return 0;
}

const char* flare_resolver_pool_last_error(void) {
    return last_error.c_str();
}

}  // extern "C"
