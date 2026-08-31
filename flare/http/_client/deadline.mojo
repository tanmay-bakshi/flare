"""Internal whole-operation deadline for blocking HTTP clients.

The public boundary accepts a duration. This module converts that duration
once to an absolute monotonic deadline, then carries the same value through
DNS, address fallback, redirects, retries, writes, and response reads.
"""

from ...dns import resolve, start_resolve
from ...net import DnsError, IpAddr, NetworkError, SocketAddr, Timeout
from ...runtime._libc_time import monotonic_now_ns
from ...tcp import TcpStream
from ...tcp.stream import _connect_with_fallback


@fieldwise_init
struct _HttpOperationDeadline(Copyable, ImplicitlyCopyable, Movable, Writable):
    """One optional absolute deadline internal to ``HttpClient``."""

    var deadline_ns: Int64
    var timeout_ms: Int

    @staticmethod
    def inactive() -> Self:
        """Return the sentinel used by the legacy untimed request path."""
        return Self(Int64(0), 0)

    @staticmethod
    def from_timeout(timeout_ms: Int) raises -> Self:
        """Validate a public duration and convert it to one deadline."""
        if timeout_ms <= 0:
            raise Error("HTTP operation timeout must be positive")
        if timeout_ms > Int(Int64.MAX // 1_000_000):
            raise Error("HTTP operation timeout is too large")
        var now_ns = monotonic_now_ns()
        var budget_ns = Int64(timeout_ms) * 1_000_000
        if now_ns > Int64.MAX - budget_ns:
            raise Error("HTTP operation deadline overflows Int64")
        return Self(now_ns + budget_ns, timeout_ms)

    def active(self) -> Bool:
        """Return whether this value carries a real deadline."""
        return self.deadline_ns != 0

    def expired(self) -> Bool:
        """Return whether the deadline has elapsed."""
        return self.active() and monotonic_now_ns() >= self.deadline_ns

    def check(self) raises:
        """Raise the stable operation timeout at or beyond the deadline."""
        if self.expired():
            raise Timeout("HTTP operation deadline", self.timeout_ms)

    def remaining_ms(self, phase_cap_ms: Int = 0) raises -> Int:
        """Return the positive, ceil-rounded budget for the next wait.

        ``phase_cap_ms`` preserves a narrower pre-existing connect/read cap.
        Zero means the operation deadline is the only bound.
        """
        if not self.active():
            return phase_cap_ms
        var remaining_ns = self.deadline_ns - monotonic_now_ns()
        if remaining_ns <= 0:
            raise Timeout("HTTP operation deadline", self.timeout_ms)
        var remaining_ms = Int(remaining_ns // 1_000_000)
        if remaining_ns % 1_000_000 != 0:
            remaining_ms += 1
        if phase_cap_ms > 0 and phase_cap_ms < remaining_ms:
            return phase_cap_ms
        return remaining_ms

    def resolve(self, host: String) raises -> List[IpAddr]:
        """Resolve ``host`` inside the operation deadline."""
        if not self.active():
            return resolve(host)
        self.check()
        var request = start_resolve(host)
        try:
            var addresses = request.wait_until(self.deadline_ns)
            self.check()
            return addresses^
        except error:
            if self.expired():
                raise Timeout("HTTP operation deadline", self.timeout_ms)
            raise error^

    def connect(
        self,
        host: String,
        port: UInt16,
        phase_cap_ms: Int,
    ) raises -> TcpStream:
        """Resolve and connect with one budget across every address."""
        if not self.active():
            return _connect_with_fallback(host, port, phase_cap_ms)
        var addresses = self.resolve(host)
        if len(addresses) == 0:
            raise DnsError("DNS resolution returned no results for: " + host)
        var last_error = String("")
        for i in range(len(addresses)):
            self.check()
            try:
                var stream = TcpStream.connect_timeout(
                    SocketAddr(addresses[i], port),
                    self.remaining_ms(phase_cap_ms),
                )
                stream._set_operation_deadline(self.deadline_ns, phase_cap_ms)
                self.check()
                return stream^
            except error:
                if self.expired():
                    raise Timeout("HTTP operation deadline", self.timeout_ms)
                last_error = String(error)
        raise NetworkError(
            "all addresses failed for " + host + ": " + last_error
        )
