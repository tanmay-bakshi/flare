"""Internal stream union shared by blocking and duplex WebSocket clients."""

from std.ffi import c_int, c_size_t, get_errno, ErrNo

from ..net import SocketAddr, NetworkError
from ..net._libc import _recv, _send, MSG_NOSIGNAL, INVALID_FD
from ..net.address import IpAddr
from ..net.socket import RawSocket, AF_INET, SOCK_STREAM
from ..tcp import TcpStream
from ..tls import TlsStream
from ..tls.stream import (
    _SSL_IO_WANT_READ,
    _SSL_IO_WANT_WRITE,
    _SSL_IO_CLOSED,
)


comptime _OWNER_IO_CHUNK: Int = 16 * 1024


struct _WsStream(Movable):
    """Hold either a TLS or plain TCP stream for WebSocket I/O."""

    var _is_tls: Bool
    var _tls: TlsStream
    var _tcp: TcpStream
    var _network_scratch: List[UInt8]
    var _network_output: List[UInt8]
    var _network_output_offset: Int
    var _network_generated: Int64
    var _network_published: Int64
    var _pending_plaintext: Int
    var _pending_fence: Int64
    var _ssl_write_pending: Bool

    def __init__(out self, var tls: TlsStream):
        self._is_tls = True
        self._tls = tls^
        self._tcp = _dummy_tcp_stream()
        self._network_scratch = List[UInt8]()
        self._network_output = List[UInt8]()
        self._network_output_offset = 0
        self._network_generated = 0
        self._network_published = 0
        self._pending_plaintext = 0
        self._pending_fence = 0
        self._ssl_write_pending = False

    def __init__(out self, var tcp: TcpStream) raises:
        self._is_tls = False
        self._tls = _dummy_tls_stream()
        self._tcp = tcp^
        self._network_scratch = List[UInt8]()
        self._network_output = List[UInt8]()
        self._network_output_offset = 0
        self._network_generated = 0
        self._network_published = 0
        self._pending_plaintext = 0
        self._pending_fence = 0
        self._ssl_write_pending = False

    def write_all(self, data: Span[UInt8, _]) raises:
        """Write all bytes to the active stream."""
        if self._is_tls:
            self._tls.write_all(data)
            return
        self._tcp.write_all(data)

    def read(mut self, buf: Pointer[UInt8, _], size: Int) raises -> Int:
        """Read up to ``size`` bytes from the active stream."""
        if self._is_tls:
            return self._tls.read(buf, size)
        return self._tcp.read(buf, size)

    def prepare_duplex(mut self) raises:
        """Put the owned socket in non-blocking mode for its owner loop."""
        if self._is_tls:
            self._tls._set_nonblocking(True)
            self._tls._enable_owner_bio()
            self._network_scratch.resize(_OWNER_IO_CHUNK, UInt8(0))
            return
        self._tcp._socket.set_nonblocking(True)

    def fd(self) -> c_int:
        """Return the owned socket descriptor."""
        if self._is_tls:
            return self._tls._fd()
        return self._tcp._socket.fd

    def read_nonblocking(
        mut self, buf: Pointer[UInt8, _], size: Int
    ) raises -> Int:
        """Advance one owner-loop read and return an ``_SSL_IO_*`` result."""
        if self._is_tls:
            return self._read_tls_nonblocking(buf, size)
        if size <= 0:
            return 0
        while True:
            var received = _recv(self.fd(), buf, c_size_t(size), c_int(0))
            if received > 0:
                return Int(received)
            if received == 0:
                return _SSL_IO_CLOSED
            var error = get_errno()
            if error == ErrNo.EINTR:
                continue
            if error == ErrNo.EAGAIN or error == ErrNo.EWOULDBLOCK:
                return _SSL_IO_WANT_READ
            raise NetworkError(
                "WebSocket receive failed with errno="
                + String(Int(error.value))
            )

    def write_nonblocking(mut self, data: Span[UInt8, _]) raises -> Int:
        """Advance one owner-loop write and return an ``_SSL_IO_*`` result."""
        if self._is_tls:
            return self._write_tls_nonblocking(data)
        if len(data) == 0:
            return 0
        while True:
            var sent = _send(
                self.fd(), data.unsafe_ptr(), c_size_t(len(data)), MSG_NOSIGNAL
            )
            if sent > 0:
                return Int(sent)
            if sent == 0:
                return _SSL_IO_CLOSED
            var error = get_errno()
            if error == ErrNo.EINTR:
                continue
            if error == ErrNo.EAGAIN or error == ErrNo.EWOULDBLOCK:
                return _SSL_IO_WANT_WRITE
            raise NetworkError(
                "WebSocket send failed with errno=" + String(Int(error.value))
            )

    def has_pending_network_output(self) -> Bool:
        """Return whether TLS ciphertext still has to reach the socket."""
        return (
            self._is_tls and self._network_published < self._network_generated
        )

    def write_blocks_receive(self) -> Bool:
        """Return whether OpenSSL requires the same write to be retried."""
        return self._is_tls and self._ssl_write_pending

    def _collect_tls_output(mut self) raises:
        while True:
            var drained = self._tls._drain_owner_ciphertext(
                self._network_output, _OWNER_IO_CHUNK
            )
            if drained == 0:
                return
            self._network_generated += Int64(drained)

    def _flush_tls_output_once(mut self) raises -> Int:
        if self._network_output_offset == len(self._network_output):
            return 0
        while True:
            var sent = _send(
                self.fd(),
                self._network_output.unsafe_ptr().unsafe_offset(
                    self._network_output_offset
                ),
                c_size_t(
                    len(self._network_output) - self._network_output_offset
                ),
                MSG_NOSIGNAL,
            )
            if sent > 0:
                var published = Int(sent)
                self._network_output_offset += published
                self._network_published += Int64(published)
                if self._network_output_offset == len(self._network_output):
                    self._network_output.clear()
                    self._network_output_offset = 0
                return published
            if sent == 0:
                return _SSL_IO_CLOSED
            var error = get_errno()
            if error == ErrNo.EINTR:
                continue
            if error == ErrNo.EAGAIN or error == ErrNo.EWOULDBLOCK:
                return _SSL_IO_WANT_WRITE
            raise NetworkError(
                "WebSocket TLS publication failed with errno="
                + String(Int(error.value))
            )

    def _receive_tls_ciphertext_once(mut self) raises -> Int:
        while True:
            var received = _recv(
                self.fd(),
                self._network_scratch.unsafe_ptr(),
                c_size_t(len(self._network_scratch)),
                c_int(0),
            )
            if received > 0:
                var count = Int(received)
                _ = self._tls._feed_owner_ciphertext(
                    Span[UInt8, _](
                        unsafe_ptr=self._network_scratch.unsafe_ptr(),
                        length=count,
                    )
                )
                return count
            if received == 0:
                return _SSL_IO_CLOSED
            var error = get_errno()
            if error == ErrNo.EINTR:
                continue
            if error == ErrNo.EAGAIN or error == ErrNo.EWOULDBLOCK:
                return _SSL_IO_WANT_READ
            raise NetworkError(
                "WebSocket TLS receive failed with errno="
                + String(Int(error.value))
            )

    def _read_tls_nonblocking(
        mut self, buf: Pointer[UInt8, _], size: Int
    ) raises -> Int:
        if size <= 0:
            return 0
        if self._ssl_write_pending:
            return _SSL_IO_WANT_READ

        self._collect_tls_output()
        var flush_result = self._flush_tls_output_once()
        if flush_result == _SSL_IO_CLOSED:
            return flush_result

        while True:
            var received = self._tls._read_nonblocking(buf, size)
            self._collect_tls_output()
            flush_result = self._flush_tls_output_once()
            if flush_result == _SSL_IO_CLOSED:
                return flush_result
            if received > 0 or received == _SSL_IO_CLOSED:
                return received
            if received == _SSL_IO_WANT_WRITE:
                raise NetworkError(
                    "TLS read blocked on an unbounded owner write BIO"
                )
            if received != _SSL_IO_WANT_READ:
                return received

            var ciphertext = self._receive_tls_ciphertext_once()
            if ciphertext > 0:
                continue
            return ciphertext

    def _complete_pending_plaintext(mut self) -> Int:
        if (
            self._pending_plaintext == 0
            or self._network_published < self._pending_fence
        ):
            return 0
        var completed = self._pending_plaintext
        self._pending_plaintext = 0
        self._pending_fence = 0
        return completed

    def _write_tls_nonblocking(mut self, data: Span[UInt8, _]) raises -> Int:
        self._collect_tls_output()
        var flush_result = self._flush_tls_output_once()
        if flush_result == _SSL_IO_CLOSED:
            return flush_result

        var completed = self._complete_pending_plaintext()
        if completed > 0:
            return completed
        if self._pending_plaintext > 0:
            return _SSL_IO_WANT_WRITE
        if len(data) == 0:
            return 0

        while True:
            var written = self._tls._write_nonblocking(data)
            self._collect_tls_output()
            flush_result = self._flush_tls_output_once()
            if flush_result == _SSL_IO_CLOSED:
                return flush_result
            if written > 0:
                self._ssl_write_pending = False
                self._pending_plaintext = written
                self._pending_fence = self._network_generated
                completed = self._complete_pending_plaintext()
                if completed > 0:
                    return completed
                return _SSL_IO_WANT_WRITE
            if written == _SSL_IO_WANT_WRITE:
                raise NetworkError(
                    "TLS write blocked on an unbounded owner write BIO"
                )
            if written == _SSL_IO_CLOSED:
                return written
            if written != _SSL_IO_WANT_READ:
                return written

            self._ssl_write_pending = True
            var ciphertext = self._receive_tls_ciphertext_once()
            if ciphertext > 0:
                continue
            return ciphertext

    def close(mut self):
        """Close the active stream."""
        if self._is_tls:
            self._tls.close()
            return
        self._tcp.close()

    def close_abortive(mut self):
        """Close without a TLS shutdown exchange after terminal I/O."""
        if self._is_tls:
            self._tls._close_abortive()
            return
        self._tcp.close()


def _dummy_tcp_stream() -> TcpStream:
    """Return an inert TCP stream for the inactive union branch."""
    var socket = RawSocket(
        c_int(INVALID_FD), c_int(AF_INET), c_int(SOCK_STREAM), True
    )
    return TcpStream(socket^, SocketAddr(IpAddr.localhost(), 0))


def _dummy_tls_stream() raises -> TlsStream:
    """Return an inert TLS stream for the inactive union branch."""
    var tcp = _dummy_tcp_stream()
    return TlsStream(tcp^, 0, 0)
