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


struct _WsStream(Movable):
    """Hold either a TLS or plain TCP stream for WebSocket I/O."""

    var _is_tls: Bool
    var _tls: TlsStream
    var _tcp: TcpStream

    def __init__(out self, var tls: TlsStream):
        self._is_tls = True
        self._tls = tls^
        self._tcp = _dummy_tcp_stream()

    def __init__(out self, var tcp: TcpStream) raises:
        self._is_tls = False
        self._tls = _dummy_tls_stream()
        self._tcp = tcp^

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
            return self._tls._read_nonblocking(buf, size)
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

    def write_nonblocking(self, data: Span[UInt8, _]) raises -> Int:
        """Advance one owner-loop write and return an ``_SSL_IO_*`` result."""
        if self._is_tls:
            return self._tls._write_nonblocking(data)
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
