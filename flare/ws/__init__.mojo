"""WebSocket client and server (RFC 6455).

Built on `flare.http` (HTTP Upgrade handshake) and `flare.tcp`. Supports
text and binary frames, ping/pong keep-alives, masking (client→server), and
clean close handshake. SIMD-accelerated payload masking for payloads ≥128 bytes.

## Public API

```mojo
from flare.ws import (
    WsClient, WsConnectAttempt, WsServer, WsServerRuntime, WsServerStop,
    WsDuplex,
    WsSender, WsReceiver, WsShutdown,
    WsFrame, WsOpcode, WsCloseCode,
    WsProtocolError, WsHandshakeError,
)
```

- `WsClient` — WebSocket client: `connect`, `connect_attempt`, strict
  subprotocol negotiation, `send_text`, `send_binary`, `recv`, `close`, and
  the consuming `split` operation.
- `WsConnectAttempt` — cancellable DNS-through-Upgrade attempt with an
  absolute handshake deadline and a shutdown handle available before dialing.
- `WsDuplex` — Linear carrier returned by client or accepted-server
  ``split(max_message_bytes)`` for one sender thread, one receiver thread, and
  an independent shutdown/close owner. The cap covers complete messages,
  including fragmented totals.
- `WsSender.send_*_within` — duplex publication within a positive millisecond
  timeout. A `False` result requires immediate shutdown.
- `WsServer` — WebSocket server: `bind` serves plaintext and `bind_tls` accepts
  `TlsServerConfig` for WSS. Both use the same Upgrade, connection, duplex,
  subprotocol, and stoppable-runtime surfaces. Its consuming `serve_stoppable`
  path returns a linear `WsServerRuntime` and an independent `WsServerStop`
  admission fence.
- `WsFrame` — A single WebSocket frame: `text`, `binary`, `ping`, `pong`, `close`.
- `WsOpcode` — Opcode byte constants (`TEXT`, `BINARY`, `PING`, `PONG`, `CLOSE`).
- `WsCloseCode` — Close status code constants (`NORMAL`, `GOING_AWAY`, …).
- `WsProtocolError` — Raised on RFC 6455 protocol violations.
- `WsHandshakeError` — Raised when the HTTP Upgrade handshake fails.

## Example

```mojo
from flare.ws import WsClient, WsFrame, WsOpcode

def main() raises:
    # Connect to a WebSocket echo server
    var ws = WsClient.connect("ws://echo.websocket.events")

    # Send a text frame
    ws.send_text("hello, flare!")

    # Receive echo
    var frame = ws.recv(max_message_bytes=65536)
    if frame.opcode == WsOpcode.TEXT:
        print(frame.text_payload()) # hello, flare!

    # Ping / pong
    ws.send_frame(WsFrame.ping())
    var pong = ws.recv(max_message_bytes=65536) # WsOpcode.PONG

    # Clean close
    ws.close()
```

### TLS WebSocket

```mojo
from flare.ws import WsClient
from flare.tls import TlsConfig

def main() raises:
    var ws = WsClient.connect("wss://echo.websocket.events", TlsConfig())
    ws.send_text("secure hello")
    var frame = ws.recv(max_message_bytes=65536)
    print(frame.text_payload())
    ws.close()
```

### Full-duplex client

```mojo
from flare.tls import TlsConfig
from flare.ws import WsClient

var ws = WsClient.connect("wss://example.com/stream", TlsConfig())
var duplex = ws^.split(max_message_bytes=65536)
var sender = duplex.take_sender()
var receiver = duplex.take_receiver()
var shutdown = duplex.take_shutdown()

# Move sender and receiver into their respective application threads. The
# receiver thread continuously drives recv; shutdown may be retained by the
# teardown owner to interrupt a blocked receive.
```

### Cancellable opening handshake

```mojo
var attempt = WsClient.connect_attempt(
    "wss://example.com/stream",
    handshake_timeout_ms=5000,
)
var shutdown = attempt.take_shutdown()
var client = attempt^.connect()
```

The shutdown handle exists before DNS begins and remains authoritative after
the completed client is split. The timeout is one absolute DNS-through-Upgrade
deadline, not a fresh budget for each phase.

### Subprotocol negotiation

```mojo
var ws = WsClient.connect(
    "wss://example.com/stream",
    subprotocols=["events.v2", "events.v1"],
)
var selected = ws.negotiated_subprotocol()
```

A server may decline an offer. When it selects a protocol, the client verifies
that the response names exactly one offered token. Servers declare their
preference order with ``WsServer.bind(addr, subprotocols=[...])``; both
``WsClient`` and the accepted ``WsConnection`` expose the optional selection.
"""

from .frame import WsFrame, WsOpcode, WsCloseCode, WsProtocolError
from .client import (
    WsClient,
    WsConnectAttempt,
    WsHandshakeError,
    WsMessage,
    WsSender,
    WsReceiver,
    WsShutdown,
    WsDuplex,
)
from ._duplex import WsPreadmissionRelease
from .server import (
    WsHandler,
    WsServer,
    WsServerStop,
    WsServerRuntime,
    WsConnection,
    WsUpgradeRequest,
)
from .client_h2 import WsOverH2Stream, bootstrap_ws_over_h2
from .server_h2 import WsOverH2ServerStream, WsH2Handler
from .auto_client import (
    WsAutoClient,
    WsAutoClientConfig,
    WsWireChoice,
    decide_wire,
)
from .extensions import (
    ExtensionOffer,
    ExtensionParameter,
    parse_extensions,
    build_permessage_deflate_offer,
    negotiate_permessage_deflate,
)
from .permessage_deflate import (
    PermessageDeflateConfig,
    PermessageDeflateContext,
    compress_message,
    decompress_message,
)
