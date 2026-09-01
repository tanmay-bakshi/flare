"""High-level WebSocket message vocabulary."""


struct WsMessage(Movable):
    """A high-level WebSocket text or binary message.

    Produced by ``WsClient.recv_message(max_message_bytes)`` and
    ``WsReceiver.recv_message()``. Use ``is_text`` to discriminate between
    message kinds.
    """

    var is_text: Bool
    var _text: String
    var _binary: List[UInt8]

    def __init__(out self, text: String):
        """Initialise a text message."""
        self.is_text = True
        self._text = text
        self._binary = List[UInt8]()

    def __init__(out self, binary: List[UInt8]):
        """Initialise a binary message."""
        self.is_text = False
        self._text = ""
        self._binary = binary.copy()

    def as_text(self) -> String:
        """Return the text payload, or an empty string for binary messages."""
        return self._text

    def as_binary(self) -> List[UInt8]:
        """Return a copy of the binary payload."""
        return self._binary.copy()
