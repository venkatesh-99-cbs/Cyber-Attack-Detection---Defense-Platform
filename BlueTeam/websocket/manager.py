import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Asynchronous WebSocket connection manager.
    Tracks active client connections, handles client connect/disconnect,
    and supports targeted personal messages and broadcast delivery.
    """

    def __init__(self):
        self.active_connections: List[Any] = []

    async def connect(self, websocket: Any) -> None:
        """
        Accepts the WebSocket connection and registers it in the active list.
        Prevents duplicate registrations of the same websocket instance.
        """
        if hasattr(websocket, "accept") and callable(websocket.accept):
            await websocket.accept()

        if websocket not in self.active_connections:
            self.active_connections.append(websocket)
            logger.info(
                f"WebSocket client connected. Active connections: {len(self.active_connections)}"
            )

    def disconnect(self, websocket: Any) -> None:
        """
        Removes the WebSocket connection from the active list.
        Safe to call if the client is not in the active list or already removed.
        """
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(
                f"WebSocket client disconnected. Active connections: {len(self.active_connections)}"
            )

    async def send_personal_message(
        self, message: Dict[str, Any], websocket: Any
    ) -> bool:
        """
        Sends a structured JSON-compatible dictionary message to a specific client.
        Safely handles and logs send failures, removing broken clients.
        Returns True on success, False on failure.
        """
        try:
            if hasattr(websocket, "send_json") and callable(websocket.send_json):
                await websocket.send_json(message)
            elif hasattr(websocket, "send_text") and callable(websocket.send_text):
                import json
                await websocket.send_text(json.dumps(message))
            return True
        except Exception as e:
            logger.warning(
                f"Failed to send personal WebSocket message to client: {e}. Removing client."
            )
            self.disconnect(websocket)
            return False

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """
        Broadcasts a structured JSON-compatible dictionary message to all connected clients.
        If a client fails during delivery, it is safely disconnected while remaining
        clients continue to receive the broadcast.
        """
        # Safe iteration over a snapshot copy of current connections
        connections_snapshot = list(self.active_connections)
        for connection in connections_snapshot:
            try:
                if hasattr(connection, "send_json") and callable(connection.send_json):
                    await connection.send_json(message)
                elif hasattr(connection, "send_text") and callable(connection.send_text):
                    import json
                    await connection.send_text(json.dumps(message))
            except Exception as e:
                logger.warning(
                    f"Failed to broadcast message to WebSocket client: {e}. Removing client."
                )
                self.disconnect(connection)

    @property
    def active_count(self) -> int:
        """Returns total active connection count."""
        return len(self.active_connections)

