from fastapi import WebSocket
from typing import Dict, Set
import json

# ============================================================================
# WebSocket Connection Manager
# ============================================================================

class WebSocketManager:
    """Manages WebSocket connections per channel"""

    def __init__(self):
        # channel_id -> set of WebSocket connections
        self.active_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, channel_id: str, websocket: WebSocket):
        """Add a new WebSocket connection for a channel"""
        await websocket.accept()
        if channel_id not in self.active_connections:
            self.active_connections[channel_id] = set()
        self.active_connections[channel_id].add(websocket)

    def disconnect(self, channel_id: str, websocket: WebSocket):
        """Remove a WebSocket connection"""
        if channel_id in self.active_connections:
            self.active_connections[channel_id].discard(websocket)
            if not self.active_connections[channel_id]:
                del self.active_connections[channel_id]

    async def broadcast_message(self, channel_id: str, message: dict):
        """Broadcast a message to all connected clients in a channel"""
        if channel_id not in self.active_connections:
            return

        # Convert message to JSON
        message_json = json.dumps(message)

        # Send to all connections, removing any that fail
        dead_connections = set()
        for connection in self.active_connections[channel_id]:
            try:
                await connection.send_text(message_json)
            except Exception:
                dead_connections.add(connection)

        # Clean up dead connections
        for connection in dead_connections:
            self.disconnect(channel_id, connection)
