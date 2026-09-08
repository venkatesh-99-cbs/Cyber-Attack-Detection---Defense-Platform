import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from BlueTeam.websocket.manager import ConnectionManager

logger = logging.getLogger(__name__)

router = APIRouter()
ws_manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Real-time WebSocket endpoint for security event and alert monitoring.
    Accepts connections via ConnectionManager, listens for client messages or disconnects,
    and cleanly unregisters the connection on exit.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected normally.")
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
    finally:
        ws_manager.disconnect(websocket)

