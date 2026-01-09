#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 26 Dec 2025 23:10:02 UTC
Status: Created
Telegram: https://t.me/EasyProTech

WebSocket routes.
"""

import json
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from ..websocket_manager import ConnectionManager


def register(app: FastAPI, ws_manager: ConnectionManager):
    """Register WebSocket routes"""

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        """WebSocket for real-time updates"""
        await ws_manager.connect(websocket)
        try:
            while True:
                data = await websocket.receive_text()

                try:
                    message = json.loads(data)
                    if message.get("type") == "ping":
                        await websocket.send_json({"type": "pong"})
                except json.JSONDecodeError:
                    pass

        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
