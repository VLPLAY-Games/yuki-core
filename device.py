import json
import time
import websockets

class Device:
    def __init__(self, device_id, device_type, websocket, capabilities=None):
        self.id = device_id
        self.type = device_type
        self.ws = websocket
        self.status = "online"
        self.capabilities = capabilities or []
        self.last_seen = time.time()

    def update_status(self, new_status):
        if new_status != self.status:
            self.status = new_status
            return True
        return False

    def update_last_seen(self):
        self.last_seen = time.time()

    async def send_json(self, data) -> bool:
        try:
            if isinstance(data, dict):
                data = json.dumps(data)
            await self.ws.send(data)
            return True
        except websockets.exceptions.ConnectionClosed:
            self.status = "offline"
            return False
        except Exception:
            self.status = "error"
            return False