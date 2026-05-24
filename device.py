import json
import time
import websockets

class Device:
    def __init__(self, device_id, device_type, websocket, capabilities=None, authorized=False):
        self.id = device_id
        self.type = device_type
        self.ws = websocket
        self.status = "pending"  # pending, online, offline, error, rejected
        self.capabilities = capabilities or []
        self.authorized = authorized
        self.last_seen = time.time()
        self.command_count = 0  # Счетчик команд
        self.last_command_time = 0

    def update_status(self, new_status):
        if new_status != self.status:
            self.status = new_status
            return True
        return False

    def update_last_seen(self):
        self.last_seen = time.time()

    def mark_offline(self):
        """Переводит устройство в офлайн, сбрасывает WebSocket."""
        self.status = "offline"
        self.ws = None
        self.update_last_seen()

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

    async def send_extended_status(self, substatus: str, details: dict = None) -> bool:
        """Отправить расширенный статус"""
        from yuki_protocol import extended_status_message
        msg = extended_status_message(self.id, self.status, substatus, details)
        return await self.send_json(msg.to_json())
    
    async def send_metrics(self, metrics: dict) -> bool:
        """Отправить метрики устройства"""
        from yuki_protocol import metrics_message
        msg = metrics_message(self.id, metrics)
        return await self.send_json(msg.to_json())
    
    async def send_to_device(self, target_device_id: str, command: str, 
                            payload: dict = None, require_response: bool = False) -> bool:
        """Отправить команду другому устройству через ядро"""
        from yuki_protocol import device_to_device_message
        msg = device_to_device_message(self.id, target_device_id, command, payload, require_response)
        return await self.send_json(msg.to_json())
    
    async def broadcast_to_devices(self, command: str, payload: dict = None, 
                                   device_filter: list = None) -> bool:
        """Широковещательная отправка другим устройствам"""
        from yuki_protocol import device_broadcast_message
        msg = device_broadcast_message(self.id, command, payload, device_filter)
        return await self.send_json(msg.to_json())
