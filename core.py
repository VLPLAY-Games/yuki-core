import asyncio
import websockets
import json
import uuid
import time
import sys
import os
import secrets
import string

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'yuki-protocol')))

from yuki_protocol import (
    YukiMessage, PROTOCOL_VERSION,
    hello_message, welcome_message, command_message,
    command_result_message, status_message, devices_update_message,
    confirm_command_message, device_auth_request_message, device_auth_response_message
)
import logger
from device import Device

# Глобальное состояние
connected_devices = {}
webui_clients = set()
lock = asyncio.Lock()

# Очередь ожидающих авторизации устройств: request_id -> (websocket, device_id, device_type, capabilities)
pending_devices = {}

HEARTBEAT_INTERVAL = 30
HEARTBEAT_TIMEOUT = 10

# --- Аутентификация по токену ---
AUTH_TOKEN = os.environ.get("YUKI_AUTH_TOKEN")
if not AUTH_TOKEN:
    token_file = os.path.join(os.path.dirname(__file__), ".token")
    if os.path.exists(token_file):
        with open(token_file, "r") as f:
            AUTH_TOKEN = f.read().strip()
    else:
        alphabet = string.ascii_letters + string.digits
        AUTH_TOKEN = ''.join(secrets.choice(alphabet) for _ in range(32))
        with open(token_file, "w") as f:
            f.write(AUTH_TOKEN)
        print("\n" + "="*60)
        print("Yuki Core: Generated new authentication token")
        print(f"   Token: {AUTH_TOKEN}")
        print(f"   Saved to: {token_file}")
        print("   Use this token in your devices to connect.")
        print("="*60 + "\n")

if AUTH_TOKEN:
    logger.info("Authentication enabled (token required)")
else:
    logger.warn("Authentication disabled – set YUKI_AUTH_TOKEN or create .token file")

# --- Список авторизованных устройств (сохраняется в файл) ---
AUTHORIZED_DEVICES_FILE = os.path.join(os.path.dirname(__file__), "authorized_devices.json")

def load_authorized_devices():
    if os.path.exists(AUTHORIZED_DEVICES_FILE):
        try:
            with open(AUTHORIZED_DEVICES_FILE, "r") as f:
                return set(json.load(f))
        except:
            return set()
    return set()

def save_authorized_device(device_id):
    authorized = load_authorized_devices()
    authorized.add(device_id)
    with open(AUTHORIZED_DEVICES_FILE, "w") as f:
        json.dump(list(authorized), f)

authorized_devices = load_authorized_devices()

# Список опасных команд, требующих подтверждения
DANGEROUS_COMMANDS = {"shutdown", "restart", "sleep", "hibernate", "lock"}

async def handle_device(websocket, path):
    device_id = None
    pending_request_id = None
    try:
        raw_init = await asyncio.wait_for(websocket.recv(), timeout=5.0)
        try:
            init_msg = YukiMessage.from_json(raw_init)
            if init_msg.type != "hello":
                await websocket.close(1003, "First message must be 'hello'")
                return
        except ValueError as e:
            await websocket.close(1003, f"Invalid protocol: {e}")
            return

        device_id = init_msg.payload.get("device_id")
        device_type = init_msg.payload.get("device_type")
        capabilities = init_msg.payload.get("capabilities", [])
        auth_token = init_msg.payload.get("auth_token")

        if not device_id or not device_type:
            await websocket.close(1003, "Missing device_id or device_type")
            return

        # Проверка аутентификации по токену
        if AUTH_TOKEN and auth_token != AUTH_TOKEN:
            logger.warn(f"Device {device_id} rejected: invalid auth token")
            await websocket.close(1008, "Invalid authentication token")
            return

        # Проверка, авторизовано ли устройство
        if device_id not in authorized_devices:
            logger.info(f"Device {device_id} requires authorization")
            # Создаём запрос авторизации
            request_id = str(uuid.uuid4())
            pending_devices[request_id] = (websocket, device_id, device_type, capabilities)
            pending_request_id = request_id

            # Отправляем запрос всем WebUI
            auth_req = device_auth_request_message(device_id, device_type, capabilities)
            auth_req.id = request_id  # используем как ID запроса
            await notify_webui_with_message(auth_req)

            # Ждём ответа (с таймаутом 60 секунд)
            try:
                # Ожидаем, пока другой обработчик не вызовет approve/reject
                # Реализуем через asyncio.Event
                event = asyncio.Event()
                pending_devices[request_id] = (websocket, device_id, device_type, capabilities, event)
                await asyncio.wait_for(event.wait(), timeout=60.0)
                # Если событие установлено – авторизация одобрена
                authorized_devices.add(device_id)
                save_authorized_device(device_id)
                logger.info(f"Device {device_id} authorized by user")
            except asyncio.TimeoutError:
                logger.warn(f"Authorization timeout for device {device_id}")
                await websocket.close(1008, "Authorization timeout")
                return
            finally:
                if request_id in pending_devices:
                    del pending_devices[request_id]

        # Если дошли сюда – устройство авторизовано
        device = Device(device_id, device_type, websocket, capabilities)
        async with lock:
            connected_devices[device_id] = device
        logger.info(f"Device connected: {device_id} ({device_type}) capabilities: {capabilities}")

        welcome = welcome_message(
            session_id=str(uuid.uuid4()),
            server_time=int(time.time()),
            heartbeat_interval=HEARTBEAT_INTERVAL
        )
        await websocket.send(welcome.to_json())
        await notify_webui()

        receive_task = asyncio.create_task(device_receive_loop(device))
        heartbeat_task = asyncio.create_task(heartbeat_monitor(device))

        done, pending = await asyncio.wait(
            [receive_task, heartbeat_task],
            return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
    except asyncio.TimeoutError:
        logger.warn("Device handshake timeout")
    except websockets.exceptions.ConnectionClosed:
        logger.info(f"Device {device_id} connection closed during handshake")
    except Exception as e:
        logger.error(f"Unexpected error in handle_device: {e}")
    finally:
        if pending_request_id and pending_request_id in pending_devices:
            del pending_devices[pending_request_id]
        async with lock:
            if device_id and device_id in connected_devices:
                del connected_devices[device_id]
        logger.info(f"Device {device_id} disconnected")
        await notify_webui()


async def device_receive_loop(device: Device):
    try:
        async for message in device.ws:
            try:
                msg = YukiMessage.from_json(message)
            except ValueError as e:
                logger.warn(f"Invalid message from {device.id}: {e}")
                continue

            if msg.type == "status":
                new_status = msg.payload.get("status", device.status)
                if device.update_status(new_status):
                    logger.info(f"Device {device.id} status changed to {new_status}")
                    await notify_webui()
            elif msg.type == "event":
                logger.info(f"Event from {device.id}: {msg.payload}")
            elif msg.type == "command_result":
                logger.info(f"Command result from {device.id}: success={msg.payload.get('success')}")
            else:
                logger.warn(f"Unhandled message type '{msg.type}' from {device.id}")
    except websockets.exceptions.ConnectionClosed:
        logger.info(f"Connection closed by device {device.id}")
    except Exception as e:
        logger.error(f"Error in receive loop for {device.id}: {e}")
    finally:
        async with lock:
            if device.id in connected_devices:
                del connected_devices[device.id]
        await notify_webui()


async def heartbeat_monitor(device: Device):
    try:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            try:
                pong_waiter = await device.ws.ping()
                await asyncio.wait_for(pong_waiter, timeout=HEARTBEAT_TIMEOUT)
                device.update_last_seen()
                logger.debug(f"Heartbeat OK for {device.id}")
            except asyncio.TimeoutError:
                logger.warn(f"Heartbeat timeout for {device.id}")
                await device.ws.close()
                break
    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        logger.error(f"Heartbeat monitor error for {device.id}: {e}")


async def handle_webui(websocket, path):
    async with lock:
        webui_clients.add(websocket)
    try:
        await send_devices_to_webui(websocket)

        async for message in websocket:
            try:
                data = json.loads(message)
                msg_type = data.get("type")

                if msg_type == "command":
                    device_id = data["device_id"]
                    cmd = data["command"]
                    payload = data.get("payload", {})

                    if cmd in DANGEROUS_COMMANDS:
                        confirm_msg = confirm_command_message(device_id, cmd, payload)
                        await websocket.send(confirm_msg.to_json())
                        continue

                    await execute_command(device_id, cmd, payload)

                elif msg_type == "confirm_response":
                    original_id = data.get("id")
                    approved = data.get("approved", False)
                    device_id = data.get("device_id")
                    cmd = data.get("command")
                    params = data.get("params", {})
                    if approved:
                        await execute_command(device_id, cmd, params)
                    else:
                        logger.info(f"Command {cmd} for {device_id} rejected by user")

                elif msg_type == "device_auth_response":
                    request_id = data.get("id")
                    approved = data.get("approved", False)
                    if request_id in pending_devices:
                        _, _, _, _, event = pending_devices[request_id]
                        if approved:
                            event.set()
                        else:
                            # Отклонено – закроем соединение
                            websocket_obj, device_id, _, _, _ = pending_devices[request_id]
                            await websocket_obj.close(1008, "Authorization rejected")
                        del pending_devices[request_id]
                    else:
                        logger.warn(f"Unknown auth request id: {request_id}")

            except json.JSONDecodeError:
                logger.warn("Invalid JSON from WebUI")
    except websockets.exceptions.ConnectionClosed:
        logger.info("WebUI disconnected")
    except Exception as e:
        logger.error(f"WebUI error: {e}")
    finally:
        async with lock:
            webui_clients.discard(websocket)


async def execute_command(device_id: str, cmd: str, payload: dict):
    async with lock:
        device = connected_devices.get(device_id)
    if device:
        cmd_msg = command_message(device_id, cmd, payload)
        success = await device.send_json(cmd_msg.to_json())
        if success:
            logger.info(f"Command sent to {device_id}: {cmd}")
        else:
            logger.error(f"Failed to send command to {device_id}")
    else:
        logger.warn(f"Command to unknown device {device_id}")


async def send_devices_to_webui(ws):
    devices_info = {}
    for d in connected_devices.values():
        devices_info[d.id] = {
            "type": d.type,
            "status": d.status,
            "capabilities": d.capabilities,
            "last_seen": d.last_seen
        }
    msg = devices_update_message(devices_info)
    await ws.send(msg.to_json())


async def notify_webui():
    if not webui_clients:
        return
    devices_info = {}
    for d in connected_devices.values():
        devices_info[d.id] = {
            "type": d.type,
            "status": d.status,
            "capabilities": d.capabilities,
            "last_seen": d.last_seen
        }
    msg = devices_update_message(devices_info)
    json_msg = msg.to_json()
    await asyncio.gather(
        *[ws.send(json_msg) for ws in webui_clients],
        return_exceptions=True
    )


async def notify_webui_with_message(msg: YukiMessage):
    """Отправляет произвольное сообщение всем WebUI."""
    if not webui_clients:
        return
    json_msg = msg.to_json()
    await asyncio.gather(
        *[ws.send(json_msg) for ws in webui_clients],
        return_exceptions=True
    )


async def main():
    async def router(websocket):
        path = websocket.request.path if hasattr(websocket, 'request') else websocket.path
        if path == "/device":
            await handle_device(websocket, path)
        elif path == "/webui":
            await handle_webui(websocket, path)
        else:
            await websocket.close(1008, "Invalid path")

    server = await websockets.serve(router, "0.0.0.0", 8000)
    logger.info("Yuki Core WebSocket server started on ws://0.0.0.0:8000")
    await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())