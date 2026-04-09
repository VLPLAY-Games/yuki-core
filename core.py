import asyncio
import websockets
import json
import uuid
import time
import sys
import os
import secrets
import string
from contextlib import suppress
from datetime import datetime, timedelta

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'yuki-protocol')))

from yuki_protocol import (
    YukiMessage, PROTOCOL_VERSION,
    hello_message, welcome_message, command_message,
    command_result_message, status_message, devices_update_message,
    confirm_command_message, device_auth_request_message
)
import logger
from device import Device

# Активные WebSocket соединения (ключ = device_id)
connected_devices = {}
# Все известные устройства (ключ = device_id, объект Device)
known_devices = {}
webui_clients = set()
lock = asyncio.Lock()
pending_devices = {}
pending_auth_events = {}
AUTHORIZED_FILE = os.path.join(os.path.dirname(__file__), "authorized_devices.json")
authorized_devices_set = set()

def load_authorized():
    global authorized_devices_set
    if os.path.exists(AUTHORIZED_FILE):
        try:
            with open(AUTHORIZED_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    authorized_devices_set = set(data.get("devices", []))
                elif isinstance(data, list):
                    authorized_devices_set = set(data)
                else:
                    authorized_devices_set = set()
            logger.info(f"Loaded {len(authorized_devices_set)} authorized devices")
        except Exception as e:
            logger.error(f"Failed to load authorized devices: {e}")
            authorized_devices_set = set()
    else:
        authorized_devices_set = set()

def save_authorized():
    try:
        with open(AUTHORIZED_FILE, "w", encoding="utf-8") as f:
            json.dump({"devices": list(authorized_devices_set)}, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Failed to save authorized devices: {e}")

load_authorized()

HEARTBEAT_INTERVAL = 30
HEARTBEAT_TIMEOUT = 10
AUTH_TIMEOUT = 60

# ------------------ Ротация токенов ------------------
TOKEN_FILE = os.path.join(os.path.dirname(__file__), ".token")
TOKEN_META_FILE = os.path.join(os.path.dirname(__file__), ".token_meta")
ROTATION_INTERVAL_HOURS = int(os.environ.get("YUKI_TOKEN_ROTATION_HOURS", "24"))  # по умолчанию 24 часа

current_token = None
token_created_at = None

def load_token():
    global current_token, token_created_at
    # Пытаемся загрузить токен из переменной окружения
    env_token = os.environ.get("YUKI_AUTH_TOKEN")
    if env_token:
        current_token = env_token
        # Если токен из окружения, считаем его статичным (без ротации)
        token_created_at = None
        logger.info("Using authentication token from environment variable (rotation disabled)")
        return

    # Иначе работаем с файлом .token
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            current_token = f.read().strip()
    else:
        current_token = None

    # Загружаем метаданные (дату создания)
    if os.path.exists(TOKEN_META_FILE):
        try:
            with open(TOKEN_META_FILE, "r", encoding="utf-8") as f:
                meta = json.load(f)
                token_created_at = meta.get("created_at")
        except:
            token_created_at = None
    else:
        token_created_at = None

    if not current_token:
        generate_new_token(save=True)

def save_token_meta():
    if token_created_at is not None:
        try:
            with open(TOKEN_META_FILE, "w", encoding="utf-8") as f:
                json.dump({"created_at": token_created_at}, f)
        except Exception as e:
            logger.error(f"Failed to save token metadata: {e}")

def generate_new_token(save=True):
    global current_token, token_created_at
    alphabet = string.ascii_letters + string.digits
    current_token = ''.join(secrets.choice(alphabet) for _ in range(32))
    token_created_at = time.time()
    if save:
        try:
            with open(TOKEN_FILE, "w", encoding="utf-8") as f:
                f.write(current_token)
            save_token_meta()
        except Exception as e:
            logger.error(f"Failed to save token: {e}")
    logger.info(f"Generated new authentication token (created at {datetime.fromtimestamp(token_created_at)})")
    return current_token

def is_token_expired():
    if token_created_at is None:
        return False  # токен из окружения или без метаданных
    age = time.time() - token_created_at
    return age > ROTATION_INTERVAL_HOURS * 3600

async def rotate_token_if_needed():
    """Проверяет необходимость ротации по времени и выполняет её."""
    if is_token_expired():
        logger.info("Token expired, rotating...")
        await perform_token_rotation(reason="time")

async def perform_token_rotation(reason="admin"):
    """Генерирует новый токен и рассылает его всем подключённым устройствам."""
    global current_token
    old_token = current_token
    new_token = generate_new_token(save=True)
    logger.info(f"Token rotated ({reason}). New token generated.")

    # Рассылаем новый токен всем онлайн-устройствам
    async with lock:
        devices = list(connected_devices.values())
    if devices:
        update_msg = {
            "type": "token_update",
            "payload": {
                "new_token": new_token,
                "reason": reason
            }
        }
        json_msg = json.dumps(update_msg)
        for device in devices:
            if device.ws and device.status == "online":
                try:
                    await device.ws.send(json_msg)
                    logger.debug(f"Sent new token to device {device.id}")
                except Exception as e:
                    logger.warn(f"Failed to send new token to {device.id}: {e}")

    # Для офлайн-устройств токен останется старым, при следующем подключении они будут отвергнуты
    return new_token

# Загружаем токен при старте
load_token()

# Фоновая задача для проверки ротации по времени
async def token_rotation_scheduler():
    while True:
        await asyncio.sleep(3600)  # проверяем каждый час
        await rotate_token_if_needed()

# ----------------------------------------------------

DANGEROUS_COMMANDS = {"shutdown", "restart", "sleep", "hibernate", "lock"}

async def wait_for_pending_authorization(device: Device, websocket) -> bool:
    auth_event = asyncio.Event()
    async with lock:
        pending_auth_events[device.id] = auth_event
    try:
        wait_auth = asyncio.create_task(auth_event.wait())
        wait_close = asyncio.create_task(websocket.wait_closed())
        done, pending = await asyncio.wait(
            {wait_auth, wait_close},
            timeout=AUTH_TIMEOUT,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        with suppress(Exception):
            await asyncio.gather(*pending, return_exceptions=True)
        if not done or wait_close in done:
            return False
        return device.status == "online"
    finally:
        async with lock:
            pending_auth_events.pop(device.id, None)

async def handle_device(websocket, path=None):
    device_id = None
    device = None
    receive_task = None
    heartbeat_task = None
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

        # Проверка токена (если задан)
        if current_token and auth_token != current_token:
            logger.warn(f"Device {device_id} rejected: invalid auth token")
            await websocket.close(1008, "Invalid authentication token")
            return

        # Проверяем, есть ли уже известное устройство с таким ID
        async with lock:
            if device_id in known_devices:
                # Переиспользуем существующий объект, обновляем данные
                device = known_devices[device_id]
                device.ws = websocket
                device.type = device_type  # на случай изменения типа
                device.capabilities = capabilities
                device.authorized = device_id in authorized_devices_set
                if not device.authorized:
                    device.status = "pending"
                    pending_devices[device_id] = device
                else:
                    device.status = "online"
                device.update_last_seen()
            else:
                is_authorized = device_id in authorized_devices_set
                device = Device(device_id, device_type, websocket, capabilities, authorized=is_authorized)
                known_devices[device_id] = device
                if not is_authorized:
                    device.status = "pending"
                    pending_devices[device_id] = device
                else:
                    device.status = "online"

            connected_devices[device_id] = device

        if device.status == "pending":
            logger.info(f"Device {device_id} ({device_type}) is pending authorization")
            await notify_webui()
            auth_req = device_auth_request_message(device_id, device_type, capabilities)
            await broadcast_to_webui(auth_req.to_json())
            approved = await wait_for_pending_authorization(device, websocket)
            if not approved:
                await websocket.close(1000, "Authorization rejected or timeout")
                device.status = "rejected"
                await notify_webui()
                return
            await complete_handshake(device)
        else:
            # Уже авторизовано – завершаем рукопожатие
            await complete_handshake(device)

        # Уведомляем WebUI о новом или обновлённом устройстве
        await notify_webui()

        receive_task = asyncio.create_task(device_receive_loop(device))
        heartbeat_task = asyncio.create_task(heartbeat_monitor(device))
        done, pending = await asyncio.wait(
            [receive_task, heartbeat_task],
            return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
            with suppress(Exception):
                await task
    except asyncio.TimeoutError:
        logger.warn("Device handshake timeout")
    except websockets.exceptions.ConnectionClosed:
        logger.info(f"Device {device_id} connection closed during handshake")
    except Exception as e:
        logger.error(f"Unexpected error in handle_device: {e}")
    finally:
        for task in (receive_task, heartbeat_task):
            if task and not task.done():
                task.cancel()
                with suppress(Exception):
                    await task

        async with lock:
            if device_id:
                # Удаляем из активных соединений, но оставляем в known_devices
                if device_id in connected_devices:
                    del connected_devices[device_id]
                if device_id in pending_devices:
                    del pending_devices[device_id]
                if device_id in pending_auth_events:
                    pending_auth_events[device_id].set()
                    del pending_auth_events[device_id]

                # Помечаем устройство как offline, если оно не было удалено намеренно
                if device_id in known_devices:
                    dev = known_devices[device_id]
                    if dev.status not in ("rejected", "offline"):
                        dev.mark_offline()
                    dev.ws = None

        logger.info(f"Device {device_id} disconnected")
        await notify_webui()

async def complete_handshake(device: Device):
    welcome = welcome_message(
        session_id=str(uuid.uuid4()),
        server_time=int(time.time()),
        heartbeat_interval=HEARTBEAT_INTERVAL
    )
    await device.ws.send(welcome.to_json())
    logger.info(f"Handshake completed for {device.id}")

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

async def handle_webui(websocket, path=None):
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
                    device_id = data.get("device_id")
                    cmd = data.get("command")
                    params = data.get("params", {})
                    approved = data.get("approved", False)
                    if approved:
                        await execute_command(device_id, cmd, params)
                    else:
                        logger.info(f"Command {cmd} for {device_id} rejected by user")
                elif msg_type == "device_auth_response":
                    device_id = data.get("device_id")
                    approved = data.get("approved", False)
                    async with lock:
                        device = pending_devices.get(device_id) or known_devices.get(device_id)
                        auth_event = pending_auth_events.get(device_id)
                    if device and device.status == "pending":
                        if approved:
                            authorized_devices_set.add(device_id)
                            save_authorized()
                            device.authorized = True
                            device.status = "online"
                            logger.info(f"Device {device_id} approved and added to whitelist")
                        else:
                            device.status = "rejected"
                            logger.info(f"Device {device_id} rejected")
                        if auth_event:
                            auth_event.set()
                        if not approved:
                            with suppress(Exception):
                                await device.ws.close(1000, "Authorization rejected")
                    await notify_webui()
                elif msg_type == "disconnect_device":
                    device_id = data.get("device_id")
                    async with lock:
                        device = connected_devices.get(device_id)
                    if device:
                        await device.ws.close(1000, "Disconnected by admin")
                        logger.info(f"Device {device_id} disconnected by admin")
                    await notify_webui()
                elif msg_type == "remove_device":
                    device_id = data.get("device_id")
                    if device_id in authorized_devices_set:
                        authorized_devices_set.remove(device_id)
                        save_authorized()
                    async with lock:
                        device = connected_devices.get(device_id)
                        if device_id in known_devices:
                            del known_devices[device_id]
                    if device:
                        await device.ws.close(1000, "Removed by admin")
                        logger.info(f"Device {device_id} removed from authorized and disconnected")
                    await notify_webui()
                elif msg_type == "rotate_token":
                    # Команда от WebUI для ручной ротации токена
                    await perform_token_rotation(reason="admin")
                    await websocket.send(json.dumps({"type": "token_rotated", "success": True}))
                elif msg_type == "get_token_info":
                    # Возвращаем информацию о текущем токене (дата создания)
                    info = {
                        "type": "token_info",
                        "payload": {
                            "created_at": token_created_at,
                            "rotation_interval_hours": ROTATION_INTERVAL_HOURS,
                            "expires_in": None
                        }
                    }
                    if token_created_at:
                        expires_at = token_created_at + ROTATION_INTERVAL_HOURS * 3600
                        info["payload"]["expires_in"] = max(0, expires_at - time.time())
                    await websocket.send(json.dumps(info))
            except json.JSONDecodeError:
                logger.warn("Invalid JSON from WebUI")
            except Exception as e:
                logger.error(f"WebUI message handling error: {e}")
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
    if device and device.status == "online":
        cmd_msg = command_message(device_id, cmd, payload)
        success = await device.send_json(cmd_msg.to_json())
        if success:
            logger.info(f"Command sent to {device_id}: {cmd}")
        else:
            logger.error(f"Failed to send command to {device_id}")
    else:
        logger.warn(f"Command to unknown or offline device {device_id}")

async def send_devices_to_webui(ws):
    devices_info = {}
    async with lock:
        for d in known_devices.values():
            devices_info[d.id] = {
                "type": d.type,
                "status": d.status,
                "capabilities": d.capabilities,
                "authorized": d.authorized,
                "last_seen": d.last_seen
            }
    msg = devices_update_message(devices_info)
    await ws.send(msg.to_json())

async def notify_webui():
    async with lock:
        clients = list(webui_clients)
        devices_snapshot = list(known_devices.values())
    if not clients:
        return
    devices_info = {}
    for d in devices_snapshot:
        devices_info[d.id] = {
            "type": d.type,
            "status": d.status,
            "capabilities": d.capabilities,
            "authorized": d.authorized,
            "last_seen": d.last_seen
        }
    msg = devices_update_message(devices_info)
    json_msg = msg.to_json()
    results = await asyncio.gather(
        *[ws.send(json_msg) for ws in clients],
        return_exceptions=True
    )
    async with lock:
        for ws, result in zip(clients, results):
            if isinstance(result, Exception):
                webui_clients.discard(ws)

async def broadcast_to_webui(message: str):
    async with lock:
        clients = list(webui_clients)
    if not clients:
        return
    results = await asyncio.gather(
        *[ws.send(message) for ws in clients],
        return_exceptions=True
    )
    async with lock:
        for ws, result in zip(clients, results):
            if isinstance(result, Exception):
                webui_clients.discard(ws)

async def main():
    # Запускаем фоновую задачу ротации токенов
    asyncio.create_task(token_rotation_scheduler())

    async def router(websocket, path=None):
        if path is None:
            path = getattr(getattr(websocket, "request", None), "path", None) or getattr(websocket, "path", None)
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