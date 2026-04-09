import asyncio
import websockets
import json
import uuid
import time
import sys
import os

# Добавляем путь к yuki-protocol
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'yuki-protocol')))

from yuki_protocol import (
    YukiMessage, PROTOCOL_VERSION,
    hello_message, welcome_message, command_message,
    command_result_message, status_message, devices_update_message
)
import logger
from device import Device

connected_devices = {}
webui_clients = set()
lock = asyncio.Lock()

HEARTBEAT_INTERVAL = 30   # секунд
HEARTBEAT_TIMEOUT = 10    # секунд ожидания pong


async def handle_device(websocket):
    device_id = None
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
        if not device_id or not device_type:
            await websocket.close(1003, "Missing device_id or device_type")
            return

        device = Device(device_id, device_type, websocket)
        async with lock:
            connected_devices[device_id] = device
        logger.info(f"Device connected: {device_id} ({device_type})")

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


async def handle_webui(websocket):
    async with lock:
        webui_clients.add(websocket)
    try:
        await send_devices_to_webui(websocket)

        async for message in websocket:
            try:
                data = json.loads(message)
                if "command" in data and "device_id" in data:
                    device_id = data["device_id"]
                    cmd = data["command"]
                    payload = data.get("payload", {})
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
            except json.JSONDecodeError:
                logger.warn("Invalid JSON from WebUI")
    except websockets.exceptions.ConnectionClosed:
        logger.info("WebUI disconnected")
    except Exception as e:
        logger.error(f"WebUI error: {e}")
    finally:
        async with lock:
            webui_clients.discard(websocket)


async def send_devices_to_webui(ws):
    devices_info = {
        d.id: {"type": d.type, "status": d.status}
        for d in connected_devices.values()
    }
    msg = devices_update_message(devices_info)
    await ws.send(msg.to_json())


async def notify_webui():
    if not webui_clients:
        return
    devices_info = {
        d.id: {"type": d.type, "status": d.status}
        for d in connected_devices.values()
    }
    msg = devices_update_message(devices_info)
    json_msg = msg.to_json()
    # Используем asyncio.gather с return_exceptions=True, чтобы одна ошибка не сломала остальные
    await asyncio.gather(
        *[ws.send(json_msg) for ws in webui_clients],
        return_exceptions=True
    )


async def main():
    # Новый API websockets (начиная с версии 12.0): обработчик принимает только websocket
    async def router(websocket):
        path = websocket.request.path if hasattr(websocket, 'request') else websocket.path
        if path == "/device":
            await handle_device(websocket)
        elif path == "/webui":
            await handle_webui(websocket)
        else:
            await websocket.close(1008, "Invalid path")

    server = await websockets.serve(router, "0.0.0.0", 8000)
    logger.info("Yuki Core WebSocket server started on ws://0.0.0.0:8000")
    await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())