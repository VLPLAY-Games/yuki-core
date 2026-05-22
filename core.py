# core.py
import asyncio
import websockets
import json
import uuid
import time
import sys
import os
import secrets
import string
import signal
import sqlite3
import logging
import psutil
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("yuki-core")

# ==================== SQLite БД ====================
DB_PATH = os.path.join(os.path.dirname(__file__), "yuki_core.db")
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'yuki-protocol')))

def init_db():
    """Инициализация базы данных SQLite"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Таблица известных устройств
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            device_type TEXT NOT NULL,
            capabilities TEXT,
            authorized INTEGER DEFAULT 0,
            last_seen REAL,
            status TEXT DEFAULT 'offline',
            blacklisted INTEGER DEFAULT 0,
            rate_limit INTEGER DEFAULT 10,
            created_at REAL,
            updated_at REAL
        )
    ''')
    
    # Таблица authorized devices (для быстрого доступа)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS authorized (
            device_id TEXT PRIMARY KEY
        )
    ''')
    
    # Таблица аудита (audit log)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            event_type TEXT,
            device_id TEXT,
            details TEXT,
            ip_address TEXT
        )
    ''')
    
    # Таблица команд (история)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS command_history (
            id TEXT PRIMARY KEY,
            timestamp REAL,
            device_id TEXT,
            command TEXT,
            payload TEXT,
            status TEXT,
            response_time REAL,
            error TEXT
        )
    ''')
    
    # Таблица метрик устройств
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            metric_type TEXT,
            value REAL,
            timestamp REAL
        )
    ''')
    
    # Таблица системных метрик
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            cpu_percent REAL,
            memory_percent REAL,
            disk_used REAL,
            disk_total REAL,
            network_rx REAL,
            network_tx REAL,
            connections INTEGER
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Database initialized")

@asynccontextmanager
async def get_db():
    """Асинхронный контекстный менеджер для БД"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def audit_log(event_type, device_id=None, details=None, ip_address=None):
    """Запись в audit log"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_log (timestamp, event_type, device_id, details, ip_address)
            VALUES (?, ?, ?, ?, ?)
        ''', (time.time(), event_type, device_id, details, ip_address))
        conn.commit()
        conn.close()
        logger.debug(f"Audit log: {event_type} - {device_id}")
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")

# ==================== Blacklist ====================
blacklisted_devices = set()

def load_blacklist():
    global blacklisted_devices
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT device_id FROM devices WHERE blacklisted = 1")
        rows = cursor.fetchall()
        blacklisted_devices = {row[0] for row in rows}
        conn.close()
        logger.info(f"Loaded {len(blacklisted_devices)} blacklisted devices")
    except Exception as e:
        logger.error(f"Failed to load blacklist: {e}")

def add_to_blacklist(device_id):
    global blacklisted_devices
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE devices SET blacklisted = 1, authorized = 0 WHERE device_id = ?", (device_id,))
        cursor.execute("DELETE FROM authorized WHERE device_id = ?", (device_id,))
        conn.commit()
        conn.close()
        blacklisted_devices.add(device_id)
        audit_log("blacklist_add", device_id, "Device added to blacklist")
        logger.info(f"Device {device_id} added to blacklist")
    except Exception as e:
        logger.error(f"Failed to add to blacklist: {e}")

def remove_from_blacklist(device_id):
    global blacklisted_devices
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE devices SET blacklisted = 0 WHERE device_id = ?", (device_id,))
        conn.commit()
        conn.close()
        blacklisted_devices.discard(device_id)
        audit_log("blacklist_remove", device_id, "Device removed from blacklist")
        logger.info(f"Device {device_id} removed from blacklist")
    except Exception as e:
        logger.error(f"Failed to remove from blacklist: {e}")

def is_blacklisted(device_id):
    return device_id in blacklisted_devices

# ==================== Rate Limiting ====================
class DeviceRateLimiter:
    def __init__(self, device_id, commands_per_minute=10):
        self.device_id = device_id
        self.commands_per_minute = commands_per_minute
        self.commands = deque()
    
    def allow(self) -> bool:
        now = time.time()
        # Удаляем команды старше 60 секунд
        while self.commands and now - self.commands[0] > 60:
            self.commands.popleft()
        
        if len(self.commands) >= self.commands_per_minute:
            return False
        
        self.commands.append(now)
        return True
    
    def get_remaining(self):
        now = time.time()
        while self.commands and now - self.commands[0] > 60:
            self.commands.popleft()
        return max(0, self.commands_per_minute - len(self.commands))

device_rate_limiters = {}

def get_rate_limiter(device_id):
    if device_id not in device_rate_limiters:
        device_rate_limiters[device_id] = DeviceRateLimiter(device_id, 10)
    return device_rate_limiters[device_id]

# ==================== Системные метрики ====================
last_net_io = None
last_net_time = None

def get_system_metrics():
    """Сбор системных метрик"""
    global last_net_io, last_net_time
    
    metrics = {
        'timestamp': time.time(),
        'cpu_percent': psutil.cpu_percent(interval=0.5),
        'memory_percent': psutil.virtual_memory().percent,
        'memory_used': psutil.virtual_memory().used,
        'memory_total': psutil.virtual_memory().total,
    }
    
    # Disk
    disk = psutil.disk_usage('/')
    metrics['disk_percent'] = disk.percent
    metrics['disk_used'] = disk.used
    metrics['disk_total'] = disk.total
    
    # Network
    net_io = psutil.net_io_counters()
    now = time.time()
    if last_net_io and last_net_time:
        time_diff = now - last_net_time
        metrics['network_rx_mbps'] = (net_io.bytes_recv - last_net_io.bytes_recv) / time_diff / 1024 / 1024
        metrics['network_tx_mbps'] = (net_io.bytes_sent - last_net_io.bytes_sent) / time_diff / 1024 / 1024
    else:
        metrics['network_rx_mbps'] = 0
        metrics['network_tx_mbps'] = 0
    
    last_net_io = net_io
    last_net_time = now
    
    # Connections
    metrics['connections'] = len(psutil.net_connections())
    
    # Process info
    process = psutil.Process()
    metrics['process_cpu'] = process.cpu_percent()
    metrics['process_memory'] = process.memory_info().rss
    
    return metrics

async def save_system_metrics():
    """Сохранение системных метрик в БД"""
    metrics = get_system_metrics()
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO system_metrics 
            (timestamp, cpu_percent, memory_percent, disk_used, disk_total, network_rx, network_tx, connections)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            metrics['timestamp'], metrics['cpu_percent'], metrics['memory_percent'],
            metrics['disk_used'], metrics['disk_total'],
            metrics['network_rx_mbps'], metrics['network_tx_mbps'],
            metrics['connections']
        ))
        conn.commit()
        conn.close()
        
        # Очистка старых метрик (храним 7 дней)
        cutoff = time.time() - 7 * 24 * 3600
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM system_metrics WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to save system metrics: {e}")

async def system_metrics_scheduler():
    """Планировщик сбора системных метрик"""
    while True:
        await asyncio.sleep(60)  # Каждую минуту
        await save_system_metrics()

# ==================== Лог ротация ====================
LOG_FOLDER = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_FOLDER, exist_ok=True)
LOG_RETENTION_DAYS = 7
LOG_MAX_SIZE_MB = 10

def rotate_logs():
    """Ротация старых логов"""
    try:
        # Удаляем старые логи
        cutoff = time.time() - LOG_RETENTION_DAYS * 24 * 3600
        for log_file in Path(LOG_FOLDER).glob("*.log"):
            if log_file.stat().st_mtime < cutoff:
                log_file.unlink()
                logger.info(f"Removed old log: {log_file.name}")
        
        # Очистка старых записей в audit_log
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cutoff_date = time.time() - 30 * 24 * 3600  # 30 дней
        cursor.execute("DELETE FROM audit_log WHERE timestamp < ?", (cutoff_date,))
        cursor.execute("DELETE FROM command_history WHERE timestamp < ?", (cutoff_date - 30 * 24 * 3600,))
        cursor.execute("DELETE FROM device_metrics WHERE timestamp < ?", (cutoff_date,))
        conn.commit()
        conn.close()
        
        logger.info("Log rotation completed")
    except Exception as e:
        logger.error(f"Log rotation failed: {e}")

async def log_rotation_scheduler():
    """Планировщик ротации логов"""
    while True:
        await asyncio.sleep(3600)  # Каждый час
        rotate_logs()

# ==================== Основное состояние ====================
connected_devices = {}
known_devices = {}
webui_clients = set()
lock = asyncio.Lock()
pending_devices = {}
pending_auth_events = {}
pending_confirm_commands = {}

HEARTBEAT_INTERVAL = 30
HEARTBEAT_TIMEOUT = 10
AUTH_TIMEOUT = 60
DANGEROUS_COMMANDS = {"shutdown", "restart", "sleep", "hibernate", "lock"}

# ==================== Работа с БД ====================
def save_device_to_db(device):
    """Сохранение устройства в БД"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO devices 
            (device_id, device_type, capabilities, authorized, last_seen, status, blacklisted, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            device.id, device.type, json.dumps(device.capabilities),
            1 if device.authorized else 0, device.last_seen, device.status,
            1 if device.id in blacklisted_devices else 0, time.time()
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to save device to DB: {e}")

def load_devices_from_db():
    """Загрузка устройств из БД"""
    devices = {}
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices")
        rows = cursor.fetchall()
        for row in rows:
            from device import Device
            device = Device(
                device_id=row[0],
                device_type=row[1],
                websocket=None,
                capabilities=json.loads(row[2]) if row[2] else [],
                authorized=bool(row[3])
            )
            device.last_seen = row[4] or time.time()
            device.status = row[5] or "offline"
            devices[device.id] = device
        conn.close()
        logger.info(f"Loaded {len(devices)} devices from database")
    except Exception as e:
        logger.error(f"Failed to load devices from DB: {e}")
    return devices

def save_command_to_history(cmd_id, device_id, command, payload, status, response_time=None, error=None):
    """Сохранение команды в историю"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO command_history 
            (id, timestamp, device_id, command, payload, status, response_time, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (cmd_id, time.time(), device_id, command, json.dumps(payload), status, response_time, error))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to save command to history: {e}")

def save_device_metric(device_id, metric_type, value):
    """Сохранение метрики устройства"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO device_metrics (device_id, metric_type, value, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (device_id, metric_type, value, time.time()))
        conn.commit()
        conn.close()
        
        # Очистка старых метрик
        cutoff = time.time() - 7 * 24 * 3600
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM device_metrics WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to save device metric: {e}")

# ==================== Токены ====================
TOKEN_FILE = os.path.join(os.path.dirname(__file__), ".token")
TOKEN_META_FILE = os.path.join(os.path.dirname(__file__), ".token_meta")
ROTATION_INTERVAL_HOURS = int(os.environ.get("YUKI_TOKEN_ROTATION_HOURS", "24"))

current_token = None
token_created_at = None

def load_token():
    global current_token, token_created_at
    env_token = os.environ.get("YUKI_AUTH_TOKEN")
    if env_token:
        current_token = env_token
        token_created_at = None
        logger.info("Using authentication token from environment variable (rotation disabled)")
        return

    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            current_token = f.read().strip()
    else:
        current_token = None

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

def generate_new_token(save=True):
    global current_token, token_created_at
    alphabet = string.ascii_letters + string.digits
    current_token = ''.join(secrets.choice(alphabet) for _ in range(32))
    token_created_at = time.time()
    if save:
        try:
            with open(TOKEN_FILE, "w", encoding="utf-8") as f:
                f.write(current_token)
            with open(TOKEN_META_FILE, "w", encoding="utf-8") as f:
                json.dump({"created_at": token_created_at}, f)
        except Exception as e:
            logger.error(f"Failed to save token: {e}")
    logger.info(f"Generated new authentication token")
    return current_token

load_token()

# ==================== WebSocket Handlers ====================

async def broadcast_command(command, payload, exclude_device=None):
    """Отправить команду всем онлайн устройствам"""
    async with lock:
        devices = list(connected_devices.values())
    
    sent_count = 0
    for device in devices:
        if device.id == exclude_device:
            continue
        if device.status == "online" and device.ws:
            cmd_id = str(uuid.uuid4())
            cmd_msg = {
                "protocol": "yuki/1.0",
                "type": "command",
                "id": cmd_id,
                "timestamp": int(time.time()),
                "payload": {
                    "command": command,
                    "params": payload
                }
            }
            success = await device.send_json(json.dumps(cmd_msg))
            if success:
                sent_count += 1
                save_command_to_history(cmd_id, device.id, command, payload, "pending")
                audit_log("broadcast_command", device.id, f"Command: {command}")
            await asyncio.sleep(0.05)  # Небольшая задержка
    
    logger.info(f"Broadcast command '{command}' sent to {sent_count} devices")
    return sent_count

async def track_command_response(device_id, cmd_id, response_time, success, error=None):
    """Трекинг времени ответа команды"""
    status = "success" if success else "error"
    save_command_to_history(cmd_id, device_id, None, None, status, response_time, error)
    
    # Сохраняем метрику времени ответа
    if response_time:
        save_device_metric(device_id, "response_time", response_time)

async def handle_device(websocket, path=None):
    device_id = None
    device = None
    receive_task = None
    heartbeat_task = None
    connect_time = time.time()

    try:
        raw_init = await asyncio.wait_for(websocket.recv(), timeout=5.0)
        try:
            from yuki_protocol import YukiMessage
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

        # Проверка черного списка
        if is_blacklisted(device_id):
            logger.warn(f"Device {device_id} is blacklisted, rejecting connection")
            await websocket.close(1008, "Device is blacklisted")
            return

        # Rate limiting проверка
        rate_limiter = get_rate_limiter(device_id)
        if not rate_limiter.allow():
            logger.warn(f"Rate limit exceeded for device {device_id}")
            await websocket.close(1008, "Rate limit exceeded")
            return

        if current_token and auth_token != current_token:
            logger.warn(f"Device {device_id} rejected: invalid auth token")
            audit_log("auth_failed", device_id, "Invalid token", websocket.remote_address[0] if websocket.remote_address else None)
            await websocket.close(1008, "Invalid authentication token")
            return

        from device import Device
        async with lock:
            if device_id in known_devices:
                device = known_devices[device_id]
                device.ws = websocket
                device.type = device_type
                device.capabilities = capabilities
            else:
                device = Device(device_id, device_type, websocket, capabilities, authorized=False)
                known_devices[device_id] = device

            device.update_last_seen()
            connected_devices[device_id] = device
            save_device_to_db(device)

        audit_log("device_connected", device_id, f"Type: {device_type}", websocket.remote_address[0] if websocket.remote_address else None)

        # Продолжение handshake...
        from yuki_protocol import welcome_message
        welcome = welcome_message(
            session_id=str(uuid.uuid4()),
            server_time=int(time.time()),
            heartbeat_interval=HEARTBEAT_INTERVAL
        )
        await device.ws.send(welcome.to_json())
        logger.info(f"Handshake completed for {device.id}")
        device.status = "online"
        save_device_to_db(device)

        await notify_webui()

        receive_task = asyncio.create_task(device_receive_loop(device, rate_limiter, connect_time))
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
        if device_id:
            async with lock:
                if device_id in connected_devices:
                    del connected_devices[device_id]
                if device_id in known_devices:
                    dev = known_devices[device_id]
                    dev.mark_offline()
                    dev.ws = None
                    save_device_to_db(dev)
            logger.info(f"Device {device_id} disconnected")
            audit_log("device_disconnected", device_id, "Connection closed")
        await notify_webui()

async def device_receive_loop(device, rate_limiter, connect_time):
    try:
        async for message in device.ws:
            if not rate_limiter.allow():
                logger.warn(f"Rate limit exceeded for device {device.id}")
                await device.ws.close(1008, "Rate limit exceeded")
                break

            start_time = time.time()
            
            try:
                from yuki_protocol import YukiMessage
                msg = YukiMessage.from_json(message)
            except ValueError as e:
                logger.warn(f"Invalid message from {device.id}: {e}")
                continue

            response_time = time.time() - start_time
            
            if msg.type == "status":
                new_status = msg.payload.get("status", device.status)
                if device.update_status(new_status):
                    logger.info(f"Device {device.id} status changed to {new_status}")
                    save_device_to_db(device)
                    await notify_webui()
                    # Трекинг uptime
                    save_device_metric(device.id, "status_change", 1 if new_status == "online" else 0)
            elif msg.type == "command_result":
                success = msg.payload.get("success", False)
                error = msg.payload.get("error")
                logger.info(f"Command result from {device.id}: success={success}, time={response_time:.3f}s")
                await track_command_response(device.id, msg.id, response_time, success, error)
                await broadcast_to_webui(json.dumps({
                    "type": "command_result",
                    "device_id": device.id,
                    "id": msg.id,
                    "payload": msg.payload
                }))
            elif msg.type == "event":
                logger.info(f"Event from {device.id}: {msg.payload}")
            elif msg.type == "pong":
                # Игнорируем pong, heartbeat уже обработан
                pass
            else:
                logger.warn(f"Unhandled message type '{msg.type}' from {device.id}")
    except websockets.exceptions.ConnectionClosed:
        logger.info(f"Connection closed by device {device.id}")
    except Exception as e:
        logger.error(f"Error in receive loop for {device.id}: {e}")

async def heartbeat_monitor(device):
    try:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            try:
                pong_waiter = await device.ws.ping()
                await asyncio.wait_for(pong_waiter, timeout=HEARTBEAT_TIMEOUT)
                device.update_last_seen()
                save_device_to_db(device)
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
    ws_id = id(websocket)
    async with lock:
        webui_clients.add(websocket)
    try:
        await send_devices_to_webui(websocket)
        await send_system_metrics_to_webui(websocket)
        
        async for message in websocket:
            try:
                data = json.loads(message)
                msg_type = data.get("type")
                
                if msg_type == "command":
                    device_id = data["device_id"]
                    cmd = data["command"]
                    payload = data.get("payload", {})
                    cmd_id = data.get("id")
                    
                    # Rate limiting проверка
                    rate_limiter = get_rate_limiter(device_id)
                    if not rate_limiter.allow():
                        await websocket.send(json.dumps({"type": "error", "message": "Rate limit exceeded for this device"}))
                        continue
                    
                    if cmd in DANGEROUS_COMMANDS:
                        confirm_id = str(uuid.uuid4())
                        pending_confirm_commands[confirm_id] = {
                            "webui_id": cmd_id,
                            "device_id": device_id,
                            "command": cmd,
                            "params": payload
                        }
                        from yuki_protocol import confirm_command_message
                        confirm_msg = confirm_command_message(device_id, cmd, payload)
                        confirm_msg.id = confirm_id
                        await websocket.send(confirm_msg.to_json())
                        continue
                    
                    await execute_command(device_id, cmd, payload, cmd_id=cmd_id)
                    
                elif msg_type == "broadcast_command":
                    cmd = data["command"]
                    payload = data.get("payload", {})
                    sent = await broadcast_command(cmd, payload)
                    await websocket.send(json.dumps({"type": "broadcast_result", "sent": sent}))
                    
                elif msg_type == "get_system_metrics":
                    metrics = get_system_metrics()
                    await websocket.send(json.dumps({"type": "system_metrics", "payload": metrics}))
                    
                elif msg_type == "get_uptime_stats":
                    device_id = data.get("device_id")
                    days = data.get("days", 7)
                    stats = get_device_uptime_stats(device_id, days)
                    await websocket.send(json.dumps({"type": "uptime_stats", "payload": stats}))
                    
                elif msg_type == "blacklist_add":
                    device_id = data.get("device_id")
                    add_to_blacklist(device_id)
                    await websocket.send(json.dumps({"type": "blacklist_result", "success": True}))
                    
                elif msg_type == "blacklist_remove":
                    device_id = data.get("device_id")
                    remove_from_blacklist(device_id)
                    await websocket.send(json.dumps({"type": "blacklist_result", "success": True}))
                    
                elif msg_type == "get_blacklist":
                    await websocket.send(json.dumps({"type": "blacklist", "devices": list(blacklisted_devices)}))
                    
                elif msg_type == "get_audit_log":
                    limit = data.get("limit", 100)
                    logs = get_audit_log(limit)
                    await websocket.send(json.dumps({"type": "audit_log", "logs": logs}))
                    
                elif msg_type == "confirm_response":
                    confirm_id = data.get("id")
                    approved = data.get("approved", False)
                    if approved and confirm_id in pending_confirm_commands:
                        info = pending_confirm_commands.pop(confirm_id)
                        await execute_command(info["device_id"], info["command"], info["params"], cmd_id=info["webui_id"])
                    else:
                        pending_confirm_commands.pop(confirm_id, None)
                        
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
                            audit_log("device_authorized", device_id, "Approved by admin")
                        else:
                            device.status = "rejected"
                            audit_log("device_rejected", device_id, "Rejected by admin")
                        if auth_event:
                            auth_event.set()
                    await notify_webui()
                    
                elif msg_type == "rotate_token":
                    await perform_token_rotation(reason="admin")
                    await websocket.send(json.dumps({"type": "token_rotated", "success": True}))
                    
                elif msg_type == "get_token_info":
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
                    
                elif msg_type == "get_devices":
                    await send_devices_to_webui(websocket)
                elif msg_type == "disconnect_device":
                    device_id = data.get("device_id")
                    async with lock:
                        device = connected_devices.get(device_id)
                    if device and device.ws:
                        try:
                            # Отправляем команду на отключение устройству
                            disconnect_msg = {
                                "protocol": "yuki/1.0",
                                "type": "disconnect",
                                "id": str(uuid.uuid4()),
                                "timestamp": int(time.time()),
                                "payload": {"reason": "admin_request"}
                            }
                            await device.ws.send(json.dumps(disconnect_msg))
                            
                            # Закрываем соединение
                            await device.ws.close(1000, "Disconnected by admin")
                            device.mark_offline()
                            save_device_to_db(device)
                            
                            # Удаляем из connected_devices
                            if device_id in connected_devices:
                                del connected_devices[device_id]
                            
                            audit_log("device_disconnected", device_id, "Disconnected by admin via WebUI")
                            await notify_webui()
                            logger.info(f"Device {device_id} disconnected by admin")
                            await websocket.send(json.dumps({"type": "disconnect_result", "success": True, "device_id": device_id}))
                        except Exception as e:
                            logger.error(f"Failed to disconnect device {device_id}: {e}")
                            await websocket.send(json.dumps({"type": "disconnect_result", "success": False, "error": str(e)}))
                    else:
                        await websocket.send(json.dumps({"type": "disconnect_result", "success": False, "error": "Device not found or already offline"}))
                        
                elif msg_type == "remove_device":
                    device_id = data.get("device_id")
                    async with lock:
                        # Сначала отключаем, если онлайн
                        device = connected_devices.get(device_id)
                        if device and device.ws:
                            try:
                                await device.ws.close(1000, "Device removed by admin")
                            except:
                                pass
                            if device_id in connected_devices:
                                del connected_devices[device_id]
                        
                        # Удаляем из known_devices
                        if device_id in known_devices:
                            del known_devices[device_id]
                        
                        # Удаляем из БД
                        try:
                            conn = sqlite3.connect(DB_PATH)
                            cursor = conn.cursor()
                            cursor.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
                            cursor.execute("DELETE FROM authorized WHERE device_id = ?", (device_id,))
                            cursor.execute("DELETE FROM command_history WHERE device_id = ?", (device_id,))
                            cursor.execute("DELETE FROM device_metrics WHERE device_id = ?", (device_id,))
                            conn.commit()
                            conn.close()
                        except Exception as e:
                            logger.error(f"Failed to remove device from DB: {e}")
                        
                        # Удаляем из черного списка, если был
                        remove_from_blacklist(device_id)
                        
                        audit_log("device_removed", device_id, "Device removed by admin via WebUI")
                        await notify_webui()
                        logger.info(f"Device {device_id} removed by admin")
                        await websocket.send(json.dumps({"type": "remove_result", "success": True, "device_id": device_id}))

                    
            except json.JSONDecodeError:
                logger.warn("Invalid JSON from WebUI")
            except Exception as e:
                logger.error(f"WebUI message handling error: {e}")
    except websockets.exceptions.ConnectionClosed:
        logger.info("WebUI disconnected")
    finally:
        async with lock:
            webui_clients.discard(websocket)

def get_device_uptime_stats(device_id, days=7):
    """Получение статистики uptime из БД"""
    cutoff = time.time() - days * 24 * 3600
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT value, timestamp FROM device_metrics 
            WHERE device_id = ? AND metric_type = 'status_change' AND timestamp > ?
            ORDER BY timestamp
        ''', (device_id, cutoff))
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            return {'online_percent': 100, 'total_online': 0, 'total_offline': 0}
        
        total_online = 0
        last_time = cutoff
        last_status = 1  # предполагаем что был online
        
        for row in rows:
            status = row[0]
            ts = row[1]
            duration = ts - last_time
            if last_status == 1:
                total_online += duration
            last_time = ts
            last_status = status
        
        # Текущий период
        current_duration = time.time() - last_time
        if last_status == 1:
            total_online += current_duration
        
        total = time.time() - cutoff
        online_percent = (total_online / total * 100) if total > 0 else 100
        
        return {
            'online_percent': round(online_percent, 1),
            'total_online': round(total_online / 3600, 1),
            'total_offline': round((total - total_online) / 3600, 1)
        }
    except Exception as e:
        logger.error(f"Failed to get uptime stats: {e}")
        return {'online_percent': 100, 'total_online': 0, 'total_offline': 0}

def get_audit_log(limit=100):
    """Получение audit логов из БД"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, event_type, device_id, details, ip_address 
            FROM audit_log 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'timestamp': row[0],
                'event_type': row[1],
                'device_id': row[2],
                'details': row[3],
                'ip_address': row[4]
            }
            for row in rows
        ]
    except Exception as e:
        logger.error(f"Failed to get audit log: {e}")
        return []

async def execute_command(device_id: str, cmd: str, payload: dict, cmd_id: str = None):
    async with lock:
        device = connected_devices.get(device_id)
    if device and device.status == "online":
        if cmd_id is None:
            cmd_id = str(uuid.uuid4())
        
        start_time = time.time()
        cmd_msg = {
            "protocol": "yuki/1.0",
            "type": "command",
            "id": cmd_id,
            "timestamp": int(time.time()),
            "payload": {
                "command": cmd,
                "params": payload
            }
        }
        success = await device.send_json(json.dumps(cmd_msg))
        response_time = time.time() - start_time
        
        save_command_to_history(cmd_id, device_id, cmd, payload, "pending" if success else "failed", response_time)
        audit_log("command_sent", device_id, f"Command: {cmd}")
        
        if success:
            logger.info(f"Command sent to {device_id}: {cmd} (id={cmd_id}, time={response_time:.3f}s)")
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
    from yuki_protocol import devices_update_message
    msg = devices_update_message(devices_info)
    await ws.send(msg.to_json())

async def send_system_metrics_to_webui(ws):
    metrics = get_system_metrics()
    await ws.send(json.dumps({"type": "system_metrics", "payload": metrics}))

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
    from yuki_protocol import devices_update_message
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

# Authorized devices
authorized_devices_set = set()
AUTHORIZED_FILE = os.path.join(os.path.dirname(__file__), "authorized_devices.json")

def load_authorized():
    global authorized_devices_set
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT device_id FROM authorized")
        rows = cursor.fetchall()
        authorized_devices_set = {row[0] for row in rows}
        conn.close()
        logger.info(f"Loaded {len(authorized_devices_set)} authorized devices from DB")
    except Exception as e:
        logger.error(f"Failed to load authorized devices: {e}")
        authorized_devices_set = set()

def save_authorized():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM authorized")
        for device_id in authorized_devices_set:
            cursor.execute("INSERT INTO authorized (device_id) VALUES (?)", (device_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to save authorized devices: {e}")

async def perform_token_rotation(reason="admin"):
    global current_token
    new_token = generate_new_token(save=True)
    logger.info(f"Token rotated ({reason})")
    
    async with lock:
        devices = list(connected_devices.values())
    if devices:
        update_msg = {
            "type": "token_update",
            "payload": {"new_token": new_token, "reason": reason}
        }
        json_msg = json.dumps(update_msg)
        for device in devices:
            if device.ws and device.status == "online":
                try:
                    await device.ws.send(json_msg)
                except Exception as e:
                    logger.warn(f"Failed to send new token to {device.id}: {e}")
    return new_token

from contextlib import suppress

# Инициализация БД и загрузка данных
init_db()
load_devices_from_db()
load_authorized()
load_blacklist()

# ==================== Main ====================
async def main():
    # Запускаем фоновые задачи
    asyncio.create_task(system_metrics_scheduler())
    asyncio.create_task(log_rotation_scheduler())
    
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
    
    try:
        await server.wait_closed()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.close()
        await server.wait_closed()
        
        # Сохраняем финальное состояние
        for device in known_devices.values():
            save_device_to_db(device)
        
        logger.info("Shutdown complete")

if __name__ == "__main__":
    asyncio.run(main())