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
import hmac
import hashlib
import re
import sqlite3
import logging
import psutil
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("yuki-core")

_AUTH_TOKEN_RE = re.compile(r'("auth_token"\s*:\s*")[^"]*(")')

def redact_tokens(raw: str) -> str:
    return _AUTH_TOKEN_RE.sub(r'\1***\2', raw)

# ==================== SQLite БД ====================
DB_PATH = os.path.join(os.path.dirname(__file__), "yuki_core.db")
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
PROTOCOL_PATH = os.path.join(PROJECT_ROOT, 'libs', 'yuki-protocol', 'python')
sys.path.insert(0, PROTOCOL_PATH)
from yuki_protocol import PROTOCOL_VERSION

def init_db():
    """Инициализация базы данных SQLite"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # WAL lets readers/writers run concurrently instead of blocking each other for up to
    # busy_timeout on every call - the default rollback-journal mode serializes all access.
    cursor.execute("PRAGMA journal_mode=WAL")

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
        device_rate_limiters[device_id] = DeviceRateLimiter(device_id, 60)
    return device_rate_limiters[device_id]

# Separate from the per-device_id limiter above: that one is keyed by whatever device_id the
# handshake claims, so one IP can brute-force many different device_ids each getting its own
# fresh limit. This one is keyed by source IP instead, checked before device_id is even trusted.
ip_handshake_limiters = {}

def get_ip_handshake_limiter(ip):
    if ip not in ip_handshake_limiters:
        ip_handshake_limiters[ip] = DeviceRateLimiter(ip, commands_per_minute=20)
    return ip_handshake_limiters[ip]

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

extended_statuses = {}  # device_id -> {substatus, details, last_update}
device_metrics_store = defaultdict(list)  # device_id -> list of metrics
MAX_METRICS_HISTORY = 100  # храним последние 100 метрик
METRICS_RETENTION_HOURS = 24  # храним метрики 24 часа

# Хранилище ожидающих ответов между устройствами
pending_device_requests = {}  # request_id -> {from_device, to_device, timestamp}

def save_device_metrics(device_id: str, metrics: dict):
    """Сохранение метрик устройства с временной меткой"""
    timestamp = time.time()
    metrics_entry = {
        "timestamp": timestamp,
        "metrics": metrics
    }
    device_metrics_store[device_id].append(metrics_entry)
    
    # Очистка старых метрик
    cutoff = timestamp - METRICS_RETENTION_HOURS * 3600
    device_metrics_store[device_id] = [
        m for m in device_metrics_store[device_id] 
        if m["timestamp"] > cutoff
    ]
    
    # Ограничение по количеству
    if len(device_metrics_store[device_id]) > MAX_METRICS_HISTORY:
        device_metrics_store[device_id] = device_metrics_store[device_id][-MAX_METRICS_HISTORY:]
    
    # Сохраняем в БД
    for key, value in metrics.items():
        if isinstance(value, (int, float)):
            save_device_metric(device_id, key, value)
    
    logger.debug(f"Saved metrics for {device_id}: {len(metrics)} metrics")
    return metrics_entry

def get_device_metrics(device_id: str, hours: int = 1, metric_names: list = None):
    """Получение метрик устройства за последние N часов"""
    cutoff = time.time() - hours * 3600
    metrics = device_metrics_store.get(device_id, [])
    filtered = [m for m in metrics if m["timestamp"] > cutoff]
    
    if metric_names:
        # Фильтруем только запрошенные метрики
        for entry in filtered:
            entry["metrics"] = {
                k: v for k, v in entry["metrics"].items() 
                if k in metric_names
            }
    
    return filtered

def get_latest_metrics(device_id: str):
    """Получение последних метрик устройства"""
    metrics_list = device_metrics_store.get(device_id, [])
    if metrics_list:
        return metrics_list[-1]
    return None


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
GRACE_PERIOD_MINUTES = int(os.environ.get("YUKI_TOKEN_GRACE_MINUTES", "30"))

current_token = None
token_created_at = None
token_from_env = False  # set when the token is admin-managed (env var / systemd credential) - core must never rotate it

# Kept valid for GRACE_PERIOD_MINUTES after a rotation so devices that were offline at the moment
# of rotation (and so never received the token_update push) aren't locked out until they notice.
previous_token = None
previous_token_expires_at = None

def load_token():
    global current_token, token_created_at, token_from_env
    env_token = os.environ.get("YUKI_AUTH_TOKEN")
    if env_token:
        current_token = env_token
        token_created_at = None
        token_from_env = True
        logger.info("Using authentication token from environment variable (rotation disabled)")
        return

    # systemd credential: `LoadCredential=yuki_auth_token:/path/to/file` exposes
    # $CREDENTIALS_DIRECTORY/yuki_auth_token - preferred over the plaintext file below.
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        cred_path = os.path.join(cred_dir, "yuki_auth_token")
        if os.path.exists(cred_path):
            with open(cred_path, "r", encoding="utf-8") as f:
                current_token = f.read().strip()
            token_created_at = None
            token_from_env = True
            logger.info("Using authentication token from systemd credential (rotation disabled)")
            return

    token_from_env = False
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            current_token = f.read().strip()
        try:
            os.chmod(TOKEN_FILE, 0o600)
        except OSError:
            pass
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
            os.chmod(TOKEN_FILE, 0o600)
            with open(TOKEN_META_FILE, "w", encoding="utf-8") as f:
                json.dump({"created_at": token_created_at}, f)
            os.chmod(TOKEN_META_FILE, 0o600)
        except Exception as e:
            logger.error(f"Failed to save token: {e}")
    logger.info(f"Generated new authentication token")
    return current_token

def _candidate_tokens():
    """Current token, plus the previous one while its post-rotation grace period hasn't expired."""
    candidates = []
    if current_token is not None:
        candidates.append(current_token)
    if previous_token is not None and previous_token_expires_at and time.time() < previous_token_expires_at:
        candidates.append(previous_token)
    return candidates

def verify_plain_token(auth_token):
    """Legacy handshake: the device sent its token directly in `hello`."""
    if current_token is None:
        return True
    if not auth_token:
        return False
    return any(hmac.compare_digest(auth_token, tok) for tok in _candidate_tokens())

def verify_challenge_response(nonce_c, nonce_s, provided_hmac):
    """New handshake: the device proves it knows the token without ever sending it."""
    if current_token is None:
        return True
    if not provided_hmac or not nonce_c or not nonce_s:
        return False
    message = f"{nonce_c}:{nonce_s}".encode()
    for tok in _candidate_tokens():
        expected = hmac.new(tok.encode(), message, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, provided_hmac):
            return True
    return False

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
                "protocol": PROTOCOL_VERSION,
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
    rate_limiter = None

    logger.info("handle_device: entered")

    remote_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
    if not get_ip_handshake_limiter(remote_ip).allow():
        # Per-IP, independent of the per-device_id limiter below - that one lets an attacker
        # brute-force many different device_ids from a single IP, each getting its own fresh quota.
        logger.warning(f"Handshake rate limit exceeded for IP {remote_ip}")
        await websocket.close(1008, "Too many handshake attempts")
        return

    try:
        raw_init = await asyncio.wait_for(websocket.recv(), timeout=10.0)
        logger.info(
            f"Received initial message: "
            f"{redact_tokens(raw_init)[:200] if raw_init else 'empty'}"
        )

        try:
            from yuki_protocol import YukiMessage

            init_msg = YukiMessage.from_json(raw_init)

            if init_msg.type != "hello":
                logger.warning(
                    f"First message is not hello: {init_msg.type}"
                )
                await websocket.close(
                    1003,
                    "First message must be 'hello'"
                )
                return

        except ValueError as e:
            logger.error(f"Invalid protocol message: {e}")
            await websocket.close(
                1003,
                f"Invalid protocol: {e}"
            )
            return

        device_id = init_msg.payload.get("device_id")
        device_type = init_msg.payload.get("device_type")
        capabilities = init_msg.payload.get("capabilities", [])
        auth_token = init_msg.payload.get("auth_token")
        nonce_c = init_msg.payload.get("nonce_c")

        if not device_id or not device_type:
            logger.warning(
                f"Missing device_id or device_type: "
                f"device_id={device_id}, device_type={device_type}"
            )
            await websocket.close(
                1003,
                "Missing device_id or device_type"
            )
            return

        logger.info(
            f"Device {device_id} attempting to connect "
            f"(type: {device_type})"
        )

        rate_limiter = get_rate_limiter(device_id)

        if not rate_limiter.allow():
            logger.warning(
                f"Rate limit exceeded for device {device_id}"
            )
            await websocket.close(
                1008,
                "Rate limit exceeded"
            )
            return

        if is_blacklisted(device_id):
            logger.warning(
                f"Device {device_id} is blacklisted, rejecting connection"
            )
            await websocket.close(
                1008,
                "Device is blacklisted"
            )
            return

        if nonce_c:
            # New handshake: the token never travels over the network, even without TLS.
            # hello{nonce_c} -> challenge{nonce_s} -> auth{hmac(token, nonce_c:nonce_s)}
            nonce_s = secrets.token_hex(16)
            challenge_msg = {
                "protocol": PROTOCOL_VERSION,
                "type": "challenge",
                "id": str(uuid.uuid4()),
                "timestamp": int(time.time()),
                "payload": {"nonce_s": nonce_s}
            }
            await websocket.send(json.dumps(challenge_msg))

            try:
                raw_auth = await asyncio.wait_for(websocket.recv(), timeout=10.0)
            except asyncio.TimeoutError:
                logger.warning(f"Device {device_id} did not respond to challenge in time")
                await websocket.close(1008, "Challenge response timeout")
                return

            try:
                auth_data = json.loads(raw_auth)
            except ValueError:
                logger.warning(f"Device {device_id} sent invalid auth response")
                await websocket.close(1003, "Invalid auth response")
                return

            if auth_data.get("type") != "auth":
                logger.warning(f"Device {device_id} sent '{auth_data.get('type')}' instead of 'auth'")
                await websocket.close(1003, "Expected 'auth' message")
                return

            provided_hmac = auth_data.get("payload", {}).get("hmac", "")
            token_valid = verify_challenge_response(nonce_c, nonce_s, provided_hmac)
        else:
            # Legacy handshake: token sent directly in hello (still supported for older devices).
            token_valid = verify_plain_token(auth_token)

        logger.info(
            f"Token validation: "
            f"token_valid={token_valid}, "
            f"has_token={bool(current_token)}, "
            f"method={'challenge' if nonce_c else 'legacy'}"
        )

        if not token_valid:
            logger.warning(
                f"Device {device_id} rejected: invalid auth token"
            )

            audit_log(
                "auth_failed",
                device_id,
                "Invalid token",
                websocket.remote_address[0]
                if websocket.remote_address
                else None
            )

            await websocket.close(
                1008,
                "Invalid authentication token"
            )
            return

        is_authorized = device_id in authorized_devices_set

        logger.info(
            f"Device {device_id} authorized in DB: {is_authorized}"
        )

        logger.info(
            f"Importing Device class for {device_id}..."
        )

        try:
            from device import Device
        except Exception as e:
            logger.exception(
                f"Failed to import Device class: {e}"
            )
            await websocket.close(
                1011,
                "Server misconfiguration"
            )
            return

        logger.info(
            f"Device class imported OK for {device_id}"
        )

        # --------------------------------------------------------
        # Создание/обновление устройства
        #
        # ВАЖНО:
        # Никаких await внутри lock.
        # Старое websocket закрывается ПОСЛЕ выхода из lock.
        # --------------------------------------------------------

        old_device = None
        old_websocket = None

        logger.info(
            f"Entering lock block for {device_id}..."
        )

        async with lock:
            old_device = connected_devices.get(device_id)

            if (
                old_device
                and old_device.ws
                and old_device.ws is not websocket
            ):
                old_websocket = old_device.ws

                logger.info(
                    f"Replacing old connection for {device_id}"
                )

                # Сразу убираем старое соединение из активных.
                connected_devices.pop(device_id, None)

            # Всегда создаём новый Device-объект для нового websocket.
            #
            # Это важно: старый handle_device() больше не сможет
            # случайно пометить новую сессию offline.

            try:
                device = Device(
                    device_id,
                    device_type,
                    websocket,
                    capabilities,
                    authorized=is_authorized
                )
            except Exception as e:
                logger.exception(
                    f"Failed to construct Device for {device_id}: {e}"
                )
                raise

            known_devices[device_id] = device

            device.update_last_seen()

            connected_devices[device_id] = device

            save_device_to_db(device)

        logger.info(
            f"Exited lock block for {device_id}, device={device}"
        )

        # --------------------------------------------------------
        # Закрываем старый websocket ВНЕ lock.
        # --------------------------------------------------------

        if old_websocket is not None:
            try:
                await asyncio.wait_for(
                    old_websocket.close(
                        1000,
                        "New connection"
                    ),
                    timeout=5
                )
            except Exception as e:
                logger.debug(
                    f"Old connection for {device_id} "
                    f"already closed: {e}"
                )

        audit_log(
            "device_connected",
            device_id,
            f"Type: {device_type}",
            websocket.remote_address[0]
            if websocket.remote_address
            else None
        )

        # --------------------------------------------------------
        # Авторизация
        # --------------------------------------------------------

        if not is_authorized:
            logger.info(
                f"Device {device_id} is NOT authorized, "
                f"requesting approval"
            )

            device.status = "pending"
            save_device_to_db(device)

            try:
                from yuki_protocol import device_auth_request_message
            except Exception as e:
                logger.exception(
                    f"Cannot import device_auth_request_message: {e}"
                )

                await websocket.close(
                    1011,
                    "Server misconfiguration: protocol helper missing"
                )
                return

            try:
                auth_request = device_auth_request_message(
                    device_id,
                    device_type,
                    capabilities
                )

                auth_request.id = str(uuid.uuid4())

                logger.info(
                    f"Built auth_request for {device_id}, "
                    f"id={auth_request.id}"
                )

            except Exception as e:
                logger.exception(
                    f"device_auth_request_message() failed "
                    f"for {device_id}: {e}"
                )

                await websocket.close(
                    1011,
                    "Failed to build auth request"
                )
                return

            auth_event = asyncio.Event()

            async with lock:
                pending_auth_events[device_id] = auth_event
                pending_devices[device_id] = device

                webui_count = len(webui_clients)

            logger.info(
                f"Broadcasting auth request to "
                f"{webui_count} WebUI client(s)"
            )

            if webui_count == 0:
                logger.warning(
                    f"No WebUI clients connected - "
                    f"auth request for {device_id} will time out "
                    f"in {AUTH_TIMEOUT}s. Open the WebUI to approve."
                )

            # ВАЖНО:
            # broadcast_to_webui() сам использует lock,
            # поэтому вызываем его только вне lock.

            try:
                await broadcast_to_webui(
                    auth_request.to_json()
                )

                logger.info(
                    f"Auth request sent for {device_id}, "
                    f"waiting for response..."
                )

            except Exception as e:
                logger.exception(
                    f"broadcast_to_webui failed for "
                    f"{device_id}: {e}"
                )

                async with lock:
                    pending_devices.pop(device_id, None)
                    pending_auth_events.pop(device_id, None)

                await websocket.close(
                    1011,
                    "Failed to notify WebUI"
                )
                return

            # ----------------------------------------------------
            # Ждём ответа WebUI
            # ----------------------------------------------------

            try:
                await asyncio.wait_for(
                    auth_event.wait(),
                    timeout=AUTH_TIMEOUT
                )

                logger.info(
                    f"Auth response received for {device_id}"
                )

            except asyncio.TimeoutError:
                logger.warning(
                    f"Authorization timeout for device {device_id}"
                )

                async with lock:
                    pending_devices.pop(device_id, None)
                    pending_auth_events.pop(device_id, None)

                await websocket.close(
                    1008,
                    "Authorization timeout"
                )
                return

            # ----------------------------------------------------
            # Проверяем авторизацию после ответа
            # ----------------------------------------------------

            async with lock:
                authorized_now = (
                    device_id in authorized_devices_set
                )

            if not authorized_now:
                logger.warning(
                    f"Device {device_id} was not authorized by admin"
                )

                async with lock:
                    pending_devices.pop(device_id, None)
                    pending_auth_events.pop(device_id, None)

                await websocket.close(
                    1008,
                    "Device not authorized"
                )
                return

            logger.info(
                f"Device {device_id} authorized, "
                f"continuing handshake"
            )

            device.authorized = True
            device.status = "online"

            save_device_to_db(device)

            async with lock:
                pending_devices.pop(device_id, None)
                pending_auth_events.pop(device_id, None)

            save_authorized()

        else:
            logger.info(
                f"Device {device_id} is already authorized"
            )

        # --------------------------------------------------------
        # Welcome
        # --------------------------------------------------------

        if rate_limiter is None:
            rate_limiter = get_rate_limiter(device_id)

        try:
            from yuki_protocol import welcome_message
        except Exception as e:
            logger.exception(
                f"Cannot import welcome_message: {e}"
            )

            await websocket.close(
                1011,
                "Server misconfiguration: welcome_message missing"
            )
            return

        welcome = welcome_message(
            session_id=str(uuid.uuid4()),
            server_time=int(time.time()),
            heartbeat_interval=HEARTBEAT_INTERVAL
        )

        await websocket.send(
            welcome.to_json()
        )

        logger.info(
            f"Welcome sent to {device.id}"
        )

        if websocket.state.name == "CLOSED":
            logger.error(
                f"WebSocket closed immediately after "
                f"welcome for {device.id}"
            )
            return

        device.status = "online"

        save_device_to_db(device)

        await notify_webui()

        logger.info(
            f"Handshake COMPLETED for {device.id}, "
            f"status set to online"
        )

        await asyncio.sleep(0.1)

        receive_task = asyncio.create_task(
            device_receive_loop(
                device,
                websocket,
                rate_limiter,
                connect_time
            )
        )

        heartbeat_task = asyncio.create_task(
            heartbeat_monitor(
                device,
                websocket
            )
        )

        try:
            await asyncio.gather(
                receive_task,
                heartbeat_task
            )

        except asyncio.CancelledError:
            logger.info(
                f"Tasks cancelled for {device.id}"
            )

        except Exception as e:
            logger.exception(
                f"Error in tasks for {device.id}: {e}"
            )

    except asyncio.TimeoutError:
        logger.warning(
            f"Device {device_id} handshake timeout"
        )

    except websockets.exceptions.ConnectionClosed as e:
        logger.info(
            f"Device {device_id} connection closed "
            f"during handshake: {e}"
        )

    except Exception as e:
        logger.exception(
            f"Unexpected error in handle_device "
            f"for {device_id}: {e}"
        )

    finally:
        logger.info(
            f"handle_device: finally block for {device_id}"
        )

        if device_id:
            was_current_connection = False
            device_to_update = None

            async with lock:
                current = connected_devices.get(device_id)

                # Удаляем только СВОЮ сессию.
                #
                # Если уже подключился новый websocket,
                # старый handle_device ничего не трогает.

                if (
                    current is device
                    and device is not None
                    and device.ws is websocket
                ):
                    connected_devices.pop(device_id, None)
                    was_current_connection = True
                    device_to_update = device

                    logger.info(
                        f"Removed {device_id} from connected_devices "
                        f"(this connection)"
                    )

                else:
                    logger.info(
                        f"Not removing {device_id} from "
                        f"connected_devices - newer connection exists"
                    )

                if (
                    device_to_update is not None
                    and known_devices.get(device_id) is device
                ):
                    device_to_update.mark_offline()
                    device_to_update.ws = None

            # Сохраняем БД уже после lock.
            if device_to_update is not None:
                save_device_to_db(device_to_update)

            # Если соединение завершилось во время авторизации,
            # будим ожидающий handle_device, чтобы он не висел 60 секунд.

            async with lock:
                auth_event = pending_auth_events.get(device_id)

            if auth_event is not None:
                auth_event.set()

                async with lock:
                    pending_auth_events.pop(device_id, None)
                    pending_devices.pop(device_id, None)

            if was_current_connection:
                logger.info(
                    f"Device {device_id} disconnected"
                )

            audit_log(
                "device_disconnected",
                device_id,
                "Connection closed"
            )

        await notify_webui()

async def device_receive_loop(device, websocket, rate_limiter, connect_time):
    # Bound to the specific `websocket` this task was created for, not device.ws - device.ws can
    # be reassigned by a newer overlapping connection for the same device_id while this task is
    # still running, which previously caused two tasks to call recv() on the same connection.
    try:
        if not websocket:
            logger.error(f"Device {device.id} has no websocket in receive loop")
            return

        async for message in websocket:
            # Пропускаем пустые или слишком короткие сообщения
            if not message or len(message) < 10:
                continue
            
            # Пропускаем сообщения без protocol (не Yuki сообщения)
            if '"protocol"' not in message:
                logger.debug(f"Non-Yuki message from {device.id}, skipping")
                continue
            
            # Проверяем, что rate_limiter существует
            if rate_limiter is None:
                logger.error(f"Rate limiter is None for {device.id}, creating new")
                rate_limiter = get_rate_limiter(device.id)
                
            if not rate_limiter.allow():
                logger.warning(f"Rate limit exceeded for device {device.id}")
                try:
                    await websocket.close(1008, "Rate limit exceeded")
                except:
                    pass
                break

            start_time = time.time()
            
            try:
                from yuki_protocol import YukiMessage
                msg = YukiMessage.from_json(message)
            except ValueError as e:
                error_msg = str(e)
                if "Unsupported protocol version" in error_msg or "Missing protocol" in error_msg:
                    logger.debug(f"Non-Yuki message from {device.id}: {error_msg}")
                else:
                    logger.warning(f"Invalid message from {device.id}: {error_msg}")
                continue
            except Exception as e:
                logger.warning(f"Unexpected error parsing message from {device.id}: {e}")
                continue

            response_time = time.time() - start_time
            
            if msg.type == "status":
                new_status = msg.payload.get("status", device.status)
                # Если пришел статус с details, но устройство уже online - не меняем статус
                if new_status == "online" or (new_status != "online" and device.status == "online"):
                    # Обновляем только last_seen
                    device.update_last_seen()
                    save_device_to_db(device)
                    if new_status != "online":
                        logger.debug(f"Device {device.id} sent status '{new_status}', keeping online")
                elif device.update_status(new_status):
                    logger.info(f"Device {device.id} status changed to {new_status}")
                    save_device_to_db(device)
                    await notify_webui()
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
                pass
            elif msg.type == "extended_status":
                # Обработка расширенного статуса
                substatus = msg.payload.get("substatus")
                details = msg.payload.get("details", {})
                
                extended_statuses[device.id] = {
                    "substatus": substatus,
                    "details": details,
                    "last_update": time.time(),
                }
                
                logger.info(f"Device {device.id} extended status: {substatus}")
                
                # Уведомляем WebUI
                await broadcast_to_webui(json.dumps({
                    "type": "extended_status",
                    "device_id": device.id,
                    "substatus": substatus,
                    "details": details
                }))
                
                # Сохраняем в БД статус-чейндж
                if substatus:
                    save_device_metric(device.id, f"substatus_{substatus}", 1)
                
            elif msg.type == "metrics":
                # Обработка метрик
                metrics = msg.payload.get("metrics", {})
                timestamp = msg.payload.get("timestamp", time.time())
                
                save_device_metrics(device.id, metrics)
                
                # Обновляем last_metrics в устройстве для отправки в devices_update
                if hasattr(device, 'last_metrics'):
                    device.last_metrics = metrics
                else:
                    device.last_metrics = metrics
                
                # Отправляем обновление устройств в WebUI (включая метрики)
                await notify_webui()
                
                # Дополнительно отправляем событие обновления метрик
                await broadcast_to_webui(json.dumps({
                    "type": "metrics_update",
                    "device_id": device.id,
                    "metrics": metrics,
                    "timestamp": timestamp
                }))
                
                # Логируем важные метрики
                if metrics.get("battery") is not None and metrics.get("battery") < 20:
                    logger.warning(f"Device {device.id} battery low: {metrics['battery']}%")
                if metrics.get("temperature") is not None and metrics.get("temperature") > 70:
                    logger.warning(f"Device {device.id} temperature high: {metrics['temperature']}°C")
                
            elif msg.type == "metrics_request":
                # Запрос метрик - отправляем последние
                latest = get_latest_metrics(device.id)
                if latest:
                    response = {
                        "protocol": PROTOCOL_VERSION,
                        "type": "metrics",
                        "id": str(uuid.uuid4()),
                        "timestamp": int(time.time()),
                        "payload": {
                            "device_id": device.id,
                            "metrics": latest["metrics"],
                            "timestamp": latest["timestamp"]
                        }
                    }
                    await device.send_json(json.dumps(response))
                
            elif msg.type == "device_to_device":
                # Прямая отправка от устройства к устройству
                from_device_id = msg.payload.get("from_device_id")
                to_device_id = msg.payload.get("to_device_id")
                command = msg.payload.get("command")
                payload = msg.payload.get("payload", {})
                require_response = msg.payload.get("require_response", False)
                
                # Проверяем, что отправитель соответствует текущему устройству
                if from_device_id != device.id:
                    logger.warning(f"Device {device.id} attempted to spoof from_device_id={from_device_id}")
                    await device.send_json(json.dumps({
                        "type": "error",
                        "payload": {"error": "Invalid from_device_id"}
                    }))
                    continue

                if rate_limiter and not rate_limiter.allow():
                    logger.warning(f"Rate limit exceeded for device {device.id} (device_to_device)")
                    await device.send_json(json.dumps({
                        "type": "error",
                        "payload": {"error": "Rate limit exceeded"}
                    }))
                    continue

                async with lock:
                    target_device = connected_devices.get(to_device_id)
                
                if not target_device or target_device.status != "online":
                    error_msg = {
                        "type": "error",
                        "id": msg.id,
                        "payload": {"error": f"Device {to_device_id} is offline or not found"}
                    }
                    await device.send_json(json.dumps(error_msg))
                    continue
                
                # Формируем сообщение для целевого устройства
                forward_msg = {
                    "protocol": PROTOCOL_VERSION,
                    "type": "device_command",
                    "id": msg.id,
                    "timestamp": int(time.time()),
                    "payload": {
                        "from_device_id": from_device_id,
                        "command": command,
                        "payload": payload,
                        "require_response": require_response
                    }
                }
                
                success = await target_device.send_json(json.dumps(forward_msg))
                
                if success:
                    logger.info(f"Device {from_device_id} -> {to_device_id}: {command}")
                    audit_log("device_to_device", from_device_id, f"Sent to {to_device_id}: {command}")
                    
                    # Если требуется ответ, сохраняем запрос
                    if require_response:
                        pending_device_requests[msg.id] = {
                            "from_device": from_device_id,
                            "to_device": to_device_id,
                            "timestamp": time.time(),
                            "command": command
                        }
                        
                        # Таймаут для ответа
                        asyncio.create_task(await_device_response(msg.id, device, to_device_id))
                else:
                    await device.send_json(json.dumps({
                        "type": "error",
                        "id": msg.id,
                        "payload": {"error": f"Failed to send to {to_device_id}"}
                    }))
                
            elif msg.type == "device_response":
                # Ответ от устройства на запрос от другого устройства
                original_id = msg.id
                success = msg.payload.get("success", False)
                result = msg.payload.get("result")
                error = msg.payload.get("error")
                
                # Находим ожидающий запрос
                if original_id in pending_device_requests:
                    req = pending_device_requests[original_id]
                    from_device_id = req["from_device"]
                    
                    async with lock:
                        original_device = connected_devices.get(from_device_id)
                    
                    if original_device and original_device.status == "online":
                        response_msg = {
                            "protocol": PROTOCOL_VERSION,
                            "type": "device_response",
                            "id": original_id,
                            "timestamp": int(time.time()),
                            "payload": {
                                "from_device_id": device.id,
                                "success": success,
                                "result": result,
                                "error": error
                            }
                        }
                        await original_device.send_json(json.dumps(response_msg))
                    
                    del pending_device_requests[original_id]
                    logger.info(f"Device response forwarded: {original_id} success={success}")
                
            elif msg.type == "device_broadcast":
                # Широковещательная команда от устройства
                from_device_id = msg.payload.get("from_device_id")
                command = msg.payload.get("command")
                payload = msg.payload.get("payload", {})
                device_filter = msg.payload.get("device_filter")
                
                if from_device_id != device.id:
                    logger.warning(f"Device {device.id} attempted to spoof broadcast from_device_id")
                    continue

                if rate_limiter and not rate_limiter.allow():
                    logger.warning(f"Rate limit exceeded for device {device.id} (device_broadcast)")
                    continue

                async with lock:
                    devices_to_send = []
                    for dev_id, dev in connected_devices.items():
                        if dev_id == device.id:
                            continue
                        if device_filter and dev_id not in device_filter:
                            continue
                        if dev.status == "online":
                            devices_to_send.append(dev)
                
                sent_count = 0
                for target_device in devices_to_send:
                    broadcast_msg = {
                        "protocol": PROTOCOL_VERSION,
                        "type": "device_broadcast",
                        "id": str(uuid.uuid4()),
                        "timestamp": int(time.time()),
                        "payload": {
                            "from_device_id": from_device_id,
                            "command": command,
                            "payload": payload
                        }
                    }
                    if await target_device.send_json(json.dumps(broadcast_msg)):
                        sent_count += 1
                    await asyncio.sleep(0.05)
                
                # Отправляем отправителю отчет о доставке
                await device.send_json(json.dumps({
                    "type": "broadcast_report",
                    "payload": {
                        "sent_to": sent_count,
                        "total": len(devices_to_send),
                        "command": command
                    }
                }))
                
                logger.info(f"Device {from_device_id} broadcast '{command}' to {sent_count} devices")

            else:
                logger.debug(f"Unhandled message type '{msg.type}' from {device.id}")
                
    except websockets.exceptions.ConnectionClosed as e:
        logger.info(f"Connection closed by device {device.id}: {e}")
    except asyncio.CancelledError:
        logger.info(f"Receive loop cancelled for {device.id}")
    except Exception as e:
        logger.error(f"Error in receive loop for {device.id}: {e}")
    finally:
        logger.info(f"Receive loop ended for {device.id}")

async def await_device_response(request_id: str, from_device, to_device_id: str):
    """Ожидание ответа от устройства с таймаутом"""
    await asyncio.sleep(30)  # 30 секунд таймаут
    if request_id in pending_device_requests:
        req = pending_device_requests[request_id]
        if req["to_device"] == to_device_id:
            # Таймаут - отправляем ошибку
            timeout_msg = {
                "type": "error",
                "id": request_id,
                "payload": {"error": "Response timeout"}
            }
            await from_device.send_json(json.dumps(timeout_msg))
            del pending_device_requests[request_id]
            logger.warning(f"Device response timeout for {request_id}")


async def heartbeat_monitor(device, websocket):
    consecutive_failures = 0
    max_failures = 3

    try:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)

            if not websocket:
                logger.warning(
                    f"Heartbeat: device {device.id} "
                    f"has no websocket, stopping monitor"
                )
                break

            async with lock:
                current = connected_devices.get(device.id)

                # Старый heartbeat не должен убивать новую сессию.
                if (
                    current is not device
                    or device.ws is not websocket
                ):
                    logger.info(
                        f"Heartbeat: newer connection exists "
                        f"for {device.id}, stopping old monitor"
                    )
                    break

            if websocket.state.name == "CLOSED":
                logger.warning(
                    f"Heartbeat: WebSocket for "
                    f"{device.id} is closed"
                )
                break

            try:
                pong_waiter = await websocket.ping()

                await asyncio.wait_for(
                    pong_waiter,
                    timeout=HEARTBEAT_TIMEOUT
                )

                device.update_last_seen()
                save_device_to_db(device)

                consecutive_failures = 0

                logger.debug(
                    f"Heartbeat OK for {device.id}"
                )

            except asyncio.TimeoutError:
                consecutive_failures += 1

                logger.warning(
                    f"Heartbeat timeout for {device.id} "
                    f"(failure {consecutive_failures}/{max_failures})"
                )

                if consecutive_failures >= max_failures:
                    logger.warning(
                        f"Heartbeat: too many failures "
                        f"for {device.id}, closing connection"
                    )

                    try:
                        await websocket.close()
                    except Exception:
                        pass

                    break

            except AttributeError as e:
                logger.error(
                    f"Heartbeat attribute error "
                    f"for {device.id}: {e}"
                )
                break

            except websockets.exceptions.ConnectionClosed as e:
                logger.info(
                    f"Heartbeat: connection closed "
                    f"for {device.id}: {e}"
                )
                break

            except Exception as e:
                logger.error(
                    f"Heartbeat unexpected error "
                    f"for {device.id}: {e}"
                )

                consecutive_failures += 1

                if consecutive_failures >= max_failures:
                    break

    except asyncio.CancelledError:
        logger.info(
            f"Heartbeat monitor cancelled for {device.id}"
        )

    except Exception as e:
        logger.error(
            f"Heartbeat monitor error for "
            f"{device.id}: {e}"
        )

    finally:
        should_update = False

        async with lock:
            current = connected_devices.get(device.id)

            if (
                current is device
                and device.ws is websocket
            ):
                device.mark_offline()
                should_update = True

        if should_update:
            save_device_to_db(device)

        await notify_webui()

        logger.info(
            f"Heartbeat monitor stopped for {device.id}"
        )


def _default_webui_origins():
    env_val = os.environ.get("YUKI_WEBUI_ALLOWED_ORIGINS")
    if env_val:
        return {o.strip() for o in env_val.split(",") if o.strip()}
    # Default assumes yuki-webui runs on its own default port (5000) on the same host as core.
    # Override YUKI_WEBUI_ALLOWED_ORIGINS if you bind it somewhere else.
    return {
        "http://localhost:5000", "https://localhost:5000",
        "http://127.0.0.1:5000", "https://127.0.0.1:5000",
    }

WEBUI_ALLOWED_ORIGINS = _default_webui_origins()

def _webui_origin_allowed(websocket):
    try:
        origin = websocket.request.headers.get("Origin")
    except Exception:
        origin = None
    if origin is None:
        return True  # non-browser clients (scripts/CLI tools) don't send an Origin header at all
    return origin in WEBUI_ALLOWED_ORIGINS

async def handle_webui(websocket, path=None):
    ws_id = id(websocket)

    if not _webui_origin_allowed(websocket):
        origin = None
        try:
            origin = websocket.request.headers.get("Origin")
        except Exception:
            pass
        logger.warning(f"WebUI connection rejected: disallowed Origin '{origin}'")
        await websocket.close(1008, "Origin not allowed")
        return

    try:
        raw_auth = await asyncio.wait_for(
            websocket.recv(),
            timeout=10.0
        )

        auth_data = json.loads(raw_auth)

    except (
        asyncio.TimeoutError,
        ValueError,
        websockets.exceptions.ConnectionClosed
    ):
        await websocket.close(
            1008,
            "Authentication required"
        )
        return

    auth_token = (
        auth_data.get("token")
        if auth_data.get("type") == "auth"
        else None
    )

    if not verify_plain_token(auth_token):
        logger.warning(
            "WebUI connection rejected: "
            "invalid or missing auth token"
        )

        audit_log(
            "webui_auth_failed",
            None,
            "Invalid token",
            websocket.remote_address[0]
            if websocket.remote_address
            else None
        )

        await websocket.close(
            1008,
            "Invalid authentication token"
        )
        return

    await websocket.send(
        json.dumps({
            "type": "auth_ok"
        })
    )

    async with lock:
        webui_clients.add(websocket)

    try:
        await send_devices_to_webui(websocket)
        await send_system_metrics_to_webui(websocket)

        async for message in websocket:
            try:
                data = json.loads(message)
                msg_type = data.get("type")

                # ====================================================
                # COMMAND
                # ====================================================

                if msg_type == "command":
                    if "device_id" in data:
                        device_id = data["device_id"]
                        cmd = data["command"]
                        payload = data.get("payload", {})
                        cmd_id = data.get("id")

                    elif (
                        "payload" in data
                        and "device_id" in data["payload"]
                    ):
                        device_id = data["payload"]["device_id"]
                        cmd = data["payload"]["command"]
                        payload = data["payload"].get(
                            "params",
                            {}
                        )
                        cmd_id = data.get("id")

                    else:
                        logger.warning(
                            f"Invalid command format: {data}"
                        )
                        continue

                    rate_limiter = get_rate_limiter(device_id)

                    if not rate_limiter.allow():
                        await websocket.send(
                            json.dumps({
                                "type": "error",
                                "message": (
                                    "Rate limit exceeded "
                                    "for this device"
                                )
                            })
                        )
                        continue

                    if cmd in DANGEROUS_COMMANDS:
                        confirm_id = str(uuid.uuid4())

                        pending_confirm_commands[confirm_id] = {
                            "webui_id": cmd_id,
                            "device_id": device_id,
                            "command": cmd,
                            "params": payload
                        }

                        from yuki_protocol import (
                            confirm_command_message
                        )

                        confirm_msg = confirm_command_message(
                            device_id,
                            cmd,
                            payload
                        )

                        confirm_msg.id = confirm_id

                        await websocket.send(
                            confirm_msg.to_json()
                        )

                        continue

                    await execute_command(
                        device_id,
                        cmd,
                        payload,
                        cmd_id=cmd_id
                    )

                # ====================================================
                # BROADCAST COMMAND
                # ====================================================

                elif msg_type == "broadcast_command":
                    cmd = data["command"]
                    payload = data.get("payload", {})

                    sent = await broadcast_command(
                        cmd,
                        payload
                    )

                    await websocket.send(
                        json.dumps({
                            "type": "broadcast_result",
                            "sent": sent
                        })
                    )

                # ====================================================
                # SYSTEM METRICS
                # ====================================================

                elif msg_type == "get_system_metrics":
                    metrics = get_system_metrics()

                    await websocket.send(
                        json.dumps({
                            "type": "system_metrics",
                            "payload": metrics
                        })
                    )

                # ====================================================
                # UPTIME
                # ====================================================

                elif msg_type == "get_uptime_stats":
                    device_id = data.get("device_id")
                    days = data.get("days", 7)

                    stats = get_device_uptime_stats(
                        device_id,
                        days
                    )

                    await websocket.send(
                        json.dumps({
                            "type": "uptime_stats",
                            "payload": stats
                        })
                    )

                # ====================================================
                # BLACKLIST
                # ====================================================

                elif msg_type == "blacklist_add":
                    device_id = data.get("device_id")

                    add_to_blacklist(device_id)

                    await websocket.send(
                        json.dumps({
                            "type": "blacklist_result",
                            "success": True
                        })
                    )

                elif msg_type == "blacklist_remove":
                    device_id = data.get("device_id")

                    remove_from_blacklist(device_id)

                    await websocket.send(
                        json.dumps({
                            "type": "blacklist_result",
                            "success": True
                        })
                    )

                elif msg_type == "get_blacklist":
                    await websocket.send(
                        json.dumps({
                            "type": "blacklist",
                            "devices": list(
                                blacklisted_devices
                            )
                        })
                    )

                # ====================================================
                # AUDIT LOG
                # ====================================================

                elif msg_type == "get_audit_log":
                    limit = data.get(
                        "limit",
                        100
                    )

                    logs = get_audit_log(limit)

                    await websocket.send(
                        json.dumps({
                            "type": "audit_log",
                            "logs": logs
                        })
                    )

                # ====================================================
                # CONFIRM RESPONSE
                # ====================================================

                elif msg_type == "confirm_response":
                    confirm_id = data.get("id")
                    approved = data.get(
                        "approved",
                        False
                    )

                    if (
                        approved
                        and confirm_id
                        in pending_confirm_commands
                    ):
                        info = (
                            pending_confirm_commands
                            .pop(confirm_id)
                        )

                        await execute_command(
                            info["device_id"],
                            info["command"],
                            info["params"],
                            cmd_id=info["webui_id"]
                        )

                    else:
                        pending_confirm_commands.pop(
                            confirm_id,
                            None
                        )

                # ====================================================
                # DEVICE AUTH RESPONSE
                # ====================================================

                elif msg_type == "device_auth_response":
                    payload = data.get(
                        "payload",
                        {}
                    )

                    device_id = payload.get(
                        "device_id"
                    )

                    approved = payload.get(
                        "approved",
                        False
                    )

                    async with lock:
                        device = (
                            pending_devices.get(device_id)
                            or known_devices.get(device_id)
                        )

                        auth_event = (
                            pending_auth_events.get(
                                device_id
                            )
                        )

                    if (
                        device
                        and device.status == "pending"
                    ):
                        if approved:
                            async with lock:
                                authorized_devices_set.add(
                                    device_id
                                )

                            save_authorized()

                            device.authorized = True
                            device.status = "online"

                            audit_log(
                                "device_authorized",
                                device_id,
                                "Approved by admin"
                            )

                        else:
                            device.status = "rejected"

                            audit_log(
                                "device_rejected",
                                device_id,
                                "Rejected by admin"
                            )

                        if auth_event:
                            auth_event.set()

                    await notify_webui()

                # ====================================================
                # TOKEN ROTATION
                # ====================================================

                elif msg_type == "rotate_token":
                    await perform_token_rotation(
                        reason="admin"
                    )

                    await websocket.send(
                        json.dumps({
                            "type": "token_rotated",
                            "success": True
                        })
                    )

                elif msg_type == "get_token_info":
                    info = {
                        "type": "token_info",
                        "payload": {
                            "created_at": token_created_at,
                            "rotation_interval_hours":
                                ROTATION_INTERVAL_HOURS,
                            "expires_in": None
                        }
                    }

                    if token_created_at:
                        expires_at = (
                            token_created_at
                            + ROTATION_INTERVAL_HOURS * 3600
                        )

                        info["payload"]["expires_in"] = max(
                            0,
                            expires_at - time.time()
                        )

                    await websocket.send(
                        json.dumps(info)
                    )

                # ====================================================
                # DEVICES
                # ====================================================

                elif msg_type == "get_devices":
                    await send_devices_to_webui(
                        websocket
                    )

                elif msg_type == "get_device_metrics":
                    device_id = data.get(
                        "device_id"
                    )

                    hours = data.get(
                        "hours",
                        1
                    )

                    metric_names = data.get(
                        "metrics"
                    )

                    metrics = get_device_metrics(
                        device_id,
                        hours,
                        metric_names
                    )

                    await websocket.send(
                        json.dumps({
                            "type": "device_metrics",
                            "device_id": device_id,
                            "metrics": metrics
                        })
                    )

                elif msg_type == "get_extended_statuses":
                    await websocket.send(
                        json.dumps({
                            "type": "extended_statuses",
                            "statuses": extended_statuses
                        })
                    )

                # ====================================================
                # REQUEST DEVICE METRICS
                # ====================================================

                elif msg_type == "request_device_metrics":
                    device_id = data.get(
                        "device_id"
                    )

                    metric_types = data.get(
                        "metric_types"
                    )

                    async with lock:
                        device = connected_devices.get(
                            device_id
                        )

                    if (
                        device
                        and device.status == "online"
                    ):
                        from yuki_protocol import (
                            metrics_request_message
                        )

                        req = metrics_request_message(
                            device_id,
                            metric_types
                        )

                        await device.send_json(
                            req.to_json()
                        )

                        await websocket.send(
                            json.dumps({
                                "type": "metrics_requested",
                                "device_id": device_id,
                                "success": True
                            })
                        )

                    else:
                        await websocket.send(
                            json.dumps({
                                "type": "metrics_requested",
                                "device_id": device_id,
                                "success": False,
                                "error": "Device offline"
                            })
                        )

                # ====================================================
                # DISCONNECT DEVICE
                # ====================================================

                elif msg_type == "disconnect_device":
                    device_id = data.get(
                        "device_id"
                    )

                    async with lock:
                        device = connected_devices.get(
                            device_id
                        )

                    if device and device.ws:
                        target_ws = device.ws

                        try:
                            disconnect_msg = {
                                "protocol": PROTOCOL_VERSION,
                                "type": "disconnect",
                                "id": str(uuid.uuid4()),
                                "timestamp": int(time.time()),
                                "payload": {
                                    "reason": "admin_request"
                                }
                            }

                            await target_ws.send(
                                json.dumps(
                                    disconnect_msg
                                )
                            )

                        except Exception as e:
                            logger.debug(
                                f"Failed to send disconnect "
                                f"message to {device_id}: {e}"
                            )

                        # ------------------------------------------------
                        # ВАЖНО:
                        # close НЕ внутри lock.
                        # ------------------------------------------------

                        try:
                            await asyncio.wait_for(
                                target_ws.close(
                                    1000,
                                    "Disconnected by admin"
                                ),
                                timeout=5
                            )
                        except Exception as e:
                            logger.debug(
                                f"WebSocket for {device_id} "
                                f"already closed: {e}"
                            )

                        async with lock:
                            if (
                                connected_devices.get(
                                    device_id
                                ) is device
                            ):
                                connected_devices.pop(
                                    device_id,
                                    None
                                )

                            if (
                                known_devices.get(
                                    device_id
                                ) is device
                            ):
                                device.mark_offline()
                                device.ws = None

                        save_device_to_db(device)

                        audit_log(
                            "device_disconnected",
                            device_id,
                            "Disconnected by admin via WebUI"
                        )

                        await notify_webui()

                        logger.info(
                            f"Device {device_id} "
                            f"disconnected by admin"
                        )

                        await websocket.send(
                            json.dumps({
                                "type": "disconnect_result",
                                "success": True,
                                "device_id": device_id
                            })
                        )

                    else:
                        await websocket.send(
                            json.dumps({
                                "type": "disconnect_result",
                                "success": False,
                                "error": (
                                    "Device not found "
                                    "or already offline"
                                )
                            })
                        )

                # ====================================================
                # REMOVE DEVICE
                # ====================================================

                elif msg_type == "remove_device":
                    device_id = (
                        data.get("device_id")
                        or (
                            data.get("payload")
                            or {}
                        ).get("device_id")
                    )

                    if not device_id:
                        logger.warning(
                            f"remove_device without "
                            f"device_id: {data}"
                        )

                        await websocket.send(
                            json.dumps({
                                "type": "remove_result",
                                "success": False,
                                "error": "Missing device_id"
                            })
                        )

                        continue

                    # ------------------------------------------------
                    # ШАГ 1.
                    # Забираем всё необходимое под lock,
                    # но НИЧЕГО не await-им.
                    # ------------------------------------------------

                    async with lock:
                        device = connected_devices.get(
                            device_id
                        )

                        target_ws = (
                            device.ws
                            if device is not None
                            else None
                        )

                        auth_event = (
                            pending_auth_events.get(
                                device_id
                            )
                        )

                        # Сразу убираем активное соединение.
                        if (
                            connected_devices.get(
                                device_id
                            ) is device
                        ):
                            connected_devices.pop(
                                device_id,
                                None
                            )

                        # Полностью удаляем объект из памяти.
                        known_devices.pop(
                            device_id,
                            None
                        )

                        # Удаляем ожидающую авторизацию.
                        pending_devices.pop(
                            device_id,
                            None
                        )

                        pending_auth_events.pop(
                            device_id,
                            None
                        )

                        # ВАЖНО:
                        # Удаляем авторизацию из ПАМЯТИ сразу,
                        # иначе reconnect может пройти без WebUI approval.
                        authorized_devices_set.discard(
                            device_id
                        )

                        blacklisted_devices.discard(
                            device_id
                        )

                    # ------------------------------------------------
                    # ШАГ 2.
                    # Разбудить handle_device(), если он ждал approval.
                    # ------------------------------------------------

                    if auth_event is not None:
                        auth_event.set()

                    # ------------------------------------------------
                    # ШАГ 3.
                    # Закрыть websocket ВНЕ lock.
                    # ------------------------------------------------

                    if target_ws is not None:
                        try:
                            await asyncio.wait_for(
                                target_ws.close(
                                    1000,
                                    "Device removed by admin"
                                ),
                                timeout=5
                            )
                        except Exception as e:
                            logger.debug(
                                f"WebSocket for removed device "
                                f"{device_id} already closed: {e}"
                            )

                    # ------------------------------------------------
                    # ШАГ 4.
                    # Удаляем данные из БД ВНЕ lock.
                    # ------------------------------------------------

                    try:
                        conn = sqlite3.connect(
                            DB_PATH
                        )

                        cursor = conn.cursor()

                        cursor.execute(
                            "DELETE FROM devices "
                            "WHERE device_id = ?",
                            (device_id,)
                        )

                        deleted_devices = (
                            cursor.rowcount
                        )

                        cursor.execute(
                            "DELETE FROM authorized "
                            "WHERE device_id = ?",
                            (device_id,)
                        )

                        cursor.execute(
                            "DELETE FROM command_history "
                            "WHERE device_id = ?",
                            (device_id,)
                        )

                        cursor.execute(
                            "DELETE FROM device_metrics "
                            "WHERE device_id = ?",
                            (device_id,)
                        )

                        conn.commit()
                        conn.close()

                        logger.info(
                            f"Removed {device_id} from DB "
                            f"(devices rows deleted: "
                            f"{deleted_devices})"
                        )

                    except Exception as e:
                        logger.error(
                            f"Failed to remove device "
                            f"from DB: {e}"
                        )

                    # ------------------------------------------------
                    # ШАГ 5.
                    # Сохраняем новый authorized state.
                    # ------------------------------------------------

                    save_authorized()

                    # ------------------------------------------------
                    # ШАГ 6.
                    # Audit и WebUI - тоже ВНЕ lock.
                    # ------------------------------------------------

                    audit_log(
                        "device_removed",
                        device_id,
                        "Device removed by admin via WebUI"
                    )

                    await notify_webui()

                    logger.info(
                        f"Device {device_id} "
                        f"removed by admin"
                    )

                    await websocket.send(
                        json.dumps({
                            "type": "remove_result",
                            "success": True,
                            "device_id": device_id
                        })
                    )

            except json.JSONDecodeError:
                logger.warning(
                    "Invalid JSON from WebUI"
                )

            except Exception as e:
                logger.exception(
                    f"WebUI message handling error: {e}"
                )

    except websockets.exceptions.ConnectionClosed:
        logger.info(
            "WebUI disconnected"
        )

    finally:
        async with lock:
            webui_clients.discard(
                websocket
            )

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
            "protocol": PROTOCOL_VERSION,
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
                "substatus": extended_statuses.get(d.id, {}).get("substatus"),
                "capabilities": d.capabilities,
                "authorized": d.authorized,
                "last_seen": d.last_seen,
                "last_metrics": getattr(d, 'last_metrics', None) or get_latest_metrics(d.id)
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
            "substatus": extended_statuses.get(d.id, {}).get("substatus"),
            "capabilities": d.capabilities,
            "authorized": d.authorized,
            "last_seen": d.last_seen,
            "last_metrics": getattr(d, 'last_metrics', None) or get_latest_metrics(d.id)
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
    global current_token, previous_token, previous_token_expires_at
    if token_from_env:
        logger.warning("Ignoring token rotation: token is admin-managed (YUKI_AUTH_TOKEN / systemd credential)")
        return current_token

    previous_token = current_token
    previous_token_expires_at = time.time() + GRACE_PERIOD_MINUTES * 60

    new_token = generate_new_token(save=True)
    logger.info(f"Token rotated ({reason}), previous token stays valid for {GRACE_PERIOD_MINUTES} more minutes")

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

async def token_rotation_scheduler():
    """Makes ROTATION_INTERVAL_HOURS actually happen instead of only rotating on manual request."""
    while True:
        await asyncio.sleep(300)
        try:
            if token_from_env or token_created_at is None:
                continue
            if time.time() - token_created_at >= ROTATION_INTERVAL_HOURS * 3600:
                logger.info("Automatic token rotation triggered")
                await perform_token_rotation(reason="automatic")
        except Exception as e:
            logger.error(f"Token rotation scheduler error: {e}")

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

    ssl_context = None
    if os.environ.get("YUKI_TLS_ENABLED", "").lower() in ("1", "true", "yes"):
        import ssl
        cert_path = os.environ.get("YUKI_TLS_CERT")
        key_path = os.environ.get("YUKI_TLS_KEY")
        if not cert_path or not key_path:
            # No silent fallback: an admin who set YUKI_TLS_ENABLED=1 believes traffic is
            # encrypted - starting in plaintext anyway would betray that without them noticing.
            raise RuntimeError(
                "YUKI_TLS_ENABLED=1 but YUKI_TLS_CERT/YUKI_TLS_KEY are not set (or point to "
                "missing files) - refusing to start in plaintext when TLS was explicitly requested"
            )
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_path, key_path)

    server = await websockets.serve(router, "0.0.0.0", 8000, ssl=ssl_context, max_size=2 * 1024 * 1024)
    logger.info(f"Yuki Core WebSocket server started on {'wss' if ssl_context else 'ws'}://0.0.0.0:8000")
    
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