import datetime
import os
import logging
from logging.handlers import RotatingFileHandler

LOG_FOLDER = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_FOLDER, exist_ok=True)

# Настройка ротируемого логгера
log_file = os.path.join(LOG_FOLDER, "yuki.log")
handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s'))

logger = logging.getLogger("yuki")
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

# Также выводим в консоль
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s'))
logger.addHandler(console_handler)

def info(msg): logger.info(msg)
def warn(msg): logger.warning(msg)
def error(msg): logger.error(msg)
def debug(msg): logger.debug(msg)