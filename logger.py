import datetime
import os

LOG_FOLDER = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_FOLDER, exist_ok=True)
LOG_FILE = os.path.join(LOG_FOLDER, datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".log")

def log(level, message):
    line = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [{level}] {message}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def info(msg): log("INFO", msg)
def warn(msg): log("WARN", msg)
def error(msg): log("ERROR", msg)
def debug(msg): log("DEBUG", msg)