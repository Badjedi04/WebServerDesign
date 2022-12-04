import os

CONFIG_DIR = "Configuration"
CONFIG = os.path.join(CONFIG_DIR, "config.ini")
LOG_DIR = "Logs"
DATA_DIR = "data"
LOGS = os.path.join(LOG_DIR, "server.log")
SPACE = " "
REQUEST_REPORT = os.path.join(DATA_DIR, "header_request.json")
RESPONSE_REPORT = os.path.join(DATA_DIR, "response_header.json")
