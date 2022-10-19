import sys
import os
from datetime import datetime

def convert_timestamp_to_gmt(timestamp):
    try:
        return datetime.strptime(timestamp, "%a, %d %b %Y %H:%M:%S GMT")
    except Exception as e:
        sys.stderr.write(f'convert_timestamp_to_gmt: error: {e}')
        return None

def get_file_last_modified_time(file_path):
    try:
        statinfo = os.stat(file_path)
        last_modified = datetime.utcfromtimestamp(statinfo.st_mtime)
        return convert_timestamp_to_gmt(last_modified)
    except Exception as e:
        sys.stderr.write(f'get_file_last_modified_time: error: {e}')
        return None     