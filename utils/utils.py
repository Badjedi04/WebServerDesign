import sys
import os
import hashlib
from datetime import datetime

def convert_string_to_datetime(timestamp):
    try:
        return datetime.strptime(timestamp, "%a, %d %b %Y %H:%M:%S GMT")
    except Exception as e:
        sys.stderr.write(f'convert_string_to_datetime: error: {e}\n')
        return None

def convert_datetime_to_string(timestamp):
    try:
        return timestamp.strftime("%a, %d %b %Y %H:%M:%S GMT")
    except Exception as e:
        sys.stderr.write(f'convert_datetime_to_string: error: {e}\n')
        return None
        
def get_file_last_modified_time(file_path):
    try:
        statinfo = os.stat(file_path)
        last_modified = datetime.utcfromtimestamp(statinfo.st_mtime)
        return convert_datetime_to_string(last_modified)
    except Exception as e:
        sys.stderr.write(f'get_file_last_modified_time: error: {e}\n')
        return None     

def convert_to_md5(value):
    hash = hashlib.md5(value)
    hexa = hash.hexdigest()
    return hexa
