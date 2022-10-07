import json
import sys
from datetime import datetime
import os

import constants

def create_response_header(status_code, config, dict_request=None):
    try:
        dict_response = {}
        dict_response["status_code"] = status_code
        dict_response["http_version"] = config["HEADERS"]["http_version"]
        dict_response["status_text"] = config["STATUS_CODE"][status_code]
        dict_response["Server"] = config["HEADERS"]["server"]
        now = datetime.utcnow()
        dict_response["Date"] = now.strftime("%a, %d %b %Y %H:%M:%S GMT")
        if dict_request:
            if status_code == "200":
                response = return_mime_type(config, dict_request["path"])
                dict_response["Content-Type"] = f'{response["mime_type"]}; charset=iso-8859-1'
                if "length" in response:
                    dict_response["Content-Length"] = response["length"]
                if "payload" in response and dict_request["method"] == "GET":
                    dict_response["payload"] = response["payload"].decode()
            if dict_request["Connection"]:
                dict_response["Connection"] = dict_request["Connection"]
        sys.stdout.write(f'create_response_header: Response Dict\n{dict_response}\n') 

        with open(constants.RESPONSE_REPORT, "w") as fobj:
            json.dump(dict_response,fobj)
    except Exception as e:
        sys.stderr.write(f'create_response_header: error {e}\n')

def return_mime_type(config, file_path=None):
    try:
        response = {}
        if file_path is None:
            sys.stdout.write(f'Mime Type returned for no file: {config["HEADERS"]["mime_types"][1]}\n')
            response["mime_type"] = config["HEADERS"]["mime_types"][1]
        else:
            with open(file_path, "rb") as fobj:
                response["payload"] = fobj.read()
            response["file_length"] = len(response["payload"])
            statinfo = os.stat(file_path)
            last_modified = datetime.utcfromtimestamp(statinfo.st_mtime)
            response["last_modified"] = last_modified.strftime("%a, %d %b %Y %H:%M:%S GMT")
            file_ext = file_path.split("/")[-1].split(".")[-1]
            sys.stdout.write(f'Response before mime-type: {response}\n')

            sys.stdout.write(f'File Ext: {file_ext}\n')

            if file_ext == "html":
                response["mime_type"] = config["HEADERS"]["mime_types"][1] 
            elif file_ext == "xml": 
                response["mime_type"] = config["HEADERS"]["mime_types"][2] 
            elif file_ext == "png":
                response["mime_type"] = config["HEADERS"]["mime_types"][3] 
            elif file_ext in ["jpg", "jpeg"]:
               response["mime_type"] = config["HEADERS"]["mime_types"][4] 
            elif file_ext == "gif":
                response["mime_type"] = config["HEADERS"]["mime_types"][5] 
            elif file_ext == "pdf":
                response["mime_type"] = config["HEADERS"]["mime_types"][6] 
            elif file_ext in ["pptx", "ppt"]:
                response["mime_type"] = config["HEADERS"]["mime_types"][7] 
            elif file_ext in ["docx", "doc"]:
                response["mime_type"] = config["HEADERS"]["mime_types"][8] 
            elif file_ext in ["http"]:
                response["mime_type"] = config["HEADERS"]["mime_types"][9] 
            elif file_ext in ["bin"]:
                response["mime_type"] = config["HEADERS"]["mime_types"][10]   
            return response             
    except Exception as e:
        sys.stderr.write(f'return_mime_type: error {e}\n')
