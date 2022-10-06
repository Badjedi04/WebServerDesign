import json
import sys
from datetime import datetime

import constants

def create_response_header(status_code, config, dict_request=None):
    try:
        dict_response = {}
        dict_response["status_code"] = status_code
        dict_response["http_version"] = config["HEADERS"]["http_version"]
        dict_response["status_text"] = config["STATUS_CODE"][status_code]
        dict_response["Server"] = config["HEADERS"]["server"]
        now = datetime.utcnow()
        dict_response["Date"] = now.strftime("%a, %d %b %Y %H:%M:%S %Z")
        if dict_request:
            if status_code == "200":
                response = return_mime_type(config, dict_request["path"])
                dict_response["Content-type"] = f'{response["mime_type"]}; charset=iso-8859-1'
                if "length" in response:
                    dict_response["Content-Length"] = response["length"]
                if "payload" in response and dict_request["method"] == "GET":
                    dict_response["payload"] = response["payload"]
            if dict_request["Connection"]:
                dict_response["Connection"] = dict_request["Connection"]
        sys.stdout.write(f'create_response_header: Response Dict\n{dict_response}\n')

        with open(constants.RESPONSE_REPORT, "w") as fobj:
            json.dump(dict_response,fobj)
    except Exception as e:
        sys.stderr.write(f'create_response_header: error {e}\n')

def return_mime_type(config, file_path=None):
    try:
        if file_path is None:
            return {"mime_type": config["HEADERS"]["mime_types"][1]}
        else:
            with open(file_path, "rb") as fobj:
                file_response = fobj.read()
                file_length = len(file_response)
            file_ext = file_path.split("/")[-1].split(".")[-1]
            if file_ext == "html":
                return {"mime_type": config["HEADERS"]["mime_types"][1], "length": file_length, "payload": file_response}
            elif file_ext == "xml":
                return {"mime_type": config["HEADERS"]["mime_types"][2], "length": file_length, "payload": file_response}
            elif file_ext == "png":
                return {"mime_type": config["HEADERS"]["mime_types"][3], "length": file_length, "payload": file_response}
            elif file_ext in ["jpg", "jpeg"]:
                return {"mime_type": config["HEADERS"]["mime_types"][4], "length": file_length, "payload": file_response}
            elif file_ext == "gif":
                return {"mime_type": config["HEADERS"]["mime_types"][5], "length": file_length, "payload": file_response}
            elif file_ext == "pdf":
                return {"mime_type": config["HEADERS"]["mime_types"][6], "length": file_length, "payload": file_response}
            elif file_ext in ["pptx", "ppt"]:
                return {"mime_type": config["HEADERS"]["mime_types"][7], "length": file_length, "payload": file_response}
            elif file_ext in ["docx", "doc"]:
                return {"mime_type": config["HEADERS"]["mime_types"][8], "length": file_length, "payload": file_response}
    except Exception as e:
        sys.stderr.write(f'return_mime_type: error {e}\n')
