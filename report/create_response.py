import json

import constants

def create_response(status_code, config):
    dict_response = {}
    dict_response["status_code"] = status_code
    dict_response["http_version"] = config["HEADERS"]["http_version"]
    dict_response["status_text"] = config["STATUS_CODE"][status_code]
    dict_response["Content-type"] = f'{return_mime_type(config)}; charset=iso-8859-1'
    dict_response["Server"] = config["HEADERS"]["server"]

    with open(constants.RESPONSE_REPORT, "w") as fobj:
        json.dump(dict_response,fobj)

def return_mime_type(config, file=None):
    if file is None:
        return config["HEADERS"]["mime_types"][1] 