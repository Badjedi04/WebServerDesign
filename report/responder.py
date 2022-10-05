import json
import os

import constants
import report.reply as reply

def handle_server_request(config):
    with open(constants.REQUEST_REPORT , "r") as fobj:
        dict_request = json.load(fobj) 
    if dict_request["method"] in ["GET", "HEAD"]:
        dict_request["path"].replace(config["MAPPING"]["host_path"], config["MAPPING"]["root_dir"])
        if os.path.exists(dict_request["path"]):
            reply.create_response(200, config, dict_request)
        else:
            reply.create_response(404, config, dict_request)
