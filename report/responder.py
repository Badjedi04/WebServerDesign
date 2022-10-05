import json
import os
import sys

import constants
import report.reply_header as reply_header

def handle_server_request(config):
    try:
        with open(constants.REQUEST_REPORT , "r") as fobj:
            dict_request = json.load(fobj) 
        if dict_request["method"] in ["GET", "HEAD"]:
            dict_request["path"] = dict_request["path"].replace(config["MAPPING"]["host_path"], config["MAPPING"]["root_dir"])
            sys.stdout.write(f'handle_server_request: path: {dict_request["path"]}\n')
            if os.path.exists(dict_request["path"]):
                sys.stdout.write(f'handle_server_request: 200 \n')
                reply_header.create_response_header("200", config, dict_request)
            else:
                sys.stdout.write(f'handle_server_request: 404 \n')
                reply_header.create_response_header("404", config, dict_request)
    except Exception as e:
        sys.stderr.write(f'handle_server_request: error: {e}\n')