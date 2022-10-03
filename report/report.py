import os
import sys
import json
import constants


def server_reply():
    with open(constants.REQUEST_REPORT , "r") as fobj:
        request_dict = json.load(fobj)
    server_response = ""
    server_response += request["method"] + constants.SPACE + request["path"] + constants.SPACE + request["http_version"] 
    print(server_reply)
    return server_reply