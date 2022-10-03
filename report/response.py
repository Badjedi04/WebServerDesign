import os
import sys
import json
import constants


def server_reply(request):
    server_response = ""
    server_response += request["method"] + constants.SPACE + request["path"] + constants.SPACE + request["http_version"] 
    print(server_reply)
    return server_reply