import os
import sys
import json
import constants

import report.responder as responder

def handle_server_response(config):
    if os.path.exists(constants.RESPONSE_REPORT):
        return server_reply(config)
    else:
        responder.handle_server_request(config)
        return server_reply(config)

def server_reply(config):
    try:
        with open(constants.RESPONSE_REPORT , "r") as fobj:
            response_dict = json.load(fobj)
        """
        HTTP/1.1 200 OK
        Date: Tue, 04 Oct 2022 10:40:39 GMT
        Server: calebsserver
        Content-Type: text/html
        Last-Modified: Sat, 20 Oct 2018 02:33:21 GMT
        Content-Length: 1936
        """
        server_response = ""
        server_response += f'HTTP/{config["HEADERS"]["http_version"]} {response_dict["status_code"]} {response_dict["status_text"]}\r\n'
        for (key, value) in response_dict.items():
            if key in ["Date", "Server", "Last-Modified", "Content-Length", "Content-Type", "Connection", "Allow"]:
                server_response += f'{key}: {value}\r\n'
            if key == "payload":
                server_response += '\r\n{value}\r\n'
        sys.stdout.write(f'Server Response: \r\n {server_response}\r\n')
        return str.encode(server_response)
    except Exception as e:
        sys.stderr.write('server_reply: error {e}\r\n')



