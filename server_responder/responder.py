import sys

import server_responder.reply_header as reply_header
import server_responder.response_handler as response_handler

def handle_server_response(config, report):
    if "response" in report:
        report = reply_header.create_response_header(config, report)
        return server_reply(config, report)
    else:
        report = response_handler.handle_server_request(config, report)
        return server_reply(config, report)

def server_reply(config, report):
    try:
        '''
        HTTP/1.1 200 OK
        Date: Tue, 04 Oct 2022 10:40:39 GMT
        Server: calebsserver
        Content-Type: text/html
        Last-Modified: Sat, 20 Oct 2018 02:33:21 GMT
        Content-Length: 1936
        '''
        server_response = str(f'HTTP/{config["HEADERS"]["http_version"]} {report["response"]["status_code"]} {report["response"]["status_text"]}\r\n').encode('utf-8')
        for (key, value) in report["response"].items():
            if key in ["Date", "Server", "Last-Modified", "Content-Length", "Content-Encoding", "Content-Type", "WWW-Authenticate", "Content-Language", "Content-Range", "Transfer-Encoding", "Vary", "Alternates", "Connection", "Allow", "Location", "ETag"]:
                temp = key + ": "  + str(value) + "\r\n"
                server_response += temp.encode('utf-8')
            sys.stdout.write(f'Server Response being created: \n {key}: {value}\n')
        if "payload" in report["response"] and len(report["response"]["payload"]) > 0:
            server_response += b'\r\n' + report["response"]["payload"]
        else:
            server_response += b'\r\n'
        sys.stdout.write(f'Server Response: \n {server_response}\n')
        return server_response
    except Exception as e:
        sys.stderr.write(f'server_reply: error {e}\n')
