import sys
import os
import server_report.reply_header as reply_header
import server_report.responder as responder


def handle_server_response(config, report):
    sys.stdout.write(f'handle_server_response called:\n')
    if "response" in report:
        sys.stdout.write(f'handle_server_response if called:\n')
        report = reply_header.create_response_header(config, report)
        return server_reply(config, report)
    else:
        sys.stdout.write(f'handle_server_response else called:\n')
        report = responder.handle_server_request(config, report)
        return server_reply(config, report)

def server_reply(config, report):
    try:
        """
        HTTP/1.1 200 OK
        Date: Tue, 04 Oct 2022 10:40:39 GMT
        Server: calebsserver
        Content-Type: text/html
        Last-Modified: Sat, 20 Oct 2018 02:33:21 GMT
        Content-Length: 1936
        """
        server_response = str(f'HTTP/{config["HEADERS"]["http_version"]} {report["response"]["status_code"]} {report["response"]["status_text"]}\r\n').encode('utf-8')
        for (key, value) in report["response"].items():
            if key in ["Date", "Server", "Last-Modified", "Content-Length", "Content-Type", "Connection", "Allow"]:
                temp = key + ": "  + str(value) + "\r\n"
                server_response += temp.encode('utf-8')
            sys.stdout.write(f'Server Response being created: \n {key}: {value}\n')
        if "payload" in report["response"] and len(report["response"]["payload"]) > 0:
            server_response += b'\r\n' + report["response"]["payload"]
        else:
            server_response += b'\r\n'
        sys.stdout.write(f'Server Response: \n {server_response}\n')

        #127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
        #172.18.0.2 - - [11/Mar/2023:23:53:12 +0000] "GET http://cs531-cs_cbrad022/a1-test/2/index.html HTTP/1.1" 200 1936
        if "Content-Length" not in report["response"]:
            report["response"]["Content-Length"] = 0
        if "request" not in report:
            report ["request"]  = {}
            report["request"]["path"] = "-"
            report["request"]["method"] = "-"
        log_line = f'127.0.0.1 - - [{report["response"]["Date"]}] "{report["request"]["method"]} {report["request"]["path"].replace(config["MAPPING"]["root_dir"], "")}" {report["response"]["status_code"]} {str(report["response"]["Content-Length"])}'
        log_file = os.path.join(config["MAPPING"]["root_dir"], config["MAPPING"]["log_file"])
        with open(log_file, "a+") as fobj:
            fobj.write(f'{log_line}\n')
        sys.stdout.write(f'{log_line}\n')
        
        return server_response
    except Exception as e:
        sys.stderr.write(f'server_reply: error {e}\n')