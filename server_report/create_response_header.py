import sys
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
        sys.stdout.write(f'server_reply called:\n')
        server_response = ""
        server_response += f'HTTP/{config["HEADERS"]["http_version"]} {report["response"]["status_code"]} {report["response"]["status_text"]}\r\n'
        for (key, value) in report["response"].items():
            if key in ["Date", "Server", "Last-Modified", "Content-Length", "Content-Type", "Connection", "Allow"]:
                server_response += f'{key}: {value}\r\n'
            sys.stdout.write(f'Server Response being created: \n {server_response}\n')
            server_response = server_response.encode('utf-8')
        if "payload" in report["response"] and len(report["response"]["payload"]) > 0:
            server_response += f'\r\n{report["response"]["payload"]}\r\n'
        else:
            server_response += f'\r\n'
        sys.stdout.write(f'Server Response: \n {server_response}\n')
        return server_response
    except Exception as e:
        sys.stderr.write(f'server_reply: error {e}\n')