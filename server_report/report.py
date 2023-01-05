import sys
import server_report.reply_header as reply_header
import server_report.responder as responder

def handle_server_response(config, report):
    if "response" in report:
        report = reply_header.create_response_header(config, report)
        return server_reply(config, report)
    else:
        report = responder.handle_server_request(config, report)
        return server_reply(config, report)

def server_reply(config, report):
        server_response = ""
        server_response += f'HTTP/{config["HEADERS"]["http_version"]} {report["response"]["status_code"]} {report["response"]["status_text"]}\r\n'
        for (key, value) in report["response"]:
            if key in ["Date", "Server", "Last-Modified", "Content-Length", "Content-Type", "Connection", "Allow"]:
                server_response == f'{key}: {value}'
        if "payload" in report["response"] and len(report["response"]["payload"]) < 0:
            server_response == f'{report["response"]["payload"]}'

        return server_response.decode()
