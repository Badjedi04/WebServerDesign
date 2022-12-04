import sys
import response.reply_header as reply_header
import response.responder as responder

def server_response_handler(config, report):
    if "response" in report:
        report = reply_header.create_header_response(config, report)
        return server_reply(config, report)
    else:
        report = responder.manage_server_request(config, report)
        return server_reply(config, report)

def server_reply(config, report):
    try:
        server_response = ""
        server_response += f'HTTP/{config["HEADERS"]["http_version"]} {report["response"]["status_code"]} {report["response"]["status_text"]}\r\n'
        for (key, value) in report["response"].items():
            if key in ["Date", "Server", "Last-Modified", "Content-Length", "Content-Type", "Connection", "Allow", "Location", "ETag"]:
                server_response += f'{key}: {value}\r\n'
            sys.stdout.write(f'Server Response being created: \n {server_response}\n')
        if "payload" in report["response"] and len(report["response"]["payload"]) > 0:
            server_response += f'\r\n{report["response"]["payload"]}\r\n'
        else:
            server_response += f'\r\n'
        sys.stdout.write(f'Server Response: \n {server_response}\n')
        return server_response.encode()
    except Exception as e:
        sys.stderr.write(f'server_reply: error {e}\n')
