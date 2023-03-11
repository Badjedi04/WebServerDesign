import os
import sys

import server_report.reply_header as reply_header

def handle_server_request(config, report):
    try:
        report["response"] = {}
        if report["request"]["method"] in ["GET", "HEAD"]:
            if report["request"]["path"].startswith(config["MAPPING"]["host_path"]):
                sys.stdout.write(f'handle_server_request: path: path starts with ptomar\n')
                report["request"]["path"] = report["request"]["path"].replace(config["MAPPING"]["host_path"], config["MAPPING"]["root_dir"])
            else:
                sys.stdout.write(f'handle_server_request: path: absolute path\n')
                report["request"]["path"] = config["MAPPING"]["root_dir"] + report["request"]["path"]
            sys.stdout.write(f'handle_server_request: path: {report["request"]["path"]}\n')
            if os.path.exists(report["request"]["path"]):
                report["response"]["status_code"] = "200"
                with open(report["request"]["path"]) as f:
                    report["response"]["body"] = f.read()
                sys.stdout.write(f'handle_server_request: 200 \n')
                return reply_header.create_response_header(config, report)
            else:
                sys.stdout.write(f'handle_server_request: 404 \n')
                report["response"]["status_code"] = "404"
                report["response"]["body"] = "404 Not Found"
                return reply_header.create_response_header(config, report)
        elif report["request"]["method"] in ["OPTIONS", "TRACE"]:   
            report["response"]["status_code"] = "200" 
            report["response"]["body"] = ""
            return reply_header.create_response_header(config, report)
    except Exception as e:
        sys.stderr.write(f'handle_server_request: error: {e}\n')
        report["response"]["status_code"] = "500"
        report["response"]["body"] = "500 Internal Server Error"
        return reply_header.create_response_header(config, report)
