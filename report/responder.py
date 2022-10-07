import json
import os
import sys

import constants
import report.reply_header as reply_header

def handle_server_request(config, report):
    try:

        if report["request"]["method"] in ["GET", "HEAD"]:
            if report["request"]["path"].startswith(config["MAPPING"]["host_path"]):
                sys.stdout.write(f'handle_server_request: path: path starts with ptomar\n')
                report["request"]["path"] = report["request"]["path"].replace(config["MAPPING"]["host_path"], config["MAPPING"]["root_dir"])
            else:
                sys.stdout.write(f'handle_server_request: path: absolute path\n')
                report["request"]["path"] = config["MAPPING"]["root_dir"] + report["request"]["path"]
            sys.stdout.write(f'handle_server_request: path: {report["request"]["path"]}\n')
            if os.path.exists(report["request"]["path"]):
                sys.stdout.write(f'handle_server_request: 200 \n')
                return reply_header.create_response_header("200", config, report)
            else:
                sys.stdout.write(f'handle_server_request: 404 \n')
                return reply_header.create_response_header("404", config, report)
        elif report["request"]["method"] == "OPTIONS":    
            return reply_header.create_response_header("200", config, report)
    except Exception as e:
        sys.stderr.write(f'handle_server_request: error: {e}\n')