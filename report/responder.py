import json
import os
import sys

import constants
import report.reply_header as reply_header

def handle_server_request(config, report):
    try:

        if report["request"]["method"] in ["GET", "HEAD"]:
            report["request"]["path"] = report["request"]["path"].replace(config["MAPPING"]["host_path"], config["MAPPING"]["root_dir"])
            sys.stdout.write(f'handle_server_request: path: {report["request"]["path"]}\n')
            if os.path.exists(report["request"]["path"]):
                sys.stdout.write(f'handle_server_request: 200 \n')
                reply_header.create_response_header("200", config, report)
            else:
                sys.stdout.write(f'handle_server_request: 404 \n')
                reply_header.create_response_header("404", config, report)
    except Exception as e:
        sys.stderr.write(f'handle_server_request: error: {e}\n')