import os
import sys

import server_report.reply_header as reply_header

def handle_server_request(config, report):
        report["response"] = {}
        if report["request"]["method"] in ["GET", "HEAD"]:
            if report["request"]["path"].startswith(config["MAPPING"]["host_path"]):
                report["request"]["path"] = report["request"]["path"]
            else:
                report["request"]["path"] = config["MAPPING"]["root_dir"] + report["request"]["path"]
            if os.path.exists(report["request"]["path"]):
                report["response"]["status_code"] = "200"
                return reply_header.create_response_header(config, report)
            else:
                report["response"]["status_code"] = "404"
                return reply_header.create_response_header(config, report)
        elif report["request"]["method"] in ["OPTIONS", "TRACE"]:   
            report["response"]["status_code"] = "200" 
            return reply_header.create_response_header(config, report)