import sys
from datetime import datetime
import os

import utils.utils as utils
import server_responder.dynamic_html as dynamic_html

def create_response_header(config, report):
    try:
        report["response"]["http_version"] = config["HEADERS"]["http_version"]
        report["response"]["status_text"] = config["STATUS_CODE"][report["response"]["status_code"]]
        report["response"]["Server"] = config["HEADERS"]["server"]
        now = utils.convert_datetime_to_string(datetime.utcnow())
        if now:
            report["response"]["Date"] = now
        if "request" in  report and report["request"]:
            if report["response"]["status_code"] == "200":
                if report["request"]["method"] == "OPTIONS":
                    report["response"]["Allow"] =  ", ".join(config["HEADERS"]["http_methods"])  
                elif report["request"]["method"] == "TRACE":
                    report["response"]["Content-Type"] = config["HEADERS"]["mime_types"][9]
                    report["response"]["payload"] = report["request"]["raw_header"]
                else:
                    mime_response = return_mime_type(config, report)
                    sys.stdout.write(f'Mime Response\n{mime_response}\n')
                    report["response"]["Content-Type"] = f'{mime_response["mime_type"]}'
                    if "file_length" in mime_response:
                        report["response"]["Content-Length"] = mime_response["file_length"]
                    if "last_modified" in mime_response:
                        report["response"]["Last-Modified"] = mime_response["last_modified"]
                    if "ETag" in mime_response:
                        report["response"]["ETag"] = mime_response["ETag"]
                    if "payload" in mime_response and report["request"]["method"] == "GET":
                        report["response"]["payload"] = mime_response["payload"]
            elif report["response"]["status_code"] not in ["200", "304"] and  report["request"]["method"] == "GET":
                report["response"]["payload"] = dynamic_html.create_error_page(report)
            if report["request"]["Connection"]:
                report["response"]["Connection"] = report["request"]["Connection"]
        sys.stdout.write(f'Report\n{report}\n') 
        return report
    except Exception as e:
        sys.stderr.write(f'create_response_header: error {e}\n')

def return_mime_type(config, report):
    try:
        mime_response = {}
        file_path = report["request"]["path"]
        if file_path is None:
            sys.stdout.write(f'Mime Type returned for no file: {config["HEADERS"]["mime_types"][1]}\n')
            mime_response["mime_type"] = config["HEADERS"]["mime_types"][1]
        elif os.path.isdir(file_path):
            sys.stdout.write(f'Mime Type returned is dir: {config["HEADERS"]["mime_types"][1]}\n')
            mime_response["mime_type"] = config["HEADERS"]["mime_types"][1]
            mime_response["payload"] = dynamic_html.create_directory_listing(report, config)      
        else:
            with open(file_path, "rb") as fobj:
                mime_response["payload"] = fobj.read()
            mime_response["file_length"] = len(mime_response["payload"])
            mime_response["ETag"] = "\"" + utils.convert_to_md5(mime_response["payload"]) + "\""
            last_modified = utils.get_file_last_modified_time(file_path)
            if last_modified:
                mime_response["last_modified"] = last_modified
            file_ext = file_path.split("/")[-1].split(".")[-1]
            sys.stdout.write(f'Response before mime-type: {mime_response}\n')

            sys.stdout.write(f'File Ext: {file_ext}\n')

            if file_ext == "txt":
                mime_response["mime_type"] = config["HEADERS"]["mime_types"][0]
            elif file_ext == "html":
                mime_response["mime_type"] = config["HEADERS"]["mime_types"][1] 
            elif file_ext == "xml": 
                mime_response["mime_type"] = config["HEADERS"]["mime_types"][2] 
            elif file_ext == "png":
                mime_response["mime_type"] = config["HEADERS"]["mime_types"][3] 
            elif file_ext in ["jpg", "jpeg"]:
                mime_response["mime_type"] = config["HEADERS"]["mime_types"][4] 
            elif file_ext == "gif":
                mime_response["mime_type"] = config["HEADERS"]["mime_types"][5] 
            elif file_ext == "pdf":
                mime_response["mime_type"] = config["HEADERS"]["mime_types"][6] 
            elif file_ext in ["pptx", "ppt"]:
                mime_response["mime_type"] = config["HEADERS"]["mime_types"][7] 
            elif file_ext in ["docx", "doc"]:
                mime_response["mime_type"] = config["HEADERS"]["mime_types"][8] 
            elif file_ext in ["http"]:
                mime_response["mime_type"] = config["HEADERS"]["mime_types"][9] 
            else:
                mime_response["mime_type"] = config["HEADERS"]["mime_types"][10]   
        return mime_response             
    except Exception as e:
        sys.stderr.write(f'return_mime_type: error {e}\n')


