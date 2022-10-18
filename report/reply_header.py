import sys
from datetime import datetime
import os

import utils
import dynamic_html

def create_response_header(config, report):
    try:
        report["response"]["http_version"] = config["HEADERS"]["http_version"]
        report["response"]["status_text"] = config["STATUS_CODE"][report["response"]["status_code"]]
        report["response"]["Server"] = config["HEADERS"]["server"]
        now = utils.convert_timestamp_to_gmt(datetime.utcnow())
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
                    response = return_mime_type(config, report)
                    report["response"]["Content-Type"] = f'{response["mime_type"]}'
                    if "file_length" in response:
                        report["response"]["Content-Length"] = response["file_length"]
                    if "last_modified" in response:
                        report["response"]["Last-Modified"] = response["last_modified"]
                    if "payload" in response and report["request"]["method"] == "GET":
                        report["response"]["payload"] = response["payload"]
            elif report["response"]["status_code"] != "200" and  report["request"]["method"] == "GET":
                report["response"]["payload"] = dynamic_html.create_error_page(report)
            if report["request"]["Connection"]:
                report["response"]["Connection"] = report["request"]["Connection"]
        sys.stdout.write(f'Report\n{report}\n') 
        return report
    except Exception as e:
        sys.stderr.write(f'create_response_header: error {e}\n')

def return_mime_type(config, report):
    try:
        response = {}
        file_path = report["request"]["path"]
        if file_path is None:
            sys.stdout.write(f'Mime Type returned for no file: {config["HEADERS"]["mime_types"][1]}\n')
            response["mime_type"] = config["HEADERS"]["mime_types"][1]
        elif os.path.isdir(file_path):
            sys.stdout.write(f'Mime Type returned is dir: {config["HEADERS"]["mime_types"][1]}\n')
            response["mime_type"] = config["HEADERS"]["mime_types"][1]
            response["payload"] = dynamic_html.create_directory_listing(report, config)      
        else:
            with open(file_path, "rb") as fobj:
                response["payload"] = fobj.read()
            response["file_length"] = len(response["payload"])
            last_modified = utils.get_file_last_modified_time(file_path)
            if last_modified:
                response["last_modified"] = last_modified
            file_ext = file_path.split("/")[-1].split(".")[-1]
            sys.stdout.write(f'Response before mime-type: {response}\n')

            sys.stdout.write(f'File Ext: {file_ext}\n')

            if file_ext == "txt":
                response["mime_type"] = config["HEADERS"]["mime_types"][0]
            elif file_ext == "html":
                response["mime_type"] = config["HEADERS"]["mime_types"][1] 
            elif file_ext == "xml": 
                response["mime_type"] = config["HEADERS"]["mime_types"][2] 
            elif file_ext == "png":
                response["mime_type"] = config["HEADERS"]["mime_types"][3] 
            elif file_ext in ["jpg", "jpeg"]:
               response["mime_type"] = config["HEADERS"]["mime_types"][4] 
            elif file_ext == "gif":
                response["mime_type"] = config["HEADERS"]["mime_types"][5] 
            elif file_ext == "pdf":
                response["mime_type"] = config["HEADERS"]["mime_types"][6] 
            elif file_ext in ["pptx", "ppt"]:
                response["mime_type"] = config["HEADERS"]["mime_types"][7] 
            elif file_ext in ["docx", "doc"]:
                response["mime_type"] = config["HEADERS"]["mime_types"][8] 
            elif file_ext in ["http"]:
                response["mime_type"] = config["HEADERS"]["mime_types"][9] 
            else:
                response["mime_type"] = config["HEADERS"]["mime_types"][10]   
            return response             
    except Exception as e:
        sys.stderr.write(f'return_mime_type: error {e}\n')


