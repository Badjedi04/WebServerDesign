import os
import sys
import hashlib
import re

import response.reply_header as reply_header
import utility_functions
from Configuration import configreader


def manage_server_request(config, report):
    try:
        report["response"] = {}
        # If method is GET or HEAD
        if report["request"]["method"] in ["GET", "HEAD"]:
            # Map the host path to the local path
            # If host path starts with https://cs531....
            report = map_host_path(report, config)
            sys.stdout.write(f'manage_server_request: path: {report["request"]["path"]}\n')
            
            # Check if file is present or not
            report = verify_file_path(report, config)
         
        elif report["request"]["method"] in ["OPTIONS", "TRACE"]:   
            report["response"]["status_code"] = "200" 
        return reply_header.create_header_response(config, report)
    except Exception as e:
        sys.stderr.write(f'manage_server_request: error: {e}\n')

def verify_file_path(report, config):
    if os.path.exists(report["request"]["path"]):
        report["response"]["status_code"] = "200"
        report = verify_file_redirects(report, config)
        report = verify_if_modified_header(report)
        report = verify_if_match_header(report)
    else:
        report["response"]["status_code"] = "404"
    return report


def verify_if_modified_header(report):
    try:
        if "If-Unmodified-Since" in report["request"] and report["request"]["method"] in ["GET"]:
            unmodified_time = utility_functions.change_string_to_datetime(report["request"]["If-Unmodified-Since"])
            sys.stdout.write(f'If-Unmodified-Since exists \n')
            if not unmodified_time:
                return report
            if utility_functions.change_string_to_datetime(utility_functions.obtain_file_last_modified_time(report["request"]["path"])) >= unmodified_time:
                report["response"]["status_code"] = "412"
                sys.stdout.write(f'If-Unmodified-Since: file modified after \n')                
        elif "If-Modified-Since" in report["request"] and  "If-None-Match" not in report["request"]:
            sys.stdout.write(f'If-Modified-Since exists \n')
            unmodified_time = utility_functions.change_string_to_datetime(report["request"]["If-Modified-Since"])
            if not unmodified_time:
                return report
            if  utility_functions.change_string_to_datetime(utility_functions.obtain_file_last_modified_time(report["request"]["path"]))  <= unmodified_time:
                sys.stdout.write(f'If-Modified-Since: file modified after \n')
                report["response"]["status_code"] = "304"
        return report
    except Exception as e:
        sys.stderr.write(f'verify_if_modified_header: error: {e}\n')



def verify_if_match_header(report):

    if "If-Match" in report["request"]:
        with open(report["request"]["path"], "rb") as fobj:
            file_content = fobj.read()
        file_md5 = utility_functions.change_to_etag(file_content)
        file_md5 = '"' + file_md5 + '"'
        sys.stdout.write(f'verify_if_match_header: md5 for file {file_md5}\n')
        if report["request"]["If-Match"] != "*" and file_md5 != report["request"]["If-Match"]:
            report["response"]["status_code"] = "412"
            sys.stdout.write(f'verify_if_match_header: 412 \n')
    elif "If-None-Match" in report["request"]:
        with open(report["request"]["path"], "rb") as fobj:
            file_content = fobj.read()
        file_md5 = utility_functions.change_to_etag(file_content)
        file_md5 = '"' + file_md5 + '"'
        sys.stdout.write(f'verify_if_match_header: md5 for file {file_md5}\n')
        if report["request"]["If-None-Match"] == "*" and file_md5 == report["request"]["If-None-Match"]:
            if report["request"]["http_method"] in ["GET", "HEAD"]:
                report["response"]["status_code"] = "304"
            else:
                report["response"]["status_code"] = "412"
    return report

def map_host_path(report, config):
    if report["request"]["path"].startswith(config["MAPPING"]["host_path"]):
        sys.stdout.write(f'manage_server_request: path: path starts with rchau\n')
        report["request"]["path"] = report["request"]["path"].replace(config["MAPPING"]["host_path"], config["MAPPING"]["root_dir"])
    else:
        sys.stdout.write(f'manage_server_request: path: absolute path\n')
        report["request"]["path"] = config["MAPPING"]["root_dir"] + report["request"]["path"]
    
    if os.path.isdir(report["request"]["path"]) and os.path.exists(os.path.join(report["request"]["path"], "index.html")):
        report["request"]["path"] = os.path.join(report["request"]["path"], "index.html")
    elif report["request"]["path"] == (config["MAPPING"]["root_dir"] + "/"):
        report["request"]["path"] = os.path.join(report["request"]["path"], "index.html")
    return report



def verify_file_redirects(report, config):
    try:
        path = report["request"]["path"].replace(config["MAPPING"]["root_dir"], "")
        sys.stdout.write(f'verify_file_redirects: Path for file redirect {path}\n')
        regex_pattern = re.compile(config["REDIRECT"]["301"].split()[0])
        sys.stdout.write(f'301 verify_file_redirects: pattern {regex_pattern}\n')
        if regex_pattern.search(path):
            sys.stdout.write(f'verify_file_redirects: path match: 301: {path}\n')
            redirect_match = regex_pattern.search(path)
            if redirect_match:
                sys.stdout.write(f'verify_file_redirects: path match: 302: {path}\n')
                split_redirect = redirect_pattern.split()[1].split("/")
                count_dollars = 0
                redirect_path = ""
                for j in split_redirect:
                    if "$" in j and j.replace("$", "").isdigit():
                        count_dollars +=1
                        redirect_path += redirect_match.group(count_dollars) + "/"
                    else:
                        redirect_path += j + "/"
                report["response"]["status_code"] = "302"
                report["response"]["Location"] = config["MAPPING"]["host_path"] + redirect_path[:-1]
                return report
        else:
            sys.stdout.write(f'verify_file_redirects: 302\n')
            for redirect_pattern in config["REDIRECT"]["302"]:
                regex_pattern = re.compile(redirect_pattern.split()[0])
                sys.stdout.write(f'302 verify_file_redirects: pattern {regex_pattern}\n')
                redirect_match = regex_pattern.search(path)
                if redirect_match:
                    sys.stdout.write(f'verify_file_redirects: path match: 302: {path}\n')
                    split_redirect = redirect_pattern.split()[1].split("/")
                    count_dollars = 0
                    redirect_path = ""
                    for j in split_redirect:
                        if "$" in j and j.replace("$", "").isdigit():
                            count_dollars +=1
                            redirect_path += redirect_match.group(count_dollars) + "/"
                        else:
                            redirect_path += j + "/"
                    report["response"]["status_code"] = "302"
                    report["response"]["Location"] = config["MAPPING"]["host_path"] + redirect_path[:-1]
                    return report
        sys.stdout.write(f'verify_file_redirects: \n {report}\n')
        return report
    except Exception as e:
        sys.stderr.write(f'verify_file_redirects: error: {e}\n')
