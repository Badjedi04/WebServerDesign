import os
import sys
import re
import hashlib

import server_responder.reply_header as reply_header
import utils.utils as utils
from configuration import configreader

def handle_server_request(config, report):
    try:
        report["response"] = {}
        # If method is GET or HEAD
        if report["request"]["method"] in ["GET", "HEAD"]:
            # Map the host path to the local path
            # If host path starts with https://cs531....
            report = fix_host_path(report, config)
            sys.stdout.write(f'handle_server_request: path: {report["request"]["path"]}\n')
            
            # Check if file is present or not
            report = check_file_path(report)
         
        elif report["request"]["method"] in ["OPTIONS", "TRACE"]:   
            report["response"]["status_code"] = "200" 
        return reply_header.create_response_header(config, report)
    except Exception as e:
        sys.stderr.write(f'handle_server_request: error: {e}\n')

def convert_to_hash(value):
    if ":" in value:
        textUtf8 = value.encode("utf-8")
        hash = hashlib.md5( textUtf8 )
        hexa = hash.hexdigest()
        return hexa
    else:
        return value

"""
This function is responsible for returning status code and redirect path on the basis of file path 
"""
def check_file_path(report):
    if os.path.exists(report["request"]["path"]):
        report["response"]["status_code"] = "200"
        report = check_file_redirects(report)
        report = check_if_modified_header(report)
    else:
        report["response"]["status_code"] = "404"
    return report

"""
Function to match If-Unmodified-Since and If-Modified-Since headers
"""
def check_if_modified_header(report):
    try:
        if "If-Unmodified-Since" in report["request"] and report["request"]["method"] in ["GET"]:
            sys.stdout.write(f'If-Unmodified-Since exists \n')
            if utils.get_file_last_modified_time(report["request"]["path"]) > utils.convert_timestamp_to_gmt(report["request"]["If-Unmodified-Since"]):
                report["response"]["status_code"] = "412"
                sys.stdout.write(f'If-Unmodified-Since: file modified after \n')                
        elif "If-Modified-Since" in report["request"]:
            sys.stdout.write(f'If-Modified-Since exists \n')
            if utils.get_file_last_modified_time(report["request"]["path"]) > utils.convert_timestamp_to_gmt(report["request"]["If-Modified-Since"]):
                sys.stdout.write(f'If-Modified-Since: file modified after \n')
                report["response"]["status_code"] = "304"
        return report
    except Exception as e:
        sys.stderr.write(f'check_if_modified_header: error: {e}\n')


"""
Function to match If-Match and If-None-Match headers
"""
def check_if_match_header(report, config):
    if os.path.exists(report["request"]["path"]):
        if "If-Match" in report["request"]:
            if configreader.convert_to_hash(report["request"]["If-Match"]):
                report["response"]["status_code"] = "412"
        report["response"]["status_code"] = "200"
        sys.stdout.write(f'handle_server_request: 200 \n')
        return reply_header.create_response_header(config, report)
    if os.path.exists(report["request"]["path"]):
        if "If-None-Match" in report["request"]:
            if configreader.convert_to_hash(report["request"]["If-None-Match"]):
                report["response"]["status_code"] = "304"
        report["response"]["status_code"] = "200"
        sys.stdout.write(f'handle_server_request: 200 \n')
        return reply_header.create_response_header(config, report)

"""
Function to set host path
"""
def fix_host_path(report, config):
    if report["request"]["path"].startswith(config["MAPPING"]["host_path"]):
        sys.stdout.write(f'handle_server_request: path: path starts with ptomar\n')
        report["request"]["path"] = report["request"]["path"].replace(config["MAPPING"]["host_path"], config["MAPPING"]["root_dir"])
    else:
        sys.stdout.write(f'handle_server_request: path: absolute path\n')
        report["request"]["path"] = config["MAPPING"]["root_dir"] + report["request"]["path"]
    return report


"""
Function to check redirects
"""
def check_file_redirects(report):
    redirect_config = configreader.read_redirect()
    # Check 301 redirects
    if re.match(redirect_config["PATH"]["301"].split(" ")[0], report["response"]["path"]):
            string_match = re.search(redirect_config["PATH"]["301"].split(" ")[0], report["response"]["path"])
            split_redirect = redirect_config["PATH"]["301"].split(" ")[1].split("/")
            count_dollars = 0
            redirect_path = ""
            for j in range(0, len(split_redirect)):
                if "$" in split_redirect[j] and split_redirect[j].replace("$", "").isdigit():
                    count_dollars += 1
                    redirect_path += string_match.group(count_dollars) + "/"
                else:
                    redirect_path += split_redirect[j] + "/"
            redirect_path = redirect_path[:-1]
            report["response"]["status_code"] = "301"
            report["response"]["Location"] = redirect_path
            report["response"]["path"] = redirect_path
    # Check 302 redirects
    else:
        temporary_pattern = redirect_config["PATH"]["302"].split("\n")
        for i in range(0, len(temporary_pattern)):
            if re.match(temporary_pattern[i].split(" ")[0], report["response"]["path"]):
                string_match = re.search(temporary_pattern[i].split(" ")[0], report["response"]["path"])
                split_redirect = temporary_pattern[i].split(" ")[1].split("/")
                count_dollars = 0
                redirect_path = ""
                for j in range(0, len(split_redirect)):
                    if "$" in split_redirect[j] and split_redirect[j].replace("$", "").isdigit():
                        count_dollars += 1
                        redirect_path += string_match.group(count_dollars) + "/"
                    else:
                        redirect_path += split_redirect[j] + "/"
                redirect_path = redirect_path[:-1]
                report["response"]["status_code"] = "302"
                report["response"]["Location"] = redirect_path
                report["response"]["path"] = redirect_path
    return report