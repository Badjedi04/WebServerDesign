import os
import sys
import re
import hashlib
from datetime import datetime
import operator
import base64
import time

import server_responder.reply_header as reply_header
import utils.utils as utils
import server_responder.authorization as authorization
import server_responder.dynamic_html as dynamic_html

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
            report = check_file_path(report, config)
         
        elif report["request"]["method"] in ["OPTIONS", "TRACE"]:  
            if report["request"]["method"] == "OPTIONS":
                authorization_info = authorization.check_authorization_directory(config, report["request"]["path"])
                if authorization_info:
                    report = check_authorization(config, report, authorization_info)
            report["response"]["status_code"] = "200" 
        return reply_header.create_response_header(config, report)
    except Exception as e:
        sys.stderr.write(f'handle_server_request: error: {e}\n')


'''
This function is responsible for returning status code and redirect path on the basis of file path 
'''
def check_file_path(report, config):
    authinfo = authorization.check_authorization_directory(config, report["request"]["path"])
    if authinfo:
        report = check_authorization(config, report, authinfo)
    sys.stdout.write(f'check_file_path: \n report: {report}\n')
    if "status_code" in report["response"] and report["response"]["status_code"] == "401":
        pass
    elif os.path.exists(report["request"]["path"]):
        report["response"]["status_code"] = "200"
        report = check_file_redirects(report, config)
        report = check_if_modified_header(report)
        report = check_if_match_header(report)
        report = check_range_request(report)
    else:
        report = check_accept_file_path(report,config)
        report = check_accept_header(report, config)
        report = check_accept_charset_header(report, config)
        report = check_accept_encoding_header(report, config)
        report = check_accept_language_header(report, config)
    return report


'''
Function to match If-Unmodified-Since and If-Modified-Since headers
'''
def check_if_modified_header(report):
    try:
        if "If-Unmodified-Since" in report["request"] and report["request"]["method"] in ["GET"]:
            unmodified_time = utils.convert_string_to_datetime(report["request"]["If-Unmodified-Since"])
            sys.stdout.write(f'If-Unmodified-Since exists \n')
            if not unmodified_time:
                return report
            if utils.convert_string_to_datetime(utils.get_file_last_modified_time(report["request"]["path"]) >= unmodified_time):
                report["response"]["status_code"] = "412"
                sys.stdout.write(f'If-Unmodified-Since: file modified after \n')                
        elif "If-Modified-Since" in report["request"] and  "If-None-Match" not in report["request"]:
            sys.stdout.write(f'If-Modified-Since exists \n')
            unmodified_time = utils.convert_string_to_datetime(report["request"]["If-Modified-Since"])
            if not unmodified_time:
                return report
            if  utils.convert_string_to_datetime(utils.get_file_last_modified_time(report["request"]["path"]))  <= unmodified_time:
                sys.stdout.write(f'If-Modified-Since: file modified after \n')
                report["response"]["status_code"] = "304"
        return report
    except Exception as e:
        sys.stderr.write(f'check_if_modified_header: error: {e}\n')


'''
Function to match If-Match and If-None-Match headers
'''
def check_if_match_header(report):

    if "If-Match" in report["request"]:
        with open(report["request"]["path"], "rb") as fobj:
            file_content = fobj.read()
        file_md5 = utils.convert_to_md5(file_content)
        file_md5 = '"' + file_md5 + '"'
        sys.stdout.write(f'check_if_match_header: md5 for file {file_md5}\n')
        if report["request"]["If-Match"] != "*" and file_md5 != report["request"]["If-Match"]:
            report["response"]["status_code"] = "412"
            sys.stdout.write(f'check_if_match_header: 412 \n')
    elif "If-None-Match" in report["request"]:
        with open(report["request"]["path"], "rb") as fobj:
            file_content = fobj.read()
        file_md5 = utils.convert_to_md5(file_content)
        file_md5 = '"' + file_md5 + '"'
        sys.stdout.write(f'check_if_match_header: md5 for file {file_md5}\n')
        if report["request"]["If-None-Match"] == "*" and file_md5 == report["request"]["If-None-Match"]:
            if report["request"]["http_method"] in ["GET", "HEAD"]:
                report["response"]["status_code"] = "304"
            else:
                report["response"]["status_code"] = "412"
    return report


'''
Function to set host path
'''
def fix_host_path(report, config):
    if report["request"]["path"].startswith(config["MAPPING"]["host_path"]):
        sys.stdout.write(f'handle_server_request: path: path starts with ptomar\n')
        report["request"]["path"] = report["request"]["path"].replace(config["MAPPING"]["host_path"], config["MAPPING"]["root_dir"])
    else:
        sys.stdout.write(f'handle_server_request: path: absolute path\n')
        report["request"]["path"] = config["MAPPING"]["root_dir"] + report["request"]["path"]
    
    if os.path.isdir(report["request"]["path"]) and os.path.exists(os.path.join(report["request"]["path"], "index.html")):
        report["request"]["path"] = os.path.join(report["request"]["path"], "index.html")
    elif report["request"]["path"] == (config["MAPPING"]["root_dir"] + "/"):
        report["request"]["path"] = os.path.join(report["request"]["path"], "index.html")
    return report


'''
Function to check redirects
'''
def check_file_redirects(report, config):
    try:
        # Check 301 redirects
        path = report["request"]["path"].replace(config["MAPPING"]["root_dir"], "")
        sys.stdout.write(f'check_file_redirects: Path for file redirect {path}\n')
        regex_pattern = re.compile(config["REDIRECT"]["301"].split()[0])
        sys.stdout.write(f'301 check_file_redirects: pattern {regex_pattern}\n')
        if regex_pattern.search(path):
            sys.stdout.write(f'check_file_redirects: path match: 301: {path}\n')
            redirect_match = regex_pattern.search(path)
            if redirect_match:
                sys.stdout.write(f'check_file_redirects: path match: 302: {path}\n')
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
        # Check 302 redirects
        else:
            sys.stdout.write(f'check_file_redirects: 302\n')
            for redirect_pattern in config["REDIRECT"]["302"]:
                regex_pattern = re.compile(redirect_pattern.split()[0])
                sys.stdout.write(f'302 check_file_redirects: pattern {regex_pattern}\n')
                redirect_match = regex_pattern.search(path)
                if redirect_match:
                    sys.stdout.write(f'check_file_redirects: path match: 302: {path}\n')
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
        sys.stdout.write(f'check_file_redirects: \n {report}\n')
        return report
    except Exception as e:
        sys.stderr.write(f'check_file_redirects: error: {e}\n')


'''
Function to match Range_header
'''   
def check_range_request(report, config=None):
    try:
        sys.stdout.write(f'check_range_request: \n')
        if "Range" in report["request"] and report["request"]["method"] == "GET":
            sys.stdout.write(f'check_range_request: True\n')
            ranges = report["request"]["Range"].split("=")[1].split("-")
            if len(ranges) == 2:
                report["response"]["range"] = ranges
                report["response"]["status_code"] = "206"
    except Exception as e:
        sys.stderr.write(f'check_range_request: error: {e}\n')
    return report


'''
Function to check accept multiple choices file
'''
def check_accept_file_path(report, config=None):
    try:
        sys.stdout.write(f'check_accept_file_path: start\n')
        if report["request"]["method"] in ["HEAD", "GET"]:
            dir_path = report["request"]["path"].rsplit("/", 1)
            for roots, dirs, files in os.walk(dir_path[0]):
                for fname in files:
                    if fname.split(".")[0] == dir_path[1]:
                        report["response"]["status_code"] = "300"
                        report["response"]["alternate"] = True
                        return report
        report["response"]["status_code"] = "404"
    except Exception as e:
        sys.stderr.write(f'check_accept_file_path: error: {e}\n')
    return report


'''
Function to match Accept_Charset header
'''
def check_accept_charset_header(report, config=None):
    try:

        if "Accept-Charset" in report["request"] and report["request"]["method"] in ["GET", "HEAD"]:
            dict_charset = {}
            charset_choices = report["request"]["Accept-Charset"].split(",")
            for charset_choice in charset_choices:
                charset_splitter = charset_choice.split(";")    
                dict_charset[charset_splitter[0]] = charset_splitter[1].split("=")[1]
            formatted_d = {}
            for key, value in dict_charset.items():
                formatted_d[key.strip()] = value
            sorted_d = dict( sorted(formatted_d.items(), key=operator.itemgetter(1),reverse=True))
            report["response"]["accept_charset"] = sorted_d
            if "status_code" not in report["response"]:
                report["response"]["status_code"] = "XXX"
        sys.stdout.write(f'check_accept_charset_header: done\n')
    except Exception as e:
        sys.stderr.write(f'check_accept_charset_header: error: {e}\n')
    return report


'''
Function to check Accept_Encoding header
'''
def check_accept_encoding_header(report, config=None):
    try:
        if "Accept-Encoding" in report["request"] and report["request"]["method"] in ["GET", "HEAD"]:
            dict_encoding = {}
            encoding_choices = report["request"]["Accept-Encoding"].split(",")
            for encoding_choice in encoding_choices:
                encoding_splitter = encoding_choice.split(";")    
                dict_encoding[encoding_splitter[0]] = encoding_splitter[1].split("=")[1]
            formatted_d = {}
            for key, value in dict_encoding.items():
                formatted_d[key.strip()] = value
            sorted_d = dict( sorted(formatted_d.items(), key=operator.itemgetter(1),reverse=True))
            report["response"]["accept_encoding"] = sorted_d
            if "status_code" not in report["response"]:
                report["response"]["status_code"] = "XXX"        
            sys.stdout.write(f'check_accept_encoding_header: done\n')
    except Exception as e:
        sys.stderr.write(f'check_accept_encoding_header: error: {e}\n')
    return report


'''
Function to check Accept_Language header
'''
def check_accept_language_header(report, config=None):
    try:
        if "Accept-Language" in report["request"] and report["request"]["method"] in ["GET", "HEAD"]:
            dict_language = {}
            language_choices = report["request"]["Accept-Language"].split(",")
            for language_choice in language_choices:
                language_splitter = language_choice.split(";")
                dict_language[language_splitter[0]] = language_splitter[1].split("=")[1]
            formatted_d = {}
            for key, value in dict_language.items():
                formatted_d[key.strip()] = value
            sorted_d = dict( sorted(formatted_d.items(), key=operator.itemgetter(1),reverse=True))
            report["response"]["accept_language"] = sorted_d
            if "status_code" not in report["response"]:
                report["response"]["status_code"] = "XXX"
        sys.stdout.write(f'check_accept_language_header: done\n')
    except Exception as e:
        sys.stderr.write(f'check_accept_language_header: error: {e}\n')
    return report


'''
Function to check Accept header
'''
def check_accept_header(report, config=None):
    try:
        if "Accept" in report["request"] and report["request"]["method"] in ["GET", "HEAD"]:
            dict_accept = {}
            accept_choices = report["request"]["Accept"].split(",")
            for accept_choice in accept_choices:
                accept_splitter = accept_choice.split(";")    
                dict_accept[accept_splitter[0]] = accept_splitter[1].split("=")[1]
            formatted_d = {}
            for key, value in dict_accept.items():
                formatted_d[key.strip()] = value
            sorted_d = dict(sorted(formatted_d.items(), key=operator.itemgetter(1),reverse=True))

            report["response"]["accept"] = sorted_d
            if "status_code" not in report["response"]:
                report["response"]["status_code"] = "XXX"
        sys.stdout.write(f'check_accept_header: done\n')
    except Exception as e:
        sys.stderr.write(f'check_accept_header: error: {e}\n')
    return report


'''
Function to check Authorization
'''
def check_authorization(config, report=None, authorization_info=None):
    try:
        sys.stdout.write(f'check_authorization:  {authorization_info}\n') 
        if "authorization" not in report["request"]:
            sys.stdout.write(f'authorization_check : auth does not exist is request\n')
            report["response"]["status_code"] = "401"
            report["response"]["www_authenticate"] = authorization_info["authorization_type"] + " realm=" \
                                                     + authorization_info["realm"]
            if authorization_info["authorization_type"] == "Digest":
                sys.stdout.write(f'authorization_check : auth type is digest\n')
                nonce = generate_nonce(report, config)
                opaque = generate_opaque(report, config)
                report["response"]["www_authenticate"] += ", algorithm=MD5, qop= auth, nonce=\"" + \
                                                          nonce + "\"" + ",opaque=\"" + opaque + "\""
                authorization.write_authorization_file(report, nonce, 0, authorization_info, "auth", opaque, config)
        else:
            sys.stdout.write(f'authorization_check : auth is not none\n')
            if report["request"]["authorization"].split(" ")[0] == "Basic" and \
                    report["request"]["authorization"].split(" ")[0] == authorization_info["authorization_type"]:
                sys.stdout.write(f'authorization_check : auth is basic\n')
                request_authorization = base64.b64decode(report["request"]["authorization"].split(" ")[-1]) \
                    .decode("utf-8")
                temp_split = request_authorization.split(":")
                temp_split[1] = hashlib.md5(temp_split[1].encode()).hexdigest()
                request_authorization = temp_split[0] + ":" + temp_split[1]
                for users in authorization_info["users"]:
                    if users == request_authorization:
                        return report
                report["response"]["status_code"] = "401"
                report["response"]["www_authenticate"] = authorization_info["authorization_type"] + " realm=" \
                                                         + authorization_info["realm"]
            elif report["request"]["authorization"].split(" ")[0] == "Digest" and \
                    report["request"]["authorization"].split(" ")[0] == authorization_info["authorization_type"]:
                sys.stdout.write(f'authorization_check : auth is digest\n')
                auth_response = read_authorization_file(report, config)
                if auth_response is None:
                    sys.stdout.write(f'auth_response : none {auth_response}\n')
                    report["response"]["status_code"] = "401"
                    report["response"]["www_authenticate"] = authorization_info["authorization_type"] + " realm=" \
                                                             + authorization_info["realm"]
                    if authorization_info["authorization_type"] == "Digest":

                        nonce = generate_nonce(report, config)
                        opaque = generate_opaque(report, config)
                        report["response"]["www_authenticate"] += ", algorithm=MD5, qop= auth, nonce=\"" + \
                                                                  nonce + "\"" + ",opaque=\"" + opaque + "\""
                        authorization.write_authorization_file(report, nonce, 0, authorization_info, "auth", opaque, config)

                else:
                    report["response"]["authorization_info"] = "qop= auth, rspauth=\"" + \
                                                               generate_response_message_digest(report, 
                                                                                                       auth_response) \
                                                               + "\", cnonce=\"" + auth_response["cnonce"] + "\", nc=" \
                                                               + auth_response["nc"]

            else:
                sys.stdout.write(f'authorization_check : auth is not basic or digest\n')
                report["response"]["status_code"] = "401"
                report["response"]["www_authenticate"] = authorization_info["authorization_type"] + " realm=" \
                                                         + authorization_info["realm"]
                if authorization_info["authorization_type"] == "Digest":
                    nonce = generate_nonce(report, config)
                    opaque = generate_opaque(report, config)
                    report["response"]["www_authenticate"] += ", algorithm=MD5, qop= auth, nonce=\"" + \
                                                              nonce + "\"" + ",opaque=\"" + opaque + "\""
                    authorization.write_authorization_file(report, nonce, 0, authorization_info, "auth", opaque, config)
        return report
    except Exception as e:
        sys.stderr.write(f'check_authorization : error {e}\n')


'''
Function to generate response message digest
'''
def generate_response_message_digest(report, authorization_info, config):
    sys.stdout.write("generate_request_message_digest\n")
    auth_info = authorization.check_authorization_directory(config, report["request"]["path"])
    for users in auth_info["users"]:
        if users.split(":")[0] == authorization_info["username"]:
            a1 = users.split(":")[-1]
    a2 = hashlib.md5((":" + authorization_info["uri"]).encode()).hexdigest()
    a3 = a1 + ":" + authorization_info["nonce"] + ":" + authorization_info["nc"] + ":" \
            + authorization_info["cnonce"]+ ":" + authorization_info["qop"] + ":" + a2

    return hashlib.md5(a3.encode()).hexdigest()


'''
Function to match nonce, realm, nc, url and qop from previous request
'''
def read_authorization_file(report, config):
    sys.stdout.write("read_authorization_file\n")
    auth_string = report["request"]["authorization"]
    auth_string = auth_string.split(", ")
    authorization_info = {}
    for info in auth_string:
        split = info.split("=")
        if "username" in split[0]:
            authorization_info["username"] = remove_quotes(split[1])
        elif "realm" in split[0]:
            authorization_info["realm"] = remove_quotes(split[1])
        elif "uri" in split[0]:
            authorization_info["uri"] = remove_quotes(split[1])
        elif "qop" in split[0]:
            authorization_info["qop"] = remove_quotes(split[1])
        elif "cnonce" in split[0]:
            authorization_info["cnonce"] = remove_quotes(split[1])
        elif "nonce" in split[0]:
            authorization_info["nonce"] = remove_quotes(split[1])
        elif "nc" in split[0]:
            authorization_info["nc"] = remove_quotes(split[1])
        elif "response" in split[0]:
            authorization_info["response"] = remove_quotes(split[1])
        elif "opaque" in split[0]:
            authorization_info["opaque"] = remove_quotes(split[1])
    sys.stdout.write("read_authorization_file: authorization_info: " + str(authorization_info))
    if os.path.exists(config["MAPPING"]["root_dir"] + "/DigestAuthorizationInfo.txt"):
        file_authorization = open(config["MAPPING"]["root_dir"] + "/DigestAuthorizationInfo.txt", "r")
        for line in file_authorization:
            file_info = {}
            line_split = line.split("|")
            for split_text in line_split:
                pair = split_text.split(":")
                if "user" in pair[0]:
                    file_info["username"] = remove_quotes(pair[1])
                elif "url" in pair[0]:
                    file_info["url"] = remove_quotes(pair[1])
                elif "nonce" in pair[0]:
                    file_info["nonce"] = remove_quotes(pair[1])
                elif "nc" in pair[0]:
                    file_info["nc"] = remove_quotes(pair[1])
                elif "qop" in pair[0]:
                    file_info["qop"] = remove_quotes(pair[1].rstrip())
                elif "realm" in pair[0]:
                    file_info["realm"] = pair[1]
                elif "opaque" in pair[0]:
                    file_info["opaque"] = pair[1].rstrip()
            sys.stdout.write("read_authorization_file: file_info: " + str(file_info))
            sys.stdout.write("read_authorization_file: auth nonce: " + authorization_info["nonce"])
            sys.stdout.write("read_authorization_file: file nonce: " + file_info["nonce"])
            sys.stdout.write("read_authorization_file: auth realm: " + authorization_info["realm"])
            sys.stdout.write("read_authorization_file: file realm: " +
                                        remove_quotes(file_info["realm"]))
            if authorization_info["nonce"] == file_info["nonce"] and authorization_info["realm"] == \
                    remove_quotes(file_info["realm"]):
                sys.stdout.write("read_authorization_file: Nonce and Realm matched")
                sys.stdout.write("read_authorization_file: Match Ncount: "
                                            + str(int(authorization_info["nc"], 16) == (int(file_info["nc"]) + 1)))
                if int(authorization_info["nc"], 16) == (int(file_info["nc"]) + 1):
                    sys.stdout.write("read_authorization_file: auth response: "
                                                + authorization_info["response"])
                    sys.stdout.write("read_authorization_file: generated response: "
                                                + str(generate_request_message_digest(authorization_info,
                                                                                            report)))
                    if authorization_info["response"] == \
                            generate_request_message_digest(authorization_info, report, config):
                        return authorization_info
    return None


'''
Function to generate request message digest
'''
def generate_request_message_digest(authorization_info, report, config):
    sys.stdout.write("generate_request_message_digest\n")
    auth_info = authorization.check_authorization_directory(config, report["request"]["path"])
    for users in auth_info["users"]:
        if users.split(":")[0] == authorization_info["username"]:
            a1 = users.split(":")[-1]
    a2 = hashlib.md5((report["request"]["method"] + ":" + authorization_info["uri"]).encode()).hexdigest()
    a3 = a1 + ":" + authorization_info["nonce"] + ":" + authorization_info["nc"] + ":" \
            + authorization_info["cnonce"]+ ":" + authorization_info["qop"] + ":" + a2
    return hashlib.md5(a3.encode()).hexdigest()


'''
Function to remove double and single quotes
'''
def remove_quotes(auth_string):
    sys.stdout.write("remove_quotes")
    if "\"" in auth_string:
        auth_string = auth_string.replace("\"", "")
    if "'" in auth_string:
        auth_string = auth_string.replace("'", "")
    return auth_string


'''
Function to generate noonce string
'''
def generate_nonce(report, config):
    nonce = base64.b64encode((str(time.time()) + " " + hashlib.md5((str(time.time()) +
                                                                    hashlib.md5(report["request"]["path"]
                                                                                .encode()).hexdigest() +
                                                                    config["MAPPING"]["private_key"]).encode())
                                .hexdigest()).encode())
    return nonce.decode("utf-8")


'''
Function to generate opaque string
'''
def generate_opaque(report, config):
    opaque = hashlib.md5((report["request"]["path"] + ":" + config["MAPPING"]["private_key"]).encode()) \
        .hexdigest()
    return opaque



