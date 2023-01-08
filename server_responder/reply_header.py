import sys
from datetime import datetime
import os

import utils.utils as utils
import server_responder.dynamic_html as dynamic_html
import configuration.configreader as configreader

def create_response_header(config, report):
    try:
        sys.stdout.write(f'create_response_header: Begin Report\n{report}\n')
        now = utils.convert_datetime_to_string(datetime.utcnow())
        report["response"]["http_version"] = config["HEADERS"]["http_version"]
        if report["response"]["status_code"] != "XXX":
            report["response"]["status_text"] = config["STATUS_CODE"][report["response"]["status_code"]]
        else:
            report["response"]["status_text"] = "TODO"
        report["response"]["Server"] = config["HEADERS"]["server"]    
        
        if now:
            report["response"]["Date"] = now
        if "request" in report and report["request"]:
            if report["response"]["status_code"] in ["200", "206"]: 
                if report["request"]["method"] == "OPTIONS":
                    report["response"]["Allow"] =  ", ".join(config["HEADERS"]["http_methods"])  
                elif report["request"]["method"] == "TRACE":
                    report["response"]["Content-Type"] = config["HEADERS"]["mime_types"][9]
                    report["response"]["payload"] = report["request"]["raw_header"]
                else:
                    report = create_file_headers(config, report)
            elif "alternate" in report["response"] or "accept" in report["response"] or "accept_encoding" in report["response"] or "accept_charset" in report["response"] or "accept_language" in report["response"]:
                sys.stdout.write("create_response_header: content-negotiation case called\n")
                    
                if "accept" in report["response"]:
                    report = perform_accept_negotiation(report, config)
                elif "accept_encoding" in report["response"] or "accept_charset" in report["response"] or "accept_language" in report["response"]:
                    report = perform_content_negotiation(report, config)
                
                if "alternate" in report["response"]:                    
                    report = create_alternate_headers(report, config) 

                if report["response"]["status_code"] in ["300", "416", "406"]:
                    if report["request"]["method"] == "GET":
                        report["response"]["payload"] = dynamic_html.create_error_page(report).encode()
                    report["response"]["Transfer-Encoding"] = "chunked"
                    report["response"]["Content-Type"] = "text/html" 

            elif report["response"]["status_code"] not in ["200", "304"] and  report["request"]["method"] == "GET":
                report["response"]["payload"] = dynamic_html.create_error_page(report).encode()
                report["response"]["Transfer-Encoding"] = "chunked"
                report["response"]["Content-Type"] = "text/html"
            
            if report["request"]["Connection"]:
                report["response"]["Connection"] = report["request"]["Connection"]
        sys.stdout.write(f'create_response_header: Report\n{report}\n') 
        if "path" not in report["response"]:
            report["response"]["path"] = report["request"]["path"]
        return report
    except Exception as e:
        sys.stderr.write(f'create_response_header: error {e}\n')
    return report


def create_file_headers(config, report):
    try:
        
        file_path = report["request"]["path"]
        if file_path is None:
            sys.stdout.write(f'create_file_headers: Mime Type returned for no file: {config["HEADERS"]["mime_types"][1]}\n')
            report["response"]["Content-Type"] = config["HEADERS"]["mime_types"][1]
        elif os.path.isdir(file_path):
            sys.stdout.write(f'Mime Type returned is dir: {config["HEADERS"]["mime_types"][1]}\n')
            report["response"]["Content-Type"] = config["HEADERS"]["mime_types"][1]
            report["response"]["payload"] = dynamic_html.create_directory_listing(report, config)      
        else:
            report = get_file_info(report, config)
            with open(file_path, "rb") as fobj:
                file_length = len(fobj.read())
            with open(file_path, "rb") as fobj:
                if "range" in report["response"]:
                    sys.stdout.write(f'Read file in partial GET: {report["response"]["range"]}\n')
                    fobj.seek(int(report["response"]["range"][0]))
                    diff = int(report["response"]["range"][1]) - int(report["response"]["range"][0]) + 1
                    sys.stdout.write(f'create_file_headers: {diff}\n')
                    report["response"]["payload"] = fobj.read(diff)
                    report["response"]["Content-Range"] = f'bytes {report["response"]["range"][0]}-{report["response"]["range"][1]}/{file_length}'
                else:
                    report["response"]["payload"] = fobj.read()
            report["response"]["Content-Length"] = len(report["response"]["payload"])
            report["response"]["ETag"] = '"' + utils.convert_to_md5(report["response"]["payload"]) + '"'
            last_modified = utils.get_file_last_modified_time(file_path)
            if last_modified:
                report["response"]["Last-Modified"] = last_modified
            if report["request"]["method"] != "GET":
                del report["response"]["payload"]
            file_ext = file_path.split("/")[-1].split(".")[1]
            sys.stdout.write(f'create_file_headers: Response created in file headers: \n{report}\n')            
    except Exception as e:
        sys.stderr.write(f'create_file_headers: error {e}\n')
    return report

"""
Function to get file extention, content-lang, content-encode
"""
def get_file_info(report, config):
    file_split = report["request"]["path"].split(".")
    sys.stdout.write(f'get_file_info: {file_split}\n')

    for idx, s in enumerate(file_split):
        s = s.lower()
        if idx == 1:
            report["response"]["Content-Type"] = return_mime_type(s, config)
            continue
        elif idx > 1:
            sys.stdout.write(f'get_file_info file ext: {s}\n')
            for key, value in config["LANGUAGE_ENCODING"].items():
                sys.stdout.write(f'get_file_info lang key: {key}\n')
                if s == key:
                    sys.stdout.write(f'get_file_info lang key: {key} match\n')
                    report["response"]["Content-Language"] = value
            for key, value in config["CONTENT_ENCODING"].items(): 
                sys.stdout.write(f'get_file_info encoding key: {key}\n')
                if key == s:
                    sys.stdout.write(f'get_file_info encoding key: {key} match\n')
                    report["response"]["Content-Encoding"] = value
            for key, value in config["CHARSET_ENCODING"].items(): 
                sys.stdout.write(f'get_file_info charset key: {key}\n')
                if key == s:
                    sys.stdout.write(f'get_file_info charset key: {key} match\n')
                    report["response"]["Content-Type"] += f'; charset={value}'
    return report 


"""
Function to create alternate headers
"""
def create_alternate_headers(report, config):
    sys.stdout.write(f'create_alternate_headers called\n')
    try:
        alternate = ""
        dir_path = report["request"]["path"].rsplit("/", 1)
        for roots, dirs, files in os.walk(dir_path[0]):
            for fname in files:
                if fname.split(".")[0] == dir_path[1]:
                    alternate += "{\"" + fname + "\" {type " + return_mime_type(fname.split(".")[1], config) + "}}," 
        sys.stdout.write(f'create_alternate_headers: {alternate[:-1]}\n')
        report["response"]["Alternates"] = alternate[:-1]
    except Exception as e:
        sys.stderr.write(f'create_alternate_headers: error {e}\n')
    return report


def perform_accept_negotiation(report, config):
    try:
        sys.stdout.write(f'perform_accept_negotiation called\n')

        accept_values = report["response"]["accept"]
        dir_path = report["request"]["path"].rsplit("/", 1)
        sys.stdout.write(f'perform_accept_negotiation: Path: {dir_path}\n')
        negotiation_file = None

        
        for roots, dirs, files in os.walk(dir_path[0]):
            for fname in files:
                sys.stdout.write(f'perform_accept_negotiation: file_negotiation: {negotiation_file}\n')
                sys.stdout.write(f'perform_accept_negotiation: file:{fname}\n')
                file_ext = return_mime_type(fname.split(".")[1], config)
                sys.stdout.write(f'perform_accept_negotiation: ext:{file_ext}\n')
                is_ambiguous = False
                for key, value in report["response"]["accept"].items():
                    if fname.split(".")[0] == dir_path[1]:
                        sys.stdout.write(f'perform_accept_negotiation: File match: {fname}\n')
                        if file_ext == key  or (key[-1] == "*" and file_ext.split("/")[0] == key.split("/")[0]):
                            sys.stdout.write(f'perform_accept_negotiation: file type match\n')
                            if negotiation_file: 
                                if key[-1] == "*":
                                    file_mime_type = return_mime_type(fname.split(".")[1], config)
                                    file_mime_type = file_mime_type.split("/")[0] + "/*"
                                    negotiation_mime_type = return_mime_type(negotiation_file.split(".")[1], config).split("/")[0] + "/*"
                                    if float(accept_values[file_mime_type]) == float(accept_values[negotiation_mime_type]):
                                        is_ambiguous = True
                                        sys.stdout.write("Accept: Both the files exists\n")
                                        #return report
                                    elif float(accept_values[file_mime_type]) > float(accept_values[negotiation_mime_type]):
                                        negotiation_file = fname
                                        is_ambiguous = False

                                else:
                                    if float(accept_values[return_mime_type(fname.split(".")[1], config)]) == float(accept_values[return_mime_type(negotiation_file.split(".")[1], config)]):
                                        is_ambiguous = True
                                        sys.stdout.write("Accept: Both the files exists\n")
                                        #return report
                                    elif float(accept_values[return_mime_type(fname.split(".")[1], config)]) > float(accept_values[return_mime_type(negotiation_file.split(".")[1], config)]):
                                        negotiation_file = fname
                                        is_ambiguous = False
                            else:
                                negotiation_file = fname
                                is_ambiguous = False
        sys.stdout.write(f'perform_accept_negotiation: file_negotiation end : {negotiation_file}\n')
        
        if is_ambiguous:
            report["response"]["status_code"] = "300"
            report["response"]["status_text"] = config["STATUS_CODE"][report["response"]["status_code"]]
            report["response"]["alternate"] = True
        elif negotiation_file:        
            report ["request"]["path"] = os.path.join(dir_path[0], negotiation_file)
            report["response"]["status_code"] = "200"
            report["response"]["status_text"] = config["STATUS_CODE"][report["response"]["status_code"]]
            report = create_file_headers(config, report)
            sys.stdout.write(f'perform_accept_negotiation: Content Negotiation file found: {report ["request"]["path"]}\n')
        else: 
            report["response"]["status_code"] = "406"
            report["response"]["status_text"] = config["STATUS_CODE"][report["response"]["status_code"]]
    except Exception as e:
        sys.stderr.write(f'perform_accept_negotiation: error {e}\n')
    return report


def perform_content_negotiation(report, config):
    try:
        sys.stdout.write(f'perform_content_negotiation: called\n')
        config_charset = config["CHARSET_ENCODING"]
        config_language = config["LANGUAGE_ENCODING"]
        config_encoding = config["CONTENT_ENCODING"]

        charset_values = list(config_charset.values())
        lang_values = list(config_language.values())
        encoding_value = list(config_encoding.values())

        sys.stdout.write(f'perform_content_negotiation: charset: {config_charset}\n')
        sys.stdout.write(f'perform_content_negotiation: lang: {config_language}\n')
        sys.stdout.write(f'perform_content_negotiation: encoding: {config_encoding}\n')


        list_headers = [False, False, False]
        list_file_match = [False, False, False]
        
        if "accept_charset" in report["response"]:
            list_headers[0] = True
        if "accept_language" in report["response"]:
            list_headers[1] = True
        if "accept_encoding" in report["response"]:
            list_headers[2] = True
        
        sys.stdout.write(f'perform_content_negotiation: list_headers: {list_headers}\n')
        dir_path = report["request"]["path"].rsplit("/", 1)
        
        encoding_match = language_match = charset_match = None

        is_ambiguous = False
        for roots, dirs, files in os.walk(dir_path[0]):
            for fname in files:
                sys.stdout.write(f'perform_content_negotiation: file: {fname}\n')
                if list_headers[0]:
                    for key, value in config_charset.items():
                        sys.stdout.write(f'perform_content_negotiation: accept_charset check: negotiation file: {charset_match}\n')
                        if fname == (dir_path[1] + "." + key):
                            if charset_match and charset_values[0] == value:
                                is_ambiguous = True
                                sys.stdout.write("Accept-Charset: Both the files exists\n")
                                #return report
                            else:
                                is_ambiguous = False
                                charset_match = fname
                                list_file_match[0] = True
                if list_headers[1]:
                    for key, value in config_language.items():
                        sys.stdout.write(f'perform_content_negotiation: accept_language check: negotiation file: {language_match}\n')
                        if fname == (dir_path[1] + "." + key):
                            if language_match and lang_values[0] == value:
                                is_ambiguous = True
                                sys.stdout.write("Accept-Language: Both the files exists\n")
                                #return report
                            else:
                                is_ambiguous = False
                                language_match = fname
                                list_file_match[1] = True
                if list_headers[2]:
                    for key, value in config_encoding.items():
                        sys.stdout.write(f'perform_content_negotiation: accept_encoding check: negotiation file: {encoding_match}\n')
                        if fname == (dir_path[1] + "." + key):
                            if encoding_match and encoding_value[0] == value:
                                is_ambiguous = True
                                sys.stdout.write("Accept-Encoding: Both the files exists\n")
                                #return report
                            else:
                                is_ambiguous = False
                                encoding_match = fname
                                list_file_match[2] = True
                
                sys.stdout.write(f'perform_content_negotiation: list_file_match : {list_file_match}  list_headers: {list_headers}\n')
        if is_ambiguous:
            report["response"]["status_code"] = "300"
            report["response"]["status_text"] = config["STATUS_CODE"][report["response"]["status_code"]]
            report["response"]["alternate"] = True
        elif list_file_match == list_headers:
            report ["request"]["path"] = os.path.join(roots, fname)
            report["response"]["status_code"] = "200"
            sys.stdout.write(f'perform_content_negotiation: Content Negotiation file found: {report ["request"]["path"]}\n')
            #return report 
        else:
            report["response"]["status_code"] = "406"
    except Exception as e:
        sys.stderr.write(f'perform_content_negotiation: error {e}\n')
    return report

"""
Function to return mime type
"""
def return_mime_type(file_ext, config):
    if file_ext == "txt":
        return config["HEADERS"]["mime_types"][0]
    elif file_ext == "html":
        return config["HEADERS"]["mime_types"][1] 
    elif file_ext == "xml": 
        return config["HEADERS"]["mime_types"][2] 
    elif file_ext == "png":
        return config["HEADERS"]["mime_types"][3] 
    elif file_ext in ["jpg", "jpeg"]:
        return config["HEADERS"]["mime_types"][4] 
    elif file_ext == "gif":
        return config["HEADERS"]["mime_types"][5] 
    elif file_ext == "pdf":
        return config["HEADERS"]["mime_types"][6] 
    elif file_ext in ["pptx", "ppt"]:
        return config["HEADERS"]["mime_types"][7] 
    elif file_ext in ["docx", "doc"]:
        return config["HEADERS"]["mime_types"][8] 
    elif file_ext in ["http"]:
        return config["HEADERS"]["mime_types"][9] 
    else:
        return config["HEADERS"]["mime_types"][10]  