"""
    Function to receive request headers
    Parameters:

    Returns:
"""
import sys 
import json

import constants

import report.reply_header as reply_header

def get_request_header(request_header, config):
    try:
        sys.stdout.write(f'Print request_header: \n{request_header}\n')
        if header_validate(request_header, config):
            sys.stdout.write(f'get_request_header: header valid\n')
        else:
            sys.stdout.write(f'get_request_header: header invalid\n')
    except Exception as e:
        sys.stderr.write(f'Parser: get_request_header error: {e}\n')


def header_validate(request_header, config):
    """
    GET http://cs531-cs_ptoma001/a1-test/2/index.html HTTP/1.1
    Host: cs531-cs_ptoma001
    Connection: close

    """
    try:
        line_splitter = request_header.splitlines()
        dict_request = parse_header(line_splitter)
        sys.stdout.write(f'Request Header size: {len(line_splitter)}\n')
        sys.stdout.write(f'Request Header : {line_splitter}\n')
        if not (line_splitter[-1].strip() or line_splitter[-1] in ['\n', '\r\n']):
            sys.stdout.write("Last line is not empty\n")
            reply_header.create_response_header("400", config, dict_request)
            return False
        for index, line in enumerate(line_splitter[:-2]):
            sys.stdout.write(f'validate header: {line}\n')
            if index == 0:
                line_splitter = line.split()
                if len(line_splitter) != 3:
                    reply_header.create_response_header("400", config, dict_request)
                    sys.stdout.write("First line is more than three\n")
                    return False
                elif line_splitter[0] not in config["HEADERS"]["http_methods"]:
                    sys.stdout.write("HTTP method not supported\n")
                    reply_header.create_response_header("501", config)
                    return False
                elif line_splitter[2]: 
                    version_splitter = line_splitter[2].split("/")
                    if version_splitter[0] != "HTTP":
                        sys.stdout.write("HTTP not used \n")
                        reply_header.create_response_header("400", config, dict_request)
                        return False                   
                    elif version_splitter[1] != config["HEADERS"]["http_version"]:
                        sys.stdout.write("HTTP version is wrong \n")
                        reply_header.create_response_header("505", config, dict_request)
                        return False 
            else:
                line_splitter = line.split(":")
                if len(line_splitter) != 2 \
                    or line_splitter[0] == "Host" and line_splitter[1].strip() != "cs531-cs_ptoma001"\
                    or line_splitter[0]  == "Connection" and line_splitter[1].strip() != "close":
                    sys.stdout.write("Either not key value pair, host name or connection is wrong \n")
                    reply_header.create_response_header("400", config, dict_request)
                    return False
        return True   
    except Exception as e:
        sys.stderr.write(f'header_validate: error {e}\n')

"""

"""    
def parse_header(request_header):
    try:
        dict_request = {}
        for index, line in enumerate(request_header):
            sys.stdout.write(f'Line  \n {line}\n')
            if line.strip():
                if index > 0:
                    line_splitter = line.split(":")
                    sys.stdout.write(f'Line Splitter \n {line_splitter}\n')
                    dict_request[line_splitter[0]] = line_splitter[1].strip()
                else:
                    line_splitter = line.split()
                    sys.stdout.write(f'Line Splitter \n {line_splitter}\n')
                    dict_request["method"] = line_splitter[0]
                    dict_request["path"] = line_splitter[1]
                    dict_request["http_version"] = line_splitter[2]

        with open(constants.REQUEST_REPORT , "w") as fobj:
            json.dump(dict_request, fobj)
        if "Connection" not in dict_request:
            dict_request["Connection"] = None
        sys.stdout.write(f'Print request dictionary \n {dict_request}\n')
        return dict_request
    except Exception as e:
        sys.stderr.write(f'parse_header: error: {e}\n')