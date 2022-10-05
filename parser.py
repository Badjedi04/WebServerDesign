"""
    Function to receive request headers
    Parameters:

    Returns:
"""
import sys 
import json
import os
import constants

import report.reply_header as reply_header

def get_request_header(request_header, config):
    try:
        sys.stdout.write(f'Print request_header: \n{request_header}\n')
        if header_validate(request_header, config):
            pass
    except Exception as e:
        sys.stderr.write(f'Parser: get_request_header error: {e}\n')
        reply_header.create_response_header("500", config)


def header_validate(request_header, config):
    """
    GET http://cs531-cs_ptoma001/a1-test/2/index.html HTTP/1.1
    Host: cs531-cs_ptoma001
    Connection: close

    """
    try:
        dict_request = parse_header(request_header)
        for index, line in enumerate(request_header.splitlines()):
            if index == 0:
                line_splitter = line.split()

                if len(line_splitter) != 3:
                    reply_header.create_response_header("400", config, dict_request)
                    return False
                elif line_splitter[0] not in config["HEADERS"]["http_methods"]:
                    reply_header.create_response_header("501", config)
                    return False
                elif line_splitter[2]: 
                    version_splitter = line_splitter[2].split("/")
                    if version_splitter[0] != "HTTP":
                        reply_header.create_response_header("400", config, dict_request)
                        return False                   
                    elif version_splitter[1] != config["HEADERS"]["http_version"]:
                        reply_header.create_response_header("505", config, dict_request)
                        return False 

            else:
                line_splitter = line.split(":")
                if len(line_splitter) != 2 \
                    or line_splitter[0] == "Host" and line_splitter[1].strip() != "cs531-cs_ptoma001"\
                    or line_splitter[0]  == "Connection" and line_splitter[1].strip() != "close":
                    reply_header.create_response_header("400", config, dict_request)
                    return False
        if request_header.splitlines()[-1].strip() is not None:
            reply_header.create_response_header("400", config, dict_request)
            return False
        return True   
    except Exception as e:
        sys.stderr(f'header_validate: error {e}\n')
        reply_header.create_response_header("500", config)

"""

"""    
def parse_header(request_header):
    try:
        dict_request = {}
        for index, line in enumerate(request_header.splitlines()):
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