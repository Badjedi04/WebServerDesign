"""
    Function to receive request headers
    Parameters:

    Returns:
"""
import sys 
import json
import os
from venv import create
import constants

import report.reply as reply

def get_request_header(request_header, config):
    try:
        sys.stdout.write(f'Print request_header: \n{request_header}\n')
        if header_validate(request_header, config):
            pass
            
    except Exception as e:
         sys.stderr.write(f'Parser: get_request_header error: {e}\n')

def header_validate(request_header, config):
    """
    GET http://cs531-cs_ptoma001/a1-test/2/index.html HTTP/1.1
    Host: cs531-cs_ptoma001
    Connection: close

    """
    dict_request = parse_header(request_header)
    try:
        for index, line in enumerate(request_header.splitlines()):
            if index == 0:
                line_splitter = line.split()

                if len(line_splitter) != 3:
                    reply.create_response("400", config, dict_request)
                    return False
                elif line_splitter[0] not in config["HEADERS"]["http_methods"]:
                    reply.create_response("501", config)
                    return False
                elif line_splitter[2]: 
                    version_splitter = line_splitter[2].split("/")
                    if version_splitter[0] != "HTTP":
                        reply.create_response("400", config, dict_request)
                        return False                   
                    elif version_splitter[1] != config["HEADERS"]["http_version"]:
                        reply.create_response("505", config, dict_request)
                        return False 

            else:
                line_splitter = line.split(":")
                if len(line_splitter) != 2 \
                    or line_splitter[0] == "Host" and line_splitter[1].strip() != "cs531-cs_ptoma001"\
                    or line_splitter[0]  == "Connection" and line_splitter[1].strip() != "close":
                    reply.create_response("400", config, dict_request)
                    return False
        if request_header.splitlines()[-1].strip() is not None:
            reply.create_response("400", config, dict_request)
            return False
        return True   
    except Exception as e:
        sys.stderr(f'header_validate: error {e}')

"""

"""    
def parse_header(request_header):
    dict_request = {}
    for index, line in enumerate(request_header.splitlines()):
        if line.strip() is None:
            continue
        elif index > 0:
            line_splitter = line.split(":")
            dict_request[line_splitter[0]] = line_splitter[1].strip()
        else:
            line_splitter = line.split()
            dict_request["method"] = line_splitter[0]
            dict_request["path"] = line_splitter[1]
            dict_request["http_version"] = line_splitter[2]

    with open(constants.REQUEST_REPORT , "w") as fobj:
        json.dump(dict_request, fobj)
    if "Connection" not in dict_request:
        dict_request["connection"] = None
    sys.stdout.write(f'Print request dictionary \n {dict_request}\n')
    return dict_request