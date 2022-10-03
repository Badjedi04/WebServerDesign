"""
    Function to receive request headers
    Parameters:

    Returns:
"""
import sys 
import json
import os
import constants


def get_request_header(request_header, config):
    try:
        sys.stdout.write(f'Print request_header: \n{request_header}\n')
        if header_validate(request_header, config):
            dict_request = {}
            for index, line in enumerate(request_header.splitlines()):
                if line.strip() is None:
                    continue
                if index > 0:
                    line_splitter = line.split(":")
                    dict_request[line_splitter[0]] = line_splitter[1].strip()
                else:
                    line_splitter = line.split()
                    dict_request["method"] = line_splitter[0]
                    dict_request["path"] = line_splitter[1]
                    dict_request["http_version"] = line_splitter[2]
            with open(constants.REQUEST_REPORT , "w") as fobj:
                json.dump(dict_request, fobj)
            sys.stdout.write(f'Print request dictionary \n {dict_request}\n')
    except Exception as e:
        sys.stderr.write(f'Parser: get_request_header error: {e}\n')

def header_validate(request_header, config):
    """
    GET http://cs531-cs_ptoma001/a1-test/2/index.html HTTP/1.1
    Host: cs531-cs_ptoma001
    Connection: close

    """
    for index, line in enumerate(request_header.splitlines()):
        if index == 0:
            line_splitter = line.split()

            if len(line_splitter) != 3 \
                or line_splitter[0] not in config["HEADERS"]["http_methods"] \
                or not line_splitter[1].startswith(config["MAPPING"]["host_path"]) \
                or line_splitter[2] is not config["HEADERS"]["http_version"]:
                print ("Gadbad")
                ##to do

        else:
            line_splitter = line.split(":")
            if len(line_splitter) != 2 \
                or line_splitter[0] == "Host" and line_splitter[1].strip() is not "cs531-cs_ptoma001"\
                or line_splitter[0]  == "Connection" and line_splitter[1].strip() is not "close":
                print ("Gadbad")
                ##to do
    if request_header.splitlines()[-1].strip() is not None:
        print ("Gadbad")
        ##to do+
    return True       