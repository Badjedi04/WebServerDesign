"""
    Function to receive request headers
    Parameters:

    Returns:
"""
import json
import os
import constants
import report.response as response


def get_request_header(request_header):
    print(request_header)
    dict_request = {}
    for index, line in enumerate(request_header.splitlines()):
        if index > 0:
            line_splitter = line.split(":")
            dict_request[line_splitter[0]] = line_splitter[1].strip()
        else:
            line_splitter = line.split()
            dict_request["method"] = line_splitter[0]
            dict_request["path"] = line_splitter[1]
            dict_request["http_version"] = line_splitter[2]
    with open(os.path.join(constants.DATA_DIR, "request.json"), "w") as fobj:
        json.dump(dict_request, fobj)
    print(dict_request)
    return(response.create_server_response(dict_request))



    