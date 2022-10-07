"""
    Function to receive request headers
    Parameters:

    Returns:
"""
import sys 
import urllib


import report.reply_header as reply_header

def get_request_header(request_header, config):
    try:
        sys.stdout.write(f'Print request_header: \n{request_header}\n')
        return header_validate(request_header, config)
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
        if line_splitter[-1].strip():
            sys.stdout.write("Line is empty found**************\n")
        if line_splitter[-1] in ['\n', '\r\n']:
            sys.stdout.write("Line is empty found case 2**************\n")
        if len(line_splitter[-1]) > 0:
            sys.stdout.write("Last line is not empty\n")
            return reply_header.create_response_header("400", config, dict_request)
        for index, line in enumerate(line_splitter[:-1]):
            sys.stdout.write(f'validate header: {line}\n')
            if index == 0:
                line_splitter = line.split()
                if len(line_splitter) != 3:
                    sys.stdout.write("First line is more than three\n")
                    return reply_header.create_response_header("400", config, dict_request)
                elif line_splitter[0] not in config["HEADERS"]["http_methods"]:
                    sys.stdout.write("HTTP method not supported\n")
                    return reply_header.create_response_header("501", config, dict_request)
                elif line_splitter[2]: 
                    version_splitter = line_splitter[2].split("/")
                    if version_splitter[0] != "HTTP":
                        sys.stdout.write("HTTP not used \n")
                        return reply_header.create_response_header("400", config, dict_request)
                    elif version_splitter[1] != config["HEADERS"]["http_version"]:
                        sys.stdout.write("HTTP version is wrong \n")
                        return reply_header.create_response_header("505", config, dict_request)
            else:
                line_splitter = line.split(":")
                if len(line_splitter) != 2 \
                    or line_splitter[0] == "Host" and line_splitter[1].strip() != "cs531-cs_ptoma001"\
                    or line_splitter[0]  == "Connection" and line_splitter[1].strip() != "close":
                    sys.stdout.write("Either not key value pair, host name or connection is wrong \n")
                    return reply_header.create_response_header("400", config, dict_request)
        return dict_request   
    except Exception as e:
        sys.stderr.write(f'header_validate: error {e}\n')

"""

"""    
def parse_header(request_header):
    try:
        dict_request = {"request":{}}
        for index, line in enumerate(request_header):
            sys.stdout.write(f'Line  \n {line}\n')
            if line.strip():
                if index > 0:
                    line_splitter = line.split(":")
                    sys.stdout.write(f'Line Splitter \n {line_splitter}\n')
                    dict_request["request"][line_splitter[0]] = line_splitter[1].strip()
                else:
                    line_splitter = line.split()
                    sys.stdout.write(f'Line Splitter \n {line_splitter}\n')
                    dict_request["request"]["method"] = line_splitter[0]
                    dict_request["request"]["path"] = urllib.parse.unquote(line_splitter[1], encoding='utf-8', errors='replace')
                    dict_request["request"]["http_version"] = line_splitter[2]

        if "Connection" not in dict_request:
            dict_request["request"]["Connection"] = None
        sys.stdout.write(f'Print request dictionary \n {dict_request}\n')
        return dict_request
    except Exception as e:
        sys.stderr.write(f'parse_header: error: {e}\n')