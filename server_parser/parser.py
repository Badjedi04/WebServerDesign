import sys 
import urllib.parse as url_parse

def get_request_header(request_header, config):
    try:
        sys.stdout.write(f'Print request_header: \n{request_header}\n')
        report =  header_validate(request_header, config)
        if "status_code" in report["response"]:
            return report
        else:
            return parse_header(request_header, config)
    except Exception as e:
        sys.stderr.write(f'Parser: get_request_header error: {e}\n')


def header_validate(request_header, config):
    """
    GET http://cs531-cs_ptoma001/a1-test/2/index.html HTTP/1.1
    Host: cs531-cs_ptoma001
    Connection: close
    """
    try:
        report = {"response": {}}
        line_splitter = request_header.splitlines()
        sys.stdout.write(f'Request Header size: {len(line_splitter)}\n')
        sys.stdout.write(f'Request Header : {line_splitter}\n')
        is_host_present = False
        is_authorization_double_present = 0 
        if len(line_splitter[-1]) > 0:
            sys.stdout.write("Last line is not empty\n")
            report["response"]["status_code"] = "400"
        for index, line in enumerate(line_splitter[:-1]):
            sys.stdout.write(f'validate header: {line}\n')
            if index == 0:
                line_splitter = line.split()
                if len(line_splitter) != 3:
                    sys.stdout.write("First line is more than three\n")
                    report["response"]["status_code"] = "400"
                    break

                elif line_splitter[0] not in config["HEADERS"]["http_methods"]:
                    sys.stdout.write("HTTP method not supported\n")
                    report["response"]["status_code"] = "501"
                    break

                elif line_splitter[2]: 
                    version_splitter = line_splitter[2].split("/")
                    if version_splitter[0] != "HTTP":
                        sys.stdout.write("HTTP not used \n")
                        report["response"]["status_code"] = "400"
                        break
                    elif version_splitter[1] != config["HEADERS"]["http_version"]:
                        sys.stdout.write("HTTP version is wrong \n")
                        report["response"]["status_code"] = "505"
                        break
            else:
                line_splitter = line.split(":", 1)
                if len(line_splitter) != 2:
                    report["response"]["status_code"] = "400"
                    break
                elif line_splitter[0]  == "Connection" and line_splitter[1].strip() not in ["close", "keep-alive"]:
                    sys.stdout.write("Either not key value pair, host name or connection is wrong \n")
                    report["response"]["status_code"] = "400"
                    break
                
                elif line_splitter[0] == "Host":
                    is_host_present = True 
                
                elif line_splitter[0] == "Authorization":
                    if is_authorization_double_present == 1:
                        sys.stdout.write("Double authorization \n")
                        is_authorization_double_present += 1 
                        report["response"]["status_code"] = "400"
                        break
                    else:
                        is_authorization_double_present +=1

                else:
                    sys.stdout.write("All OK \n")
                                              
        if not is_host_present and "status_code" not in report["response"] and is_authorization_double_present >= 2:
            report["response"]["status_code"] = "400"
        return report   
    except Exception as e:
        sys.stderr.write(f'header_validate: error {e}\n')


'''
Function to create parse header
'''  
def parse_header(request_header,config=None):
    try:
        dict_request = {"request":{}}
        dict_request["request"]["raw_header"] = request_header
        line_splitter = request_header.splitlines()
        for index, line in enumerate(line_splitter):
            sys.stdout.write(f'Line  \n {line}\n')
            if line.strip():
                if index > 0:
                    line_splitter = line.split(":", 1)
                    sys.stdout.write(f'Line Splitter \n {line_splitter}\n')
                    dict_request["request"][line_splitter[0]] = line_splitter[1].strip()
                else:
                    line_splitter = line.split()
                    sys.stdout.write(f'Line Splitter \n {line_splitter}\n')
                    dict_request["request"]["method"] = line_splitter[0]
                    dict_request["request"]["path"] = url_parse.unquote(line_splitter[1], encoding='utf-8', errors='replace')
                    dict_request["request"]["http_version"] = line_splitter[2]

        if "Connection" not in dict_request["request"]:
            dict_request["request"]["Connection"] = None
        sys.stdout.write(f'Print request dictionary \n {dict_request}\n')
        return dict_request
    except Exception as e:
        sys.stderr.write(f'parse_header: error: {e}\n') 
