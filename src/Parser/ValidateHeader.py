import re
import socket
from src.Constants import *


class ValidateHeader:
    def __init__(self, debug_logger, config_instance):
        self.__debug_logger = debug_logger
        self.__config_instance = config_instance

    '''    
    Validate HTTP headers
    Output: Response Code, Request Method, Requested Resource 
    '''

    def validate_header(self, client_header):
        requested_resource = None
        request_method = None
        host_missing = True
        response_code = None
        modified_case = None
        connection_close = False
        self.__debug_logger.debug("validate_header:" + str(client_header))
        for index_parse in range(0, (len(client_header))):
            if index_parse == 0:
                # Check if 1st line in request header has three parts(Method Name, resource path, http info)
                if len(client_header[index_parse].split(" ")) != 3:
                    if response_code is None:
                        response_code = STATUS_BAD_REQUEST
                else:
                    # Split the first line of header by space
                    parsed_components = client_header[index_parse].split(" ", 1)
                    request_method = parsed_components[0]
                    # Parse Http Info
                    http_info = parsed_components[1].split(" ", 1)[-1]
                    # Parse Resource Path
                    requested_resource = parsed_components[1].split(" ", 1)[0]
                    self.__debug_logger.debug("validate_header: Requested Method: " + request_method)
                    # Check if the method is implemented else return response code501
                    if not ((request_method == 'GET') | (request_method == 'HEAD') | (request_method == 'OPTIONS')
                            | (request_method == "TRACE")):
                        if response_code is None:
                            response_code = 501
                    else:
                        self.__debug_logger.debug("Requested File: " + requested_resource)
                        self.__debug_logger.debug("HTTP Info: " + http_info)
                        # Check http info
                        if response_code is None:
                            response_code = self.__check_http_validity(http_info)
            else:
                # Parse rest of the header lines
                parsed_components = client_header[index_parse].split(" ", 1)
                self.__debug_logger.debug("validate_header: Key: " + parsed_components[0] + " Value: " +
                                          parsed_components[1])
                if parsed_components[0] == "Host:":
                    host_missing = False
                    if response_code is None:
                        response_code, requested_resource = self.__validate_hostname(parsed_components[1],
                                                                                     requested_resource)
                        self.__debug_logger.debug("validate_header: Response from Validate Hostname: "
                                                  + str(response_code))
                elif parsed_components[0] == "Connection:":
                    self.__debug_logger.debug("validate_header: Connection parsed")
                    if parsed_components[1] == "close":
                        connection_close = True
                    elif not ((parsed_components[1] == "close") | (parsed_components[1] == "keep-alive")):
                        if response_code is None:
                            response_code = STATUS_BAD_REQUEST
                elif parsed_components[0] == "If-Modified-Since:":
                    self.__debug_logger.debug("validate_header: If-Modified-Since parsed**************")
                    if modified_case is None or modified_case[0] != "NonMatch":
                        modified_case = ["Modified", parsed_components[1]]
                elif parsed_components[0] == "If-Unmodified-Since:":
                    self.__debug_logger.debug("validate_header: If-Unmodified-Since parsed")
                    if modified_case is None or modified_case[0] != "Match":
                        modified_case = ["Unmodified", parsed_components[1]]
                elif parsed_components[0] == "If-Match:":
                    self.__debug_logger.debug("validate_header: If-Match parsed")
                    modified_case = ["Match", parsed_components[1]]
                elif parsed_components[0] == "If-None-Match:":
                    self.__debug_logger.debug("validate_header: If-Non-Match parsed")
                    modified_case = ["NoneMatch", parsed_components[1]]
                elif ":" in parsed_components[0]:
                    self.__debug_logger.debug(parsed_components[0] + "Parsed")
                    continue
                else:
                    self.__debug_logger.debug("validate_header: Bad Header because not a valid header line")
                    if response_code is None:
                        response_code = STATUS_BAD_REQUEST
        if host_missing:
            self.__debug_logger.debug("validate_header: Bad Header because not a valid header line")
            if response_code is None:
                response_code = STATUS_BAD_REQUEST
        return response_code, request_method, requested_resource, connection_close, modified_case

    '''
    Function to check HTTP version and validity 
    '''

    def __check_http_validity(self, http_info):
        self.__debug_logger.debug("check_http_validity")
        if "HTTP/" in http_info:
            http_version = http_info.split(FORWARD_SLASH)[-1]
            if re.match("^\d+?\.\d+?$", http_version) is None:
                response_code = STATUS_BAD_REQUEST
                return response_code
            if http_version != self.__config_instance.http_version:
                self.__debug_logger.debug("validate_header: HTTP Version: " + http_version)
                response_code = 505
                return response_code
        else:
            response_code = STATUS_BAD_REQUEST
            return response_code
        return None

    '''
    Function to validate hostname
    '''
    def __validate_hostname(self, hostname, requested_resource):
        self.__debug_logger.debug("validate_header: Host Header line being parsed")
        ip_addr = None
        # Check if request header has more than one hostname
        if len(hostname.split(" ")) > 1:
            response_code = STATUS_BAD_REQUEST
            return response_code, requested_resource
        # Check if hostname is valid
        try:
            if ":" in hostname:
                ip_addr = hostname.split(":")[0]
            else:
                ip_addr = hostname
            self.__debug_logger.debug("validate_header: Hostname: " + ip_addr)
            socket.inet_aton(ip_addr)
            # Check if resource path contains hostname then it needs to be chopped off to create absolute
            # path
            if hostname in requested_resource:
                requested_resource = requested_resource.replace(hostname, "")
                if "http://" in requested_resource or "https://" in requested_resource:
                    requested_resource = requested_resource.replace("https://", "")
                    requested_resource = requested_resource.replace("http://", "")
                    self.__debug_logger.debug("validate_header: Hostname is relative: Requested File: "
                                              + requested_resource)

                self.__debug_logger.debug("validate_header: requested_resource: " + requested_resource)
            self.__debug_logger.debug("validate_header: requested_resource: " + requested_resource)
        except Exception as err:
            self.__debug_logger.debug("validate_header: " + str(err))
            try:
                socket.gethostbyname(ip_addr)
                # Check if resource path contains hostname then it needs to be chopped off to create absolute
                # path
                if hostname in requested_resource:
                    requested_resource = requested_resource.replace(hostname, "")
                    if "http://" in requested_resource or "https://" in requested_resource:
                        requested_resource = requested_resource.replace("https://", "")
                        requested_resource = requested_resource.replace("http://", "")
                        self.__debug_logger.debug("validate_header: Hostname is relative: Requested File: "
                                                  + requested_resource)

                    self.__debug_logger.debug("validate_header: requested_resource: " + requested_resource)
                self.__debug_logger.debug("validate_header: requested_resource: " + requested_resource)
                self.__debug_logger.debug("validate_header: Hostname to IP: " + ip_addr)
            except Exception as err:
                self.__debug_logger.debug("validate_header: " + str(err))
                response_code = STATUS_BAD_REQUEST
                return response_code, requested_resource
        return None, requested_resource
