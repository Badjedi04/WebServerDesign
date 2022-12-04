import re
import socket
from src.Constants import *
from src.HttpHeadersObject import HTTPHeadersObject


class ValidateHeader:
    def __init__(self, debug_logger, config_instance):
        self.__debug_logger = debug_logger
        self.__config_instance = config_instance
        self.__report = HTTPHeadersObject().report

    '''    
    Validate HTTP headers
    Output: Response Code, Request Method, Requested Resource 
    '''

    def validate_header(self, client_header):
        host_missing = True
        list_implemented_methods = ["GET", "HEAD", "OPTIONS", "TRACE"]
        self.__debug_logger.debug("validate_header:" + str(client_header))
        for index_parse in range(0, (len(client_header))):
            if index_parse == 0:
                # Check if 1st line in request header has three parts(Method Name, resource path, http info)
                if len(client_header[index_parse].split(" ")) != 3:
                    if self.__report["response"]["status_code"] is None:
                        self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                else:
                    # Split the first line of header by space
                    parsed_components = client_header[index_parse].split(" ", 1)
                    self.__report["request"]["method"] = parsed_components[0]
                    # Parse Http Info
                    http_info = parsed_components[1].split(" ", 1)[-1]
                    # Parse Resource Path
                    self.__report["request"]["path"] = parsed_components[1].split(" ", 1)[0]
                    self.__debug_logger.debug("validate_header: Requested Method: "
                                              + str(self.__report["request"]["method"]))
                    # Check if the method is implemented else return response code501
                    if self.__report["request"]["method"] not in list_implemented_methods:
                        if self.__report["response"]["status_code"] is None:
                            self.__report["response"]["status_code"] = STATUS_NOT_IMPLEMENTED
                    else:
                        self.__debug_logger.debug("validate_header: Requested File: "
                                                  + str(self.__report["request"]["path"]))
                        self.__debug_logger.debug("validate_header: HTTP Info: " + http_info)
                        # Check http info
                        if self.__report["response"]["status_code"] is None:
                            self.__check_http_validity(http_info)
            else:
                # Parse rest of the header lines
                if self.__report["response"]["status_code"] != STATUS_BAD_REQUEST:
                    parsed_components = client_header[index_parse].split(" ", 1)
                    self.__debug_logger.debug("validate_header: Key: " + parsed_components[0] + " Value: " +
                                              parsed_components[1])
                    if parsed_components[0] == "Host:":
                        self.__debug_logger.debug("Host name being parsed")
                        host_missing = False
                        if self.__report["response"]["status_code"] is None:
                            self.__validate_hostname(parsed_components[1])
                            self.__debug_logger.debug("validate_header: Response from Validate Hostname: "
                                                      + str(self.__report["response"]["status_code"]))
                    elif parsed_components[0] == "Connection:":
                        if self.__report["request"]["connection_close"] is True:
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                        self.__debug_logger.debug("validate_header: Connection parsed")
                        if parsed_components[1] == "close":
                            self.__report["request"]["connection_close"] = True
                        elif not ((parsed_components[1] == "close") | (parsed_components[1] == "keep-alive")):
                            if self.__report["response"]["status_code"] is None:
                                self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                    elif parsed_components[0] == "If-Modified-Since:":
                        if self.__report["request"]["modified"] is not None and self.__report["request"]["modified"][0]\
                                == "Modified":
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                        self.__debug_logger.debug("validate_header: If-Modified-Since parsed")
                        if self.__report["request"]["modified"] is None or \
                                self.__report["request"]["modified"][0] != "NonMatch":
                            self.__report["request"]["modified"] = ["Modified", parsed_components[1]]
                    elif parsed_components[0] == "If-Unmodified-Since:":
                        if self.__report["request"]["modified"] is not None and self.__report["request"]["modified"][0]\
                                == "Unmodified":
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                        self.__debug_logger.debug("validate_header: If-Unmodified-Since parsed")
                        if self.__report["request"]["modified"] is None or \
                                self.__report["request"]["modified"][0] != "Match":
                            self.__report["request"]["modified"] = ["Unmodified", parsed_components[1]]
                    elif parsed_components[0] == "User-Agent:":
                        if self.__report["request"]["user_agent"] is not None:
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                        self.__debug_logger.debug("validate_header: Referer parsed:" + parsed_components[1])
                        self.__report["request"]["user_agent"] = parsed_components[1]
                    elif parsed_components[0] == "If-Match:":
                        if self.__report["request"]["modified"] is not None and self.__report["request"]["modified"][0]\
                                == "Match":
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                        self.__debug_logger.debug("validate_header: If-Match parsed")
                        self.__report["request"]["modified"] = ["Match", parsed_components[1]]
                    elif parsed_components[0] == "If-None-Match:":
                        if self.__report["request"]["modified"] is not None and self.__report["request"]["modified"][0]\
                                == "NoneMatch":
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                        self.__debug_logger.debug("validate_header: If-Non-Match parsed")
                        self.__report["request"]["modified"] = ["NoneMatch", parsed_components[1]]
                    elif parsed_components[0] == "If-Range:":
                        if self.__report["request"]["if_range"] is not None:
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                        self.__debug_logger.debug("validate_header: If-Range parsed:" + parsed_components[1])
                        self.__report["request"]["if_range"] = parsed_components[1]
                    elif parsed_components[0] == "Referer:":
                        if self.__report["request"]["referrer"] is not None:
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                        self.__debug_logger.debug("validate_header: Referer parsed:" + parsed_components[1])
                        self.__report["request"]["referrer"] = parsed_components[1]
                    elif parsed_components[0] == "Authorization:":
                        if self.__report["request"]["authorization"] is not None:
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                        self.__debug_logger.debug("validate_header: Authorization parsed:" + parsed_components[1])
                        self.__report["request"]["authorization"] = parsed_components[1]
                    elif parsed_components[0] == "Range:":
                        if self.__report["request"]["range"] is not None:
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                        self.__debug_logger.debug("validate_header: Range header: " + str(parsed_components[1]))
                        list_byte_range = parsed_components[1].split("=")[-1].split("-")
                        if len(list_byte_range) == 2:
                            if list_byte_range[0] == "":
                                list_byte_range[1] = "-" + list_byte_range[1]
                            elif list_byte_range[1] == "":
                                list_byte_range[0] = list_byte_range[0] + "-"
                        self.__report["request"]["range"] = list_byte_range
                    elif parsed_components[0] == "Accept:":
                        if self.__report["request"]["accept"] is not None:
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                        self.__debug_logger.debug("validate_header: Accept:" + parsed_components[1])
                        self.__report["request"]["accept"] = parsed_components[1]
                    elif parsed_components[0] == "Accept-Language:":
                        if self.__report["request"]["accept_language"] is not None:
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                        self.__debug_logger.debug("validate_header: Accept-Language:" + parsed_components[1])
                        self.__report["request"]["accept_language"] = parsed_components[1]
                    elif parsed_components[0] == "Accept-Charset:":
                        if self.__report["request"]["accept_charset"] is not None:
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                        self.__debug_logger.debug("validate_header: Accept-Charset:" + parsed_components[1])
                        self.__report["request"]["accept_charset"] = parsed_components[1]
                    elif parsed_components[0] == "Accept-Encoding:":
                        if self.__report["request"]["accept_encoding"] is not None:
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                        self.__debug_logger.debug("validate_header: Accept-Encoding:" + parsed_components[1])
                        self.__report["request"]["accept_encoding"] = parsed_components[1]
                    elif parsed_components[0] == "Negotiate:":
                        if self.__report["request"]["negotiate"] is not None:
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
                        self.__debug_logger.debug("validate_header: Negtotiate:" + parsed_components[1])
                        self.__report["request"]["negotiate"] = parsed_components[1]
                    elif ":" in parsed_components[0]:
                        self.__debug_logger.debug("validate_header: " + parsed_components[0] + "Parsed")
                        continue
                    else:
                        self.__debug_logger.debug("validate_header: Bad Header because not a valid header line")
                        if self.__report["response"]["status_code"] is None:
                            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
        if host_missing:
            self.__debug_logger.debug("validate_header: Bad Header because host is missing")
            if self.__report["response"]["status_code"] is None:
                self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
        return self.__report

    '''
    Function to check HTTP version and validity 
    '''

    def __check_http_validity(self, http_info):
        self.__debug_logger.debug("__check_http_validity: start")
        if "HTTP/" in http_info:
            self.__report["request"]["http_version"] = http_info.split(FORWARD_SLASH)[-1]
            if re.match("^\d+?\.\d+?$", self.__report["request"]["http_version"]) is None:
                self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
            if self.__report["request"]["http_version"] != self.__config_instance.http_version:
                self.__debug_logger.debug("validate_header: HTTP Version: "
                                          + str(self.__report["request"]["http_version"]))
                self.__report["response"]["status_code"] = STATUS_HTTP_VERSION_NOT_SUPPORTED
        else:
            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST

    '''
    Function to validate hostname
    '''
    def __validate_hostname(self, hostname):
        self.__debug_logger.debug("validate_header: Host Header line being parsed")
        # Check if request header has more than one hostname
        if len(hostname.split(" ")) > 1:
            self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
            return self.__report["response"]["status_code"], self.__report["request"]["path"]
        # Check if hostname is valid
        port_number = None
        try:
            if ":" in hostname:
                self.__report["request"]["host"] = hostname.split(":")[0]
                port_number = hostname.split(":")[1]
            else:
                self.__report["request"]["host"] = hostname
            self.__debug_logger.debug("validate_header: Hostname: " + str(self.__report["request"]["host"]))
            socket.inet_aton(hostname)
            # Check if resource path contains hostname then it needs to be chopped off to create absolute
            # path
            if self.__report["request"]["host"] in self.__report["request"]["path"]:
                self.__report["request"]["path"] = self.__report["request"]["path"].\
                    replace(self.__report["request"]["host"], "")
                if port_number is not None and ":" + port_number in self.__report["request"]["path"]:
                    self.__report["request"]["path"] = self.__report["request"]["path"].replace(":" + port_number, "")
                if "http://" in self.__report["request"]["path"] or "https://" in self.__report["request"]["path"]:
                    self.__report["request"]["path"] = self.__report["request"]["path"].replace("https://", "")
                    self.__report["request"]["path"] = self.__report["request"]["path"].replace("http://", "")
                    self.__debug_logger.debug("validate_header: Hostname is relative: Requested File: "
                                              + str(self.__report["request"]["path"]))

                self.__debug_logger.debug("validate_header: requested_resource:"
                                          + str(self.__report["request"]["path"]))
            self.__debug_logger.debug("validate_header: requested_resource: " + str(self.__report["request"]["path"]))
        except Exception as err:
            self.__debug_logger.debug("validate_header: " + str(err))

            try:
                socket.gethostbyname(self.__report["request"]["host"])
                self.__debug_logger.debug("validate_header: Checking host by domain name passed")
                # Check if resource path contains hostname then it needs to be chopped off to create absolute
                # path
                if self.__report["request"]["host"] in self.__report["request"]["path"]:
                    self.__report["request"]["path"] = self.__report["request"]["path"]. \
                        replace(self.__report["request"]["host"], "")
                    if port_number is not None and ":" + port_number in self.__report["request"]["path"]:
                        self.__report["request"]["path"] = self.__report["request"]["path"].replace(":" + port_number, "")
                    if "http://" in self.__report["request"]["path"] or "https://" in self.__report["request"]["path"]:
                        self.__report["request"]["path"] = self.__report["request"]["path"].replace("https://", "")
                        self.__report["request"]["path"] = self.__report["request"]["path"].replace("http://", "")
                        self.__debug_logger.debug("validate_header: Hostname is relative: Requested File: "
                                                  + str(self.__report["request"]["path"]))

                    self.__debug_logger.debug("validate_header: requested_resource: "
                                              + str(self.__report["request"]["path"]))
                self.__debug_logger.debug("validate_header: requested_resource: "
                                          + str(self.__report["request"]["path"]))
                self.__debug_logger.debug("validate_header: Hostname to IP: " + str(self.__report["request"]["host"]))
            except Exception as err:
                self.__debug_logger.debug("validate_header: " + str(err))
                self.__report["response"]["status_code"] = STATUS_BAD_REQUEST
