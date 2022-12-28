import hashlib
import time
import socket
from datetime import timezone
import glob

from src.UtilityMethods import *
from src.HTMLTemplate import create_dynamic_error_pages
from src.HTMLTemplate import create_directory_listing
from src.HTMLTemplate import create_response_300_page


class ReturnResponseHeaders:

    def __init__(self, debug_logger=None, access_logger=None, config_instance=None, mime_type=None,
                 content_encoding=None, content_language=None, charset_parser=None):
        self.__debug_logger = debug_logger
        self.__access_logger = access_logger
        self.__config_instance = config_instance
        self.__config_mime_type = mime_type
        self.__content_encoding = content_encoding
        self.__content_language = content_language
        self.__charset_parser = charset_parser

    '''
    Function to return response header based on request 
    '''

    def create_status_200_response_headers(self, report=None, conn=None, client_header=None):
        self.__debug_logger.debug("create_status_200_response_headers: Start")
        if report["response"]["content_location"] is not None:
            resource_location = report["response"]["content_location"]
        else:
            resource_location = report["request"]["path"]
        if if_status_code_200_class(report) and is_method_get_head(report):
            self.__debug_logger.debug("create_status_200_response_headers: Status 200 Class and Method Get or Head")
            if os.path.isdir(self.__config_instance.root_folder + resource_location):
                self.__debug_logger.debug("create_status_200_response_headers: Status 200 Class and Method Get or Head:"
                                          " Resource is directory")
                if os.path.isfile(self.__config_instance.root_folder + resource_location
                                  + self.__config_instance.default_page):
                    if report["response"]["content_location"] is not None:
                        report["response"]["content_location"] = resource_location + self.__config_instance.default_page
                    report["request"]["path"] = resource_location + self.__config_instance.default_page
                    self.server_get_head_resources(report=report)
                else:
                    directory_listing_file = create_directory_listing(report, self.__config_instance)
                    file_directory_listing = open(directory_listing_file, "r")
                    directory_listing_content = ""
                    while True:
                        payload = file_directory_listing.readline()
                        payload += file_directory_listing.readline()
                        directory_listing_content += str(hex(len(payload))[2:]) + "\n" + payload + "\n"
                        if not payload: break
                    report["response"]["transfer_encoding"] = "chunked"
                    if report["request"]["method"] == "GET":
                        report["response"]["payload"] = directory_listing_content.encode()
                    report["response"]["content_length"] = len(directory_listing_content)
                    file_directory_listing.close()
                    mime_type, content_encoding, content_language, character_set_encoding = \
                        check_file_extensions(directory_listing_file, self.__config_mime_type, self.__content_encoding,
                                              self.__content_language, self.__charset_parser)
                    if mime_type is not None:
                        report["response"]["content_type"] = mime_type
                    if content_encoding is not None:
                        report["response"]["content_encoding"] = content_encoding
                    if content_language is not None:
                        report["response"]["content_language"] = content_language
                    if character_set_encoding is not None:
                        report["response"]["character_set"] = character_set_encoding
                    response_header = self.__gen_headers(report=report)
                    server_response = response_header.encode()
                    if report["request"]["method"] == "GET":
                        server_response += report["response"]["payload"]
                    self.__debug_logger.debug("create_status_200_response_headers: " + str(server_response))
                    try:
                        self.__debug_logger.debug("create_status_200_response_headers: Data sent: "
                                                  + str(conn.send(server_response)))
                    except Exception as e:
                        self.__debug_logger.debug("create_status_200_response_headers: Error: " + str(e))
                    self.__write_common_log(report)
            # Check if requested resource is a file
            elif os.path.isfile(self.__config_instance.root_folder + resource_location):
                self.__debug_logger.debug("create_status_200_response_headers: Method is get or head : Is file")

                self.server_get_head_resources(report=report)
        elif report["response"]["status_code"] == STATUS_OK and \
                (report["request"]["method"] == "TRACE" or
                 report["request"]["method"] == "OPTIONS"):
            if report["request"]["method"] == "TRACE":
                report["response"]["payload"] = ""
                for parts in client_header:
                    report["response"]["payload"] += parts + HEADER_END_LINE
                report["response"]["payload"] += HEADER_END_LINE
                report["response"]["payload"] = report["response"]["payload"].encode()
                report["response"]["content_length"] = len(report["response"]["payload"])
                report["response"]["content_type"] = "message/http"
                response_header = self.__gen_headers(report=report)
            else:
                report["response"]["content_length"] = 0
                report["response"]["content_type"] = "text/html"
                response_header = self.__gen_headers(report=report)
            server_response = response_header.encode()
            if report["request"]["method"] == "TRACE":
                server_response += report["response"]["payload"]
            self.__debug_logger.debug("create_status_200_response_headers: " + str(server_response))
            try:
                self.__debug_logger.debug("create_status_200_response_headers: Data sent: "
                                          + str(conn.send(server_response)))
            except Exception as e:
                self.__debug_logger.debug("create_status_200_response_headers: Error:" + str(e))
            self.__write_common_log(report)
        elif report["response"]["status_code"] is not None and \
                report["response"]["status_code"] != STATUS_OK:
            self.__debug_logger.debug("create_status_200_response_headers: Error Status Code")
            return self.return_error_response_headers(report=report)
        if report["request"]["connection_close"] and (report["response"]["status_code"] == STATUS_OK or
                                                      report["response"]["status_code"] == STATUS_PARTIAL_CONTENT):
            self.__debug_logger.debug("create_status_200_response_headers: Closing connection with client")
            return CLOSE_CONNECTION

    '''
    Function to serve resources for get and head methods
    '''

    def server_get_head_resources(self, report=None):
        self.__debug_logger.debug("server_get_head_resources: Is File:" + report["request"]["path"])
        if report["response"]["content_location"] is not None:
            resource_location = report["response"]["content_location"]
        else:
            resource_location = report["request"]["path"]
        mime_type, content_encoding, content_language, character_set_encoding = \
            check_file_extensions(resource_location, self.__config_mime_type, self.__content_encoding,
                                  self.__content_language, self.__charset_parser)
        if mime_type is not None:
            report["response"]["content_type"] = mime_type
        if content_encoding is not None:
            report["response"]["content_encoding"] = content_encoding
        if content_language is not None:
            report["response"]["content_language"] = content_language
        if character_set_encoding is not None:
            report["response"]["character_set"] = character_set_encoding
        if report["request"]["modified"] is not None:
            report = self.__check_modified_cases(report)

        if if_status_code_200_class(report):
            file_handle = open(self.__config_instance.root_folder + resource_location, "rb")
            payload = file_handle.read()
            file_handle.close()
            if report["request"]["range"] is None or not is_method_get_head(report):
                report["response"]["payload"] = payload
            else:
                report = self.__fix_range_request(report)

                if report["request"]["if_range"] is not None:
                    last_modified_time = check_file_modified_time(report, self.__config_instance)
                    last_modified_time = datetime.strptime(last_modified_time, "%a, %d %b %Y %H:%M:%S")
                    if_range_time = datetime.strptime(report["request"]["if_range"].replace(" GMT", ""),
                                                      "%a, %d %b %Y %H:%M:%S")
                    if if_range_time < last_modified_time:
                        report["response"]["status_code"] = STATUS_OK
                        report["response"]["payload"] = payload
                    # Bad syntax
                    elif len(report["request"]["range"]) != 2 or len(payload) and int(report["request"]["range"][1]) < \
                            int(report["request"]["range"][0]):
                        report["response"]["payload"] = payload
                        report["response"]["status_code"] = STATUS_OK
                    elif int(report["request"]["range"][0]) > (len(payload) -1) and \
                        int(report["request"]["range"][1]) > (len(payload) - 1):
                        report["response"]["content_range"] = "*/" + str(len(payload))
                        report["response"]["status_code"] = STATUS_REQUESTED_RANGE_NOT_SATISFIABLE
                        return self.return_error_response_headers(report)
                    elif int(report["request"]["range"][1]) > len(payload) and int(report["request"]["range"][1]) > \
                            int(report["request"]["range"][0]):
                        report["response"]["payload"] = payload[int(report["request"]["range"][0]): len(payload)]
                        report["response"]['content_range'] = report["request"]["range"][0] + "-" + \
                                                              str((len(payload) - 1)) + FORWARD_SLASH + \
                                                              str(len(payload))
                    else:
                        report["response"]["payload"] = payload[int(report["request"]["range"][0]):
                                                                int(report["request"]["range"][1]) + 1]
                        report["response"]['content_range'] = report["request"]["range"][0] + "-" + \
                                                              report["request"]["range"][1] + \
                                                              FORWARD_SLASH + str(len(payload))
                else:
                    '''
                    report["response"]["payload"] = payload[int(report["request"]["range"][0]):
                                                            int(report["request"]["range"][1]) + 1]
                    report["response"]['content_range'] = report["request"]["range"][0] + "-" + \
                                                          report["request"]["range"][1] + \
                                                          FORWARD_SLASH + str(len(payload))
                    '''
                    if len(report["request"]["range"]) != 2 or len(payload) and int(report["request"]["range"][1]) < \
                            int(report["request"]["range"][0]):
                        report["response"]["payload"] = payload
                        report["response"]["status_code"] = STATUS_OK
                    elif int(report["request"]["range"][0]) > (len(payload) -1) and \
                        int(report["request"]["range"][1]) > (len(payload) - 1):
                        report["response"]["content_range"] = "*/" + str(len(payload))
                        report["response"]["status_code"] = STATUS_REQUESTED_RANGE_NOT_SATISFIABLE
                        return self.return_error_response_headers(report)
                    elif int(report["request"]["range"][1]) > len(payload) and int(report["request"]["range"][1]) > \
                            int(report["request"]["range"][0]):
                        report["response"]["payload"] = payload[int(report["request"]["range"][0]): len(payload)]
                        report["response"]['content_range'] = report["request"]["range"][0] + "-" + \
                                                              str((len(payload) - 1)) + FORWARD_SLASH + \
                                                              str(len(payload))
                    else:
                        report["response"]["payload"] = payload[int(report["request"]["range"][0]):
                                                                int(report["request"]["range"][1]) + 1]
                        report["response"]['content_range'] = report["request"]["range"][0] + "-" + \
                                                              report["request"]["range"][1] + \
                                                              FORWARD_SLASH + str(len(payload))
            if report["response"]["status_code"] == STATUS_OK or report["response"]["status_code"] == STATUS_PARTIAL_CONTENT:
                report["response"]["content_length"] = len(report["response"]["payload"])
                if report["response"]["content_location"] is None:
                    report["response"]["etag"] = hashlib.md5(report["response"]["payload"]).hexdigest() + ";" + \
                                                 hashlib.md5(report["request"]["path"].encode('utf-8')).hexdigest()
                else:
                    report["response"]["etag"] = hashlib.md5(report["response"]["payload"]).hexdigest() + ";" +\
                        hashlib.md5(report["response"]["content_location"].encode('utf-8')).hexdigest()

                response_header = self.__gen_headers(report=report)
                server_response = response_header.encode()
                self.__debug_logger.debug(str(server_response))
                if report["request"]["method"] == "GET":
                    server_response += report["response"]["payload"]
                try:
                    self.__debug_logger.debug("server_get_head_resources: Data sent: " +
                                              str(report["connection"].send(server_response)))
                except Exception as e:
                    self.__debug_logger.debug("server_get_head_resources: Error: " + str(e))
                self.__write_common_log(report=report)
                if report["request"]["connection_close"]:
                    self.__debug_logger.debug("server_get_head_resources: Closing connection with client")
                    return CLOSE_CONNECTION
        else:
            return self.return_error_response_headers(report=report)

    '''
    Function to fix range header 
    '''

    def __fix_range_request(self, report):
        list_range = report["request"]["range"]
        if len(list_range) == 1:
            return report
        else:
            if list_range[0] == "":
                if "-" in list_range[1]:
                    if report["response"]["content_location"] is not None:
                        resource = report["response"]["content_location"]
                    else:
                        resource = report["request"]["path"]
                    file_handle = open(self.__config_instance.root_folder + resource, "rb")
                    file_length = len(file_handle.read())
                    file_handle.close()
                    list_range[0] = str(file_length - int(list_range[1].split("-")[-1]))
                    list_range[1] = str(file_length - 1)
                    report["request"]["range"] = list_range
            elif list_range[1] == "":
                if "-" in list_range[0]:
                    if report["response"]["content_location"] is not None:
                        resource = report["response"]["content_location"]
                    else:
                        resource = report["request"]["path"]
                    file_handle = open(self.__config_instance.root_folder + resource, "rb")
                    file_length = len(file_handle.read())
                    file_handle.close()
                    list_range[0] = str(file_length - int(list_range[1].split("-")[0]))
                    list_range[1] = str(file_length - 1)
                    report["request"]["range"] = list_range
        return report

    '''
    Function to serve If-Match, If-None-Match, If-Modified-Since and If-Unmodified-Since
    '''

    def __check_modified_cases(self, report=None):
        list_modified_strings = ["Modified", "Unmodified", "Match", "NoneMatch"]
        if report["response"]["content_location"] is not None:
            resource_location = report["response"]["content_location"]
        else:
            resource_location = report["request"]["path"]
        # Check If-Modified-Since
        if report["request"]["modified"][0] == list_modified_strings[0]:
            try:
                modified_time = datetime.strptime(report["request"]["modified"][1].replace(" GMT", ""),
                                                  "%a, %d %b %Y %H:%M:%S")

                file_modified_time = os.path.getmtime(self.__config_instance.root_folder
                                                      + resource_location)
                file_modified_time = datetime.utcfromtimestamp(file_modified_time)
                if file_modified_time <= modified_time:
                    report["response"]["status_code"] = STATUS_UNMODIFIED
            except ValueError as e:
                self.__debug_logger.debug("__check_modified_cases: Error: " + str(e))
                report["response"]["status_code"] = STATUS_OK
        # Check If-Unmodified-Since
        elif report["request"]["modified"][0] == list_modified_strings[1]:
            try:
                modified_time = datetime.strptime(report["request"]["modified"][1].replace(" GMT", ""),
                                                  "%a, %d %b %Y %H:%M:%S")
                file_modified_time = os.path.getmtime(self.__config_instance.root_folder
                                                      + resource_location)
                file_modified_time = datetime.utcfromtimestamp(file_modified_time)
                if file_modified_time < modified_time:
                    report["response"]["status_code"] = STATUS_PRECONDITION_FAILED
                    return report
            except ValueError as e:
                self.__debug_logger.debug("server_get_head_resources: Error: " + str(e))
                report["response"]["status_code"] = STATUS_OK
        # Check If-Match
        elif report["request"]["modified"][0] == list_modified_strings[2]:
            list_etags = report["request"]["modified"][1].split(COMMA_SEPARATOR)
            file_handle = open(self.__config_instance.root_folder + resource_location, "rb")
            file_content = file_handle.read()
            file_handle.close()
            file_content_hash = hashlib.md5(file_content).hexdigest() + ";" + \
                                hashlib.md5(resource_location.encode('utf-8')).hexdigest()
            is_tag_match = False
            for tags in list_etags:
                tags = tags.replace("\"", "").strip()
                if tags == file_content_hash:
                    is_tag_match = True
                    break
            if not is_tag_match:
                report["response"]["status_code"] = STATUS_PRECONDITION_FAILED
            else:
                report["response"]["status_code"] = STATUS_OK
        elif report["request"]["modified"][0] == list_modified_strings[3]:
            list_etags = report["request"]["modified"][1].split(",")
            file_handle = open(self.__config_instance.root_folder + resource_location, "rb")
            file_content = file_handle.read()
            file_handle.close()
            file_content_hash = hashlib.md5(file_content).hexdigest() + ";" + \
                                hashlib.md5(resource_location.encode('utf-8')).hexdigest()
            is_tag_match = False
            for tags in list_etags:
                tags = tags.replace("\"", "").strip()
                if tags == file_content_hash:
                    is_tag_match = True
                    break
            if is_tag_match:
                report["response"]["status_code"] = STATUS_UNMODIFIED
            else:
                report["response"]["status"] = STATUS_OK
        return report

    '''
    Function to add status code text
    '''

    def __add_status_code_text(self, report):
        self.__debug_logger.debug("__add_status_code_text: Start")
        server_response_header = ""
        if report["response"]["status_code"] == STATUS_OK:
            server_response_header += str(report["response"]["status_code"]) + ' OK'
        elif report["response"]["status_code"] == STATUS_PARTIAL_CONTENT:
            server_response_header += str(report["response"]["status_code"]) + ' Partial Content'
        elif report["response"]["status_code"] == STATUS_MOVED_PERMANENTLY:
            server_response_header += str(report["response"]["status_code"]) + ' Moved Permanently'
        elif report["response"]["status_code"] == STATUS_FOUND:
            server_response_header += str(report["response"]["status_code"]) + ' Found'
        elif report["response"]["status_code"] == STATUS_UNMODIFIED:
            server_response_header += str(report["response"]["status_code"]) + ' Not Modified'
        elif report["response"]["status_code"] == STATUS_BAD_REQUEST:
            server_response_header += str(report["response"]["status_code"]) + ' Bad Request'
        elif report["response"]["status_code"] == STATUS_FORBIDDEN:
            server_response_header += str(report["response"]["status_code"]) + ' Forbidden'
        elif report["response"]["status_code"] == STATUS_NOT_FOUND:
            server_response_header += str(report["response"]["status_code"]) + ' Not Found'
        elif report["response"]["status_code"] == STATUS_REQUEST_TIMEOUT:
            server_response_header += str(report["response"]["status_code"]) + ' Request Timeout'
        elif report["response"]["status_code"] == STATUS_PRECONDITION_FAILED:
            server_response_header += str(report["response"]["status_code"]) + ' Precondition Failed'
        elif report["response"]["status_code"] == STATUS_MULTIPLE_CHOICE:
            server_response_header += str(report["response"]["status_code"]) + ' Multiple Choice'
        elif report["response"]["status_code"] == STATUS_NOT_ACCEPTABLE:
            server_response_header += str(report["response"]["status_code"]) + ' Not Acceptable'
        elif report["response"]["status_code"] == STATUS_REQUESTED_RANGE_NOT_SATISFIABLE:
            server_response_header += str(report["response"]["status_code"]) + ' Requested Range Not Satisfiable'
        elif report["response"]["status_code"] == STATUS_INTERNAL_SERVER_ERROR:
            server_response_header += str(report["response"]["status_code"]) + ' Internal Server Error'
        elif report["response"]["status_code"] == STATUS_NOT_IMPLEMENTED:
            server_response_header += str(report["response"]["status_code"]) + " Not Implemented"
        elif report["response"]["status_code"] == STATUS_HTTP_VERSION_NOT_SUPPORTED:
            server_response_header += str(report["response"]["status_code"]) + ' HTTP Version Not Supported'
        elif report["response"]["status_code"] == STATUS_AUTHORIZATION_REQUIRED:
            server_response_header += str(report["response"]["status_code"]) + ' Authorization Required'
        else:
            print(report["response"]["status_code"])
        return server_response_header

    '''
    Function to generate server response headers
    '''

    def __gen_headers(self, report=None):
        self.__debug_logger.debug("__gen_headers: Start")
        server_response_header = 'HTTP/1.1 '
        server_response_header += self.__add_status_code_text(report)
        server_response_header += HEADER_END_LINE
        report["response"]["current_date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S")
        report["response"]["current_date"] += " GMT"
        server_response_header += 'Date: ' + report["response"]["current_date"] + HEADER_END_LINE
        server_response_header += 'Server: ' + self.__config_instance.server_name + HEADER_END_LINE
        if report["response"]["content_length"] is not None and report["response"]["transfer_encoding"] is None:
            server_response_header += 'Content-Length: ' + str(report["response"]["content_length"]) + HEADER_END_LINE
        if is_method_get_head(report) and if_status_code_200_class(report) and report["request"]["path"] is not None:
            report["response"]["last_modified"] = check_file_modified_time(report, self.__config_instance)
            report["response"]["last_modified"] += " GMT"
            server_response_header += 'Last-Modified: ' + report["response"]["last_modified"] + HEADER_END_LINE
            if report["response"]["etag"] is not None:
                server_response_header += 'Etag: ' + "\"" + str(report["response"]["etag"]) + "\"" + HEADER_END_LINE
        if report["response"]["content_type"] is not None:
            if report["response"]["character_set"] is None:
                server_response_header += 'Content-Type: ' + report["response"]["content_type"] + HEADER_END_LINE
            else:
                server_response_header += 'Content-Type: ' + report["response"]["content_type"] + ";" + \
                                          ' charset=' + report["response"]["character_set"] + HEADER_END_LINE
        if report["response"]["status_code"] == STATUS_NOT_IMPLEMENTED or (report["request"]["method"] is not None and
                                                                           report["request"]["method"] == "OPTIONS" and
                                                                           report["request"]["path"] == "*"):
            report["response"]["allow"] = "GET, HEAD, OPTIONS, TRACE"
            server_response_header += 'Allow:' + " " + report["response"]["allow"] + HEADER_END_LINE
        elif report["request"]["method"] is not None and report["request"]["method"] == "OPTIONS" and \
                report["request"]["path"] != "*":
            report["response"]["allow"] = "GET, HEAD, OPTIONS, TRACE"
            server_response_header += 'Allow:' + " " + report["response"]["allow"] + HEADER_END_LINE
        if report["response"]["status_code"] == STATUS_MOVED_PERMANENTLY or \
                report["response"]["status_code"] == STATUS_FOUND:
            server_response_header += "Location: " + report["response"]["location"] + HEADER_END_LINE
        if report["response"]["accept_ranges"] is not None:
            server_response_header += "Accept-Ranges: " + report["response"]["accept_ranges"] + HEADER_END_LINE
        if report["response"]["content_location"] is not None:
            server_response_header += "Content-Location: " + report["response"]["content_location"] + HEADER_END_LINE
        if report["response"]["alternatives"] is not None:
            server_response_header += "Alternates: " + report["response"]["alternatives"] + HEADER_END_LINE
        if report["response"]["content_range"] is not None:
            server_response_header += "Content-Range: bytes " + report["response"]["content_range"] + HEADER_END_LINE
        if report["response"]["transfer_encoding"] is not None:
            server_response_header += "Transfer-Encoding: " + report["response"]["transfer_encoding"] + HEADER_END_LINE
        if report["response"]["content_encoding"] is not None:
            server_response_header += "Content-Encoding: " + report["response"]["content_encoding"] + HEADER_END_LINE
        if report["response"]["content_language"] is not None:
            server_response_header += "Content-Language: " + report["response"]["content_language"] + HEADER_END_LINE
        if report["response"]["vary"] is not None:
            server_response_header += "Vary: " + report["response"]["vary"] + HEADER_END_LINE
        if report["response"]["TCN"] is not None:
            server_response_header += "TCN: " + report["response"]["TCN"] + HEADER_END_LINE
        if report["response"]["www_authenticate"] is not None:
            server_response_header += "WWW-Authenticate: " + report["response"]["www_authenticate"] + HEADER_END_LINE
        if report["response"]["authorization_info"] is not None:
            server_response_header += "Authentication-Info: " + report["response"]["authorization_info"] \
                                      + HEADER_END_LINE
        if report["request"]["connection_close"]:
            server_response_header += 'Connection: close' + HEADER_END_LINE
        self.__debug_logger.debug("__gen_headers: " + server_response_header)
        self.__debug_logger.debug("__gen_headers: End")
        server_response_header += HEADER_END_LINE
        return server_response_header

    '''
    Function to get list of extensions for resources
    '''

    def __get_extensions(self, list_of_files):
        # Parse Extensions
        # 0: Mime Type
        # 1: Charset Extension
        # 2: Language Extension
        # 3: Encoding Extension
        list_extensions = [[], [], [], []]
        for files in list_of_files:
            mime_type, content_encoding_ext, content_language_ext, character_set_encoding_ext = \
                check_file_extensions(files, self.__config_mime_type, self.__content_encoding,
                                      self.__content_language, self.__charset_parser)
            list_extensions[0].append(mime_type)
            list_extensions[1].append(character_set_encoding_ext)
            list_extensions[2].append(content_language_ext)
            list_extensions[3].append(content_encoding_ext)
        return list_extensions

    '''
    Function to get list of files matching the resource
    '''

    def __get_list_of_files(self, report):
        list_of_files = []
        list_of_files_length = []
        for files in glob.glob(self.__config_instance.root_folder + report["request"]["path"] + "*"):
            file_handle = open(files, "rb")
            list_of_files.append(files)
            list_of_files_length.append(len(file_handle.read()))
            file_handle.close()
        return list_of_files, list_of_files_length

    '''
    Return error response header
    '''

    def return_error_response_headers(self, report=None):
        report["response"]["content_length"] = 0
        self.__debug_logger.debug("return_error_response_headers: Start")
        if is_method_get_head(report) and (report["response"]["status_code"] != STATUS_UNMODIFIED and
                                           report["response"]["status_code"] != STATUS_REQUESTED_RANGE_NOT_SATISFIABLE):
            if report["response"]["status_code"] == STATUS_MULTIPLE_CHOICE:
                self.__debug_logger.debug("return_error_response_headers: Case: " + str(STATUS_MULTIPLE_CHOICE))
                error_page_file_name = create_response_300_page(report, self.__config_instance,
                                                                self.__config_mime_type, self.__content_encoding,
                                                                self.__content_language, self.__charset_parser)
            else:
                error_page_file_name = create_dynamic_error_pages(report, self.__config_instance)
                if report["response"]["status_code"] == STATUS_NOT_ACCEPTABLE:
                    list_files, list_file_length = self.__get_list_of_files(report)
                    list_extensions = self.__get_extensions(list_files)
                    report = set_alternatives_header(report, list_files, list_extensions, list_file_length)
            file_error_page = open(error_page_file_name, "r")
            error_page_file_content = ""
            while True:
                payload = file_error_page.readline()
                payload += file_error_page.readline()
                error_page_file_content += str(hex(len(payload))[2:]) + "\n" + payload + "\n"
                if not payload:
                    break
            file_error_page.close()
            report["response"]["transfer_encoding"] = "chunked"
            report["response"]["payload"] = error_page_file_content.encode()
            report["response"]["content_length"] = len(report["response"]["payload"])
            resource_path = self.__config_instance.error_folder + "Error" + str(report["response"]["status_code"]) \
                            + ".html"
            mime_type, content_encoding, content_language, character_set_encoding = \
                check_file_extensions(resource_path, self.__config_mime_type, self.__content_encoding,
                                      self.__content_language, self.__charset_parser)
            if mime_type is not None:
                report["response"]["content_type"] = mime_type
            if content_encoding is not None:
                report["response"]["content_encoding"] = content_encoding
            if content_language is not None:
                report["response"]["content_language"] = content_language
            if character_set_encoding is not None:
                report["response"]["character_set"] = character_set_encoding
            response_header = self.__gen_headers(report=report)
        else:
            response_header = self.__gen_headers(report=report)

        server_response = response_header.encode()
        if report["request"]["method"] == "GET" and \
                report["response"]["status_code"] != STATUS_REQUESTED_RANGE_NOT_SATISFIABLE:
            server_response += report["response"]["payload"]
        self.__debug_logger.debug("return_error_response_headers: return_response_header: " + str(server_response))
        try:
            self.__debug_logger.debug("return_error_response_headers: Data sent: " +
                                      str(report["connection"].send(server_response)))
            self.__write_common_log(report)
        except Exception as e:
            self.__debug_logger.debug("return_error_response_headers: Sending Data Error: " + str(e))
            return CLOSE_CONNECTION
        if report["request"]["connection_close"]:
            self.__debug_logger.debug("return_error_response_headers: Closing connection with client")
            return CLOSE_CONNECTION

    '''
    Function to access log
    '''

    def __write_common_log(self, report=None):
        current_date = time.strftime("%d/%b/%Y:%H:%M:%S %z", time.localtime())
        if self.__config_instance.resolve_hostname == "Y":
            try:
                hostname = socket.gethostbyname(report["connection"].getpeername()[0])
            except Exception as e:
                self.__debug_logger.debug("__write_common_log: Error" + str(e))
                try:
                    hostname = report["connection"].getpeername()[0]
                except Exception as e:
                    self.__debug_logger.debug("__write_common_log: Error" + str(e))
                    self.__debug_logger.debug("__write_common_log: Connection close by client")
                    hostname = self.__config_instance.default_ip_addr
        else:
            try:
                hostname = report["connection"].getpeername()[0]
            except Exception as e:
                self.__debug_logger.debug("__write_common_log: Error" + str(e))
                self.__debug_logger.debug("__write_common_log: Connection close by client")
                hostname = self.__config_instance.default_ip_addr
        if report["request"]["method"] is None:
            report["request"]["method"] = ""
        if report["request"]["path"] is None:
            report["request"]["path"] = ""
        if report["response"]["status_code"] == STATUS_REQUEST_TIMEOUT:
            self.__access_logger.debug(hostname + " - " + "- " + "[" + current_date + "] \" - -" + "HTTP/" + " "
                                       + report["request"]["http_version"] + " "
                                       + str(report["response"]["status_code"])
                                       + "\" " + str(report["response"]["content_length"]))

            self.__debug_logger.debug(hostname + " - " + "- " + "[" + current_date + "] " + "HTTP/" + " "
                                      + report["request"]["http_version"] + " " + str(report["response"]["status_code"])
                                      + " " + str(report["response"]["content_length"]))
        else:
            self.__access_logger.debug(hostname + " - " + "- " + "[" + current_date + "] \"" + report["request"]["method"]
                                       + " " + report["request"]["path"] + " " + "HTTP/" + " "
                                       + self.__config_instance.http_version + "\" "
                                       + str(report["response"]["status_code"]) + " "
                                       + str(report["response"]["content_length"]))

            self.__debug_logger.debug(hostname + " - " + "- " + "[" + current_date + "] " + report["request"]["method"]
                                      + " " + report["request"]["path"] + " " + "HTTP/" + " "
                                      + self.__config_instance.http_version + " "
                                      + str(report["response"]["status_code"])
                                      + " " + str(report["response"]["content_length"]))
