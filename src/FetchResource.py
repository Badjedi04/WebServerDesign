import getpass
import re
import glob
import base64
import hashlib
import time
from urllib.parse import unquote

from src.ConfigParsers.Redirect import RedirectParser
from src.ConfigParsers.AcceptEncodingParser import AcceptEncodingParser
from src.UtilityMethods import *


class FetchResource:

    def __init__(self, debug_logger=None, config_instance=None, mime_type=None, content_language=None,
                 content_encoding=None, charset_parser=None, authorization_parser=None):
        self.__debug_logger = debug_logger
        self.__config_instance = config_instance
        self.__redirect_parser = RedirectParser("Configuration" + FORWARD_SLASH + "Redirect.ini")
        self.__accept_encoding = AcceptEncodingParser("Configuration" + FORWARD_SLASH + "AcceptEncoding.ini")
        self.__mime_type_parser = mime_type
        self.__content_language_parser = content_language
        self.__content_encoding_parser = content_encoding
        self.__charset_parser = charset_parser
        self.__authorization_parser = authorization_parser

    '''
    Function to write debug logs
    '''

    def __write_debug_logs(self, message):
        if self.__debug_logger is not None:
            self.__debug_logger.debug(message)

    '''
    Function to fetch resource 
    Output: Response Code, Requested Resource 
    '''

    def fetch_resource(self, report=None):
        if os.path.isdir(self.__config_instance.root_folder + report["request"]["path"]) and \
                report["request"]["path"][-1] != FORWARD_SLASH:
            self.__debug_logger.debug("fetch_resource: Redirect")
            report["response"]["status_code"] = STATUS_MOVED_PERMANENTLY
            report["response"]["location"] = "http://" + report["request"]["host"] + \
                                             report["request"]["path"] + FORWARD_SLASH
        elif is_method_get_head(report):
            self.__write_debug_logs("fetch_resource: request method is get or head")
            authorization_info = check_authorization_directory(self.__config_instance,
                                                               self.__config_instance.root_folder
                                                               + report["request"]["path"])

            if authorization_info is not None:
                report = self.__check_authorization(report=report, authorization_info=authorization_info)
            report = self.__server_get_head_method(report)
        else:
            self.__write_debug_logs("fetch_resource: request method is not get or head")
            report["response"]["status_code"] = STATUS_OK
            if report["request"]["method"] == "OPTIONS":
                authorization_info = check_authorization_directory(self.__config_instance,
                                                                   self.__config_instance.root_folder
                                                                   + report["request"]["path"])

                if authorization_info is not None:
                    report = self.__check_authorization(report=report, authorization_info=authorization_info)
        return report

    '''
    Function to serve head and get methods
    '''

    def __server_get_head_method(self, report=None):
        self.__debug_logger.debug("__server_get_head_method: Start")
        report["request"]["path"] = unquote(report["request"]["path"])
        # Check virtual urls
        for key in self.__redirect_parser.virtual_uri:
            if key in report["request"]["path"]:
                report["request"]["path"] = report["request"]["path"].replace(key, self.__redirect_parser.logs_redirect)
                break
        # Check for regex redirects
        if not STATUS_OK:
            report = self.__check_regex_redirects(report=report)
        # Check if any error status code is set
        if report["response"]["status_code"] is not None and not if_status_code_200_class(report):
            self.__debug_logger.debug("__server_get_head_method: Redirect")
            return report
        # Check if resource can be served to the user id (403)
        elif not (getpass.getuser() == "staff" or getpass.getuser() == "root" or getpass.getuser() == "rchau004"):
            self.__write_debug_logs("__server_get_head_method: forbidden zone: "
                                    + str(self.__config_instance.root_folder + report["request"]["path"]))
            report["response"]["status_code"] = STATUS_FORBIDDEN
        # Check if requested resource is a directory
        else:
            self.__debug_logger.debug("__server_get_head_method: Perform Content Negotiation")
            if not (report["response"]["status_code"] == STATUS_AUTHORIZATION_REQUIRED or
                    report["response"]["status_code"] == STATUS_FORBIDDEN):
                report = self.__check_content_negotiation(report)
        return report

    '''
    Function to check authorization
    '''

    def __check_authorization(self, report=None, authorization_info=None):
        self.__debug_logger.debug("__check_authorization: " + str(authorization_info))
        if report["request"]["authorization"] is None:
            report["response"]["status_code"] = STATUS_AUTHORIZATION_REQUIRED
            report["response"]["www_authenticate"] = authorization_info["authorization_type"] + " realm=" \
                                                     + authorization_info["realm"]
            if authorization_info["authorization_type"] == "Digest":
                nonce = self.__generate_nonce(report)
                opaque = self.__generate_opaque(report)
                report["response"]["www_authenticate"] += ", algorithm=MD5, qop= auth, nonce=\"" + \
                                                          nonce + "\"" + ",opaque=\"" + opaque + "\""
                self.__write_authorization_file(report, nonce, 0, authorization_info, "auth", opaque)
        else:
            if report["request"]["authorization"].split(" ")[0] == "Basic" and \
                    report["request"]["authorization"].split(" ")[0] == authorization_info["authorization_type"]:
                request_authorization = base64.b64decode(report["request"]["authorization"].split(" ")[-1]) \
                    .decode("utf-8")
                temp_split = request_authorization.split(":")
                temp_split[1] = hashlib.md5(temp_split[1].encode()).hexdigest()
                request_authorization = temp_split[0] + ":" + temp_split[1]
                for users in authorization_info["users"]:
                    if users == request_authorization:
                        return report
                report["response"]["status_code"] = STATUS_AUTHORIZATION_REQUIRED
                report["response"]["www_authenticate"] = authorization_info["authorization_type"] + " realm=" \
                                                         + authorization_info["realm"]
            elif report["request"]["authorization"].split(" ")[0] == "Digest" and \
                    report["request"]["authorization"].split(" ")[0] == authorization_info["authorization_type"]:
                auth_response = self.__read_authorization_file(report)
                if auth_response is None:
                    report["response"]["status_code"] = STATUS_AUTHORIZATION_REQUIRED
                    report["response"]["www_authenticate"] = authorization_info["authorization_type"] + " realm=" \
                                                             + authorization_info["realm"]
                    if authorization_info["authorization_type"] == "Digest":
                        nonce = self.__generate_nonce(report)
                        opaque = self.__generate_opaque(report)
                        report["response"]["www_authenticate"] += ", algorithm=MD5, qop= auth, nonce=\"" + \
                                                                  nonce + "\"" + ",opaque=\"" + opaque + "\""
                        self.__write_authorization_file(report, nonce, 0, authorization_info, "auth", opaque)

                else:
                    report["response"]["authorization_info"] = "qop= auth, rspauth=\"" + \
                                                               self.__generate_response_message_digest(report, 
                                                                                                       auth_response) \
                                                               + "\", cnonce=\"" + auth_response["cnonce"] + "\", nc=" \
                                                               + auth_response["nc"]

            else:
                report["response"]["status_code"] = STATUS_AUTHORIZATION_REQUIRED
                report["response"]["www_authenticate"] = authorization_info["authorization_type"] + " realm=" \
                                                         + authorization_info["realm"]
                if authorization_info["authorization_type"] == "Digest":
                    nonce = self.__generate_nonce(report)
                    opaque = self.__generate_opaque(report)
                    report["response"]["www_authenticate"] += ", algorithm=MD5, qop= auth, nonce=\"" + \
                                                              nonce + "\"" + ",opaque=\"" + opaque + "\""
                    self.__write_authorization_file(report, nonce, 0, authorization_info, "auth", opaque)
        return report

    '''
    Function to generate response message digest
    '''
    def __generate_response_message_digest(self, report, authorization_info):
        self.__debug_logger.debug("__generate_request_message_digest")
        auth_info = check_authorization_directory(self.__config_instance,
                                                  self.__config_instance.root_folder
                                                  + report["request"]["path"])
        for users in auth_info["users"]:
            if users.split(":")[0] == authorization_info["username"]:
                a1 = users.split(":")[-1]
        a2 = hashlib.md5((":" + authorization_info["uri"]).encode()).hexdigest()
        a3 = a1 + ":" + authorization_info["nonce"] + ":" + authorization_info["nc"] + ":" \
             + authorization_info["cnonce"]+ ":" + authorization_info["qop"] + ":" + a2

        return hashlib.md5(a3.encode()).hexdigest()

    '''
    Function to write to authorization file
    '''

    def __write_authorization_file(self, report, nonce, nc, authorization_info, qop, opaque):
        self.__debug_logger.debug("__write_authorization_file")
        if os.path.exists(self.__config_instance.debug_folder + "/DigestAuthorizationInfo.txt"):
            file_authorization = open(self.__config_instance.debug_folder + "/DigestAuthorizationInfo.txt", "w")
        else:
            file_authorization = open(self.__config_instance.debug_folder + "/DigestAuthorizationInfo.txt", "w")
        file_authorization.write("user: " + "|url:" + report["request"]["path"] + "|nonce:" + nonce + "|nc:" + str(nc)
                                 + "|realm:" + authorization_info["realm"] + "|qop:" + qop + "|opaque:" + opaque + "\n")
        file_authorization.close()

    '''
    Function to match nonce, realm, nc, url and qop from previous request
    '''

    def __read_authorization_file(self, report):
        self.__debug_logger.debug("__read_authorization_file")
        auth_string = report["request"]["authorization"]
        auth_string = auth_string.split(", ")
        authorization_info = {}
        for info in auth_string:
            split = info.split("=")
            if "username" in split[0]:
                authorization_info["username"] = self.__remove_quotes(split[1])
            elif "realm" in split[0]:
                authorization_info["realm"] = self.__remove_quotes(split[1])
            elif "uri" in split[0]:
                authorization_info["uri"] = self.__remove_quotes(split[1])
            elif "qop" in split[0]:
                authorization_info["qop"] = self.__remove_quotes(split[1])
            elif "cnonce" in split[0]:
                authorization_info["cnonce"] = self.__remove_quotes(split[1])
            elif "nonce" in split[0]:
                authorization_info["nonce"] = self.__remove_quotes(split[1])
            elif "nc" in split[0]:
                authorization_info["nc"] = self.__remove_quotes(split[1])
            elif "response" in split[0]:
                authorization_info["response"] = self.__remove_quotes(split[1])
            elif "opaque" in split[0]:
                authorization_info["opaque"] = self.__remove_quotes(split[1])
        self.__debug_logger.debug("__read_authorization_file: authorization_info: " + str(authorization_info))
        if os.path.exists(self.__config_instance.debug_folder + "/DigestAuthorizationInfo.txt"):
            file_authorization = open(self.__config_instance.debug_folder + "/DigestAuthorizationInfo.txt", "r")
            for line in file_authorization:
                file_info = {}
                line_split = line.split("|")
                for split_text in line_split:
                    pair = split_text.split(":")
                    if "user" in pair[0]:
                        file_info["username"] = self.__remove_quotes(pair[1])
                    elif "url" in pair[0]:
                        file_info["url"] = self.__remove_quotes(pair[1])
                    elif "nonce" in pair[0]:
                        file_info["nonce"] = self.__remove_quotes(pair[1])
                    elif "nc" in pair[0]:
                        file_info["nc"] = self.__remove_quotes(pair[1])
                    elif "qop" in pair[0]:
                        file_info["qop"] = self.__remove_quotes(pair[1].rstrip())
                    elif "realm" in pair[0]:
                        file_info["realm"] = pair[1]
                    elif "opaque" in pair[0]:
                        file_info["opaque"] = pair[1].rstrip()
                self.__debug_logger.debug("__read_authorization_file: file_info: " + str(file_info))
                self.__debug_logger.debug("__read_authorization_file: auth nonce: " + authorization_info["nonce"])
                self.__debug_logger.debug("__read_authorization_file: file nonce: " + file_info["nonce"])
                self.__debug_logger.debug("__read_authorization_file: auth realm: " + authorization_info["realm"])
                self.__debug_logger.debug("__read_authorization_file: file realm: " +
                                          self.__remove_quotes(file_info["realm"]))
                if authorization_info["nonce"] == file_info["nonce"] and authorization_info["realm"] == \
                        self.__remove_quotes(file_info["realm"]):
                    self.__debug_logger.debug("__read_authorization_file: Nonce and Realm matched")
                    self.__debug_logger.debug("__read_authorization_file: Match Ncount: "
                                              + str(int(authorization_info["nc"], 16) == (int(file_info["nc"]) + 1)))
                    if int(authorization_info["nc"], 16) == (int(file_info["nc"]) + 1):
                        self.__debug_logger.debug("__read_authorization_file: auth response: "
                                                  + authorization_info["response"])
                        self.__debug_logger.debug("__read_authorization_file: generated response: "
                                                  + str(self.__generate_request_message_digest(authorization_info,
                                                                                               report)))
                        if authorization_info["response"] == \
                                self.__generate_request_message_digest(authorization_info, report):
                            return authorization_info
        return None

    '''
    Function to generate request message digest
    '''

    def __generate_request_message_digest(self, authorization_info, report):
        self.__debug_logger.debug("__generate_request_message_digest")
        auth_info = check_authorization_directory(self.__config_instance,
                                                           self.__config_instance.root_folder
                                                           + report["request"]["path"])
        for users in auth_info["users"]:
            if users.split(":")[0] == authorization_info["username"]:
                a1 = users.split(":")[-1]
        a2 = hashlib.md5((report["request"]["method"] + ":" + authorization_info["uri"]).encode()).hexdigest()
        a3 = a1 + ":" + authorization_info["nonce"] + ":" + authorization_info["nc"] + ":" \
             + authorization_info["cnonce"]+ ":" + authorization_info["qop"] + ":" + a2
        return hashlib.md5(a3.encode()).hexdigest()

    '''
    Function to remove double and single quotes
    '''

    def __remove_quotes(self, auth_string):
        self.__debug_logger.debug("__remove_quotes")
        if "\"" in auth_string:
            auth_string = auth_string.replace("\"", "")
        if "'" in auth_string:
            auth_string = auth_string.replace("'", "")
        return auth_string

    '''
    Function to generate noonce string
    '''

    def __generate_nonce(self, report):
        nonce = base64.b64encode((str(time.time()) + " " + hashlib.md5((str(time.time()) +
                                                                        hashlib.md5(report["request"]["path"]
                                                                                    .encode()).hexdigest() +
                                                                        self.__config_instance.private_key).encode())
                                  .hexdigest()).encode())
        return nonce.decode("utf-8")

    '''
    Function to generate opaque string
    '''

    def __generate_opaque(self, report):
        opaque = hashlib.md5((report["request"]["path"] + ":" + self.__config_instance.private_key).encode()) \
            .hexdigest()
        return opaque

    '''
    Function to check content negotiation
    '''

    def __check_content_negotiation(self, report=None):
        self.__debug_logger.debug("Content Negotiation: Start")
        if report["request"]["negotiate"] is not None:
            report["response"]["status_code"] = STATUS_MULTIPLE_CHOICE
            list_of_files, list_of_files_length = self.__get_list_of_files(report)
            list_of_extensions = self.__get_extensions(list_of_files)
            report = self.__set_vary_header(list_of_extensions, report)
            report["response"]["TCN"] = "list"
        elif has_accept_headers(report):
            if os.path.exists(self.__config_instance.root_folder + report["request"]["path"]):
                if is_method_get_head(report) and report["request"]["range"] is not None:
                    report["response"]["status_code"] = STATUS_PARTIAL_CONTENT
                else:
                    report["response"]["status_code"] = STATUS_OK
                file_path = report["request"]["path"].split(".", 1)[0]
                list_of_files = []
                for files in glob.glob(self.__config_instance.root_folder + file_path + "*"):
                    list_of_files.append(files)
                list_of_extensions = self.__get_extensions(list_of_files)
                report = self.__set_vary_header(list_of_extensions, report)
                report["response"]["TCN"] = "choice"
                report["response"]["content_location"] = report["request"]["path"]
            else:
                report = self.__check_accept_headers(report)
        else:
            if os.path.exists(self.__config_instance.root_folder + report["request"]["path"]):
                if is_method_get_head(report) and report["request"]["range"] is not None:
                    report["response"]["status_code"] = STATUS_PARTIAL_CONTENT
                else:
                    report["response"]["status_code"] = STATUS_OK
            else:
                list_of_files, list_of_files_length = self.__get_list_of_files(report)
                if len(list_of_files) == 0:
                    report["response"]["status_code"] = STATUS_NOT_FOUND
                else:
                    if is_method_get_head(report) and report["request"]["range"] is not None:
                        report["response"]["status_code"] = STATUS_PARTIAL_CONTENT
                    else:
                        report["response"]["status_code"] = STATUS_OK

                    report["response"]["status_code"] = STATUS_MULTIPLE_CHOICE
                    list_of_files, list_of_files_length = self.__get_list_of_files(report)
                    list_of_extensions = self.__get_extensions(list_of_files)
                    report = self.__set_vary_header(list_of_extensions, report)
                    report["response"]["TCN"] = "list"
        return report

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
                check_file_extensions(files, self.__mime_type_parser, self.__content_encoding_parser,
                                      self.__content_language_parser, self.__charset_parser)
            list_extensions[0].append(mime_type)
            list_extensions[1].append(character_set_encoding_ext)
            list_extensions[2].append(content_language_ext)
            list_extensions[3].append(content_encoding_ext)
        return list_extensions

    '''
    Function to set vary header
    '''

    def __set_vary_header(self, list_of_extensions, report):
        self.__debug_logger.debug("__set_vary_header: Start")
        vary = "negotiate"
        for index_ext in range(0, len(list_of_extensions)):
            temp = []
            for extension in list_of_extensions[index_ext]:
                if extension is not None and extension not in temp:
                    temp.append(extension)
            if len(temp) > 1:
                if index_ext == 0:
                    vary += ",accept"
                elif index_ext == 1:
                    vary += ",accept-charset"
                elif index_ext == 2:
                    vary += ",accept-language"
                elif index_ext == 3:
                    vary += ",accept-encoding"
        if vary != "negotiate":
            report["response"]["vary"] = vary
        return report

    '''
    Function to check content negotiation for accept, accept-language, accept-encoding, accept-charset headers
    '''

    def __check_accept_headers(self, report=None):
        self.__debug_logger.debug("__check_accept_headers: Start")
        # list of Accept Header Parameters:
        # Pos 0: Accept Header
        # Pos 1: Charset Header
        # Pos 2: Language Header
        # Pos 3: Encoding Header
        # Split accept headers and add them to list
        list_accept_headers = [None, None, None, None]
        if report["request"]["accept_language"] is not None:
            temp = report['request']["accept_language"].split(",")
            list_accept_headers[2] = sort_accept_headers(temp)
        if report["request"]["accept_encoding"] is not None:
            temp = report['request']["accept_encoding"].split(",")
            list_accept_headers[3] = sort_accept_headers(temp)
        if report["request"]["accept_charset"] is not None:
            temp = report['request']["accept_charset"].split(",")
            list_accept_headers[1] = sort_accept_headers(temp)
        if report["request"]["accept"] is not None:
            temp = report["request"]["accept"].split(",")
            list_accept_headers[0] = sort_accept_headers(temp)
        self.__debug_logger.debug("__check_accept_headers: Accept Headers Sorted: " + str(list_accept_headers))
        # list of index accept headers:
        # Pos 0: Accept Header
        # Pos 1: Charset Header
        # Pos 2: Language Header
        # Pos 3: Encoding Header
        list_index_accept = [None, None, None, None]
        # Check all matching files names
        list_of_files, list_of_files_length = self.__get_list_of_files(report)
        list_of_extensions = self.__get_extensions(list_of_files)
        report = self.__set_vary_header(list_of_extensions, report)
        list_matching_files = self.__get_matching_files(list_accept_headers, list_of_extensions, list_of_files)
        list_final_matching_files = []
        for index_accept in range(0, len(list_accept_headers)):
            if list_accept_headers[index_accept] is not None:
                if len(list_matching_files[index_accept]) == 0:
                    report["response"]["status_code"] = STATUS_NOT_ACCEPTABLE
                    list_of_files, list_of_files_length = self.__get_list_of_files(report)
                    list_of_extensions = self.__get_extensions(list_of_files)
                    report = self.__set_vary_header(list_of_extensions, report)
                    report["response"]["TCN"] = "list"
                    return report
                elif len(list_matching_files[index_accept]) > 1:
                    report["response"]["status_code"] = STATUS_MULTIPLE_CHOICE
                    list_of_files, list_of_files_length = self.__get_list_of_files(report)
                    list_of_extensions = self.__get_extensions(list_of_files)
                    report = self.__set_vary_header(list_of_extensions, report)
                    report["response"]["TCN"] = "list"
                    return report
                else:
                    list_final_matching_files.append(list_matching_files[index_accept][0].replace("public", ""))
        if len(list_final_matching_files) == 0:
            report["response"]["status_code"] = STATUS_NOT_ACCEPTABLE
            list_of_files, list_of_files_length = self.__get_list_of_files(report)
            list_of_extensions = self.__get_extensions(list_of_files)
            report = self.__set_vary_header(list_of_extensions, report)
            report["response"]["TCN"] = "list"
            return report
        elif len(list_final_matching_files) == 1:
            if is_method_get_head(report) and report["request"]["range"] is not None:
                report["response"]["status_code"] = STATUS_PARTIAL_CONTENT
            else:
                report["response"]["status_code"] = STATUS_OK
            list_of_files, list_of_files_length = self.__get_list_of_files(report)
            list_of_extensions = self.__get_extensions(list_of_files)
            report = self.__set_vary_header(list_of_extensions, report)
            report["response"]["TCN"] = "choice"
            report["response"]["content_location"] = list_final_matching_files[0].replace("public", "")
            return report
        else:
            report["response"]["status_code"] = STATUS_MULTIPLE_CHOICE
            list_of_files, list_of_files_length = self.__get_list_of_files(report)
            list_of_extensions = self.__get_extensions(list_of_files)
            report = self.__set_vary_header(list_of_extensions, report)
            report["response"]["TCN"] = "list"
            return report

    '''
    Function to get list of matching files with accept headers
    '''

    def __get_matching_files(self, list_accept_headers, list_of_extensions, list_of_files):
        list_of_matching_files = [[], [], [], []]
        self.__debug_logger.debug("__get_matching_files: Start")
        for index_accept in range(0, len(list_accept_headers)):
            if list_accept_headers[index_accept] is not None:
                for index_accept_ext in range(0, len(list_accept_headers[index_accept])):
                    for index_extension in range(0, len(list_of_extensions[index_accept])):
                        if float(list_accept_headers[index_accept][index_accept_ext].split(";")[-1].split("=")[-1]) \
                                > 0.0:
                            if list_accept_headers[index_accept][index_accept_ext].split(";")[0].split("/")[0] == \
                                    list_of_extensions[index_accept][index_extension].split("/")[0] and \
                                    list_accept_headers[index_accept][index_accept_ext].split(";")[0].split("/")[-1] \
                                    == "*":
                                list_of_matching_files[index_accept].append(list_of_files[index_extension])
                            elif list_accept_headers[index_accept][index_accept_ext].split(";")[0] == \
                                    list_of_extensions[index_accept][index_extension]:
                                list_of_matching_files[index_accept].append(list_of_files[index_extension])
                            elif list_accept_headers[index_accept][index_accept_ext].split(";")[0] == \
                                    self.__accept_encoding.check_accept_encoding_type\
                                        (list_of_extensions[index_accept][index_extension]):
                                list_of_matching_files[index_accept].append(list_of_files[index_extension])
                    # If one extension match then no need to match with other accept extensions
                    if len(list_of_matching_files[index_accept]) > 0:
                        if index_accept_ext + 1 < (len(list_accept_headers[index_accept])):
                            if float(list_accept_headers[index_accept][index_accept_ext].split(";")[-1].split("=")[-1])\
                                > float(list_accept_headers[index_accept][index_accept_ext + 1].split(";")[-1].
                                                split("=")[-1]):
                                break

        self.__debug_logger.debug("__get_matching_files: Matching Files: " + str(list_of_matching_files))
        return list_of_matching_files

    '''
    Function to check regex based redirect
    '''

    def __check_regex_redirects(self, report=None):
        self.__debug_logger.debug("__check_regex_redirects: Start")
        permanent_pattern = self.__redirect_parser.permanent
        temporary_pattern = self.__redirect_parser.temporary_redirect
        # Check 301
        if re.match(permanent_pattern.split(" ")[0], report["request"]["path"]):
            string_match = re.search(permanent_pattern.split(" ")[0], report["request"]["path"])
            split_redirect = permanent_pattern.split(" ")[1].split(FORWARD_SLASH)
            count_dollars = 0
            redirect_path = ""
            for j in range(0, len(split_redirect)):
                if "$" in split_redirect[j] and split_redirect[j].replace("$", "").isdigit():
                    count_dollars += 1
                    redirect_path += string_match.group(count_dollars) + FORWARD_SLASH
                else:
                    redirect_path += split_redirect[j] + FORWARD_SLASH
            report["response"]["location"] = "http://" + report["request"]["host"] + redirect_path[:-1]
            report["response"]["status_code"] = STATUS_MOVED_PERMANENTLY
            return report
        # Check 302
        temporary_pattern = temporary_pattern.split("\n")
        for i in range(0, len(temporary_pattern)):
            if re.match(temporary_pattern[i].split(" ")[0], report["request"]["path"]):
                string_match = re.search(temporary_pattern[i].split(" ")[0], report["request"]["path"])
                split_redirect = temporary_pattern[i].split(" ")[1].split(FORWARD_SLASH)
                count_dollars = 0
                redirect_path = ""
                for j in range(0, len(split_redirect)):
                    if "$" in split_redirect[j] and split_redirect[j].replace("$", "").isdigit():
                        count_dollars += 1
                        redirect_path += string_match.group(count_dollars) + FORWARD_SLASH
                    else:
                        redirect_path += split_redirect[j] + FORWARD_SLASH
                report["response"]["location"] = "http://" + report["request"]["host"] + redirect_path[:-1]
                report["response"]["status_code"] = STATUS_FOUND
                return report
        return report