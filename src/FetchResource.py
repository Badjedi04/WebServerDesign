import os
import getpass
import re
from urllib.parse import unquote

from src.Constants import *


class FetchResource:

    def __init__(self, debug_logger, config_instance, redirect_instance):
        self.__debug_logger = debug_logger
        self.__config_instance = config_instance
        self.__redirect_parser = redirect_instance

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

    def fetch_resource(self, requested_resource, request_method):
        if os.path.isdir(self.__config_instance.root_folder + requested_resource) and \
                requested_resource[-1] != FORWARD_SLASH:
            response_code = STATUS_MOVED_PERMANENTLY
            requested_resource = requested_resource + FORWARD_SLASH
            return response_code, requested_resource
        elif request_method == "GET" or request_method == "HEAD":
            self.__write_debug_logs("fetch_resource: request method: " + request_method)
            response_code, requested_resource = self.server_get_head_method(requested_resource)
            return response_code, requested_resource
        elif request_method == "OPTIONS" or request_method == "TRACE":
            self.__write_debug_logs("fetch_resource: request method" + request_method)
            response_code = STATUS_OK
            return response_code, requested_resource

    '''
    Function to serve head and get methods
    '''

    def server_get_head_method(self, requested_resource):
        requested_resource = unquote(requested_resource)
        # Check virtual urls
        for key in self.__redirect_parser.virtual_uri:
            if key in requested_resource:
                requested_resource = requested_resource.replace(key, self.__redirect_parser.logs_redirect)
                break

        # Check for regex redirects
        response_code, requested_resource = self.check_regex_redirects(requested_resource)
        if response_code != STATUS_OK:
            return response_code, requested_resource
        # Check if resource exists on server
        elif not os.path.exists(self.__config_instance.root_folder + requested_resource):
            self.__write_debug_logs(str(self.__config_instance.root_folder + requested_resource))
            self.__write_debug_logs("Requested resource missing 404: " + requested_resource)
            response_code = 404
            return response_code, requested_resource
        # Check if resource can be served to the user id
        elif not (getpass.getuser() == "staff" or getpass.getuser() == "root" or getpass.getuser() == "msiddique"):
            self.__write_debug_logs("fetch_resource: forbidden zone: " + str(self.__config_instance.root_folder
                                                                             + requested_resource))
            response_code = 403
            return response_code, requested_resource
        # Check if requested resource is a directory
        elif os.path.exists(self.__config_instance.root_folder + requested_resource):
            response_code = 200
            return response_code, requested_resource

    '''
    Function to check regex based redirect
    '''

    def check_regex_redirects(self, requested_resource):
        permanent_pattern = self.__redirect_parser.permanent
        temporary_pattern = self.__redirect_parser.temporary_redirect
        # Check 301
        if re.match(permanent_pattern.split(" ")[0], requested_resource):
            string_match = re.search(permanent_pattern.split(" ")[0], requested_resource)
            split_redirect = permanent_pattern.split(" ")[1].split(FORWARD_SLASH)
            count_dollars = 0
            redirect_path = ""
            for j in range(0, len(split_redirect)):
                if "$" in split_redirect[j] and split_redirect[j].replace("$", "").isdigit():
                    count_dollars += 1
                    redirect_path += string_match.group(count_dollars) + FORWARD_SLASH
                else:
                    redirect_path += split_redirect[j] + FORWARD_SLASH
            redirect_path = redirect_path[:-1]
            return STATUS_MOVED_PERMANENTLY, redirect_path
        # Check 302
        temporary_pattern = temporary_pattern.split("\n")
        for i in range(0, len(temporary_pattern)):
            if re.match(temporary_pattern[i].split(" ")[0], requested_resource):
                string_match = re.search(temporary_pattern[i].split(" ")[0], requested_resource)
                split_redirect = temporary_pattern[i].split(" ")[1].split(FORWARD_SLASH)
                count_dollars = 0
                redirect_path = ""
                for j in range(0, len(split_redirect)):
                    if "$" in split_redirect[j] and split_redirect[j].replace("$", "").isdigit():
                        count_dollars += 1
                        redirect_path += string_match.group(count_dollars) + FORWARD_SLASH
                    else:
                        redirect_path += split_redirect[j] + FORWARD_SLASH
                redirect_path = redirect_path[:-1]
                return STATUS_FOUND, redirect_path
        return STATUS_OK, requested_resource
