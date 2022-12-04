#!usr/bin/env/python3
import socket
import time
import os
import hashlib
import logging
import logging.handlers
from datetime import datetime
from datetime import timezone
from threading import Timer
from threading import Thread
import threading
import sys

from src.MimeTypeReader import MimeTypeReader
from src.ConfigReader import ConfigReader
from src.AccessReader import AccessReader
from src.Constants import *
from src.Parser.ValidateHeader import ValidateHeader
from src.FetchResource import FetchResource
from src.Redirect import Redirect


class Server:

    """
    Init Function instantiates Config File, Log Files and socket.
    Sets the value for host and port
    """

    def __init__(self, host=None, port=None):
        self.__config_instance = ConfigReader("Configuration" + FORWARD_SLASH + "Config.ini")
        self.__config_mime_type = MimeTypeReader("Configuration" + FORWARD_SLASH + "MimeTypes.ini")
        self.__config_access = AccessReader("Configuration" + FORWARD_SLASH + "Access.ini")
        self.__redirect_parser = Redirect("Configuration" + FORWARD_SLASH + "Redirect.ini")
        if host is None:
            self.__host = self.__config_instance.default_ip_addr
        else:
            self.__host = host
        if port is None:
            self.__port = int(self.__config_instance.default_port)
        else:
            self.__port = port
        self.__access_logger = self.__set_up_logger('ACCESS_LOGS', self.__config_instance.access_debugging_folder
                                                    + FORWARD_SLASH + 'access.log')
        self.__debug_logger = self.__set_up_logger('DEBUG_LOGS', self.__config_instance.debug_folder + FORWARD_SLASH
                                                   + 'Debug.log')
        self.__server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__connection_timeout = None

    '''
    Function to set up logging handle and return it
    '''
    @staticmethod
    def __set_up_logger(name, log_file, level=logging.DEBUG):
        handler = logging.FileHandler(log_file, mode="w")
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.addHandler(handler)
        return logger

    '''
    Function to bind socket to a host and port
    '''
    def activate_server(self):
        try:
            self.__debug_logger.debug("activate_server: function started")
            self.__server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.__server_socket.bind((self.__host, self.__port))
            self.__wait_for_connections()
        except socket.error as err:
            self.__debug_logger.debug("activate_server: Error: " + str(err))
            exit(1)

    def shut_down(self, socket_connection):
        try:
            self.__connection_timeout.cancel()
            socket_connection.shutdown(socket.SHUT_RDWR)
            socket_connection.close()

        except Exception as err:
            self.__debug_logger.debug("shut_down: Error: " + str(err))

    '''
    Function to generate server response headers
    '''

    def __gen_headers(self, response_code=0, content_length=None, content_type=None, requested_resource=None,
                      request_method=None, etag=None, connection_close=True):
        self.__debug_logger.debug("__gen_headers: Start")
        server_response_header = 'HTTP/1.1 '
        if response_code == STATUS_OK:
            server_response_header += str(response_code) + ' OK'
        elif response_code == STATUS_MOVED_PERMANENTLY:
            server_response_header += str(response_code) + ' Moved Permanently'
        elif response_code == STATUS_FOUND:
            server_response_header += str(response_code) + ' Found'
        elif response_code == STATUS_UNMODIFIED:
            server_response_header += str(response_code) + ' Unmodified'
        elif response_code == STATUS_BAD_REQUEST:
            server_response_header += str(response_code) + ' Bad Request'
        elif response_code == STATUS_FORBIDDEN:
            server_response_header += str(response_code) + ' Forbidden'
        elif response_code == STATUS_NOT_FOUND:
            server_response_header += str(response_code) + ' Not Found'
        elif response_code == STATUS_REQUEST_TIMEOUT:
            server_response_header += str(response_code) + ' Request Timeout'
        elif response_code == STATUS_PRECONDITION_FAILED:
            server_response_header += str(response_code) + ' Precondition Failed'
        elif response_code == STATUS_INTERNAL_SERVER_ERROR:
            server_response_header += str(response_code) + ' Internal Server Error'
        elif response_code == STATUS_NOT_IMPLEMENTED:
            server_response_header += str(response_code) + " Not Implemented"
        elif response_code == STATUS_HTTP_VERSION_NOT_SUPPORTED:
            server_response_header += str(response_code) + ' HTTP Version Not Supported'
        else:
            print(response_code)
        server_response_header += HEADER_END_LINE
        current_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S")
        current_date += " GMT"
        server_response_header += 'Date: ' + current_date + '\r\n'
        server_response_header += 'Server: ' + self.__config_instance.server_name + '\r\n'
        if content_length is not None:
            server_response_header += 'Content-Length: ' + str(content_length) + '\r\n'
        if (request_method == "GET" or request_method == "HEAD") and response_code == 200 \
                and requested_resource is not None:
            modified_time = os.path.getmtime(self.__config_instance.root_folder + requested_resource)
            modified_time = datetime.utcfromtimestamp(modified_time)
            modified_time = datetime.strftime(modified_time, "%a, %d %b %Y %H:%M:%S")
            modified_time += " GMT"
            server_response_header += 'Last-Modified: ' + modified_time + '\r\n'
            if etag is not None:
                server_response_header += 'Etag: ' + "\"" + str(etag) + "\"" + HEADER_END_LINE
        if content_type is not None:
            server_response_header += 'Content-Type: ' + content_type + '\r\n'
        if response_code == STATUS_NOT_IMPLEMENTED or (request_method is not None and request_method == "OPTIONS" and
                                                       requested_resource == "*"):
            server_response_header += 'Allow: GET, HEAD, OPTIONS, TRACE \r\n'
        elif request_method is not None and request_method == "OPTIONS" and requested_resource != "*":
            server_response_header += 'Allow: GET, HEAD, OPTIONS, TRACE \r\n'
        if response_code == STATUS_MOVED_PERMANENTLY or response_code == STATUS_FOUND:
            server_response_header += "Location: " + requested_resource + HEADER_END_LINE
        if connection_close:
            server_response_header += 'Connection: close\r\n'
        self.__debug_logger.debug("__gen_headers: " + server_response_header)
        self.__debug_logger.debug("__gen_headers: End")
        server_response_header += "\r\n"
        return server_response_header

    '''
    Return error response header
    '''

    def __return_error_response_headers(self, request_method=None, response_code=0, conn=None, client_header=None,
                                        requested_resource=None, connection_close=True):
        error_file = None
        content_length = 0
        if (request_method == "GET" or request_method == "HEAD") and response_code != STATUS_UNMODIFIED:
            error_file = self.__create_dynamic_error_pages(response_code)
            error_file = error_file.encode()
            content_length = len(error_file)
            response_header = self.__gen_headers(response_code=response_code, content_length=content_length,
                                                 content_type=self.__config_mime_type.check_mime_type(
                                                     self.__config_instance.error_folder, "Error" + str(response_code)
                                                                                          + ".html"),
                                                 request_method=request_method, requested_resource=requested_resource,
                                                 connection_close=connection_close)
        else:
            response_header = self.__gen_headers(response_code=response_code, request_method=request_method,
                                                 requested_resource=requested_resource,
                                                 connection_close=connection_close)

        server_response = response_header.encode()
        if request_method == "GET":
            server_response += error_file
        self.__debug_logger.debug("__return_error_response_headers: return_response_header: " + str(server_response))
        try:
            self.__debug_logger.debug("__return_error_response_headers: Data sent: " + str(conn.send(server_response)))
        except Exception as e:
            self.__debug_logger.debug("__return_error_response_headers: Sending Data Error: " + str(e))
            threading.current_thread().exit()
        self.__write_common_log(response_code, content_length, client_header, conn)
        if connection_close:
            self.__debug_logger.debug("__return_error_response_headers: Closing connection with client")
            self.__connection_timeout.cancel()
            self.shut_down(conn)

    '''
    Function to create directory listings
    '''

    def __create_directory_listing(self, path, resource_directory):
        file_html_page = open(self.__config_instance.error_folder + "/DirectoryListing.html", "w")
        html_content = """
        <!DOCTYPE html>
        <html>
            <head>Index of {}</head> 
            <body>
                <h1> Index of {}</h1>
                {}
            </body>
        </html>"""
        if resource_directory != FORWARD_SLASH:
            directory_listing = [f for f in os.listdir(path + resource_directory)]
        else:
            directory_listing = [f for f in os.listdir(path)]

        table_content = ""
        for i in range(0, len(directory_listing)):
            if resource_directory != FORWARD_SLASH:
                modified_time = os.path.getmtime(self.__config_instance.root_folder + resource_directory + FORWARD_SLASH
                                                 + directory_listing[i])
            else:
                modified_time = os.path.getmtime(self.__config_instance.root_folder + resource_directory
                                                 + directory_listing[i])
            modified_time = datetime.utcfromtimestamp(modified_time / 1000.0)
            modified_time = datetime.strftime(modified_time, "%a, %d %b %Y %H:%M:%S")
            if directory_listing != FORWARD_SLASH:
                if os.path.isfile(self.__config_instance.root_folder + resource_directory + FORWARD_SLASH
                                  + directory_listing[i]):
                    file_size = str(os.path.getsize(self.__config_instance.root_folder + resource_directory
                                                    + FORWARD_SLASH + directory_listing[i]))
                else:
                    file_size = "--"
            else:
                if os.path.isfile(self.__config_instance.root_folder + resource_directory + directory_listing[i]):
                    file_size = str(os.path.getsize(self.__config_instance.root_folder + resource_directory
                                                    + directory_listing[i]))
                else:
                    file_size = "--"
            links_to_listings = "<a href= {}>{}</a>"
            if resource_directory != FORWARD_SLASH:
                self.__debug_logger.debug("__create_directory_listing: Requested Resource is not /")
                if os.path.isfile(self.__config_instance.root_folder + resource_directory + FORWARD_SLASH
                                  + directory_listing[i]):
                    links_to_listings = links_to_listings.format(resource_directory + FORWARD_SLASH
                                                                 + directory_listing[i], directory_listing[i])
                    self.__debug_logger.debug("__create_directory_listing: Requested Resource is file: "
                                              + links_to_listings)
                else:
                    links_to_listings = links_to_listings.format(resource_directory + FORWARD_SLASH
                                                                 + directory_listing[i] + FORWARD_SLASH,
                                                                 directory_listing[i] + FORWARD_SLASH)
                    self.__debug_logger.debug("__create_directory_listing: Requested Resource is dir: "
                                              + links_to_listings)
            else:
                self.__debug_logger.debug("__create_directory_listing: Requested Resource is /")
                if os.path.isfile(self.__config_instance.root_folder + resource_directory + directory_listing[i]):
                    links_to_listings = links_to_listings.format(resource_directory + directory_listing[i],
                                                                 directory_listing[i])
                    self.__debug_logger.debug("__create_directory_listing: Requested Resource is file: "
                                              + links_to_listings)
                else:
                    links_to_listings = links_to_listings.format(resource_directory + directory_listing[i]
                                                                 + FORWARD_SLASH, directory_listing[i] + FORWARD_SLASH)
                    self.__debug_logger.debug("__create_directory_listing: Requested Resource is dir: " +
                                              links_to_listings)
            table_content += "<tr>" \
                             "<td>{}</td>" \
                             "<td>{}</td>" \
                             "<td>{}</td>" \
                             "</tr>"
            table_content = table_content.format(links_to_listings, modified_time, file_size)

            table_html = "<table>" \
                         "<tr>" \
                         "<th>Name </th>" \
                         "<th> Last Modified Time</th>" \
                         "<th> Size</th>" \
                         "</tr>" \
                         "{}" \
                         "</table>"
            table_html = table_html.format(table_content)
        content = html_content.format(resource_directory, resource_directory, table_html)
        file_html_page.write(content)
        file_html_page.close()
        return content

    '''
    Function to create dynamic error pages
    '''

    def __create_dynamic_error_pages(self, response_code):
        file_html_page = open(self.__config_instance.error_folder + "/Error" + str(response_code) + ".html", "w")
        html_content = """
                <!DOCTYPE html>
                <html>
                    <head>{}</head> 
                    <body>
                        <h1>{}</h1>
                    </body>
                </html>"""
        content = html_content.format(response_code, response_code)
        file_html_page.write(content)
        file_html_page.close()
        return content

    def __write_common_log(self, response_code, content_length, client_header, conn):
        current_date = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
        if self.__config_instance.resolve_hostname == "Y":
            try:
                hostname = socket.gethostbyname(conn.getpeername()[0])
            except Exception as e:
                self.__debug_logger.debug("__write_common_log: Error" + str(e))
                hostname = conn.getpeername()[0]
        else:
            hostname = conn.getpeername()[0]
        if client_header is not None:
            self.__access_logger.debug(hostname + " - " + "- " + "[" + current_date + "] " + client_header[0] + " "
                                       + str(response_code) + " " + str(content_length))

            self.__debug_logger.debug(self.__host + " - " + "- " + "\"[" + current_date + "]\" " + client_header[0]
                                      + " " + str(response_code) + " " + str(content_length))
        else:
            self.__access_logger.debug(hostname + " - " + "- " + "[" + current_date + "] " + "-" + " "
                                       + str(response_code) + " " + str(content_length))

            self.__debug_logger.debug(self.__host + " - " + "- " + "\"[" + current_date + "]\" " + "-"
                                      + " " + str(response_code) + " " + str(content_length))

    '''
    Listening to clients and responding with response headers
    '''
    def __wait_for_connections(self):
        while True:

            self.__debug_logger.debug("__wait_for_connections: Awaiting New connection")
            self.__server_socket.listen(3)  # maximum number of queued connections
            conn, addr = self.__server_socket.accept()
            self.__debug_logger.debug("__wait_for_connections: Got connection from:" + str(addr))
            Thread(target=self.__start_client, args=(conn, addr)).start()

    '''
    Listen to clients
    '''

    def __start_client(self, conn, addr):
        while True:
            try:
                data = conn.recv(1024)  # receive data from client
            except Exception as e:
                self.__debug_logger.debug("__start_client: connection closed" + str(e))
                sys.exit()
            if len(data) > 0:
                if self.__connection_timeout is not None:
                    self.__debug_logger.debug("__start_client: Timer canceled")
                    self.__connection_timeout.cancel()
                self.__connection_timeout = Timer(int(self.__config_instance.default_timeout),
                                                  self.__generate_timeout_header, args=(conn, "Timeout"))
                self.__connection_timeout.start()
                self.__debug_logger.debug("__start_client: Timer started")
                client_message = bytes.decode(data)  # decode it to string
                self.__debug_logger.debug("__start_client: Request Header: " + str(client_message))
                client_message = client_message.split(HEADER_END_LINE + HEADER_END_LINE)
                try:
                    self.__debug_logger.debug("__start_client: Request Header Length: " + str(len(client_message)))
                    for header_index in range(0, len(client_message) - 1):
                        self.__debug_logger.debug("__start_client: Parsing Header number: " + str(header_index + 1))
                        client_message[header_index] = client_message[header_index].replace(HEADER_END_LINE, "\n")
                        client_headers = client_message[header_index].split('\n')
                        client_header = list(filter(lambda a: a != "", client_headers))
                        self.__debug_logger.debug("__start_client: Formatted Request Header: " + str(client_header))

                        val_header = ValidateHeader(self.__debug_logger, self.__config_instance)
                        response_code, request_method, requested_resource, connection_close, modified_case = \
                            val_header.validate_header(client_header)
                        if response_code is not None:
                            self.__return_error_response_headers(request_method=request_method, response_code=response_code,
                                                                 conn=conn, client_header=client_header,
                                                                 requested_resource=requested_resource,
                                                                 connection_close=connection_close)
                        else:
                            serve_response = FetchResource(self.__debug_logger, self.__config_instance,
                                                           self.__redirect_parser)
                            response_code, requested_resource = serve_response.fetch_resource(requested_resource,
                                                                                              request_method)
                            if response_code is not None and response_code != STATUS_OK:
                                self.__return_error_response_headers(request_method=request_method,
                                                                     response_code=response_code, conn=conn,
                                                                     client_header=client_header,
                                                                     requested_resource=requested_resource,
                                                                     connection_close=connection_close)
                            elif response_code == STATUS_OK and (request_method == "GET" or request_method == "HEAD"):
                                if os.path.isdir(self.__config_instance.root_folder + requested_resource):
                                    response_content = None
                                    if os.path.isfile(self.__config_instance.root_folder + requested_resource
                                                      + self.__config_instance.default_page):
                                        self.serve_get_head_resources(request_method=request_method,
                                                                      requested_resource=requested_resource + self.
                                                                      __config_instance.default_page,
                                                                      modified_case=modified_case, conn=conn,
                                                                      connection_close=connection_close,
                                                                      client_header=client_header, response_code=STATUS_OK)
                                    else:
                                        if request_method == "GET":
                                            response_content = self.__create_directory_listing(self.__config_instance.
                                                                                               root_folder,
                                                                                               requested_resource)
                                            self.__debug_logger.debug(response_content)
                                            response_content = response_content.encode()
                                            content_length = len(response_content)
                                        else:
                                            content_length = 0
                                        response_header = self.__gen_headers(response_code=response_code,
                                                                             content_length=content_length,
                                                                             content_type=self.__config_mime_type.
                                                                             check_mime_type(self.__config_instance.
                                                                                             error_folder,
                                                                                             "DirectoryListing.html"),
                                                                             requested_resource=requested_resource,
                                                                             request_method=request_method,
                                                                             connection_close=connection_close)
                                        server_response = response_header.encode()
                                        if request_method == "GET":
                                            server_response += response_content
                                        self.__debug_logger.debug("__start_client: " + str(server_response))
                                        try:
                                            self.__debug_logger.debug("__start_client: Data sent: "
                                                                      + str(conn.send(server_response)))
                                        except Exception as e:
                                            self.__debug_logger.debug("__start_client: Error: " + str(e))
                                        self.__write_common_log(response_code, content_length, client_header, conn)
                                        if connection_close:
                                            self.__debug_logger.debug("__start_client: Closing connection with client")
                                            self.shut_down(conn)
                                # Check if requested resource is a file
                                elif os.path.isfile(self.__config_instance.root_folder + requested_resource):
                                    self.serve_get_head_resources(request_method=request_method,
                                                                  requested_resource=requested_resource,
                                                                  modified_case=modified_case, conn=conn,
                                                                  connection_close=connection_close,
                                                                  client_header=client_header, response_code=STATUS_OK)
                            elif response_code == STATUS_OK and (request_method == "TRACE" or request_method == "OPTIONS"):
                                response_content = None
                                if request_method == "TRACE":
                                    response_content = ""
                                    for parts in client_header:
                                        response_content += parts + HEADER_END_LINE
                                    response_content += HEADER_END_LINE
                                    response_content = response_content.encode()
                                    content_length = len(response_content)
                                    response_header = self.__gen_headers(response_code=response_code,
                                                                         content_length=content_length,
                                                                         content_type="message/http",
                                                                         requested_resource=requested_resource,
                                                                         connection_close=connection_close)
                                else:
                                    content_length = 0
                                    response_header = self.__gen_headers(response_code=response_code,
                                                                         content_length=content_length,
                                                                         content_type="text/html",
                                                                         requested_resource=requested_resource,
                                                                         request_method="OPTIONS",
                                                                         connection_close=connection_close)
                                server_response = response_header.encode()
                                if request_method == "TRACE":
                                    server_response += response_content
                                self.__debug_logger.debug("__start_client: " + str(server_response))
                                try:
                                    self.__debug_logger.debug("__start_client: Data sent: "
                                                              + str(conn.send(server_response)))
                                except Exception as e:
                                    self.__debug_logger.debug("__start_client: Error:" + str(e))
                                self.__write_common_log(response_code, content_length, client_header, conn)
                                if connection_close:
                                    self.__debug_logger.debug("__start_client: Closing connection with client")
                                    self.shut_down(conn)
                except Exception as err:
                    self.__debug_logger.debug("__start_client: Error" + str(err))
                    self.__connection_timeout.cancel()
                    response_code = 500
                    self.__return_error_response_headers(response_code=response_code, conn=conn,
                                                         client_header=client_header, connection_close=True)
    '''
    Function to serve resources for get and head methods
    '''

    def serve_get_head_resources(self, request_method=None, requested_resource=None, modified_case=None, conn=None,
                                 connection_close=False, client_header=None, response_code=None):
        self.__debug_logger.debug("serve_get_head_resources: Is File:" + requested_resource)
        if modified_case is not None:
            response_code = self.check_modified_cases(modified_case, requested_resource)
        if response_code == STATUS_OK:
            file_handle = open(self.__config_instance.root_folder + requested_resource, "rb")
            file_content = file_handle.read()
            file_handle.close()
            content_length = len(file_content)
            md5_hash = hashlib.md5(file_content).hexdigest()
            response_header = self.__gen_headers(response_code=response_code,
                                                 content_length=content_length,
                                                 content_type=self.__config_mime_type.
                                                 check_mime_type(self.__config_instance.
                                                                 root_folder,
                                                                 requested_resource),
                                                 requested_resource=requested_resource,
                                                 request_method=request_method, etag=md5_hash,
                                                 connection_close=connection_close)
            server_response = response_header.encode()
            self.__debug_logger.debug(str(server_response))
            if request_method == "GET":
                server_response += file_content
            try:
                self.__debug_logger.debug("serve_get_head_resources: Data sent: " + str(conn.send(server_response)))
            except Exception as e:
                self.__debug_logger.debug("serve_get_head_resources: Error: " + str(e))
            self.__write_common_log(response_code, content_length, client_header, conn)
            if connection_close:
                self.__debug_logger.debug("serve_get_head_resources: Closing connection with client")
                self.shut_down(conn)
        else:
            self.__return_error_response_headers(request_method=request_method,
                                                 response_code=response_code,
                                                 conn=conn, client_header=client_header,
                                                 requested_resource=requested_resource,
                                                 connection_close=connection_close)

    '''
    Function to serve If-Match, If-None-Match, If-Modified-Since and If-Unmodified-Since
    '''

    def check_modified_cases(self, modified_case=None, requested_resource=None):
        list_modified_strings = ["Modified", "Unmodified", "Match", "NoneMatch"]
        # Check If-Modified-Since
        if modified_case[0] == list_modified_strings[0]:
            try:
                modified_time = datetime.strptime(modified_case[1].replace(" GMT", ""),
                                                  "%a, %d %b %Y %H:%M:%S")
                file_modified_time = os.path.getmtime(self.__config_instance.root_folder
                                                      + requested_resource)
                file_modified_time = datetime.utcfromtimestamp(file_modified_time)
                if file_modified_time <= modified_time:
                    return STATUS_UNMODIFIED
            except ValueError as e:
                self.__debug_logger.debug("serve_get_head_resources: Error: " + str(e))
                return STATUS_OK
        # Check If-Unmodified-Since
        elif modified_case[0] == list_modified_strings[1]:
            try:
                modified_time = datetime.strptime(modified_case[1].replace(" GMT", ""),
                                                  "%a, %d %b %Y %H:%M:%S")
                file_modified_time = os.path.getmtime(self.__config_instance.root_folder
                                                      + requested_resource)
                file_modified_time = datetime.utcfromtimestamp(file_modified_time)
                if file_modified_time < modified_time:
                    return STATUS_PRECONDITION_FAILED
            except ValueError as e:
                self.__debug_logger.debug("serve_get_head_resources: Error: " + str(e))
                return STATUS_OK
        # Check If-Match
        elif modified_case[0] == list_modified_strings[2]:
            list_etags = modified_case[1].split(COMMA_SEPARATOR)
            file_handle = open(self.__config_instance.root_folder + requested_resource, "rb")
            file_content = file_handle.read()
            file_handle.close()
            file_content_hash = hashlib.md5(file_content).hexdigest()
            is_tag_match = False
            for tags in list_etags:
                tags = tags.replace("\"", "").strip()
                if tags == file_content_hash:
                    is_tag_match = True
                    break
            if not is_tag_match:
                return STATUS_PRECONDITION_FAILED
        elif modified_case[0] == list_modified_strings[3]:
            list_etags = modified_case[1].split(",")
            file_handle = open(self.__config_instance.root_folder + requested_resource, "rb")
            file_content = file_handle.read()
            file_handle.close()
            file_content_hash = hashlib.md5(file_content).hexdigest()
            is_tag_match = False
            for tags in list_etags:
                tags = tags.replace("\"", "").strip()
                if tags == file_content_hash:
                    is_tag_match = True
                    break
            if is_tag_match:
                return STATUS_UNMODIFIED
        return STATUS_OK

    def __generate_timeout_header(self, conn, recv):
        print(recv)
        self.__return_error_response_headers(request_method="", response_code=STATUS_REQUEST_TIMEOUT,
                                             conn=conn, connection_close=True)
