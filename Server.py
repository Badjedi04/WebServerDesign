#!usr/bin/env/python3
import socket
import time
import os
import logging
import re
import logging.handlers
from datetime import datetime
from datetime import timezone

from MimeTypeReader import MimeTypeReader
from ConfigReader import ConfigReader

try:
    from urllib import unquote
except ImportError:
    from urllib.parse import unquote

from urllib.parse import urlparse
from AccessReader import AccessReader



class Server:

    """
    Init Function instantiates Config File, Log Files and socket.
    Sets the value for host and port
    """

    def __init__(self, host, port):
        self.config_instance = ConfigReader("Configuration/Config.ini")
        self.config_mime_type = MimeTypeReader("Configuration/MimeTypes.ini")
        self.config_access = AccessReader("Configuration/Access.ini")
        if host is None:
            self.host = self.config_instance.default_hostname
        else:
            self.host = host
        if port is None:
            self.port = int(self.config_instance.default_port)
        else:
            self.port = port
        self.access_logger = self.set_up_logger('ACCESS_LOGS', self.config_instance.access_debugging_folder + "/" +
                                                'Common.log')
        self.debug_logger = self.set_up_logger('DEBUG_LOGS', self.config_instance.debug_folder + "/" + 'Debug.log')
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    '''
    Function to set up logging handle and return it
    '''

    def set_up_logger(self, name, log_file, level=logging.DEBUG):
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
            self.debug_logger.debug("activate_server: function started")
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.wait_for_connections()
        except socket.error as err:
            self.debug_logger.debug(err)
            exit(1)

    def shut_down(self):
        try:
            self.server_socket.shutdown(socket.SHUT_RDWR)
        except Exception as err:
            self.debug_logger.debug(err)
            exit(1)

    '''
    Function to generate server response headers
    '''

    def gen_headers(self, response_code=0, content_length=0, content_type=None, requested_resource=None,
                    request_method=None):
        self.debug_logger.debug("gen_headers: Start")
        server_response_header = ''
        if response_code == 200:
            server_response_header = 'HTTP/1.1 200 OK\n'
        elif response_code == 400:
            server_response_header = "HTTP/1.1 400 Bad Request\n"
        elif response_code == 403:
            server_response_header = 'HTTP/1.1 403 Forbidden\n'
        elif response_code == 404:
            server_response_header = 'HTTP/1.1 404 Not Found\n'
        elif response_code == 500:
            server_response_header = 'HTTP/1.1 500 Internal Server Error\n'
        elif response_code == 505:
            server_response_header = 'HTTP/1.1 505 HTTP Version Not Supported\n'
        elif response_code == 501:
            server_response_header = "HTTP/1.1 501 Not Implemented\n"
        else:
            print(response_code)
        current_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S")
        current_date += " GMT"
        server_response_header += 'Date: ' + current_date + '\r\n'

        server_response_header += 'Server: ' + self.config_instance.server_name + '\r\n'
        server_response_header += 'Content-Length: ' + str(content_length) + '\r\n'
        if (request_method == "GET" or request_method == "HEAD") and response_code == 200:
            if requested_resource is None:
                server_response_header += 'Last-Modified: ' + current_date + '\r\n'
            elif not (os.path.exists(self.config_instance.root_folder + requested_resource)):
                server_response_header += 'Last-Modified: ' + current_date + '\r\n'
            else:
                modified_time = os.path.getmtime(self.config_instance.root_folder + requested_resource)
                modified_time = datetime.fromtimestamp(modified_time)
                modified_time = datetime.strftime(modified_time, "%a, %d %b %Y %H:%M:%S")
                modified_time += " GMT"
                server_response_header += 'Last-Modified: ' + modified_time + '\r\n'
        if content_length != 0 or (request_method == "GET" and response_code == 200):
            server_response_header += 'Content-Type: ' + content_type + '\r\n'
        if response_code == 501 or (request_method is not None and request_method == "OPTIONS" and
                                    requested_resource == "*"):
            server_response_header += 'Allow: GET, HEAD, OPTIONS, TRACE \r\n'
        elif request_method is not None and request_method == "OPTIONS" and requested_resource != "*":
            server_response_header += 'Allow: GET, HEAD, OPTIONS, TRACE \r\n'
        self.debug_logger.debug("gen_headers: " + server_response_header)
        server_response_header += 'Connection: close\r\n\r\n'
        self.debug_logger.debug(server_response_header)
        self.debug_logger.debug("gen_headers: End")
        return server_response_header

    '''
    Check if url is absolute
    '''

    def is_absolute(self, url):
        return bool(urlparse(url).netloc)

    '''
    Return error response header
    '''

    def return_error_response_header(self, request_method=None, response_code=0, conn=None, client_header=None,
                                     requested_resource=None):

        if request_method == "GET":
            error_file = "Error" + str(response_code) + ".html"
            file_handle = open(self.config_instance.error_folder + "/" + error_file, "rb")
            response_content = file_handle.read()
            file_handle.close()
            content_length = len(response_content)
            response_header = self.gen_headers(response_code=response_code, content_length=content_length,
                                               content_type=self.config_mime_type.check_mime_type(
                                                   self.config_instance.error_folder, error_file),
                                               request_method=request_method, requested_resource=requested_resource)
        else:
            content_length = 0
            response_header = self.gen_headers(response_code=response_code, content_length=content_length,
                                                request_method=request_method)

        server_response = response_header.encode()
        if request_method == "GET":
            server_response += response_content
        self.debug_logger.debug("return_response_header: " + str(server_response))
        conn.send(server_response)
        self.debug_logger.debug("return_response_header: Closing connection with client")
        conn.close()
        self.write_common_log(response_code, content_length, client_header)

    '''
    Validate HTTP headers
    '''

    def validate_header(self, client_header, conn):
        requested_resource = ""
        request_method = None
        host_missing = True
        self.debug_logger.debug("validate_header:" + str(client_header))
        for index_parse in range(0, (len(client_header))):
            if index_parse == 0:
                # Check if 1st line has three parts
                if len(client_header[index_parse].split(" ")) != 3:
                    response_code = 400
                    self.return_error_response_header(request_method=request_method, response_code=response_code,
                                                      conn=conn, client_header=client_header,
                                                      requested_resource=requested_resource)
                    return False, request_method, requested_resource
                # Split the first line of header by space
                parsed_components = client_header[index_parse].split(" ", 1)
                request_method = parsed_components[0]
                self.debug_logger.debug("validate_header: Requested Method: " + request_method)
                if not ((request_method == 'GET') | (request_method == 'HEAD') | (request_method == 'OPTIONS')
                        | (request_method == "TRACE")):
                    response_code = 501
                    self.return_error_response_header(request_method=request_method, response_code=response_code,
                                                      conn=conn, client_header=client_header,
                                                      requested_resource=requested_resource)
                    return False, request_method, requested_resource
                http_info = parsed_components[1].split(" ", -1)[-1]
                file_parts = parsed_components[1].split(" ", -1)
                for index_parts in range(0, len(file_parts) - 1):
                    requested_resource += file_parts[index_parts]
                self.debug_logger.debug("Requested File: " + requested_resource)
                self.debug_logger.debug("HTTP Info: " + http_info)
                if "HTTP/" in http_info:
                    http_version = http_info.split("/")[-1]
                    if re.match("^\d+?\.\d+?$", http_version) is None:
                        response_code = 400
                        self.return_error_response_header(request_method=request_method, response_code=response_code,
                                                          conn=conn, client_header=client_header,
                                                          requested_resource=requested_resource)
                        return False, request_method, requested_resource
                    if http_version != self.config_instance.http_version:
                        self.debug_logger.debug("validate_header: HTTP Version: " + http_version)
                        response_code = 505
                        self.return_error_response_header(request_method=request_method, response_code=response_code,
                                                          conn=conn, client_header=client_header,
                                                          requested_resource=requested_resource)
                        return False, request_method, requested_resource
                else:
                    response_code = 400
                    self.return_error_response_header(request_method=request_method, response_code=response_code,
                                                      conn=conn, client_header=client_header,
                                                      requested_resource=requested_resource)
                    return False, request_method, requested_resource
            else:
                parsed_components = client_header[index_parse].split(" ", 1)
                self.debug_logger.debug("validate_header: Key: " + parsed_components[0] + " Value: " +
                                        parsed_components[1])
                if parsed_components[0] == "Host:":
                    host_missing = False
                    self.debug_logger.debug("validate_header: Host Header line being parsed")
                    if len(parsed_components[1].split(" ")) > 1:
                        response_code = 400
                        self.return_error_response_header(request_method=request_method, response_code=response_code,
                                                          conn=conn, client_header=client_header,
                                                          requested_resource=requested_resource)
                        return False, request_method, requested_resource
                    try:
                        if ":" in parsed_components[1]:
                            ip_addr = parsed_components[1].split(":")[0]
                        else:
                            ip_addr = parsed_components[1]
                        if parsed_components[1] in requested_resource:
                            requested_resource = requested_resource.replace(parsed_components[1], "")
                            if "http://" in requested_resource or "https://" in requested_resource:
                                requested_resource = requested_resource.replace("https://","")
                                requested_resource = requested_resource.replace("http://","")
                                self.debug_logger.debug("validate_header: Hostname is relative: Requested File: "
                                                        + requested_resource)
                            self.debug_logger.debug("validate_header: requested_resource: " + requested_resource)
                        self.debug_logger.debug("validate_header: requested_resource: " + requested_resource)
                        self.debug_logger.debug("validate_header: Hostname: " + ip_addr)
                        socket.inet_aton(ip_addr)
                    except Exception as err:
                        self.debug_logger.debug("validate_header: " + str(err))
                        try:
                            socket.gethostbyname(ip_addr)
                            self.debug_logger.debug("validate_header: Hostname to IP: " + ip_addr)
                            if parsed_components[1] in requested_resource:
                                requested_resource = requested_resource.replace(parsed_components[1], "")
                                if "http://" in requested_resource or "https://" in requested_resource:
                                    requested_resource = requested_resource.replace("https://", "")
                                    requested_resource = requested_resource.replace("http://", "")
                                print(requested_resource)
                                self.debug_logger.debug("validate_header: Hostname is relative: Requested File: "
                                                        + requested_resource)
                        except Exception as err:
                            self.debug_logger.debug("validate_header: " + str(err))
                            response_code = 400
                            self.return_error_response_header(request_method=request_method,
                                                              response_code=response_code,
                                                              conn=conn, client_header=client_header,
                                                              requested_resource=requested_resource)
                            return False, request_method, requested_resource
                elif parsed_components[0] == "Connection:":
                    self.debug_logger.debug("validate_header: Connection parsed")
                    if not ((parsed_components[1] == "close") | (parsed_components[1] == "keep-alive")):
                        response_code = 400
                        self.return_error_response_header(request_method=request_method, response_code=response_code,
                                                          conn=conn, client_header=client_header,
                                                          requested_resource=requested_resource)
                        return False, request_method, requested_resource
                elif parsed_components[0] == "User-Agent:":
                    self.debug_logger.debug("validate_header: User Agent Parsed")
                    continue
                elif parsed_components[0] == "Accept:":
                    self.debug_logger.debug("validate_header: Accept Parsed")
                    continue
                elif ":" in parsed_components[0]:
                    self.debug_logger.debug(parsed_components[0] + "Parsed")
                    continue
                else:
                    self.debug_logger.debug("validate_header: Bad Header because not a valid header line")
                    response_code = 400
                    self.return_error_response_header(request_method=request_method, response_code=response_code,
                                                      conn=conn, client_header=client_header,
                                                      requested_resource=requested_resource)
                    return False, request_method, requested_resource
        if host_missing:
            self.debug_logger.debug("validate_header: Bad Header because not a valid header line")
            response_code = 400
            self.return_error_response_header(request_method=request_method, response_code=response_code,
                                              conn=conn, client_header=client_header,
                                              requested_resource=requested_resource)
            return False, request_method, requested_resource
        return True, request_method, requested_resource

    def create_directory_listing(self, path, resource_dir):
        file_html_page = open(self.config_instance.error_folder + "/DirectoryListing.html", "w")
        html_content = """
        <!DOCTYPE html>
        <html>
            <head>Index of {}</head> 
            <body>
                <h1> Index of {}</h1>
                {}
            </body>
        </html>"""
        if resource_dir != "/":
            directory_listing = [f for f in os.listdir(path + resource_dir)]
        else:
            directory_listing = [f for f in os.listdir(path)]

        table_content = ""
        for i in range(0, len(directory_listing)):
            if resource_dir != "/":
                modified_time = os.path.getctime(self.config_instance.root_folder + resource_dir + "/"
                                             + directory_listing[i])
            else:
                modified_time = os.path.getctime(self.config_instance.root_folder + resource_dir + directory_listing[i])
            modified_time = datetime.fromtimestamp(modified_time / 1000.0)
            modified_time = datetime.strftime(modified_time, "%a, %d %b %Y %H:%M:%S")
            if directory_listing != "/":
                if os.path.isfile(self.config_instance.root_folder + resource_dir + "/" + directory_listing[i]):
                    file_size = str(os.path.getsize(self.config_instance.root_folder + resource_dir + "/"
                                                + directory_listing[i]))
                else:
                    file_size = "--"
            else:
                if os.path.isfile(self.config_instance.root_folder + resource_dir + directory_listing[i]):
                    file_size = str(os.path.getsize(self.config_instance.root_folder + resource_dir
                                                    + directory_listing[i]))
                else:
                    file_size = "--"
            links_to_listings = "<a href= {}>{}</a>"
            if resource_dir != "/":
                self.debug_logger.debug("create_directory_listing: Requested Resource is not /")
                if os.path.isfile(self.config_instance.root_folder + resource_dir + "/" + directory_listing[i]):
                    links_to_listings = links_to_listings.format(resource_dir + "/" + directory_listing[i],
                                                                 directory_listing[i])
                    self.debug_logger.debug("create_directory_listing: Requested Resource is file: " + links_to_listings)
                else:
                    links_to_listings = links_to_listings.format(resource_dir + "/" + directory_listing[i] + "/",
                                                                 directory_listing[i] + "/")
                    self.debug_logger.debug("create_directory_listing: Requested Resource is dir: " +links_to_listings)
            else:
                self.debug_logger.debug("create_directory_listing: Requested Resource is /")
                if os.path.isfile(self.config_instance.root_folder + resource_dir + directory_listing[i]):
                    links_to_listings = links_to_listings.format(resource_dir + directory_listing[i],
                                                                 directory_listing[i])
                    self.debug_logger.debug("create_directory_listing: Requested Resource is file: " + links_to_listings)
                else:
                    links_to_listings = links_to_listings.format(resource_dir + directory_listing[i] + "/",
                                                                 directory_listing[i] + "/")
                    self.debug_logger.debug("create_directory_listing: Requested Resource is dir: " + links_to_listings)
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
        content = html_content.format(resource_dir, resource_dir, table_html)
        file_html_page.write(content)
        file_html_page.close()
        return content

    def fetch_resource(self, requested_resource, request_method, conn, client_header):

        if request_method == "GET" or request_method == "HEAD":
            self.debug_logger.debug("fetch_resource: request method: "+ request_method)
            requested_resource = unquote(requested_resource)
            for key in self.config_access.virtual_uri:
                if key in requested_resource:
                    requested_resource = requested_resource.replace(key, )
                    break
            if not os.path.exists(self.config_instance.root_folder + requested_resource):
                self.debug_logger.debug(str(self.config_instance.root_folder + requested_resource))
                self.debug_logger.debug("Requested resource missing 404: " + requested_resource)
                response_code = 404
                self.return_error_response_header(request_method=request_method, response_code=response_code,
                                                  conn=conn, client_header=client_header,
                                                  requested_resource=requested_resource)
            elif os.stat(self.config_instance.root_folder + requested_resource).st_uid != os.getuid():
                self.debug_logger.debug("fetch_resource: forbidden zone")
                self.debug_logger.debug(str(self.config_instance.root_folder + requested_resource))
                self.debug_logger.debug("File or folder is forbidden: 403")
                response_code = 403
                self.return_error_response_header(request_method=request_method, response_code=response_code,
                                                  conn=conn, client_header=client_header,
                                                  requested_resource=requested_resource)
            elif os.path.isdir(self.config_instance.root_folder + requested_resource):
                response_code = 200
                if request_method == "GET":
                    response_content = self.create_directory_listing(self.config_instance.root_folder,
                                                                     requested_resource)
                    self.debug_logger.debug(response_content)
                    response_content = response_content.encode()
                    content_length = len(response_content)
                else:
                    content_length = 0
                response_header = self.gen_headers(response_code=response_code, content_length=content_length,
                                                   content_type=self.config_mime_type.check_mime_type
                                                   (self.config_instance.error_folder, "DirectoryListing.html"),
                                                   requested_resource=requested_resource, request_method=request_method)
                server_response = response_header.encode()
                if request_method == "GET":
                    server_response += response_content
                self.debug_logger.debug(str(server_response))
                conn.send(server_response)
                self.debug_logger.debug("Closing connection with client")
                conn.close()
                self.write_common_log(response_code, content_length, client_header)
            elif os.path.isfile(self.config_instance.root_folder + requested_resource):
                self.debug_logger.debug("fetch_resource: Is File:" + requested_resource)
                response_code = 200
                file_handle = open(self.config_instance.root_folder + requested_resource, "rb")
                file_content = file_handle.read()
                file_handle.close()
                content_length = len(file_content)
                response_header = self.gen_headers(response_code=response_code, content_length=content_length,
                                                   content_type=self.config_mime_type.check_mime_type
                                                   (self.config_instance.root_folder, requested_resource),
                                                   requested_resource=requested_resource, request_method=request_method)
                server_response = response_header.encode()
                self.debug_logger.debug(str(server_response))
                if request_method == "GET":
                    server_response += file_content
                conn.send(server_response)
                self.debug_logger.debug("Closing connection with client")
                conn.close()
                self.write_common_log(response_code, content_length, client_header)

        elif request_method == "OPTIONS" or request_method == "TRACE":
            self.debug_logger.debug("fetch_resource: request method" + request_method)
            response_code = 200
            if request_method == "TRACE":
                response_content = ""
                for parts in client_header:
                    response_content += parts + "\r\n"
                response_content += "\r\n"
                response_content = response_content.encode()
                content_length = len(response_content)
                response_header = self.gen_headers(response_code=response_code, content_length=content_length,
                                                   content_type="message/http", requested_resource=requested_resource)
            else:
                content_length = 0
                response_header = self.gen_headers(response_code=response_code, content_length=content_length,
                                                   content_type="text/html", requested_resource=requested_resource,
                                                   request_method="OPTIONS")
            server_response = response_header.encode()
            if request_method == "TRACE":
                server_response += response_content
            self.debug_logger.debug(str(server_response))
            conn.send(server_response)
            self.debug_logger.debug("Closing connection with client")
            conn.close()
            self.write_common_log(response_code, content_length, client_header)

    def write_common_log(self, response_code, content_length, client_header):
        current_date = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
        if self.config_instance.resolve_hostname == "Y":
            hostname = socket.gethostbyname(self.host)
        else:
            hostname = self.host
        self.access_logger.debug(hostname + " - " + "- " + "[" + current_date + "] " + client_header[0] + " "
                                 + str(response_code) + " " + str(content_length) + "\n")

        self.debug_logger.debug(self.host + " - " + "- " + "\"[" + current_date + "]\" " + client_header[0] + " "
                                + str(response_code) + " " + str(content_length) + "\n")

    def wait_for_connections(self):
        while True:
            self.debug_logger.debug("wait_for_connections: Awaiting New connection")
            self.server_socket.listen(3)  # maximum number of queued connections
            conn, addr = self.server_socket.accept()
            self.debug_logger.debug("wait_for_connections: Got connection from:" + str(addr))
            data = conn.recv(1024)  # receive data from client
            client_message = bytes.decode(data)  # decode it to string
            self.debug_logger.debug("wait_for_connections: Request Header" + str(client_message))
            client_message = client_message.replace("\r\n", "\n")
            client_headers = client_message.split('\n')
            client_header = list(filter(lambda a: a != "", client_headers))
            self.debug_logger.debug("wait_for_connections: Formatted Request Header: " + str(client_header))
            try:
                is_header_valid, request_method, requested_resource = self.validate_header(client_header, conn)
                self.debug_logger.debug("wait_for_connections: Is header valid: " + str(is_header_valid))
                if is_header_valid:
                    self.fetch_resource(requested_resource, request_method, conn, client_header)
            except Exception as err:
                self.debug_logger.debug("wait_for_connections: " + str(err))
                response_code = 500
                self.return_error_response_header(response_code=response_code, conn=conn, client_header=client_header)


s = Server("0.0.0.0", 80)
s.activate_server()
