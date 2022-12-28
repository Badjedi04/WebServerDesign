#!usr/bin/env/python3
import socket
import logging
import logging.handlers
from threading import Timer
from threading import Thread
import sys
import os

from src.Constants import *
from src.ValidateHeader import ValidateHeader
from src.FetchResource import FetchResource
from src.ReturnResponseHeaders import ReturnResponseHeaders
from src.ConfigParsers.ConfigReader import ConfigReader
from src.ConfigParsers.AccessReader import AccessReader
from src.ConfigParsers.MimeTypeReader import MimeTypeReader
from src.ConfigParsers.ContentEncodingParser import ContentEncodingParser
from src.ConfigParsers.ContentLanguageParser import ContentLanguageParser
from src.ConfigParsers.CharsetParser import CharsetParser
from src.ConfigParsers.AuthorizationParser import AuthorizationParser
from src.HttpHeadersObject import HTTPHeadersObject


class Server:

    """
    Init Function instantiates Config File, Log Files and socket.
    Sets the value for host and port
    """

    def __init__(self, host=None, port=None):
        self.__config_instance = ConfigReader("Configuration" + FORWARD_SLASH + "Config.ini")
        self.__config_access = AccessReader("Configuration" + FORWARD_SLASH + "Access.ini")
        self.__mime_type_parser = MimeTypeReader("Configuration" + FORWARD_SLASH + "MimeTypes.ini")
        self.__content_encoding_parser = ContentEncodingParser("Configuration" + FORWARD_SLASH
                                                               + "ContentEncoding.ini")
        self.__content_language_parser = ContentLanguageParser("Configuration" + FORWARD_SLASH + "ContentLanguage.ini")
        self.__charset_parser = CharsetParser("Configuration" + FORWARD_SLASH + "CharacterSetEncoding.ini")
        self.__authorization_parser = AuthorizationParser("Configuration" + FORWARD_SLASH + "Authorization.ini")
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
        if os.path.exists(self.__config_instance.debug_folder + "/DigestAuthorizationInfo.txt"):
            os.remove(self.__config_instance.debug_folder + "/DigestAuthorizationInfo.txt")
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
            self.__debug_logger.debug("shut_down: Closing Connection: " + str(socket_connection))
            self.__connection_timeout.cancel()
            socket_connection.shutdown(socket.SHUT_RDWR)
            socket_connection.close()

        except Exception as err:
            self.__debug_logger.debug("shut_down: Error: " + str(err))

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
        report = None
        return_response_header = ReturnResponseHeaders(self.__debug_logger, self.__access_logger,
                                                       self.__config_instance, self.__mime_type_parser,
                                                       self.__content_encoding_parser, self.__content_language_parser,
                                                       self.__charset_parser)
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
                                                  self.__generate_timeout_header, args=(conn, return_response_header))
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
                        report = val_header.validate_header(client_header)
                        report["connection"] = conn
                        self.__debug_logger.debug("__start_client: After Validating Header: " + str(report))
                        if report["response"]["status_code"] is not None:
                            response = return_response_header.return_error_response_headers(report=report)
                            if response == CLOSE_CONNECTION:
                                self.shut_down(report["connection"])
                                break
                        else:
                            serve_response = FetchResource(self.__debug_logger, self.__config_instance,
                                                           self.__mime_type_parser, self.__content_language_parser,
                                                           self.__content_encoding_parser, self.__charset_parser,
                                                           self.__authorization_parser)
                            report = serve_response.fetch_resource(report=report)
                            self.__debug_logger.debug("__start_client: After Fetching Resource: " + str(report))
                            response = return_response_header.create_status_200_response_headers(report, conn,
                                                                                                 client_header)
                            if response == CLOSE_CONNECTION:
                                self.shut_down(report["connection"])
                                break

                except Exception as err:
                    self.__debug_logger.debug("__start_client: Error: " + str(err))
                    self.__connection_timeout.cancel()
                    report["response"]["status_code"] = STATUS_INTERNAL_SERVER_ERROR
                    response = return_response_header.return_error_response_headers(report=report)
                    if response == CLOSE_CONNECTION:
                        self.shut_down(report["connection"])
                        break
    '''
    Function called on timeout
    '''

    def __generate_timeout_header(self, conn, return_response_header=None):
        self.__debug_logger.debug("__generate_timeout_header: called")
        report = HTTPHeadersObject().report
        report["response"]["status_code"] = STATUS_REQUEST_TIMEOUT
        report["connection"] = conn
        report["request"]["http_version"] = "1.1"
        report["request"]["connection_close"] = True
        response = return_response_header.return_error_response_headers(report=report)
        if response == CLOSE_CONNECTION:
            self.shut_down(report["connection"])

