import socket
import sys
from WebServerDesign.Testing.RequestHeaders import *


class Tester:

    def __init__(self, host='',port=5010, request_header="" ):
        self.host = host
        self.port = port
        self.request_header = request_header.encode()

    def activate_client(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((self.host, self.port))
        except Exception as err:
            print(err)
            exit()
        self.connect_to_server()

    def connect_to_server(self):
        self.client_socket.send(self.request_header)
        response = self.client_socket.recv(4096)
        # response = response.decode()
        print(response)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == 1:
            c = Tester("0.0.0.0", 5010, TEST_200)
            c.activate_client()
        elif sys.argv[1] == 2:
            c = Tester("0.0.0.0", 5010, TEST_HTTP_VERSION)
            c.activate_client()
        elif sys.argv[1] == 3:
            c = Tester("0.0.0.0", 5010, TEST_HTTP_METHOD)
            c.activate_client()
        elif sys.argv[1] == 4:
            c = Tester("0.0.0.0", 5010, TEST_PPT_MIME_TYPE)
            c.activate_client()
    else:
        c = Tester("0.0.0.0", 5010, TEST_200)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_HTTP_VERSION)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_HTTP_METHOD)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_PPT_MIME_TYPE)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_XML_MIME_TYPE)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_HTML_MIME_TYPE)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_NO_MIME_TYPE)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_JPEG_MIME_TYPE)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_GIF_MIME_TYPE)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_TEXT_MIME_TYPE)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_NO_EXTENTION)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_HTML_SPACE_MIME_TYPE)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_HEAD_HTML_SPACE_MIME_TYPE)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_TRACE_HEADER)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_OPTIONS_HEADER)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_400)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_HEADER)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_403)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_403_FOLDER)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_HTTP_MISSING)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_HOST_MISSING)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_ABSOLUTE_URI)
        c.activate_client()
        c = Tester("0.0.0.0", 5010, TEST_ABSOLUTE_URI_1)
        c.activate_client()