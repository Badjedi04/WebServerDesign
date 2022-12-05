import socket


class Tester:

    def __init__(self, host='',port=5010, testing_option=0):
        self.host = host
        self.port = port
        self.testing_option = testing_option

    def activate_client(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((self.host, self.port))
        except Exception as err:
            print(err)
            exit()
        if self.testing_option == 1:
            request_header = self.test_http_version_fail().encode()
            self.connect_to_server(request_header)
            request_header = self.test_http_version_pass().encode()
            self.connect_to_server(request_header)
        else:
            request_header = self.test_http_version_fail().encode()
            self.connect_to_server(request_header)
            request_header = self.test_http_version_pass().encode()
            self.connect_to_server(request_header)

    def connect_to_server(self, request_header):
        self.client_socket.send(request_header)
        response = self.client_socket.recv(4096)
        print(response)

    '''
    Test HTTP Version Fail Case
    '''
    def test_http_version_fail(self):
        self.connect_to_server()
        h = 'GET / HTTP/3.1\r\n'
        h += 'Host: 127.0.0.1:5010\r\n'
        h += 'User-Agent: Tester/0.1\r\n'
        h += 'Accept: */*\r\n\r\n'  # signal that the conection wil be closed after complting the request
        return h

    '''
    Test HTTP Version Pass Case
    '''
    def test_http_version_pass(self):
        self.connect_to_server()
        h = 'GET / HTTP/1.1\r\n'
        h += 'Host: 127.0.0.1:5010\r\n'
        h += 'User-Agent: Tester/0.1\r\n'
        h += 'Accept: */*\r\n\r\n'  # signal that the conection wil be closed after complting the request
        return h


c= Tester("0.0.0.0", 5010, 0)
c.activate_client()
