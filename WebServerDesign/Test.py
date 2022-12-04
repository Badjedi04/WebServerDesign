import socket
import time


class Server:

    def __init__(self, host='',port=5010):
        self.host = host
        self.port = port
        self.www_dir = "www"

    def activate_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
        except socket.error as err:
            print(err)
            exit()
        self.wait_for_connections()

    def shut_down(self):
        try:
            self.server_socket.shutdown(socket.SHUT_RDWR)
        except Exception as err:
            print(err)
            exit()

    def gen_headers(self, code, content_length, content_type):
        h = ''
        if code == 200:
            h = 'HTTP/1.1 200 OK\n'
        elif code == 404:
            h = 'HTTP/1.1 404 Not Found\n'
        elif code == 505:
            h = 'HTTP/1.1 505 HTTP Version Not Supported'
        elif code == 501:
            h = "HTTP/1.1 501 Not Implemented"
        current_date = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
        h += 'Date: ' + current_date + '\r\n'
        h += 'Server: Simple-Python-HTTP-Server\r\n'
        h += 'Content-Lenth: ' + str(content_length) + '\r\n'
        h += 'Last-Modified: ' + current_date + '\r\n'
        h += 'Content-Type: ' + content_type + '\r\n'
        if code == 501:
            h += 'Allow: GET, HEAD, OPTIONS, TRACE \r\n'
        h += 'Connection: close\r\n\r\n'  # signal that the conection wil be closed after complting the request

        return h

    def wait_for_connections(self):
        while True:
            print("Awaiting New connection")
            self.server_socket.listen(3)  # maximum number of queued connections
            conn, addr = self.server_socket.accept()
            print("Got connection from:", addr)
            data = conn.recv(1024)  # receive data from client
            response_message = bytes.decode(data)  # decode it to string
            print(response_message)
            request_method = response_message.split(' ')[0]
            print("Method: ", request_method.split(" "))
            print("Request body: ", response_message)
            print(response_message.split(" "))
            response_message = response_message.replace("\r\n", " ")
            if (request_method == 'GET') | (request_method == 'HEAD') | (request_method == 'OPTIONS') \
                    | (request_method == "TRACE"):
                parsed_header = response_message.split(' ')
                print(parsed_header)

                for index_parse in range(0, len(parsed_header)):
                    if "HTTP" in parsed_header[index_parse]:
                        http_version = parsed_header[index_parse].split("/")[-1]
                        if http_version != "1.1":
                            response_content = b"<html><body><p>Error 505: HTTP Version Not Supported</p>" \
                                               b"<p>Python HTTP server</p></body></html>"
                            response_header = self.gen_headers(505, len(response_content), "text/html")
                            server_response = response_header.encode()
                            server_response += response_content
                            flag = 0
                            break
                if flag == 1:
                    index_parse += 1
                    if "Host" == parsed_header[index_parse]:
                        if ":" in parsed_header[index_parse + 1]:
                            port_number = parsed_header[index_parse + 1].split(":")[-1]
                            if not port_number.isdigit():
                                response_content = b"<html><body><p>Error 400: Bad Request Header</p>" \
                                                   b"<p>Python HTTP server</p></body></html>"
                                response_header = self.gen_headers(400, len(response_content), "text/html")
                                server_response = response_header.encode()
                                server_response += response_content
                                flag = 0
                    index_parse += 2
                    if not ":" in parsed_header[index_parse]:
                        response_content = b"<html><body><p>Error 400: Bad Request Header</p>" \
                                           b"<p>Python HTTP server</p></body></html>"
                        response_header = self.gen_headers(400, len(response_content), "text/html")
                        server_response = response_header.encode()
                        server_response += response_content
                        flag = 0

                conn.send(server_response)
                print("Closing connection with client")
                conn.close()
            else:
                response_content = b"<html><body><p>Error 501: Not Implemented</p>" \
                                   b"<p>Python HTTP server</p></body></html>"
                response_header = self.gen_headers(501, len(response_content), "text/html")
                server_response = response_header.encode()
                server_response += response_content
                print(server_response)
                conn.send(server_response)
                print("Closing connection with client")
                conn.close()
                # file_requested = file_requested[1]  # get 2nd element

                # file_requested = file_requested.split('?')[0]  # disregard anything after '?'
                '''
                if file_requested == '/':  # in case no file is specified by the browser
                    file_requested = '/index.html'  # load index.html by default
                file_requested = self.www_dir + file_requested
                print("Serving web page [", file_requested, "]")
                try:
                    file_handler = open(file_requested, 'rb')
                    if (request_method == 'GET'):  # only read the file when GET
                        response_content = file_handler.read()  # read file content
                    file_handler.close()
                    response_headers = self._gen_headers(200)
                except Exception as e:  # in case file was not found, generate 404 page
                    print("Warning, file not found. Serving response code 404\n", e)
                    response_headers = self._gen_headers(404)
                    if (request_method == 'GET'):
                        response_content = b"<html><body><p>Error 404: File not found</p><p>Python HTTP server</p></body></html>"
                        server_response = response_headers.encode()  # return headers for GET and HEAD
                if (request_method == 'GET'):
                    server_response += response_content  # return additional conten for GET only
                conn.send(server_response)
                print("Closing connection with client")
                conn.close()
            else:
                print("Unknown HTTP request method:", request_method)
            '''
    '''
    def graceful_shutdown(sig, dummy):
        s.shutdown()  # shut down the server
        import sys
        sys.exit(1)
    '''


s = Server("0.0.0.0",80)
s.activate_server()
