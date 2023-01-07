import socket
import sys
from threading import Thread, Timer

import server_parser.parser as parser
import server_responder.responder as responder

"""
Function to start Server
Parameters:
    ip_addr (str): IP Address
    port (int): Port Number
Returns:
"""
def run_server(config):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((config["SERVER"]["ip_addr"], config["SERVER"]["port"]  ))
    wait_for_connections(server_socket, config)

def wait_for_connections(server_socket, config):
    while True:
        server_socket.listen(config["SERVER"]["connections"])
        conn, addr = server_socket.accept()
        Thread(target=start_client, args=(conn, addr, config)).start()


def close_connection(conn, timeout=False, config=None):
    sys.stdout.write("Going to close connection\n")
    sys.stdout.write("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
    sys.stdout.write("Going to close connection\n")
    sys.stdout.write("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
    if timeout:
        report = {}
        report["response"] = {}
        report["response"]["http_version"] = config["HEADERS"]["http_version"]
        report["response"]["status_code"] = "418"
        report["response"]["status_text"] = config["STATUS_CODE"][report["response"]["status_code"]]
        report["response"]["Server"] = config["HEADERS"]["server"]
        report["response"]["Connection"] = "close" 
        
        conn.send(responder.server_reply(config, report))
    sys.stdout.write("Going to close connection\n")
    sys.stdout.write("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
    if timeout:
        report = {}
        report["response"] = {}
        report["response"]["http_version"] = config["HEADERS"]["http_version"]
        report["response"]["status_code"] = "408"
        report["response"]["status_text"] = config["STATUS_CODE"][report["response"]["status_code"]]
        report["response"]["Server"] = config["HEADERS"]["server"]
        report["response"]["Connection"] = "close" 
        
        conn.send(responder.server_reply(config, report))
    conn.shutdown(socket.SHUT_RDWR)
    conn.close()


def start_client(conn, addr, config):
    connection_timeout = None
    while True:
        try:
            data = conn.recv(1024)  # receive data from client
            if data:
                if connection_timeout is not None:
                    connection_timeout.cancel()
                connection_timeout = Timer(config["SERVER"]["timeout"], close_connection, args=(conn, True, config))
                connection_timeout.start()                
                sys.stdout.write("*********************************************************************************\n")
                sys.stdout.write("Server Data received\n")
                response_header = data.decode()
                response_header = decompose_headers(response_header, config)
                for header in response_header:
                    server_report = parser.get_request_header(header, config)
                    sys.stdout.write("Server Data Parsed\n")
                    server_response = responder.handle_server_response(config, server_report)
                    if server_response:
                        conn.send(server_response)
                        if "Connection" in server_report["request"] and server_report["request"]["Connection"] == "close":
                            sys.stdout.write("Connection close called due to Connection:close header\n")
                            connection_timeout.cancel()
                            close_connection(conn)
                    else:
                        conn.send(str.encode("null"))
                sys.stdout.write("Server response sent\n")
                sys.stdout.write("???????????????????????????????????????????????????????????????????????????????\n")
                break
        except Exception as e:
            sys.stderr.write(f'start_client:error: {e}\n')


def decompose_headers(response_header, config):
    sys.stdout.write(f'decompose_headers called\n')
    list_header_splitter = response_header.splitlines()
    list_header = []
    sys.stdout.write(f'Header splitted: \n {list_header_splitter}\n')
    temp = ""
    for line in list_header_splitter:
        if len(line) > 0:
            temp += line + "\n"
        else:
            temp += "\n"
            list_header.append(temp)
            temp = ""
        sys.stdout.write(f'Header splitted each: \n {list_header}\n')
    return list_header