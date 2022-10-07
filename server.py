import socket
import sys
from threading import Thread, Timer

import parser
import report.report as report
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


def close_connection(conn):
    conn.shutdown(socket.SHUT_RDWR)
    conn.close()


def start_client(conn, addr, config):
    while True:
        try:
            data = conn.recv(1024)  # receive data from client
            connection_timeout = Timer(30, close_connection, args=(conn))
            connection_timeout.start()
            if data:
                sys.stdout.write("Server Data received\n")
                response = parser.get_request_header(data.decode(), config)
                sys.stdout.write("Server Data Parsed\n")
                conn.send(report.handle_server_response(config, response))
                sys.stdout.write("Server response sent\n")
                break
            else:
                sys.stdout.write("Server No Data received\n")
        except Exception as e:
            sys.stderr.write(f'start_client:error: {e}\n')
            sys.exit()
   