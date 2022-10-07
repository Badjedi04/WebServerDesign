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
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((config["SERVER"]["ip_addr"], config["SERVER"]["port"]  ))
    connection_timeout = None

    wait_for_connections(server_socket, config, connection_timeout)

def wait_for_connections(server_socket, config, connection_timeout):
    while True:
        server_socket.listen(config["SERVER"]["connections"])
        conn, addr = server_socket.accept()
        Thread(target=start_client, args=(conn, addr, config, connection_timeout)).start()


def close_connection(conn):
    sys.stdout.write("Going to close connection\n")
    sys.stdout.write("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
    conn.shutdown(socket.SHUT_RDWR)
    conn.close()


def start_client(conn, addr, config, connection_timeout):
    try:
        data = conn.recv(1024)  # receive data from client

        if data:
            if connection_timeout is not None:
                connection_timeout.cancel()
            connection_timeout = Timer(15, close_connection, args=(conn))
            connection_timeout.start()                
            sys.stdout.write("*********************************************************************************\n")
            sys.stdout.write("Server Data received\n")
            response = parser.get_request_header(data.decode(), config)
            sys.stdout.write("Server Data Parsed\n")
            conn.send(report.handle_server_response(config, response))
            sys.stdout.write("Server response sent\n")
            sys.stdout.write("???????????????????????????????????????????????????????????????????????????????\n")

        else:
            sys.stdout.write("Server No Data received\n")
    except Exception as e:
        sys.stderr.write(f'start_client:error: {e}\n')
        sys.exit()
   