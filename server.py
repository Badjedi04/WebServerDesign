import socket
import sys
from threading import Thread, Timer

"""
Function to start Server

Parameters:
    ip_addr (str): IP Address
    port (int): Port Number

Returns:

"""
def run_server(ip_addr, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip_addr, port))
    wait_for_connections(server_socket)

def wait_for_connections(server_socket):
    while True:
        server_socket.listen(3)
        conn, addr = server_socket.accept()
        Thread(target=start_client, args=(conn, addr)).start()


def close_connection(conn, connection_timeout):
    connection_timeout.cancel()
    conn.shutdown(socket.SHUT_RDWR)
    conn.close()


def start_client(conn, addr):
    while True:
        try:
            data = conn.recv(1024)  # receive data from client
            connection_timeout = Timer(30, close_connection, args=(conn, connection_timeout))
            connection_timeout.start()
            conn.sendall(data)
            break
        except Exception as e:
            print("connection closed" + str(e))
            sys.exit()
   