import socket
import sys
from threading import Thread

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
    server_socket.listen(3)
    conn, addr = server_socket.accept()
    Thread(target=start_client, args=(conn, addr)).start()


def start_client(conn, addr):
    while True:
        try:
            data = conn.recv(1024)  # receive data from client
            conn.sendall(data)
            conn.close()
            break
        except Exception as e:
            print("connection closed" + str(e))
            sys.exit()

        