#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 8005 Network Security & Applications Development
Final Project
Student:
    - Hung Yu (Angus) Lin, A01034410, Set 6J
----------------------------------------------------------------------------------------------------
server.py
    The server of a client/server secure SSL chat application. The server accepts connections
    on a specific port and once clients have established a connection with it, it will echo
    whatever it receivers to other connected clients.
----------------------------------------------------------------------------------------------------
"""
from socket import *
from _thread import *
import ssl


LOG_PATH = "server_log.txt"
CONFIGURATION_PATH = "server_configuration.txt"


def read_configuration():
    """
    Reads configuration file and set Server variables.
    :return: configuration
    """

    configuration = {
        'server_address_IPv4': '',
        'server_address_IPv6': '',
        'server_port_IPv4': 0,
        'server_port_IPv6': 0,
        'server_port_TLS_IPv4': 0,
        'server_port_TLS_IPv6': 0,
    }

    with open(file=CONFIGURATION_PATH, mode='r', encoding='utf-8') as file:
        fp = [line.rstrip('\n') for line in file]
        for line in fp:
            if line.isspace() or line.startswith('#'):
                continue

            config_data = line.split('=')
            if config_data[0] in configuration:
                if config_data[0] in ('server_address_IPv4', 'server_address_IPv6'):
                    configuration[config_data[0]] = config_data[1]
                else:
                    data = config_data[1]
                    if data.isdigit():
                        configuration[config_data[0]] = int(config_data[1])
                    else:
                        print("Invalid configuration, server ports must be integers.")
                        exit()
    return configuration


def server_thread(sock):
    conn, addr = sock.accept()
    print('Client Connected: \t\t\t\t', conn.getpeername())
    while True:
        data = conn.recv(1024)
        if data:
            print(conn.getpeername(), ' Sent:', data.decode('utf8'))
            print("Server echoing: \t\t\t\t", data.decode('utf8'))
            conn.sendall(data)
        else:
            print('Closed Connection: \t\t\t\t', conn.getpeername(), '\n')
            conn.close()
            break


def start_server():
    print("Starting Server.\n")
    configuration = read_configuration()
    IPv4_HOST = configuration['server_address_IPv4']
    IPv6_HOST = configuration['server_address_IPv6']
    IPv4_PORT = configuration['server_port_IPv4']
    IPv6_PORT = configuration['server_port_IPv6']
    TLS_IPv4_PORT = configuration['server_port_TLS_IPv4']
    TLS_IPv6_PORT = configuration['server_port_TLS_IPv6']

    try:
        addrinfo = getaddrinfo(IPv6_HOST, IPv6_PORT, AF_INET6, SOCK_STREAM, SOL_TCP)
        print(addrinfo)
        (family, socktype, proto, canonname, sockaddr) = addrinfo[0]

        addrinfo2 = getaddrinfo(IPv6_HOST, TLS_IPv6_PORT, AF_INET6, SOCK_STREAM, SOL_TCP)
        (family2, socktype2, proto2, canonname2, sockaddr2) = addrinfo2[0]

        with socket(AF_INET, SOCK_STREAM) as IPv4_sock, \
                socket(family, socktype, proto) as IPv6_sock, \
                socket(AF_INET, SOCK_STREAM) as sock1, \
                socket(family2, socktype2, proto2) as sock2:

            IPv4_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            IPv4_sock.bind((IPv4_HOST, IPv4_PORT))
            IPv4_sock.listen(10)
            print("Listening on: ", IPv4_sock.getsockname())
            start_new_thread(server_thread, (IPv4_sock,))

            IPv6_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            IPv6_sock.bind(sockaddr)
            IPv6_sock.listen(10)
            print("Listening on: ", IPv6_sock.getsockname())
            start_new_thread(server_thread, (IPv6_sock,))

            sock1.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            TLS_IPv4_sock = ssl.wrap_socket(sock1, ssl_version=ssl.PROTOCOL_TLS,
                                       certfile="cert.pem", keyfile="cert.pem",)
            TLS_IPv4_sock.bind((IPv4_HOST, TLS_IPv4_PORT))
            TLS_IPv4_sock.listen(10)
            print("Listening on: ", TLS_IPv4_sock.getsockname())
            start_new_thread(server_thread, (TLS_IPv4_sock,))

            sock2.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            TLS_IPv6_sock = ssl.wrap_socket(sock2, ssl_version=ssl.PROTOCOL_TLS,
                                       certfile="cert.pem", keyfile="cert.pem", )
            TLS_IPv6_sock.bind(sockaddr2)
            TLS_IPv6_sock.listen(10)
            print("Listening on: ", TLS_IPv6_sock.getsockname(), "\n")

            conn, addr = TLS_IPv6_sock.accept()
            print('Client Connected: \t\t\t\t', conn.getpeername())
            while True:
                data = conn.recv(1024)
                if data:
                    print(conn.getpeername(), ' Sent:', data.decode('utf8'))
                    print("Server echoing: \t\t\t\t", data.decode('utf8'))
                    conn.sendall(data)
                else:
                    print('Closed Connection: \t\t\t\t', conn.getpeername())
                    conn.close()
                    break

    except error as msg:
        print('Error Code : ' + str(msg[0]) + ' Message ' + msg[1])


if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt as e:
        print("Server Shutdown")
        exit()