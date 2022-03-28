#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 8005 Network Security & Applications Development
Final Project
Student:
    - Hung Yu (Angus) Lin, A01034410, Set 6J
----------------------------------------------------------------------------------------------------
client.py
    The client of a client/server secure SSL chat application. The server accepts connections
    on a specific port and once clients have established a connection with it, it will echo
    whatever it receivers to other connected clients.
----------------------------------------------------------------------------------------------------
"""
import socket
import sys
from socket import *
from _thread import *
import ssl

LOG_PATH = "client_log.txt"
CONFIGURATION_PATH = "client_configuration.txt"


def read_configuration():
    """
    Reads configuration file and set Client variables.
    :return: configuration
    """

    configuration = {
        'server_address_IPv4': '',
        'server_address_IPv6': '',
        'server_port_IPv4': 0,
        'server_port_IPv6': 0,
        'server_port_TLS': 0,
        'echo_string': '',
    }

    with open(file=CONFIGURATION_PATH, mode='r', encoding='utf-8') as file:
        fp = [line.rstrip('\n') for line in file]
        for line in fp:
            if line.isspace() or line.startswith('#'):
                continue

            config_data = line.split('=')
            if config_data[0] in configuration:
                if config_data[0] in ('server_address_IPv4', 'server_address_IPv6', 'echo_string'):
                    configuration[config_data[0]] = config_data[1]
                else:
                    data = config_data[1]
                    if data.isdigit():
                        configuration[config_data[0]] = int(config_data[1])
                    else:
                        print("Invalid configuration, server ports must be integers.")
                        exit()
    return configuration


def client_echo(conn, echo):
    conn.sendall(echo.encode('utf8'))
    print("Sending String to Server: \t", echo)
    data = conn.recv(1024)
    if data:
        print("Reply from Server: \t\t\t", data.decode('utf8'))


def start_client():
    print("Starting Client.")
    configuration = read_configuration()
    IPv4_HOST = configuration['server_address_IPv4']
    IPv6_HOST = configuration['server_address_IPv6']
    IPv4_PORT = configuration['server_port_IPv4']
    IPv6_PORT = configuration['server_port_IPv6']
    TLS_PORT = configuration['server_port_TLS']
    echo_string = configuration['echo_string']

    try:
        # IPv4 Socket Echo Request.
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            sock.connect((IPv4_HOST, IPv4_PORT))
            print(f"\nIPv4 connection to Server:\t IP = {IPv4_HOST}, Port = {IPv4_PORT}")
            client_echo(sock, echo_string)

        # IPv6 Socket Echo Request.
        addrinfo = getaddrinfo(IPv6_HOST, IPv6_PORT, AF_INET6, SOCK_STREAM, SOL_TCP)
        (family, socktype, proto, canonname, sockaddr) = addrinfo[0]
        with socket(family, socktype, proto) as sock:
            sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            sock.connect(sockaddr)
            sock_name = sock.getsockname()
            print(f"\nIPv6 connection to Server:\t IP = {IPv6_HOST}, Port = {IPv6_PORT}")
            print(sock_name)
            client_echo(sock, echo_string)

        # TLS Socket Echo Request.
        with socket(AF_INET, SOCK_STREAM) as my_sock:
            my_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            sock = ssl.wrap_socket(my_sock, ssl_version=ssl.PROTOCOL_TLS,
                                   certfile="cert.pem", keyfile="cert.pem", )

            sock.connect((IPv4_HOST, TLS_PORT))
            print(f"\nTLS connection to Server:\t IP = {IPv4_HOST}, Port = {TLS_PORT}")
            client_echo(sock, echo_string)

    except error as msg:
        print('Error Code : ' + str(msg[0]) + ' Message ' + msg[1])


if __name__ == "__main__":
    start_client()

