#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 8005 Network Security & Applications Development
Final Project
Student:
    - Hung Yu (Angus) Lin, A01034410, Set 6J
----------------------------------------------------------------------------------------------------
portforward.py
    A simple port forwarding server that forwards any incoming
    Implemented with epoll (edge-triggered) asynchronous server to handle multiple simultaneous
    two-way traffic.
----------------------------------------------------------------------------------------------------
"""
import resource
import time
from resource import setrlimit
from socket import *
from _thread import *
from contextlib import contextmanager
import socket
import select
import ssl


class ServerSummary:
    """
    Holds varies statistics summarize scalability and performance stress test for the epoll server.
    """

    def __init__(self, host_ip):
        self.host_ip = host_ip
        self.total_client_conns = 0
        self.total_data_forward = 0


class ClientSocketInfo:
    """
    Holds varies statistics of individual client connections for further processing and to log.
    """

    def __init__(self, src_sock, fwd_sock):
        self.src_sock = src_sock
        self.fwd_sock = fwd_sock
        self.echo_request = ''
        self.total_data_forward = 0


class PortForward:
    """
    Holds information for a port forward entry of IP:Port -> IP:Port.
    """

    def __init__(self, ipvtype, src_ip, src_port, fw_ip, fw_port, tls):
        self.ipvtype = ipvtype
        self.src_ip = src_ip
        try:
            self.src_port = int(src_port)
        except ValueError:
            print(f"Port numbers must be integers. '{src_port}' is invalid.")
            exit()
        self.fw_ip = fw_ip
        try:
            self.fw_port = int(fw_port)
        except ValueError:
            print(f"Port numbers must be integers.'{fw_port}' is invalid.")
            exit()
        if tls == "TLS":
            self.is_tls = True
        else:
            self.is_tls = False

LOG_PATH = "portforward_log.txt"
CONFIGURATION_PATH = "portforward_config.txt"
BUFFER_SIZE = 4096
clients_summary = {}
configuration = {
    'host_address_IPv4': '',
    'host_address_IPv6': '',
}
port_forward = []


def read_configuration():
    """
    Reads configuration file and set Epoll Server variables.
    :return: None
    """
    with open(file=CONFIGURATION_PATH, mode='r', encoding='utf-8') as file:
        fp = [line.rstrip('\n') for line in file]
        for line in fp:
            if line.isspace() or line.startswith('#'):
                continue

            if line.startswith('host_address_IPv4') or line.startswith('host_address_IPv6'):
                config_data = line.split('=')
                configuration[config_data[0]] = config_data[1]

            elif line.startswith('IPv4') or line.startswith('IPv6'):
                config_data = line.split(',')
                pf_entry = PortForward(*config_data)
                port_forward.append(pf_entry)
            else:
                print(f"Invalid configuration, following line with incorrect format: {line}")
                exit()
    setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))


def create_listening_sockets():
    sockets = []
    for entry in port_forward:
        if entry.is_tls:
            if entry.ipvtype == "IPv4":
                sock = socket.socket(AF_INET, SOCK_STREAM)
                server = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLS,
                                         certfile="cert.pem", keyfile="priv.key", )
                server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                server.bind((configuration['host_address_IPv4'], entry.src_port))
                server.listen(10)
                server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                print(f"Listening on : {server.getsockname()}")
                start_new_thread(start_TLS_server, (server,))
            elif entry.ipvtype == "IPv6":
                addrinfo = getaddrinfo(configuration['host_address_IPv6'], entry.src_port, AF_INET6,
                                       SOCK_STREAM, SOL_TCP)
                (family, socktype, proto, canonname, sockaddr) = addrinfo[0]
                sock = socket.socket(family, socktype, proto)
                server = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLS,
                                         certfile="cert.pem", keyfile="priv.key", )
                server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                server.bind(sockaddr)
                server.listen(10)
                server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                print(f"Listening on : {server.getsockname()}")
                start_new_thread(start_TLS_server, (server,))
            continue

        if entry.ipvtype == "IPv4":
            server = socket.socket(AF_INET, SOCK_STREAM)
            server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            server.bind((configuration['host_address_IPv4'], entry.src_port))
            server.listen(100)
            server.setblocking(False)
            server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            print(f"Listening on : {server.getsockname()}")
            sockets.append(server)
        elif entry.ipvtype == "IPv6":
            addrinfo = getaddrinfo(configuration['host_address_IPv6'], entry.src_port, AF_INET6,
                                   SOCK_STREAM, SOL_TCP)
            (family, socktype, proto, canonname, sockaddr) = addrinfo[0]
            server = socket.socket(family, socktype, proto)
            server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            server.bind(sockaddr)
            server.listen(100)
            server.setblocking(False)
            server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            print(f"Listening on : {server.getsockname()}")
            sockets.append(server)

    return sockets


def start_epoll_server():
    """
    Main Epoll Server Function
    Initialize the non-blocking socket with select and epoll to accept client connections for extended echo.

    Epoll watches for 3 main events:
        Epoll Socket Event:
            If event is from epoll server listening socket, accept client connection.
        Read Event:
            If event is socket available to read (client echo request), receive message.
        Write Event:
            If event is socket available to write (server echo response), send message.

    :return: None
    """
    sockets = create_listening_sockets()
    # For loop for sockets, pass to epoll. change epoll to accept list of sockets for registering
    with epoll_context_manager(sockets, select.EPOLLIN) as epoll:

        client_sockets = {}
        while True:
            events = epoll.poll(1)

            for sockdes, event in events:
                # If event is from epoll server listening socket, accept client connection.
                if any(s.fileno() == sockdes for s in sockets):
                    next(accept_connection(s, client_sockets, epoll) for s in sockets if s.fileno() == sockdes)

                # If event is socket available to read (client echo request), receive message.
                elif event & select.EPOLLIN:
                    receive_handler(sockdes, client_sockets, epoll)

                # If event is socket available to write (server echo response), send message.
                elif event & select.EPOLLOUT:
                    send_handler(sockdes, client_sockets, epoll)


def accept_connection(server, client_sockets, epoll):
    """
    Processes new client connections, and register the connection to epoll.
    :param server: server socket
    :param client_sockets: dictionary of active client sockets
    :param epoll: epoll reference
    :return: None
    """
    connection, address = server.accept()
    connection.setblocking(0)

    for pf in port_forward:
        if connection.getpeername()[0] in pf.src_ip and connection.getsockname()[1] == pf.src_port:
            fwd_sock = create_forwarding_sockets(pf)

            print(f'Client Connected from IP: {connection.getpeername()[0]}, Port: {connection.getpeername()[1]} \n'
                  f'                   to IP: {connection.getsockname()[0]} Port: {connection.getsockname()[1]}.\n'
                  f'        Forwarding to IP: {fwd_sock.getpeername()[0]}, Port: {fwd_sock.getpeername()[1]}.\n')

            ip_address = address[0]
            if ip_address not in clients_summary:
                clients_summary[ip_address] = ServerSummary(ip_address)

            clients_summary[ip_address].total_client_conns += 1

            client_sock_info = ClientSocketInfo(connection, fwd_sock)
            client_sock_info_fwd = ClientSocketInfo(fwd_sock, connection)
            fd = connection.fileno()
            fd_fwd = fwd_sock.fileno()
            epoll.register(fd, select.EPOLLIN)
            epoll.register(fd_fwd, select.EPOLLIN)
            client_sockets[fd] = client_sock_info
            client_sockets[fd_fwd] = client_sock_info_fwd
            return

    print(f"No matching Port Forward Entry for {address}, closing connection.")
    connection.close()


def create_forwarding_sockets(entry):
    try:
        if entry.ipvtype == "IPv4":
            fwd_sock = socket.socket(AF_INET, SOCK_STREAM)
            fwd_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            fwd_sock.connect((entry.fw_ip, entry.fw_port))
            fwd_sock.setblocking(False)
            fwd_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        else:  # For IPv6
            addrinfo = getaddrinfo(entry.fw_ip, entry.fw_port, AF_INET6,
                                   SOCK_STREAM, SOL_TCP)
            (family, socktype, proto, canonname, sockaddr) = addrinfo[0]
            fwd_sock = socket.socket(family, socktype, proto)
            fwd_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            fwd_sock.connect(sockaddr)
            fwd_sock.setblocking(False)
            fwd_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return fwd_sock
    except error as msg:
        print('Error Code : ' + str(msg[0]) + ' Message ' + msg[1])


def receive_handler(sockdes, client_sockets, epoll):
    """
    Handles receiving client request messages, and trigger an echo response from server back to client.
    :param sockdes: client socket number
    :param client_sockets: dictionary of active client sockets
    :param epoll: epoll reference
    :return: None
    """
    try:
        conn = client_sockets[sockdes].src_sock
    except KeyError:
        print("Client closed socket")
        return
    # data = conn.recv(BUFFER_SIZE).decode('utf8')
    data = conn.recv(BUFFER_SIZE)
    sockdes_fwd = client_sockets[sockdes].fwd_sock.fileno()
    # Check if connection still open
    # print("data recv:", data)
    if data:
        client_sockets[sockdes_fwd].echo_request = data
        data_len = len(data)
        fwd_sock = client_sockets[sockdes].fwd_sock
        if sockdes in client_sockets:
            client_sockets[sockdes].total_data_forward += data_len  # log
        elif fwd_sock.fileno() in client_sockets:
            client_sockets[fwd_sock.fileno()].total_data_forward += data_len  # log
        if client_sockets[sockdes].src_sock.getpeername()[0] in clients_summary:
            clients_summary[client_sockets[sockdes].src_sock.getpeername()[0]]\
                .total_data_forward += data_len  # log
        elif client_sockets[fwd_sock.fileno()].src_sock.getpeername()[0] in clients_summary:
            clients_summary[client_sockets[fwd_sock.fileno()].src_sock.getpeername()[0]] \
                .total_data_forward += data_len  # log
        epoll.modify(sockdes_fwd, select.EPOLLOUT)
    else:
        try:
            print_connection_results(sockdes, client_sockets)
            epoll.unregister(sockdes)
            epoll.unregister(sockdes_fwd)
            client_sockets[sockdes].src_sock.close()
            client_sockets[sockdes].fwd_sock.close()
            client_sockets[sockdes_fwd].src_sock.close()
            client_sockets[sockdes_fwd].fwd_sock.close()
            del client_sockets[sockdes]
            del client_sockets[sockdes_fwd]
        except KeyError:
            print("Client closed socket")
            return
        return


def send_handler(sockdes, client_sockets, epoll):
    """
    Handles sending server's echo responses to the client messages.
    :param sockdes: client socket number
    :param client_sockets: dictionary of active client socket
    :param epoll: epoll reference
    :return: None
    """
    # client_sockets[sockdes].src_sock.send(client_sockets[sockdes].echo_request.encode('utf8'))
    try:
        client_sockets[sockdes].src_sock.sendall(client_sockets[sockdes].echo_request)
        epoll.modify(sockdes, select.EPOLLIN)
    except KeyError:
        print("Server closed connection")
        return


def start_TLS_server(server):
    try:
        while True:
            conn, adr = server.accept()
            accept_success = False
            for entry in port_forward:
                if conn.getpeername()[0] in entry.src_ip and conn.getsockname()[1] == entry.src_port:
                    if entry.ipvtype == "IPv4":
                        sock = socket.socket(AF_INET, SOCK_STREAM)
                        fwd_sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLS,
                                                   certfile="cert.pem", keyfile="priv.key", )
                        fwd_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                        fwd_sock.connect((entry.fw_ip, entry.fw_port))
                        fwd_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    else:  # For IPv6
                        addrinfo = getaddrinfo(entry.fw_ip, entry.fw_port, AF_INET6,
                                               SOCK_STREAM, SOL_TCP)
                        (family, socktype, proto, canonname, sockaddr) = addrinfo[0]
                        sock = socket.socket(family, socktype, proto)
                        fwd_sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLS,
                                                   certfile="cert.pem", keyfile="priv.key", )
                        fwd_sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                        fwd_sock.connect(sockaddr)
                        fwd_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    print(f'Client Connected from IP: {conn.getpeername()[0]}, Port: {conn.getpeername()[1]} \n'
                          f'                   to IP: {conn.getsockname()[0]}, Port: {conn.getsockname()[1]}.\n'
                          f'        Forwarding to IP: {fwd_sock.getpeername()[0]}, Port: {fwd_sock.getpeername()[1]}.\n')

                    ip_address = adr[0]
                    if ip_address not in clients_summary:
                        clients_summary[ip_address] = ServerSummary(ip_address)

                    clients_summary[ip_address].total_client_conns += 1

                    start_new_thread(TLS_thread, (conn, fwd_sock,))
                    # start_new_thread(TLS_thread, (fwd_sock, conn,))
                    accept_success = True
                    break
            if not accept_success:
                print(f"No matching Port Forward TLS Entry for {adr}, closing connection.")
                conn.close()

    except KeyboardInterrupt as e:
        print("TLS socket Closed")


def TLS_thread(sock, fwd_sock):
    total_data = 0
    while True:
        data = sock.recv(BUFFER_SIZE)
        if data:
            total_data += len(data)
            fwd_sock.send(data)
        else:
            clients_summary[sock.getpeername()[0]].total_data_forward += total_data  # log
            log_data = (
                f"Connection closed: {sock.getpeername()}\n"
                f"    Total data forward = {total_data}\n"
            )
            print(log_data)
            with open(file=LOG_PATH, mode="a", encoding='utf-8') as file:
                file.write(log_data)
            sock.close()
            fwd_sock.close()
            break
        data = fwd_sock.recv(BUFFER_SIZE)
        if data:
            total_data += len(data)
            sock.send(data)
        else:
            sock.close()
            fwd_sock.close()
            break


def print_summary():
    """
    Prints summary all connections from all hosts received by server, and their activities.
    :return: None
    """
    log_data = f''
    log_data += (
        f'------------------------------------------------------------------\n'
        f'Server Summary:\n'
        f'------------------------------------------------------------------\n'
        f'Total Remote Hosts: {len(clients_summary)}\n'
    )
    for key, client in clients_summary.items():
        log_data += (
            f"\n[{client.host_ip}]:\n"
            f"    Total connections = {client.total_client_conns}\n"
            f"    Total data forward = {client.total_data_forward}\n"
        )
    log_data += '------------------------------------------------------------------\n'
    print(log_data)
    with open(file=LOG_PATH, mode="a", encoding='utf-8') as file:
        file.write(log_data)


def print_connection_results(sockdes, client_sockets):
    """
    Prints a summary of a single client socket's connection activties.
    :param sockdes: client socket number
    :param client_sockets: dictionary of active client sockets
    :return: None
    """
    log_data = (
        f"Connection closed: {client_sockets[sockdes].src_sock.getpeername()}\n"
        f"    Total data forward = {client_sockets[sockdes].total_data_forward}\n"
    )
    print(log_data)
    with open(file=LOG_PATH, mode="a", encoding='utf-8') as file:
        file.write(log_data)


@contextmanager
def epoll_context_manager(sockets, epoll_option):
    """
    Epoll loop Context manager, use context manager to free epoll resources upon termination.
    :param sockets: List of sockets for Epoll server args
    :param epoll_option: Epoll server options
    :return:
    """
    eps = select.epoll()
    for sock in sockets:
        eps.register(sock.fileno(), epoll_option)
    try:
        yield eps
    finally:
        print_summary()
        print("\nExiting epoll loop")
        for sock in sockets:
            eps.unregister(sock.fileno())
            sock.close()
        eps.close()


@contextmanager  # Socket Context (resource) manager
def socket_context_manager(*args, **kwargs):
    sd = socket.socket(*args, **kwargs)
    try:
        yield sd
    finally:
        print("Listening Socket Closed")
        sd.close()


# Start the epoll server & Process keyboard interrupt CTRL-C
if __name__ == '__main__':
    try:
        read_configuration()
        start_epoll_server()
    except KeyboardInterrupt as e:
        print("Server Shutdown")
        exit()  # Don't really need this because of context managers
