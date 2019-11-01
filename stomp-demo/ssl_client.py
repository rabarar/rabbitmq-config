#!/usr/bin/python3

import socket
import ssl

host_addr = '127.0.0.1'
host_port = 8000
server_sni_hostname = 'Rob Baruch'
server_cert = '/Users/robert/rabbitmq/testca/cacert.pem'
client_cert = '/Users/robert/rabbitmq/client/cert.pem'
client_key = '/Users/robert/rabbitmq/client/key.pem'


context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_cert)
context.load_cert_chain(certfile=client_cert, keyfile=client_key)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn = context.wrap_socket(s, server_side=False, server_hostname=server_sni_hostname)
conn.connect((host_addr, host_port))
print("SSL established. Peer: {}".format(conn.getpeercert()))
print("Sending: 'Hello, world!")
conn.send(b"Hello, world!")
print("Closing connection")
conn.close()
