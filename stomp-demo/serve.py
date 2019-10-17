import http.server, ssl

server_address = ('localhost', 8000)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket,
                               server_side=True,
                               certfile='/Users/robert/rabbitmq/server/cert.pem',
                               keyfile='/Users/robert/rabbitmq/server/key.pem',
                               ssl_version=ssl.PROTOCOL_TLSv1)
httpd.serve_forever()
