import ssl
import socket

class DynamicCertHandler:
    def generate_dynamic_cert(self, domain: str):
        cert = ssl.create_default_context().wrap_socket(socket.socket(), server_hostname=domain)
        return cert
