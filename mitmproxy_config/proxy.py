import logging
from mitmproxy import http
import ssl
import socket
import requests
from mitmproxy.tools import main
from mitmproxy.websocket import WebSocketMessage

# Configure Python's built-in logging module
logging.basicConfig(
    format='%(asctime)s [%(levelname)s] - %(message)s',
    level=logging.INFO
)


# Dynamic Certificate Handling
class DynamicCertificateInjector:
    def __init__(self):
        self.certificate_cache = {}

    def request(self, flow: http.HTTPFlow):
        domain = flow.request.host
        if domain not in self.certificate_cache:
            self.certificate_cache[domain] = self.generate_dynamic_cert(domain)

        flow.server_conn.sslcontext = self.certificate_cache[domain]
        logging.info(f"Injected dynamic certificate for {domain}")

    def generate_dynamic_cert(self, domain: str):
        cert = ssl.create_default_context().wrap_socket(socket.socket(), server_hostname=domain)
        return cert


# SSL Pinning Bypass using Frida
class SSLPinningBypass:
    def request(self, flow: http.HTTPFlow):
        # Frida script invocation or hooking would go here
        pass


# WebSocket Message Interception
class WebSocketInterceptor:
    def websocket_message(self, flow: WebSocketMessage):  # Correct usage for intercepting WebSocket message frames
        if flow.type == "text":
            logging.info(f"WebSocket message intercepted: {flow.content}")
            # Modify the content of the WebSocket message here
            flow.content = "Modified: " + flow.content.decode("utf-8")
            logging.info(f"WebSocket message modified: {flow.content}")


# Traffic Analysis with Elasticsearch Integration
class TrafficAnalyzer:
    def request(self, flow: http.HTTPFlow):
        data = {
            "url": flow.request.url,
            "headers": dict(flow.request.headers),
            "method": flow.request.method
        }
        response = requests.post("http://localhost:9200/traffic_logs/_doc/", json=data)
        if response.status_code == 201:
            logging.info(f"Traffic logged to Elasticsearch: {flow.request.url}")
        else:
            logging.error(f"Failed to log traffic to Elasticsearch: {response.text}")


# Report Generator using Jinja2 (dynamic HTML reporting)
class ReportGenerator:
    def __init__(self, traffic_data):
        self.traffic_data = traffic_data

    def generate_report(self):
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader('mitmproxy_config'))
        template = env.get_template('report_template.html')

        report = template.render(requests=self.traffic_data)

        with open("report.html", "w") as f:
            f.write(report)
        logging.info("Report generated and saved as report.html")


# Add classes to the mitmproxy addons
addons = [
    DynamicCertificateInjector(),
    SSLPinningBypass(),
    WebSocketInterceptor(),
    TrafficAnalyzer()
]


# Function to prompt the user for input arguments
def get_mitmproxy_arguments():
    # Get the arguments interactively from the user
    listen_host = input("Enter the listen host (default 0.0.0.0): ") or "0.0.0.0"
    listen_port = input("Enter the listen port (default 8080): ") or "8080"
    mode = input("Enter the proxy mode (default regular, options: regular, transparent, reverse): ") or "regular"
    show_host = input("Show host information in logs? (y/n, default: y): ") or "y"

    # Return the arguments as a list to pass to mitmproxy
    mitmproxy_arguments = [
        "mitmproxy",  # The name of the program (first argument)
        "--listen-host", listen_host,  # Bind to the host provided
        "--listen-port", listen_port,  # Bind to the port provided
        "--mode", mode,  # Set the proxy mode
    ]

    if show_host.lower() == 'y':
        mitmproxy_arguments.append("--showhost")

    return mitmproxy_arguments


# Main function to run mitmproxy
def run_mitmproxy():
    # Get the user inputs for arguments
    mitmproxy_arguments = get_mitmproxy_arguments()

    # Add any optional arguments or custom options
    mitmproxy_arguments += ['--set', 'console_eventlog_verbosity=error']

    # Use mitmproxy.main to start the proxy programmatically
    main.mitmproxy(mitmproxy_arguments + addons)


# Run the mitmproxy
if __name__ == '__main__':
    run_mitmproxy()