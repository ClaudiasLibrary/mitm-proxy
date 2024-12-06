# Man-In-The-Middle Proxy

This project is a Man-in-the-Middle (MITM) Proxy tool built using `mitmproxy`.
It allows for real-time HTTP/HTTPS traffic interception, modification, and analysis.
It includes advanced features such as SSL Pinning Bypass, WebSocket Modification, Dynamic SSL Certificates, and real-time traffic analysis with Elasticsearch integration.

## Features

- **SSL Pinning Bypass**: Bypass SSL Pinning in mobile applications using Frida.
- **Dynamic SSL Certificate Handling**: Inject dynamic SSL certificates for each intercepted domain.
- **WebSocket Traffic Interception**: Intercept and modify WebSocket messages in real-time.
- **Real-Time Traffic Analysis**: Log and send intercepted traffic to Elasticsearch for real-time analysis.
- **Reporting & Visualization**: Generate dynamic HTML reports of the intercepted traffic using Jinja2 templates.

## Requirements

1. Python 3.x
2. mitmproxy
3. frida-tools (for SSL Pinning Bypass)
4. Elasticsearch (optional for real-time analysis)
5. Jinja2 (for HTML report generation)

### Install dependencies:

pip install -r requirements.txt

## Example:
Here is an example of how the mitmproxy runs after the user inputs the configuration:

```bash
Enter the listen host (default 0.0.0.0): 0.0.0.0
Enter the listen port (default 8080): 8080
Enter the proxy mode (default regular, options: regular, transparent, reverse): regular
Show host information in logs? (y/n, default: y): y
```
This starts the proxy on 0.0.0.0:8080 in regular mode, and the proxy will log detailed information about the traffic being intercepted.

