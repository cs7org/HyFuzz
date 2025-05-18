# At the top of service_detector.py (with other imports)
import socket
import ssl
import re


# Inside your function
def detect_http_service(ip, port, hostname=None):
    if hostname is None:
        hostname = ip

    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=1) as sock:
            if port in [443, 8443]:  # Assuming HTTPS for these ports
                try:
                    sock = context.wrap_socket(sock, server_hostname=hostname)
                except ssl.SSLError as e:
                    print(f"SSL error connecting to {ip}:{port}: {e}")
                    return "Unknown"
            sock.send(b"GET / HTTP/1.1\r\nHost: " + hostname.encode() + b"\r\n\r\n")
            response = sock.recv(4096).decode("utf-8", errors="ignore")

            if not response.startswith("HTTP/"):
                print(f"Non-HTTP response from {ip}:{port}")
                return "Unknown"

            server_match = re.search(r"Server: (.+)", response, re.IGNORECASE)
            return server_match.group(1).strip() if server_match else "Unknown"

    except socket.timeout:
        print(f"Timeout connecting to {ip}:{port}")
        return "Unknown"
    except ConnectionRefusedError:
        print(f"Connection refused to {ip}:{port}")
        return "Unknown"
    except Exception as e:
        print(f"Error detecting service on {ip}:{port}: {e}")
        return "Unknown"