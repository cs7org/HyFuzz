import threading
import socket
from config import PORTS_TO_SCAN


def scan_port(ip, port, open_ports):
    """Scan a single port to check if it is open.

    Args:
        ip (str): Target IP address
        port (int): Port number to scan
        open_ports (list): List to store open ports (shared across threads)

    Returns:
        None
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    except Exception as e:
        print(f"Error scanning port {port}: {e}")


def scan_http_ports(target_ip, ports=PORTS_TO_SCAN):
    """Perform multi-threaded scanning of common HTTP ports.

    Args:
        target_ip (str): Target IP address
        ports (list): List of ports to scan (default: PORTS_TO_SCAN from config)

    Returns:
        list: Sorted list of open ports
    """
    open_ports = []
    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(target_ip, port, open_ports))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    return sorted(open_ports)