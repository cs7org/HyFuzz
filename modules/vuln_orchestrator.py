# vuln_orchestrator.py

import re
from modules.exp_tester import (
    test_path_traversal,
    test_sql_injection,
    test_nginx_1_8_http_smuggling,
    test_nginx_1_8_buffer_overflow,
    test_nginx_1_8_cve_2016_0747,
    test_nginx_1_18_cve_2021_23017,
    test_nginx_1_18_cve_2021_3618,
    test_nginx_1_18_cve_2020_12440,
)

# Registry of version-specific test cases
VULN_TEST_REGISTRY = [
    {
        "condition": lambda s: re.search(r"nginx.*1\.8", s, re.IGNORECASE),
        "tests": [
            ("HTTP request smuggling", test_nginx_1_8_http_smuggling),
            ("Buffer overflow", test_nginx_1_8_buffer_overflow),
            ("CVE-2016-0747", test_nginx_1_8_cve_2016_0747),
        ]
    },
    {
        "condition": lambda s: re.search(r"nginx.*1\.18", s, re.IGNORECASE),
        "tests": [
            ("CVE-2021-23017", test_nginx_1_18_cve_2021_23017),
            ("CVE-2021-3618", test_nginx_1_18_cve_2021_3618),
            ("CVE-2020-12440", test_nginx_1_18_cve_2020_12440),
        ]
    },
    # Extendable registry
]


def perform_vulnerability_scan(target_ip, port, service_string, logger=None):
    """
    Scans for known vulnerabilities based on service type and version.

    Args:
        target_ip (str): Target IP address
        port (int): Target port
        service_string (str): The detected service string, e.g. 'nginx 1.18.0'
        logger (logging.Logger): Optional logger

    Returns:
        tuple: (List of found vulnerabilities, Boolean indicating if any were found)
    """
    results = []

    def log(msg):
        if logger:
            logger.info(msg)
        else:
            print(msg)

    # Generic tests (not version specific)
    if test_path_traversal(target_ip, port, service_string):
        results.append(("Path Traversal", True))
        log(f"[+] Port {port}: Path traversal vulnerability found")

    elif test_sql_injection(target_ip, port):
        results.append(("SQL Injection", True))
        log(f"[+] Port {port}: SQL injection vulnerability found")

    # Version-specific tests
    for entry in VULN_TEST_REGISTRY:
        if entry["condition"](service_string):
            for description, test_fn in entry["tests"]:
                try:
                    if test_fn(target_ip, port):
                        results.append((description, True))
                        log(f"[+] Port {port}: {description} vulnerability found")
                except Exception as e:
                    log(f"[!] Error running test '{description}' on port {port}: {e}")

    return results, bool(results)
