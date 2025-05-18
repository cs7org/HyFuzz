import json


def generate_report(target_ip, open_ports, service, cve_list, fuzz_results):
    """Generate a vulnerability detection report and save it as a JSON file.

    Args:
        target_ip (str): Target IP address
        open_ports (list): List of open ports detected
        service (str): Detected service and version
        cve_list (list): List of CVEs associated with the service
        fuzz_results (dict): Results from fuzz testing

    Returns:
        None
    """
    report = {
        "target_ip": target_ip,
        "open_ports": open_ports,
        "service": service,
        "cve_list": cve_list,
        "fuzz_results": fuzz_results
    }
    report_file = f"{target_ip}_report.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=4)
    print(f"Report generated: {report_file}")