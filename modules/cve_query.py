import json
import re
from config import CVE_DATABASE_PATH


def load_cve_database():
    try:
        with open(CVE_DATABASE_PATH, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print("CVE database file not found!")
        return {}





def filter_cves_by_version(cve_list, version):
    """
    Filter CVEs by matching the normalized version string.

    Args:
        cve_list (list): Raw CVEs with description
        version (str): Version string to match (e.g., 1.18)

    Returns:
        list: Filtered CVEs with version match
    """
    norm_version = version.strip()
    filtered = []
    for cve in cve_list:
        desc = cve.get("description", "")
        if norm_version in desc:
            filtered.append(cve)
    return filtered