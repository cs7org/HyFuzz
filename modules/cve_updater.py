import requests
import json
import urllib.parse

def search_cve_by_product(product_name, limit=10):
    base_url = "https://cvedb.shodan.io/cves"
    query = {"product": product_name}
    url = f"{base_url}?{urllib.parse.urlencode(query)}"

    print(f"\n[+] Searching for vulnerabilities related to: {product_name}")
    print(f"[+] Request URL: {url}")

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        cves = data.get("cves", [])
        if not cves:
            print("[-] No vulnerability information found.")
            return

        print(f"[+] Found {len(cves)} CVEs related to '{product_name}' (showing top {limit}):")

        for idx, cve in enumerate(cves[:limit], start=1):
            print(f"\n[{idx}] CVE ID: {cve.get('cve_id')}")
            print(f"     Summary: {cve.get('summary')}")
            print(f"     CVSS: {cve.get('cvss')}, EPSS: {cve.get('epss')}")
            print(f"     Published: {cve.get('published_time')}")

        # Save all results to a JSON file
        filename = f"cve_{product_name.lower().replace(' ', '_')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(cves, f, ensure_ascii=False, indent=2)

        print(f"\n[+] All data has been saved to: {filename}")

    except Exception as e:
        print(f"[!] An error occurred during the request or parsing: {e}")

if __name__ == "__main__":
    product = input("Enter the product name to search (e.g., php, nginx, log4j): ")
    search_cve_by_product(product)
