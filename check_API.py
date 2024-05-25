import requests

def get_cve_info(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for non-200 status codes
        cve_info = response.json()
        return cve_info
    except requests.exceptions.RequestException as e:
        print("Error fetching CVE information:", e)
        return None

def print_cve_info(cve_info):
    if not cve_info or "vulnerabilities" not in cve_info:
        print("CVE information not found or error in fetching details.")
        return

    # Extracting information from the JSON response based on its structure
    for vulnerability in cve_info["vulnerabilities"]:
        cve = vulnerability["cve"]
        print("CVE ID:", cve["id"])
        
        print("Published:", cve["published"])
        print("Last Modified:", cve["lastModified"])
        print("Description:")
        for description in cve["descriptions"]:
            print(f"- {description['value']} [{description['lang']}]")
        
        # Check if 'metrics' key exists before accessing it
        if "metrics" in vulnerability:
            print("Severity:")
            for metric in vulnerability["metrics"].get("cvssMetricV3", []):
                print(f"- CVSS v3 Base Score: {metric['cvssData']['baseScore']} ({metric['cvssData']['baseSeverity']})")
            for metric in vulnerability["metrics"].get("cvssMetricV2", []):
                print(f"- CVSS v2 Base Score: {metric['cvssData']['baseScore']} ({metric['baseSeverity']})")
        else:
            print("Severity: Not available")

        print("Weaknesses:")
        for weakness in vulnerability.get("weaknesses", []):
            for description in weakness["description"]:
                print(f"- {description['value']}")
        print("References:")
        for reference in vulnerability.get("references", []):
            print(f"- {reference['url']} ({reference['source']})")

def main():
    cve_id = input("Enter CVE ID: ")
    cve_info = get_cve_info(cve_id)
    print_cve_info(cve_info)

if __name__ == "__main__":
    main()
