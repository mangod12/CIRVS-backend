import requests
import os
import json

def fetch_cve_details(cve_id):
    """Fetch CVE details from the NVD API."""
    api_key = os.getenv("NVD_API_KEY")  # Ensure you set this environment variable
    headers = {"apiKey": api_key} if api_key else {}
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        # Extract relevant information from the response
        if 'vulnerabilities' in data and data['vulnerabilities']:
            vuln_data = data['vulnerabilities'][0]['cve']
            return {
                'id': vuln_data.get('id', 'N/A'),
                'description': vuln_data.get('descriptions', [{}])[0].get('value', 'N/A'),
                'published': vuln_data.get('published', 'N/A'),
                'modified': vuln_data.get('lastModified', 'N/A')
            }
        else:
            return {'error': f"No CVE data found for {cve_id}"}
    except requests.RequestException as e:
        return {'error': f"Failed to fetch CVE details for {cve_id}: {e}"}

def save_report(vulns, output_folder="output"): 
    """Save the vulnerability report to a JSON file."""
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    report_path = os.path.join(output_folder, "vulnerability_report.json")
    try:
        with open(report_path, "w") as file:
            json.dump(vulns, file, indent=4)
        return report_path
    except Exception as e:
        raise RuntimeError(f"Failed to save report: {e}")
