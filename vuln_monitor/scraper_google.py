# scraper_google.py
import requests
from bs4 import BeautifulSoup

def fetch_google_vulnerabilities():
    url = "https://security.googleblog.com/"
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    vulnerabilities = []
    for item in soup.find_all('h2', class_='post-title'):
        vulnerabilities.append({
            "Product Name": "Chrome",
            "OEM Name": "Google",
            "Severity Level": "High",  # Placeholder
            "Vulnerability": item.get_text(strip=True),
            "Mitigation Strategy": "Check Google Blog",
            "Published Date": "Unknown",
            "Unique ID": "NA"
        })
    return vulnerabilities
