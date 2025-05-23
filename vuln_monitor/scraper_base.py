import requests
from requests.exceptions import RequestException

# scraper_base.py
class ScraperBase:
    def fetch(self):
        raise NotImplementedError("Each scraper must implement the fetch method.")

    def fetch_with_retries(self, url, retries=3, timeout=10):
        for attempt in range(retries):
            try:
                response = requests.get(url, timeout=timeout)
                response.raise_for_status()
                return response.text
            except RequestException as e:
                if attempt < retries - 1:
                    continue
                else:
                    raise RuntimeError(f"Failed to fetch data from {url} after {retries} attempts: {e}")
