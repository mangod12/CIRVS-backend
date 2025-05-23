# scraper_utils.py
def normalize_data(vulns):
    return [v for v in vulns if 'Vulnerability' in v]
