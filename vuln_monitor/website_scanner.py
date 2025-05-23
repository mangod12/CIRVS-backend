import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
from datetime import datetime

class WebsiteVulnerabilityScanner:
    def __init__(self):
        self.logger = logging.getLogger("vuln_scanner")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def scan_website(self, url):
        """Scan a website for common vulnerabilities."""
        vulnerabilities = []
        
        try:
            self.logger.info(f"Scanning website: {url}")
            response = self.session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Check for common vulnerabilities
            vulnerabilities.extend(self._check_exposed_directories(url))
            vulnerabilities.extend(self._check_headers(response))
            vulnerabilities.extend(self._check_forms(soup, url))
            vulnerabilities.extend(self._check_outdated_frameworks(soup, response))
            vulnerabilities.extend(self._check_ssl_issues(url))
            
        except Exception as e:
            self.logger.error(f"Error scanning {url}: {e}")
            vulnerabilities.append({
                'Product Name': 'Website',
                'OEM Name': urlparse(url).netloc,
                'Severity Level': 'Medium',
                'Vulnerability': f'Failed to scan website: {str(e)}',
                'Mitigation Strategy': 'Ensure website is accessible and properly configured',
                'Published Date': datetime.now().strftime('%Y-%m-%d'),
                'Unique ID': f'SCAN-ERROR-{int(datetime.now().timestamp())}'
            })
        
        return vulnerabilities

    def _check_exposed_directories(self, base_url):
        """Check for exposed sensitive directories."""
        vulnerabilities = []
        sensitive_paths = [
            '/admin', '/wp-admin', '/administrator', '/phpmyadmin',
            '/.git', '/.env', '/config', '/backup', '/backups',
            '/test', '/dev', '/staging', '/.htaccess'
        ]
        
        for path in sensitive_paths:
            try:
                test_url = urljoin(base_url, path)
                response = self.session.head(test_url, timeout=5)
                if response.status_code in [200, 301, 302, 403]:
                    vulnerabilities.append({
                        'Product Name': 'Website',
                        'OEM Name': urlparse(base_url).netloc,
                        'Severity Level': 'High' if path in ['/.git', '/.env'] else 'Medium',
                        'Vulnerability': f'Exposed sensitive directory: {path}',
                        'Mitigation Strategy': f'Restrict access to {path} or remove if not needed',
                        'Published Date': datetime.now().strftime('%Y-%m-%d'),
                        'Unique ID': f'EXPOSED-DIR-{abs(hash(test_url))}'
                    })
            except:
                continue
        
        return vulnerabilities

    def _check_headers(self, response):
        """Check for missing security headers."""
        vulnerabilities = []
        headers = response.headers
        
        security_headers = {
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-Frame-Options': 'Missing X-Frame-Options header (Clickjacking protection)',
            'X-XSS-Protection': 'Missing X-XSS-Protection header',
            'Strict-Transport-Security': 'Missing HSTS header',
            'Content-Security-Policy': 'Missing Content Security Policy header'
        }
        
        for header, description in security_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    'Product Name': 'Website',
                    'OEM Name': urlparse(response.url).netloc,
                    'Severity Level': 'Medium',
                    'Vulnerability': description,
                    'Mitigation Strategy': f'Add {header} header to improve security',
                    'Published Date': datetime.now().strftime('%Y-%m-%d'),
                    'Unique ID': f'MISSING-HEADER-{abs(hash(header))}'
                })
        
        return vulnerabilities

    def _check_forms(self, soup, url):
        """Check for forms without CSRF protection."""
        vulnerabilities = []
        forms = soup.find_all('form')
        
        for form in forms:
            # Check if form has CSRF token
            csrf_found = False
            inputs = form.find_all('input')
            for inp in inputs:
                if inp.get('name') and any(token in inp.get('name', '').lower() 
                                         for token in ['csrf', 'token', '_token']):
                    csrf_found = True
                    break
            
            if not csrf_found and form.get('method', '').lower() == 'post':
                vulnerabilities.append({
                    'Product Name': 'Website',
                    'OEM Name': urlparse(url).netloc,
                    'Severity Level': 'Medium',
                    'Vulnerability': 'Form without CSRF protection detected',
                    'Mitigation Strategy': 'Implement CSRF tokens in all forms',
                    'Published Date': datetime.now().strftime('%Y-%m-%d'),
                    'Unique ID': f'NO-CSRF-{abs(hash(str(form)))}'
                })
        
        return vulnerabilities

    def _check_outdated_frameworks(self, soup, response):
        """Check for outdated frameworks and libraries."""
        vulnerabilities = []
        content = response.text.lower()
        
        # Check for common frameworks with version indicators
        framework_patterns = {
            r'jquery[/-](\d+\.\d+\.\d+)': ('jQuery', 'Update to latest jQuery version'),
            r'bootstrap[/-](\d+\.\d+\.\d+)': ('Bootstrap', 'Update to latest Bootstrap version'),
            r'wordpress.*?(\d+\.\d+\.\d+)': ('WordPress', 'Update WordPress to latest version'),
        }
        
        for pattern, (framework, mitigation) in framework_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                version = match.group(1)
                vulnerabilities.append({
                    'Product Name': 'Website',
                    'OEM Name': urlparse(response.url).netloc,
                    'Severity Level': 'Medium',
                    'Vulnerability': f'Potentially outdated {framework} version {version} detected',
                    'Mitigation Strategy': mitigation,
                    'Published Date': datetime.now().strftime('%Y-%m-%d'),
                    'Unique ID': f'OUTDATED-{framework.upper()}-{abs(hash(version))}'
                })
        
        return vulnerabilities

    def _check_ssl_issues(self, url):
        """Check for SSL/TLS issues."""
        vulnerabilities = []
        
        if not url.startswith('https://'):
            vulnerabilities.append({
                'Product Name': 'Website',
                'OEM Name': urlparse(url).netloc,
                'Severity Level': 'High',
                'Vulnerability': 'Website not using HTTPS',
                'Mitigation Strategy': 'Implement SSL/TLS certificate and redirect HTTP to HTTPS',
                'Published Date': datetime.now().strftime('%Y-%m-%d'),
                'Unique ID': f'NO-HTTPS-{abs(hash(url))}'
            })
        
        return vulnerabilities

def scan_multiple_websites(urls):
    """Scan multiple websites for vulnerabilities."""
    scanner = WebsiteVulnerabilityScanner()
    all_vulnerabilities = []
    
    for url in urls:
        try:
            vulns = scanner.scan_website(url)
            all_vulnerabilities.extend(vulns)
        except Exception as e:
            logging.error(f"Failed to scan {url}: {e}")
    
    return all_vulnerabilities
