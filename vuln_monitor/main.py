# main.py
from vuln_monitor.config import load_config
from vuln_monitor.scraper_google import fetch_google_vulnerabilities
from vuln_monitor.scraper_utils import normalize_data
from vuln_monitor.email_alerts import send_email_alert
from vuln_monitor.database import init_db, is_duplicate, save_vuln
from vuln_monitor.logger import setup_logger
from vuln_monitor.cve_integration import fetch_cve_details, save_report
from vuln_monitor.website_scanner import scan_multiple_websites
import logging
import os

def process_vulnerability(vuln, config, logger):
    """Process a single vulnerability: check for duplicates, save, and send alerts."""
    cve_id = vuln.get("Unique ID", "NA")
    if not is_duplicate(cve_id):
        logger.info(f"New vulnerability found: {cve_id}")
        save_vuln(vuln)

        msg = f"""Product: {vuln['Product Name']}
OEM: {vuln['OEM Name']}
Severity: {vuln['Severity Level']}
Vulnerability: {vuln['Vulnerability']}
Mitigation: {vuln['Mitigation Strategy']}
Published Date: {vuln['Published Date']}
Unique ID: {cve_id}
"""
        send_email_alert("New Vulnerability Alert", msg, config)
        logger.info(f"Email alert sent for {cve_id}")
    else:
        logger.info(f"Duplicate vulnerability skipped: {cve_id}")

def run_monitor(websites=None):
    setup_logger()
    logger = logging.getLogger("vuln_monitor")

    try:
        logger.info("Loading configuration...")
        config = load_config()

        logger.info("Initializing database...")
        init_db()

        # Create output folder
        output_folder = "output"
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
            logger.info(f"Created output folder: {output_folder}")

        detailed_vulns = []

        # Scan websites if provided
        if websites:
            logger.info(f"Scanning {len(websites)} websites for vulnerabilities...")
            website_vulns = scan_multiple_websites(websites)
            detailed_vulns.extend(website_vulns)
            logger.info(f"Found {len(website_vulns)} website vulnerabilities")

        # Fetch traditional vulnerabilities
        logger.info("Fetching vulnerabilities from sources...")
        vulns = normalize_data(fetch_google_vulnerabilities())

        for vuln in vulns:
            try:
                process_vulnerability(vuln, config, logger)
                cve_id = vuln.get("Unique ID", "NA")
                if cve_id != "NA" and cve_id.startswith("CVE-"):
                    logger.info(f"Fetching CVE details for {cve_id}")
                    cve_details = fetch_cve_details(cve_id)
                    vuln["CVE Details"] = cve_details
                detailed_vulns.append(vuln)
            except Exception as e:
                logger.error(f"Error processing vulnerability {vuln.get('Unique ID', 'NA')}: {e}", exc_info=True)

        logger.info("Saving vulnerability report...")
        report_path = save_report(detailed_vulns, output_folder)
        logger.info(f"Vulnerability report saved at {report_path}")
        
        return detailed_vulns, report_path

    except Exception as e:
        logger.error(f"Error in run_monitor: {e}", exc_info=True)
        return [], None
