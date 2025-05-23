# webapp.py - Flask web interface for the Vulnerability Alert & Reporting Tool
from flask import Flask, render_template, request
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vuln_monitor.main import run_monitor

app = Flask(__name__)

def format_report(vulns):
    if not vulns:
        return "<b>No vulnerabilities found.</b>"
    lines = []
    for i, vuln in enumerate(vulns, 1):
        lines.append(f"<b>{i}. Product Name:</b> {vuln.get('Product Name', 'N/A')}")
        lines.append(f"&nbsp;&nbsp;Product Version: {vuln.get('Product Version', 'NA')}")
        lines.append(f"&nbsp;&nbsp;OEM Name: {vuln.get('OEM Name', 'N/A')}")
        lines.append(f"&nbsp;&nbsp;Severity Level: {vuln.get('Severity Level', 'N/A')}")
        lines.append(f"&nbsp;&nbsp;Vulnerability: {vuln.get('Vulnerability', 'N/A')}")
        lines.append(f"&nbsp;&nbsp;Mitigation Strategy: {vuln.get('Mitigation Strategy', 'N/A')}")
        lines.append(f"&nbsp;&nbsp;Published Date: {vuln.get('Published Date', 'N/A')}")
        lines.append(f"&nbsp;&nbsp;Unique ID: {vuln.get('Unique ID', 'N/A')}")
        if 'CVE Details' in vuln and isinstance(vuln['CVE Details'], dict):
            cve = vuln['CVE Details']
            lines.append(f"&nbsp;&nbsp;CVE Description: {cve.get('description', 'N/A')}")
            lines.append(f"&nbsp;&nbsp;CVE Published: {cve.get('published', 'N/A')}")
            lines.append(f"&nbsp;&nbsp;CVE Modified: {cve.get('modified', 'N/A')}")
        lines.append('<hr>')
    return '<br>'.join(lines)

@app.route('/', methods=['GET', 'POST'])
def index():
    report = ''
    email = ''
    websites = ''
    if request.method == 'POST':
        email = request.form['email'].strip()
        websites = request.form['websites'].strip()
        # Save email to config
        from vuln_monitor.config import load_config
        import yaml
        config = load_config()
        config['email']['recipients'] = [email]
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'configs', 'settings.yaml')
        with open(config_path, 'w') as file:
            yaml.dump(config, file, default_flow_style=False)
        # Run the monitor
        url_list = [w.strip() for w in websites.split('\n') if w.strip()]
        vulns, _ = run_monitor(url_list)
        report = format_report(vulns)
    return render_template('index.html', report=report, email=email, websites=websites)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
