# Backend Flask API for Vulnerability Monitor
from flask import Flask, request, jsonify
import os
import sys
from flask_cors import CORS

# Ensure vuln_monitor is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'vuln_monitor'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vuln_monitor.main import run_monitor

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    email = data.get('email', '')
    websites = data.get('websites', [])
    # Save email to config
    from vuln_monitor.config import load_config
    import yaml
    config = load_config()
    config['email']['recipients'] = [email]
    config_path = os.path.join(os.path.dirname(__file__), 'configs', 'settings.yaml')
    with open(config_path, 'w') as file:
        yaml.dump(config, file, default_flow_style=False)
    # Run the monitor
    vulns, _ = run_monitor(websites)
    return jsonify({'vulnerabilities': vulns})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
