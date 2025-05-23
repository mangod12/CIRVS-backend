# Backend for Vulnerability Alert & Reporting Tool

This folder contains the backend (Flask API and all vulnerability logic) for the Vulnerability Monitor system.

## How to Run

1. Install dependencies:
   ```sh
   pip install flask requests beautifulsoup4 pyyaml
   ```
2. (Optional) Set your NVD API key as an environment variable:
   ```sh
   set NVD_API_KEY=your_nvd_api_key
   ```
3. Configure `configs/settings.yaml` with your email and SMTP details.
4. Start the backend API:
   ```sh
   python webapp.py
   ```

## API Endpoint
- `POST /api/scan` with JSON `{ "email": "...", "websites": ["..."] }` returns vulnerabilities as JSON.

## Contents
- All Python code, configs, and output folders.
