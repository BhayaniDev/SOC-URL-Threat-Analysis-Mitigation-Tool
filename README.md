said
🔐 SOC URL Threat Analysis & Mitigation Tool

A custom-built, Python-based Threat Intelligence platform that simulates a Level 1/Level 2 SOC Analyst workflow. It analyzes suspicious URLs using passive OSINT, evaluates cryptographic security, and aggregates community threat intel to provide an automated risk score and mandatory SOC mitigation steps in real-time. Ideal for triaging potential phishing links and malicious beacons without active scanning.

🚀 Features

✅ Extracts passive domain intelligence (WHOIS) to flag newly registered domains
✅ Evaluates SSL/TLS certificates for expiration and issuer validity
✅ Inspects HTTP security headers (HSTS, CSP, X-Frame-Options)
✅ Integrates VirusTotal API v3 for crowdsourced threat intelligence
✅ Calculates automated risk scores (0-100) with severity levels
✅ Generates mandatory SOC mitigation steps and analyst reasoning
✅ Provides a clean, interactive dark-mode dashboard via Streamlit

🛠️ Requirements

Python 3.x
Linux (tested on Kali, Ubuntu) / Windows / macOS
Internet connection for API queries
Python Libraries

pip install streamlit python-whois requests

(Note: ssl, socket, and urllib are part of Python’s standard library)

📦 Usage

Clone the Repository

git clone https://github.com/YourUsername/SOC-URL-Analyzer.git
cd SOC-URL-Analyzer

Set Up Virtual Environment (Recommended for Kali Linux)

python3 -m venv soc-env
source soc-env/bin/activate

Install Dependencies

pip install streamlit python-whois requests

Configure API Key (Optional)

Obtain a free VirusTotal API key from https://www.google.com/search?q=virustotal.com.
You can enter this directly in the web dashboard UI under the configuration sidebar.

Run the Tool

streamlit run app.py

The dashboard will automatically open in your default web browser (usually http://localhost:8501).
To stop it, press Ctrl + C in the terminal.

📊 Dashboard Output

All detected threats, OSINT data, and mitigations are displayed dynamically on the Streamlit web interface.

Example Output:
🎯 Threat Score: 85/100 - CRITICAL RISK
🚨 CRITICAL BLOCK: Immediately block this domain at your Secure Web Gateway (SWG).

📌 Use Cases

Triaging user-reported phishing emails and suspicious links
Enriching Incident Response (IR) investigations without tipping off attackers
Lightweight vendor security assessment for baseline web controls


