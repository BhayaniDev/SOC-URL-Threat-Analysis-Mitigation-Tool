🔐 SOC-Oriented URL Threat Analysis & Mitigation Tool

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

🎯 Project Overview

The SOC URL Threat Analysis Tool is a custom-built, Python-based Threat Intelligence platform designed to simulate the workflow of a Level 1/Level 2 Security Operations Center (SOC) Analyst.

When triaging potential phishing links, malicious beacons, or user-reported suspicious URLs, analysts require rapid, non-intrusive intelligence. This tool automates the extraction of passive OSINT, evaluates cryptographic security, aggregates community threat intel (VirusTotal), and processes the findings through a custom Risk Scoring Engine to provide mandatory, actionable mitigation steps.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

🛡️ Security & Ethics First

Passive Intelligence Only: This tool does not perform intrusive scanning, directory brute-forcing, or payload execution against the target.

Safe Triage: Designed to gather context without tipping off adversaries or triggering malicious web-hooks.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

✨ Key Features

✅ Passive Domain Intelligence (WHOIS): Extracts registrar data and calculates domain age to flag newly registered "burner" domains commonly used in phishing campaigns.

✅ Cryptographic Validation (SSL/TLS): Inspects certificate issuers and expiration dates without executing HTTP payloads.

✅ HTTP Security Header Inspection: Safely requests server headers to verify the presence of critical defensive configurations (HSTS, CSP, X-Frame-Options).

✅ VirusTotal API v3 Integration: Securely aggregates crowdsourced threat intelligence from over 90 security vendors to detect zero-day malicious URLs.

✅ Analyst Risk Scoring Engine: Automatically calculates a threat score (0-100) based on weighted risk factors, assigning a severity level (Low, Medium, High, Critical).

✅ Automated SOC Mitigations: Maps identified vulnerabilities to specific incident response playbooks (e.g., SWG blocking, proxy monitoring, server reconfiguration).

✅ Interactive Dashboard: Features a clean, dark-mode web UI built with Streamlit for rapid data visualization.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

🚀 Installation & Setup

This project is designed to run in an isolated Python Virtual Environment to prevent system-wide package conflicts (PEP 668 compliant).

Clone the repository & navigate to the directory: git clone https://github.com/yourusername/soc-url-analyzer.git
cd soc-url-analyzer
