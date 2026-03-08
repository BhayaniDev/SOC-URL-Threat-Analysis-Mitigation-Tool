import streamlit as st
import whois
import ssl
import socket
import requests
import base64
from urllib.parse import urlparse
from datetime import datetime

# --- HELPER FUNCTIONS ---

def extract_domain(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed_url = urlparse(url)
    return parsed_url.netloc

def get_whois_data(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            age = (datetime.now() - creation_date).days
            return {"creation_date": creation_date, "age_days": age, "registrar": w.registrar, "status": "Success"}
        else:
            return {"status": "No creation date found"}
    except Exception as e:
        return {"status": f"Error: {e}"}

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_to_expiry = (expiry_date - datetime.now()).days
                issuer = dict(x[0] for x in cert['issuer'])
                return {"expiry_date": expiry_date, "days_to_expiry": days_to_expiry, "issuer": issuer.get('organizationName', 'Unknown'), "status": "Success"}
    except Exception as e:
        return {"status": f"Error or No HTTPS: {e}"}

def get_security_headers(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url 
    headers_to_check = {
        'Strict-Transport-Security': 'HSTS (Forces HTTPS)',
        'Content-Security-Policy': 'CSP (Prevents XSS)',
        'X-Frame-Options': 'Clickjacking Protection'
    }
    results = {}
    try:
        response = requests.head(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5, allow_redirects=True)
        for header, description in headers_to_check.items():
            if header in response.headers:
                results[header] = {"status": "✅ Present", "desc": description}
            else:
                results[header] = {"status": "❌ Missing", "desc": description}
        return {"status": "Success", "data": results}
    except requests.exceptions.RequestException as e:
        return {"status": f"Error fetching headers: {e}"}

def get_virustotal_reputation(url, api_key):
    if not api_key:
        return {"status": "No API Key provided"}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return {"status": "Success", "stats": stats}
        elif response.status_code == 404:
            return {"status": "Not found in VT database (Unscanned)"}
        elif response.status_code == 401:
            return {"status": "Invalid API Key"}
        else:
            return {"status": f"API Error {response.status_code}"}
    except Exception as e:
        return {"status": f"Request failed: {e}"}

# --- RISK SCORING & MITIGATION ENGINE ---

def analyze_risk_and_mitigate(whois_results, ssl_results, header_results, vt_results):
    """Calculates risk score out of 100 and maps findings to SOC mitigations."""
    score = 0
    reasons = []
    mitigations = []

    # 1. VirusTotal check
    if vt_results.get('status') == "Success":
        malicious = vt_results['stats'].get('malicious', 0)
        suspicious = vt_results['stats'].get('suspicious', 0)
        if malicious > 0:
            score += 50
            reasons.append(f"🔴 Flagged malicious by {malicious} VT vendors (+50)")
            mitigations.append("🚨 **CRITICAL BLOCK:** Immediately block this domain at your Secure Web Gateway (SWG), Firewall, and DNS sinkhole. Hunt for internal endpoints that have recently beaconed to this URL and isolate them for Incident Response triage.")
        elif suspicious > 0:
            score += 20
            reasons.append(f"🟠 Flagged suspicious by {suspicious} VT vendors (+20)")
            mitigations.append("⚠️ **MONITOR:** Domain shows suspicious activity. Monitor traffic to this URL and consider temporary proxy blocking pending further malware analysis.")

    # 2. WHOIS Domain Age check
    if whois_results.get('status') == "Success":
        age = whois_results.get('age_days')
        if isinstance(age, int) and age < 30:
            score += 25
            reasons.append(f"🔴 Newly registered domain (Age: {age} days) (+25)")
            mitigations.append("🕵️ **PHISHING RISK:** Treat this domain as highly suspicious. If business justification is lacking, block it at the proxy level. Warn users about potential spear-phishing originating from this domain.")

    # 3. SSL/TLS check
    if ssl_results.get('status') == "Success":
        days_to_expiry = ssl_results.get('days_to_expiry')
        if isinstance(days_to_expiry, int) and days_to_expiry < 15:
            score += 10
            reasons.append(f"🟠 SSL expires very soon ({days_to_expiry} days) (+10)")
            mitigations.append("🔄 **CERT RENEWAL:** Notify the domain owner/IT team to renew the SSL certificate before expiration to prevent service disruption and browser warnings.")
    else:
        score += 20
        reasons.append("🔴 Missing or invalid HTTPS certificate (+20)")
        mitigations.append("🔒 **ENCRYPTION FAILURE:** The site lacks secure encryption. Block POST requests to this domain to prevent credential harvesting. Educate users not to submit passwords or sensitive data here.")

    # 4. Security Headers check
    if header_results.get('status') == "Success":
        missing_headers = [h for h, v in header_results['data'].items() if "Missing" in v['status']]
        missing_count = len(missing_headers)
        if missing_count > 0:
            score += (missing_count * 5)
            reasons.append(f"🟡 Missing {missing_count} HTTP security headers (+{missing_count * 5})")
            mitigations.append(f"🛠️ **SERVER CONFIG:** The target web server is misconfigured. If this is an internal or vendor asset, require the administrators to implement the following headers: {', '.join(missing_headers)} to prevent XSS, Clickjacking, and downgrade attacks.")

    # Base case for safe URLs
    if not mitigations:
        mitigations.append("✅ **NO ACTION REQUIRED:** No immediate mitigations required based on current passive intelligence. Continue standard network monitoring.")

    # Cap score at 100 maximum
    score = min(score, 100)

    # Determine Risk Label
    if score < 15:
        level, color = "LOW RISK", "#00cc66" 
    elif score < 40:
        level, color = "MEDIUM RISK", "#ffcc00" 
    elif score < 70:
        level, color = "HIGH RISK", "#ff6600" 
    else:
        level, color = "CRITICAL RISK", "#cc0000" 

    return score, level, color, reasons, mitigations

# --- STREAMLIT DASHBOARD UI ---

def main():
    st.set_page_config(page_title="SOC URL Analyzer", page_icon="🔐", layout="wide")
    
    st.title("🔐 SOC URL Threat Analysis & Mitigation Tool")
    st.markdown("Passive OSINT, Risk Assessment & SOC Playbook Guidance")
    st.divider()

    with st.sidebar:
        st.header("⚙️ Configuration")
        vt_api_key = st.text_input("VirusTotal API Key (Optional):", type="password", help="Get a free key at virustotal.com")
        
        st.header("🎯 Target Input")
        target_url = st.text_input("Enter URL to analyze:", placeholder="https://example.com")
        analyze_btn = st.button("Analyze URL", type="primary")

    if analyze_btn and target_url:
        domain = extract_domain(target_url)
        st.subheader(f"🔍 Analysis Results for: `{domain}`")
        
        with st.spinner("Gathering Threat Intel & calculating risk..."):
            whois_results = get_whois_data(domain)
            ssl_results = get_ssl_info(domain)
            header_results = get_security_headers(target_url)
            vt_results = get_virustotal_reputation(target_url, vt_api_key)
            
            # Run the scoring & mitigation engine
            score, risk_level, color, reasoning, mitigations = analyze_risk_and_mitigate(whois_results, ssl_results, header_results, vt_results)
            
        # Display the Big Threat Score
        st.markdown(f"### 🎯 Threat Score: {score}/100 - <span style='color:{color}; font-weight:bold;'>{risk_level}</span>", unsafe_allow_html=True)
        st.progress(score / 100)
        
        # Split Reasoning and Mitigation into two clean columns
        col_reason, col_mitigate = st.columns(2)
        
        with col_reason:
            st.markdown("#### 🧠 Analyst Risk Reasoning")
            if score == 0:
                st.success("✅ No significant risk indicators found. The URL appears to be safe and well-configured.")
            else:
                for reason in reasoning:
                    st.write(reason)
                    
        with col_mitigate:
            st.markdown("#### 🛡️ Mandatory SOC Mitigations")
            for action in mitigations:
                if "CRITICAL" in action or "PHISHING" in action:
                    st.error(action)
                elif "ENCRYPTION" in action or "SERVER CONFIG" in action:
                    st.warning(action)
                else:
                    st.success(action)
        
        st.divider()

        # Detailed Findings Expanders
        st.markdown("### 📊 Detailed OSINT Findings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            with st.expander("🦠 VirusTotal Threat Intelligence", expanded=True):
                if vt_results['status'] == "Success":
                    st.write(f"**Malicious:** {vt_results['stats']['malicious']}")
                    st.write(f"**Suspicious:** {vt_results['stats']['suspicious']}")
                    st.write(f"**Harmless:** {vt_results['stats']['harmless']}")
                else:
                    st.write(vt_results['status'])

            with st.expander("📝 WHOIS Intelligence"):
                st.write(f"**Status:** {whois_results['status']}")
                if whois_results['status'] == "Success":
                    st.write(f"**Age:** {whois_results.get('age_days', 'N/A')} days")
                    st.write(f"**Registrar:** {whois_results['registrar']}")
        
        with col2:
            with st.expander("🔒 SSL/TLS Certificate Data", expanded=True):
                st.write(f"**Status:** {ssl_results['status']}")
                if ssl_results['status'] == "Success":
                    st.write(f"**Issuer:** {ssl_results['issuer']}")
                    st.write(f"**Expires In:** {ssl_results['days_to_expiry']} days")

            with st.expander("🛡️ HTTP Security Headers"):
                if header_results['status'] == "Success":
                    for header, info in header_results['data'].items():
                        st.write(f"**{header}:** {info['status']}")

    elif analyze_btn and not target_url:
        st.warning("Please enter a URL to analyze.")

if __name__ == "__main__":
    main()
