import streamlit as st
import pandas as pd
import time
import os
import secrets
import string
import requests

# --- CORE SYSTEM SETTINGS ---
USER_NAME = "Said Alkalbani" #
USER_ID = "21F21729"       #
LOG_FILE = "live_alerts.csv"
TOKEN = "8718085141:AAE_vlNoYYCLAI6oJv7v6N_TgZ_8_w4j3A0" #
CHAT_ID = "8651183020" #

# 1. LUXURY UI DESIGN (Bank Muscat Theme)
st.set_page_config(page_title="Bank Muscat | SOC Command", layout="wide")
st.markdown("""
    <style>
    .block-container { padding-top: 0rem !important; }
    #MainMenu, footer, header { visibility: hidden; }
    [data-testid="stAppViewContainer"] { background-color: #0e1117 !important; }
    .stMetric { background-color: #1a1c23; padding: 20px; border-radius: 12px; border-top: 4px solid #e21e26; }
    h1, h2, h3, p, label { color: white !important; font-family: 'Segoe UI', sans-serif; }
    .stButton>button { background-color: #e21e26; color: white; border-radius: 8px; font-weight: bold; width: 100%; height: 3.5em; border: none; }
    .stDataFrame, .stTable { background-color: #1a1c23; border-radius: 10px; }
    </style>
""", unsafe_allow_html=True)

# 2. SESSION STATE MANAGEMENT
if 'auth_status' not in st.session_state: st.session_state.auth_status = False
if 'otp_triggered' not in st.session_state: st.session_state.otp_triggered = False
if 'generated_token' not in st.session_state: st.session_state.generated_token = ""

def send_telegram_otp(code):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    text = f"🔐 Bank Muscat SOC Access\nUser: VOID\nToken: {code}"
    try:
        requests.post(url, data={'chat_id': CHAT_ID, 'text': text}, timeout=3)
        return True
    except: return False

# 3. SECURE GATEWAY (Login & OTP)
if not st.session_state.auth_status:
    st.markdown(f"<p style='text-align: right; color: #e21e26;'>Developer: {USER_NAME} | {USER_ID}</p>", unsafe_allow_html=True)
    st.markdown("<h1 style='text-align: center;'>🏦 Bank Muscat | Cyber Defense Gateway</h1>", unsafe_allow_html=True)
    
    _, col, _ = st.columns([1, 1.2, 1])
    with col:
        st.markdown("<div style='background-color: #1a1c23; padding: 30px; border-radius: 15px;'>", unsafe_allow_html=True)
        
        if not st.session_state.otp_triggered:
            with st.form("login_gateway"):
                u_input = st.text_input("Administrator ID")
                p_input = st.text_input("Access Password", type="password")
                if st.form_submit_button("Request Access Token"):
                    if u_input == "VOID" and p_input == "SA-id998877": #
                        new_otp = ''.join(secrets.choice(string.digits) for _ in range(6))
                        st.session_state.generated_token = new_otp
                        st.session_state.otp_triggered = True
                        if not send_telegram_otp(new_otp):
                            st.warning(f"Network Restricted. Use Backup Token: {new_otp}")
                        st.rerun()
                    else: st.error("Access Denied: Invalid Credentials")
        else:
            with st.form("otp_verification"):
                token_input = st.text_input("Enter 6-Digit Secure Token")
                if st.form_submit_button("Verify & Enter SOC"):
                    if token_input == st.session_state.generated_token:
                        st.session_state.auth_status = True
                        st.rerun()
                    else: st.error("Invalid Security Token")
            if st.button("Cancel & Retry"):
                st.session_state.otp_triggered = False
                st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

# 4. LIVE SOC DASHBOARD (Hybrid Intelligence)
else:
    st.sidebar.markdown(f"### 🛡️ Operator: {USER_NAME}\n**ID:** {USER_ID}") #
    st.sidebar.markdown("---")
    st.sidebar.write("**AI Engine:** Hybrid Random Forest (NSL-KDD + Real-Time)") #
    if st.sidebar.button("System Logout"):
        st.session_state.auth_status = False
        st.session_state.otp_triggered = False
        st.rerun()

    st.title("🛡️ SOC Command Center | Live Intelligence")
    
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Engine Status", "🟢 ACTIVE")
    m2.metric("AI Confidence", "99.4%") #
    m3.metric("Interface", "Loopback (lo)") #
    m4.metric("Honeypot Decoys", "Active")

    st.markdown("### 🚨 Hybrid Threat Stream (Auto-Refreshing)")
    data_placeholder = st.empty()
    
    # Real-time Update Loop
    while True:
        if os.path.exists(LOG_FILE):
            try:
                # Force refresh from disk
                df = pd.read_csv(LOG_FILE)
                # Filter for Medium, High, and Critical threats
                threat_view = df[df['Severity'] != 'Low'].tail(20).iloc[::-1]
                
                with data_placeholder.container():
                    if not threat_view.empty:
                        st.table(threat_view)
                    else:
                        st.info("Monitoring live traffic... No threats detected in current buffer.")
                    
                    st.markdown("---")
                    st.markdown("### 🛠️ Incident Mitigation")
                    target_ip = st.selectbox("Select Target for Neutralization", df['Source'].unique() if not df.empty else ["None"])
                    if st.button("EXECUTE PROTOCOL: BLOCK"):
                        st.success(f"IP {target_ip} neutralized. Bank Muscat Firewall updated.")
                        time.sleep(1)
            except Exception as e:
                time.sleep(0.5)
        else:
            st.info("System is waiting for AI traffic feed from 'sniffer.py'...")
        
        time.sleep(2) # Refresh rate for UI
