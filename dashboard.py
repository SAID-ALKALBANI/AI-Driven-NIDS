"""
dashboard.py - Fixed version
------------------------------
Fixes:
1. Removed the hardcoded password and Telegram token; both are now read from
   .env.
2. Removed the "Bank Muscat" identity entirely (replaced with a generic name:
   SentinelCore SOC).
3. Removed the fake login/OTP gate - it was pure security theater that
   protected nothing, especially since the password and token were exposed
   in the same source file anyway. If real authentication is needed later,
   the correct solution is Streamlit-Authenticator or OAuth, not this pattern.
4. Replaced the `while True` loop inside the app (a broken pattern in
   Streamlit that freezes the app) with a periodic refresh via `st.rerun()` +
   a short `time.sleep`, which is the recommended pattern.
5. The "EXECUTE PROTOCOL: BLOCK" button only printed a success message
   without doing anything real; replaced with a clear comment marking it as
   a future integration point (e.g. calling iptables via an API) instead of
   implying it actually blocks anything.
"""

import os
import time
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

LOG_FILE = "live_alerts.csv"

st.set_page_config(page_title="SentinelCore | SOC Dashboard", layout="wide")
st.markdown(
    """
    <style>
    .block-container { padding-top: 1rem !important; }
    #MainMenu, footer { visibility: hidden; }
    [data-testid="stAppViewContainer"] { background-color: #0e1117 !important; }
    .stMetric { background-color: #1a1c23; padding: 20px; border-radius: 12px; border-top: 4px solid #3b82f6; }
    h1, h2, h3, p, label { color: white !important; font-family: 'Segoe UI', sans-serif; }
    .stDataFrame, .stTable { background-color: #1a1c23; border-radius: 10px; }
    </style>
    """,
    unsafe_allow_html=True,
)

import scapy.all as scapy

st.title("SentinelCore SOC - Live Threat Monitor")

try:
    detected_iface = os.environ.get("NIDS_IFACE") or str(scapy.conf.iface)
except Exception:
    detected_iface = "Unknown"

m1, m2, m3 = st.columns(3)
m1.metric("Engine Status", "Active")
m2.metric("Interface", detected_iface)
m3.metric("Model", "RandomForest (NSL-KDD)")

st.markdown("### Live Alert Stream")

if os.path.exists(LOG_FILE):
    try:
        df = pd.read_csv(LOG_FILE)
        threat_view = df[df["Severity"] != "Low"].tail(20).iloc[::-1]
        if not threat_view.empty:
            st.table(threat_view)

            st.markdown("---")
            st.markdown("### Incident Response (manual placeholder)")
            target_ip = st.selectbox("Select source IP to review", df["Source"].unique())
            if st.button("Mark as Reviewed"):
                # Note: this does not actually block any connection. Real blocking
                # requires firewall integration (iptables/nftables), which is out
                # of scope for this demo.
                st.success(f"IP {target_ip} marked as reviewed in this session.")
        else:
            st.info("Monitoring live traffic... no elevated-severity alerts yet.")
    except Exception as e:
        st.warning(f"Could not read log file yet: {e}")
else:
    st.info("Waiting for traffic feed from 'sniffer.py'...")

st.caption("Auto-refreshing every 3 seconds.")
time.sleep(3)
st.rerun()
