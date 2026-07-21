"""
sniffer.py - Fully integrated version
-----------------------------------------
This replaces the old signature-only detection (port == 80 / ICMP rules)
with the real pipeline that was missing before:

    raw packets -> ConnectionTracker (flow_aggregator.py) -> IDSEngine (ai_logic.py)

Every finished or timed-out connection is scored by the actual trained
Random Forest model, not by hardcoded port rules.

Remaining fixes carried over from the previous version:
- No hardcoded Telegram token / password - read from .env.
- No "Bank Muscat" branding.
- No unsafe file permissions.

Run with: sudo python sniffer.py   (root is required for raw packet capture)
Test only against your own network / devices that you own or are authorized
to monitor.
"""

import os
import time
import threading
from datetime import datetime

import pandas as pd
import requests
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from dotenv import load_dotenv

from flow_aggregator import ConnectionTracker
from ai_logic import IDSEngine

load_dotenv()


class Config:
    LOG_FILE = "live_alerts.csv"
    SYSTEM_LOG = "ids_internal.log"
    COLUMNS = ["Time", "Source", "Destination", "Service", "Flag", "Prediction", "Confidence", "Severity"]

    TELEGRAM_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

    IDLE_TIMEOUT_SECONDS = 5.0     # how long a quiet connection waits before being scored
    SWEEP_INTERVAL_SECONDS = 1.0   # how often we check for timed-out connections
    ALERT_COOLDOWN_SECONDS = 5.0   # suppress repeat console/Telegram alerts for the
                                    # same (source, prediction type) within this window -
                                    # every connection is still logged to the CSV either way,
                                    # this only reduces console/Telegram spam during things
                                    # like a fast port scan that produces dozens of distinct
                                    # connections in the same second.


class NIDSSniffer:
    def __init__(self, model_path: str = "ids_model_v3.pkl"):
        self.tracker = ConnectionTracker()
        self.engine = IDSEngine(model_path)
        self.initialize_system()
        self._last_sweep = time.time()
        self._last_alert_time = {}  # (src_ip, prediction_type) -> last alert timestamp

    def initialize_system(self):
        if not os.path.exists(Config.LOG_FILE) or os.stat(Config.LOG_FILE).st_size == 0:
            pd.DataFrame(columns=Config.COLUMNS).to_csv(Config.LOG_FILE, index=False)
        with open(Config.SYSTEM_LOG, "a") as f:
            f.write(f"[{datetime.now()}] ENGINE_START\n")
        print(f"[*] Logging initialized: {Config.LOG_FILE}")
        print(f"[*] Model loaded, ready to score live connections.")

    def telegram_sender(self, message: str):
        if not Config.TELEGRAM_TOKEN or not Config.TELEGRAM_CHAT_ID:
            return
        try:
            requests.post(
                f"https://api.telegram.org/bot{Config.TELEGRAM_TOKEN}/sendMessage",
                data={"chat_id": Config.TELEGRAM_CHAT_ID, "text": message},
                timeout=2,
            )
        except Exception:
            pass

    def process_packet(self, packet):
        if not packet.haslayer(IP):
            return

        src, dst = packet[IP].src, packet[IP].dst
        payload_len = len(packet[IP].payload)
        now = time.time()

        if packet.haslayer(TCP):
            protocol, dport, flags = "tcp", packet[TCP].dport, str(packet[TCP].flags)
        elif packet.haslayer(UDP):
            protocol, dport, flags = "udp", packet[UDP].dport, ""
        elif packet.haslayer(ICMP):
            protocol, dport, flags = "icmp", 0, ""
        else:
            return

        key, conn = self.tracker.ingest_packet(src, dst, dport, protocol, payload_len, flags, now)

        # Score immediately once a connection looks finished (FIN/RST seen);
        # otherwise it will be picked up later by sweep_timeouts().
        if self.tracker.is_finished(key):
            self.score_connection(key)

        if now - self._last_sweep > Config.SWEEP_INTERVAL_SECONDS:
            self._last_sweep = now
            for finished_key, result in self.tracker.sweep_timeouts(now, Config.IDLE_TIMEOUT_SECONDS):
                self.log_result(finished_key, result)

    def score_connection(self, key):
        result = self.tracker.finalize(key)
        if result:
            self.log_result(key, result)

    def log_result(self, key, feature_result):
        numeric_features, categorical_features = feature_result
        prediction = self.engine.analyze_raw(numeric_features, categorical_features)

        src_ip, dst_ip, dst_port, protocol = key
        timestamp = datetime.now().strftime("%H:%M:%S")

        row = [
            timestamp, src_ip, dst_ip,
            categorical_features["service"], categorical_features["flag"],
            prediction["type"], prediction["confidence"], prediction["severity"],
        ]

        try:
            df = pd.read_csv(Config.LOG_FILE)
            new_row_df = pd.DataFrame([row], columns=Config.COLUMNS)
            # Avoid pandas' FutureWarning about concatenating with an empty/
            # all-NA DataFrame (happens on the very first logged row, right
            # after initialize_system() creates an empty, header-only file).
            if df.empty:
                new_row_df.to_csv(Config.LOG_FILE, index=False)
            else:
                pd.concat([df, new_row_df], ignore_index=True).to_csv(Config.LOG_FILE, index=False)
        except Exception as e:
            print(f"[!] Logging error: {e}")

        if prediction["type"] != "Normal":
            alert_key = (src_ip, prediction["type"])
            now = time.time()
            last_time = self._last_alert_time.get(alert_key, 0)

            if now - last_time >= Config.ALERT_COOLDOWN_SECONDS:
                self._last_alert_time[alert_key] = now
                print(f"[{timestamp}] ALERT: {prediction['type']} ({prediction['confidence']}%) "
                      f"from {src_ip} -> {dst_ip}:{dst_port} [{prediction['severity']}]")
                threading.Thread(
                    target=self.telegram_sender,
                    args=(f"NIDS Alert\nType: {prediction['type']}\nFrom: {src_ip}\n"
                          f"Confidence: {prediction['confidence']}%\nSeverity: {prediction['severity']}",),
                ).start()
            # else: suppressed to avoid console/Telegram spam - the row above
            # is still written to live_alerts.csv regardless, so no data is lost.


def detect_default_interface() -> str:
    """
    Auto-detects the network interface currently used for outbound traffic
    (the one with the default route) instead of requiring it to be hardcoded.
    Can still be overridden manually via the NIDS_IFACE environment variable
    if auto-detection picks the wrong one (e.g. multiple active adapters).
    """
    override = os.environ.get("NIDS_IFACE")
    if override:
        print(f"[*] Using interface from NIDS_IFACE override: {override}")
        return override

    try:
        iface = scapy.conf.iface
        print(f"[*] Auto-detected active interface: {iface}")
        return str(iface)
    except Exception as e:
        print(f"[!] Could not auto-detect interface ({e}), falling back to 'eth0'.")
        print("[!] Run 'ip a' to find your real interface name, then set it via "
              "NIDS_IFACE=<name> or edit this fallback.")
        return "eth0"


if __name__ == "__main__":
    sniffer = NIDSSniffer()
    print("[*] Monitoring interface... (Ctrl+C to stop)")
    iface = detect_default_interface()
    try:
        scapy.sniff(store=0, prn=sniffer.process_packet, iface=iface)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
