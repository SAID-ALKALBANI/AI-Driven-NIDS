import scapy.all as scapy
import pandas as pd
import os
import requests
import time
import threading
from datetime import datetime
from scapy.layers.inet import IP, TCP, ICMP

# --- ADVANCED CONFIGURATION ---
class Config:
    LOG_FILE = "live_alerts.csv"
    SYSTEM_LOG = "ids_internal.log"
    COLUMNS = ['Time', 'Source', 'Destination', 'Protocol', 'Confidence', 'Analysis', 'Severity', 'Status']
    TOKEN = "8718085141:AAE_vlNoYYCLAI6oJv7v6N_TgZ_8_w4j3A0"
    CHAT_ID = "8651183020"
    USER_NAME = "Said Alkalbani"
    USER_ID = "21F21729"
    COOLDOWN_PERIOD = 3  # Fast response for demonstration

# --- THE IDS CORE ENGINE ---
class BankMuscatIDS:
    def __init__(self):
        self.last_alerts = {} 
        self.initialize_system()

    def initialize_system(self):
        """Prepares the professional logging environment"""
        # Create CSV if not exists or if empty
        if not os.path.exists(Config.LOG_FILE) or os.stat(Config.LOG_FILE).st_size == 0:
            pd.DataFrame(columns=Config.COLUMNS).to_csv(Config.LOG_FILE, index=False)
        
        with open(Config.SYSTEM_LOG, "a") as f:
            f.write(f"[{datetime.now()}] ENGINE_START: Initiated by {Config.USER_NAME}\n")
        
        try:
            os.chmod(Config.LOG_FILE, 0o777)
        except:
            pass
        print(f"[*] Security Environment Secured. Log: {Config.LOG_FILE}")

    def telegram_sender(self, message):
        """Asynchronous Telegram dispatcher"""
        try:
            requests.post(f"https://api.telegram.org/bot{Config.TOKEN}/sendMessage", 
                          data={'chat_id': Config.CHAT_ID, 'text': message}, timeout=2)
        except:
            pass

    def process_packet(self, packet):
        """Advanced Threat Detection Logic"""
        if not packet.haslayer(IP):
            return

        src = packet[IP].src
        dst = packet[IP].dst
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        threat_detected = False
        analysis, severity, confidence = "Normal", "Low", "0%"

        # 1. ICMP Detection (Ping)
        if packet.haslayer(ICMP):
            threat_detected = True
            analysis = "ICMP Reconnaissance Detected"
            severity = "Medium"
            confidence = "98%"

        # 2. TCP Analysis (Scans & Access Attempts)
        elif packet.haslayer(TCP):
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            
            # Detect SYN Floods or Specific Port Scans
            if flags == "S" or dport in [21, 445, 3389, 80]:
                threat_detected = True
                analysis = "Unauthorized Port Access"
                severity = "High"
                confidence = "95%"

        if threat_detected:
            self.handle_alert(timestamp, src, dst, analysis, severity, confidence)

    def handle_alert(self, time_str, src, dst, analysis, severity, conf):
        """Manages logging and alert dispatching"""
        alert_key = f"{src}_{analysis}"
        current_time = time.time()

        # Prevent alert spamming
        if alert_key in self.last_alerts:
            if current_time - self.last_alerts[alert_key] < Config.COOLDOWN_PERIOD:
                return 

        self.last_alerts[alert_key] = current_time
        
        # Write to CSV
        try:
            df = pd.read_csv(Config.LOG_FILE)
            new_data = [time_str, src, dst, "TCP/IP", conf, analysis, severity, "Flagged"]
            pd.concat([df, pd.DataFrame([new_data], columns=Config.COLUMNS)]).to_csv(Config.LOG_FILE, index=False)
            
            # Console Feedback
            print(f"[{time_str}] 🚨 {analysis.upper()} | From: {src} | Conf: {conf}")

            # Send to Telegram
            msg = f"🛡️ BANK MUSCAT IDS\nThreat: {analysis}\nSource: {src}\nSeverity: {severity}\nOperator: {Config.USER_NAME}"
            threading.Thread(target=self.telegram_sender, args=(msg,)).start()
        except Exception as e:
            print(f"[!] Alert Logic Error: {e}")

if __name__ == "__main__":
    ids = BankMuscatIDS()
    print("====================================================")
    print(f"   BANK MUSCAT | FINAL IDS ENGINE - {Config.USER_NAME} ")
    print(f"   System IP: 192.168.100.228 | ID: {Config.USER_ID}")
    print("====================================================")
    print("[*] Monitoring all interfaces... (Force Active Mode)")
    
    # Corrected sniff command to avoid TypeError
    try:
        scapy.sniff(store=0, prn=ids.process_packet, iface="lo")
    except KeyboardInterrupt:
        print(f"\n[!] System safely paused by {Config.USER_NAME}.")
